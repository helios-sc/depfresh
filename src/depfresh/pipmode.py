"""Minimal remediation for manifests resolved at build time.

Requirements files and ``pyproject.toml`` projects without a lock ship
whatever a fresh resolution picks when the image is built.  depfresh models
that build for the deploy platform instead of the machine it runs on:

1. resolve the manifest with ``uv pip compile --python-platform <target>
   --python-version X.Y`` (default ``x86_64-unknown-linux-gnu``);
2. audit that set and plan the lowest fixing release per vulnerable package;
3. edit *only* the affected requirement lines: a pin moves to the fixed
   version (``==``), a floor is raised to it (``>=``), comments, markers,
   extras, ordering and every other line stay as they are; a vulnerable
   transitive package that the file does not list gets a commented floor
   line (``pkg>=X  # depfresh: GHSA-…``);
4. when a pin elsewhere in the file blocks a fix (``fastapi==0.129.0``
   caps Starlette below 1.0), find the lowest co-upgrade with a resolution
   that prefers every current version (``--resolution lowest-direct`` with
   the baseline as preferences) and pin that;
5. resolve the edited manifest again, fresh, as the build would, and
   audit it.

A floor is never read as the version that ships: the baseline is the
resolution, so ``google-cloud-storage>=2.10.0`` stays at the 3.17.1 the
build installs instead of being "upgraded" to 2.19.0.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tomlkit
from packaging.requirements import InvalidRequirement, Requirement

from depfresh.advisories import AdvisorySources, FixPlan, TargetEnv, evaluate_marker
from depfresh.constraints import admit_version, normalise
from depfresh.exceptions import (
    CommandError,
    DepfreshError,
    DirectReferenceError,
    PrivateIndexError,
)
from depfresh.indexes import PrivateScope, other_index_note, private_scope
from depfresh.lockmode import check_static_dependencies, is_pypi_index
from depfresh.models import ImportCheck, PackageChange, Vulnerability
from depfresh.parsers import DependencyFormat
from depfresh.remediation import (
    Auditor,
    ImportGate,
    RemediationOptions,
    cobump_problem,
    database_findings,
    diff_sets,
    keep_repository_findings_open,
    plan,
    record_plans,
    snapshot_plans,
)
from depfresh.reqlines import (
    COMMENT_RE,
    RequirementsTree,
    check_no_direct_references,
    inspect_tree,
    parse_lines,
)
from depfresh.textio import TextFile, read_text_file, with_newlines_of
from depfresh.uv import create_venv, run, uv_env

log = logging.getLogger("depfresh")

PIP_FORMATS = (
    DependencyFormat.REQUIREMENTS_SIMPLE,
    DependencyFormat.REQUIREMENTS_HASHED,
    DependencyFormat.REQUIREMENTS_IN,
    DependencyFormat.PYPROJECT_PEP621,
)

_NAME = re.compile(r"^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?")


# ---------------------------------------------------------------------------
# uv pip compile output
# ---------------------------------------------------------------------------


@dataclass
class Resolution:
    """A ``uv pip compile`` result.

    Attributes:
        pins: ``{name: version}`` of every resolved registry package.
        via: ``{name: {parents}}`` from the ``# via`` annotations.
        index: ``{name: index_url}`` from ``--emit-index-annotation``.
        direct_refs: Resolved lines that are URLs or paths.
        text: The raw output, reusable as a preferences file.
    """

    pins: dict[str, str] = field(default_factory=dict)
    via: dict[str, set[str]] = field(default_factory=dict)
    index: dict[str, str] = field(default_factory=dict)
    direct_refs: list[str] = field(default_factory=list)
    text: str = ""

    def private(self, scope: PrivateScope | None = None) -> dict[str, str]:
        """Packages of *scope* (see :mod:`depfresh.indexes`), ``{name: index}``."""
        scope = scope or PrivateScope()
        return {
            name: self.index.get(name) or scope.pinned.get(name, "") for name in self.pins
            if scope.is_private(name, self.index.get(name))
        }

    def public_pins(self, scope: PrivateScope | None = None) -> dict[str, str]:
        """The packages to audit: every pin outside *scope*."""
        private = self.private(scope)
        return {n: v for n, v in self.pins.items() if n not in private}

    def other_index(self, scope: PrivateScope | None = None) -> dict[str, str]:
        """Audited packages that a non-PyPI index serves, ``{name: url}``."""
        private = self.private(scope)
        return {
            name: self.index[name] for name in self.pins
            if name not in private and name in self.index and not is_pypi_index(self.index[name])
        }


def parse_compile_output(text: str) -> Resolution:
    """Parse ``uv pip compile --annotation-style line --emit-index-annotation`` output."""
    result = Resolution(text=text)
    last: str | None = None
    for raw in text.splitlines():
        if not raw.strip():
            continue
        if raw[:1].isspace():
            note = raw.strip()
            if last and note.startswith("# from "):
                result.index[last] = note[len("# from "):].strip()
            continue
        if raw.startswith(("#", "-")):
            continue
        code, _, comment = raw.partition("  # via ")
        code = code.split(" #", 1)[0].strip()
        try:
            req = Requirement(code)
        except InvalidRequirement:
            continue
        name = normalise(req.name)
        if req.url:
            result.direct_refs.append(code)
            last = None
            continue
        pins = [s.version for s in req.specifier if s.operator in ("==", "===")]
        if not pins:
            continue
        result.pins[name] = pins[0]
        result.via[name] = {
            normalise(p.strip()) for p in comment.split(",")
            if p.strip() and not p.strip().startswith("-r") and "(" not in p
        }
        last = name
    return result


# ---------------------------------------------------------------------------
# Line-preserving manifest editors
# ---------------------------------------------------------------------------


def split_requirement(code: str) -> tuple[str, int, int] | None:
    """Locate the version specifier in a requirement string.

    Returns ``(name, start, end)`` with the specifier at ``code[start:end]``
    (empty when there is none), or ``None`` when *code* is not a registry
    requirement (comment, option, URL or path).
    """
    match = _NAME.match(code)
    if match is None:
        return None
    start = match.end()
    marker = code.find(";", start)
    end = marker if marker != -1 else len(code)
    spec = code[start:end]
    if spec.lstrip().startswith("@"):
        return None
    lead = len(spec) - len(spec.lstrip())
    trail = len(spec.rstrip())
    return match.group(1), start + lead, start + max(lead, trail)


def _code_part(line: str) -> str:
    """The requirement text of a physical line: no newline, comment, options or ``\\``."""
    body = line.rstrip("\r\n")
    comment = re.search(r"(^|\s)#", body)
    if comment:
        body = body[:comment.start()]
    option = re.search(r"\s--?[a-z]", body)
    if option:
        body = body[:option.start()]
    body = body.rstrip()
    if body.endswith("\\"):
        body = body[:-1].rstrip()
    return body


@dataclass
class _Entry:
    """One registry requirement of a requirements file.

    Attributes:
        start, end: Physical line range (continuations included).
        name: Normalised project name.
        requirement: The logical requirement (name, extras, specifier, marker).
        spec: Its specifier text.
        marker: Its marker text, or ``None``.
        options: Per-requirement options other than ``--hash``.
        hashed: Whether the entry carries ``--hash`` options.
    """

    start: int
    end: int
    name: str
    requirement: str
    spec: str
    marker: str | None
    options: str
    hashed: bool


class AmbiguousRequirementError(DepfreshError):
    """Raised when a package to edit is listed on several lines that all apply."""


class RequirementsDocument:
    """A requirements file that can be edited one requirement at a time.

    With *env*, an entry whose marker is false for that target is left alone,
    and editing a package that several applicable lines list is refused
    (:class:`AmbiguousRequirementError`): depfresh would have to guess which
    line ships.
    """

    def __init__(self, text: str, env: TargetEnv | None = None) -> None:
        self.lines = text.splitlines(keepends=True)
        self.newline = "\r\n" if self.lines and self.lines[0].endswith("\r\n") else "\n"
        self.env = env
        self.all_entries: list[_Entry] = []
        self.direct_refs: list[str] = []
        self.appended: list[str] = []
        self._parse()

    def _parse(self) -> None:
        for line in parse_lines("".join(self.lines)):
            if line.kind == "direct":
                self.direct_refs.append(line.requirement or line.code)
                continue
            if line.kind != "registry":
                continue
            requirement = line.requirement
            split = split_requirement(requirement)
            if split is None:
                continue
            name, s, e = split
            marker = requirement.split(";", 1)[1].strip() if ";" in requirement[e:] else None
            options = line.code[line.code.find(requirement) + len(requirement):].strip()
            other = " ".join(t for t in re.split(r"\s+(?=--)", options)
                             if t and not t.startswith("--hash"))
            self.all_entries.append(_Entry(
                line.start, line.end, normalise(name), requirement, requirement[s:e], marker,
                other, "--hash" in options,
            ))

    def _applies(self, entry: _Entry) -> bool:
        return self.env is None or evaluate_marker(entry.marker, self.env)

    def entries_for(self, name: str) -> list[_Entry]:
        """Every entry of *name* whose marker holds on the target."""
        key = normalise(name)
        return [e for e in self.all_entries if e.name == key and self._applies(e)]

    @property
    def ambiguous(self) -> dict[str, list[int]]:
        """``{name: [line numbers]}`` for packages several applicable lines list."""
        seen: dict[str, list[int]] = {}
        for entry in self.all_entries:
            if self._applies(entry):
                seen.setdefault(entry.name, []).append(entry.start + 1)
        return {name: lines for name, lines in seen.items() if len(lines) > 1}

    @property
    def entries(self) -> dict[str, _Entry]:
        """The single applicable entry of every unambiguous package."""
        ambiguous = self.ambiguous
        out: dict[str, _Entry] = {}
        for entry in self.all_entries:
            if self._applies(entry) and entry.name not in ambiguous:
                out.setdefault(entry.name, entry)
        return out

    def listed(self) -> dict[str, str]:
        """``{name: specifier}`` of the applicable, unambiguous requirements."""
        return {name: entry.spec for name, entry in self.entries.items()}

    def entry(self, name: str) -> _Entry:
        """The one applicable entry of *name*.

        Raises:
            AmbiguousRequirementError: When several applicable lines list it.
            KeyError: When none does.
        """
        found = self.entries_for(name)
        if len(found) > 1:
            lines = ", ".join(str(e.start + 1) for e in found)
            raise AmbiguousRequirementError(
                f"{normalise(name)} is listed on lines {lines} and more than one applies to "
                f"the target; depfresh will not guess which one ships. Merge them, or make "
                "their markers exclusive."
            )
        if not found:
            raise KeyError(name)
        return found[0]

    def set_spec(self, name: str, spec: str, hashes: list[str] | None = None) -> None:
        """Replace the specifier of *name* (and its ``--hash`` lines when given)."""
        entry = self.entry(name)
        first = self.lines[entry.start]
        newline = self.newline if first.endswith(("\n", "\r")) else ""
        if entry.start == entry.end and not (entry.hashed and hashes is not None):
            code = _code_part(first)
            split = split_requirement(code)
            if split is not None:
                _, s, e = split
                self.lines[entry.start] = first[:s] + spec + first[e:]
                entry.spec = spec
                return
        indent = first[:len(first) - len(first.lstrip())]
        _, s, e = split_requirement(entry.requirement) or ("", 0, 0)
        requirement = re.sub(r"\s+", " ", entry.requirement[:s] + spec + entry.requirement[e:])
        requirement = re.sub(r"\s*;\s*", " ; ", requirement)
        last = self.lines[entry.end].rstrip("\r\n")
        comment_match = COMMENT_RE.search(last)
        comment = comment_match.group(0) if comment_match else ""
        options = f" {entry.options}" if entry.options else ""
        if entry.hashed and hashes is not None:
            block = [f"{indent}{requirement}{options} \\{self.newline}"]
            for j, digest in enumerate(hashes):
                cont = " \\" if j < len(hashes) - 1 else comment
                block.append(f"    --hash={digest}{cont}{self.newline}")
        else:
            block = [f"{indent}{requirement}{options}{comment}{self.newline}"]
        if not newline:
            block[-1] = block[-1].rstrip("\r\n")
        if not self.lines[entry.end].endswith(("\n", "\r")):
            block[-1] = block[-1].rstrip("\r\n")
        delta = len(block) - (entry.end - entry.start + 1)
        self.lines[entry.start:entry.end + 1] = block
        for other in self.all_entries:
            if other.start > entry.start:
                other.start += delta
                other.end += delta
        entry.end = entry.start + len(block) - 1
        entry.requirement = requirement
        entry.spec = spec

    def append(self, line: str) -> None:
        """Add *line* at the end of the file."""
        self.appended.append(line)

    def render(self) -> str:
        out = "".join(self.lines)
        if self.appended:
            if out and not out.endswith(("\n", "\r")):
                out += self.newline
            out += "".join(f"{line}{self.newline}" for line in self.appended)
        return out


class PyprojectDocument:
    """``[project]`` dependencies of a pyproject.toml, edited with tomlkit."""

    def __init__(
        self, text: str, extras: Iterable[str], all_extras: bool, env: TargetEnv | None = None,
    ) -> None:
        self.env = env
        self.original = text
        self.doc = tomlkit.parse(text)
        self.extras = list(extras)
        self.all_extras = all_extras
        self.direct_refs: list[str] = []
        project: Any = self.doc.get("project", {})
        self.arrays: list[tuple[str, Any]] = []
        if "dependencies" in project:
            self.arrays.append(("", project["dependencies"]))
        optional: Any = project.get("optional-dependencies", {})
        for group in optional:
            if all_extras or group in self.extras:
                self.arrays.append((str(group), optional[group]))
        for _, array in self.arrays:
            for item in array:
                try:
                    if Requirement(str(item)).url:
                        self.direct_refs.append(str(item))
                except InvalidRequirement:
                    continue

    def _items(self) -> list[tuple[Any, int, str]]:
        """Requirement strings whose marker holds on the target (all, without a target)."""
        found = []
        for _, array in self.arrays:
            for i, item in enumerate(array):
                text = str(item)
                if split_requirement(text) is None:
                    continue
                if self.env is not None:
                    try:
                        marker = Requirement(text).marker
                    except InvalidRequirement:
                        continue
                    if not evaluate_marker(str(marker) if marker else None, self.env):
                        continue
                found.append((array, i, text))
        return found

    def listed(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for _, _, text in self._items():
            split = split_requirement(text)
            if split is not None:
                name, s, e = split
                out.setdefault(normalise(name), text[s:e])
        return out

    def set_spec(self, name: str, spec: str, hashes: list[str] | None = None) -> None:
        for array, i, text in self._items():
            split = split_requirement(text)
            if split is None or normalise(split[0]) != normalise(name):
                continue
            _, s, e = split
            array[i] = text[:s] + spec + text[e:]

    def append(self, line: str, *, extra: str | None = None) -> None:
        requirement, _, comment = line.partition("  # ")
        target = next((a for g, a in self.arrays if g == (extra or "")), None)
        if target is None:
            project: Any = self.doc.setdefault("project", tomlkit.table())
            if "dependencies" not in project:
                project["dependencies"] = tomlkit.array()
            target = project["dependencies"]
            self.arrays.insert(0, ("", target))
        target.multiline(True)
        target.add_line(requirement.strip(), comment=comment.strip() or None)

    def render(self) -> str:
        return with_newlines_of(tomlkit.dumps(self.doc), self.original)


def strip_pyproject_direct_refs(text: str) -> str:
    """Drop direct requirements from every dependency list (--ignore-direct-references).

    Direct means ``name @ url``, or a name ``[tool.uv.sources]`` maps to a
    path, workspace member, VCS repository or URL.
    """
    doc = tomlkit.parse(text)
    sourced = set(local_sources(doc.unwrap()))
    project: Any = doc.get("project", {})
    arrays = [project["dependencies"]] if "dependencies" in project else []
    arrays += list((project.get("optional-dependencies") or {}).values())
    for array in arrays:
        for i in reversed(range(len(array))):
            try:
                req = Requirement(str(array[i]))
            except InvalidRequirement:
                continue
            if req.url or normalise(req.name) in sourced:
                del array[i]
    return tomlkit.dumps(doc)


def local_sources(pyproject: dict[str, Any]) -> dict[str, str]:
    """``{name: kind}`` for ``[tool.uv.sources]`` entries uv would build or fetch directly.

    Index sources (``{ index = "…" }``) are not included: those resolve from
    an index like any registry requirement.
    """
    sources = pyproject.get("tool", {}).get("uv", {}).get("sources") or {}
    found: dict[str, str] = {}
    for name, source in sources.items():
        entries = source if isinstance(source, list) else [source]
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            kind = next((k for k in ("path", "workspace", "git", "url") if k in entry), None)
            if kind is not None:
                found[normalise(str(name))] = kind
    return found


def source_direct_refs(manifest: Path, listed: dict[str, str]) -> list[str]:
    """Listed dependencies that ``[tool.uv.sources]`` maps to a path, VCS or URL."""
    data = tomlkit.parse(manifest.read_text(encoding="utf-8")).unwrap()
    return [
        f"{name} ([tool.uv.sources]: {kind})"
        for name, kind in sorted(local_sources(data).items()) if name in listed
    ]


def open_document(
    fmt: DependencyFormat, text: str, options: RemediationOptions,
) -> RequirementsDocument | PyprojectDocument:
    if fmt == DependencyFormat.PYPROJECT_PEP621:
        return PyprojectDocument(text, options.extras, options.all_extras, env=options.env)
    return RequirementsDocument(text, env=options.env)


def check_unambiguous(doc: RequirementsDocument | PyprojectDocument, names: Iterable[str]) -> None:
    """Refuse to edit a package that several applicable lines list."""
    if isinstance(doc, RequirementsDocument):
        for name in names:
            if normalise(name) in doc.ambiguous:
                doc.entry(name)  # raises AmbiguousRequirementError


# ---------------------------------------------------------------------------
# Workspace: a scratch copy of the manifest and its includes
# ---------------------------------------------------------------------------


class PipWorkspace:
    """The manifest (as UTF-8) plus every file it includes, in a scratch directory.

    uv runs with the *target* directory as its working directory, so the
    project's uv configuration (``uv.toml``, ``[tool.uv]``) applies exactly
    as it would for the real build, while the inputs are scratch copies laid
    out like the target, so relative ``-r``/``-c`` includes resolve.
    """

    def __init__(
        self,
        uv: str,
        target_dir: Path,
        manifest: Path,
        fmt: DependencyFormat,
        work_dir: Path,
        options: RemediationOptions,
        ignore_direct_references: bool,
    ) -> None:
        self.uv = uv
        self.target_dir = target_dir.resolve()
        self.fmt = fmt
        self.options = options
        self.root = work_dir / "manifest"
        self.root.mkdir(parents=True, exist_ok=True)
        self.original: TextFile = read_text_file(manifest)
        self.manifest_name = manifest.name
        try:
            self.manifest_rel = manifest.resolve().relative_to(self.target_dir)
        except ValueError:
            self.manifest_rel = Path(manifest.name)
        self.commands: list[str] = []
        self.ignore_direct_references = ignore_direct_references
        self.counter = 0
        self._extra_pins: dict[str | None, dict[str, str]] = {}
        self.tree: RequirementsTree | None = None
        #: What counts as private: the manifest's own pins (pyproject.toml),
        #: or those of the pyproject.toml files next to a requirements file
        #: and in the target, plus the explicit indexes of every uv.toml uv
        #: would read from here.
        pins = [manifest] if fmt == DependencyFormat.PYPROJECT_PEP621 else [
            manifest.parent / "pyproject.toml", self.target_dir / "pyproject.toml",
        ]
        configs = [d / "uv.toml" for d in (self.target_dir, *self.target_dir.parents)]
        self.scope = private_scope(dict.fromkeys(pins), configs)
        if fmt != DependencyFormat.PYPROJECT_PEP621:
            self.tree = inspect_tree(manifest, self.target_dir)
            if not ignore_direct_references:
                check_no_direct_references(self.tree, manifest)
            self._copy_includes(manifest.resolve())

    def _copy_includes(self, manifest: Path) -> None:
        """Mirror every included file into the scratch root, without direct lines.

        Direct lines are refused unless --ignore-direct-references, in which
        case they are dropped from every copy, so uv never meets a path,
        archive, VCS or URL requirement of the target.
        """
        assert self.tree is not None
        for path in self.tree.files:
            if path == manifest:
                continue
            dest = self.root / self.tree.relative(path)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(self.tree.sanitized(path), encoding="utf-8")

    def write(self, text: str) -> Path:
        """Write a candidate manifest (UTF-8, direct references stripped if allowed)."""
        self.counter += 1
        if self.fmt == DependencyFormat.PYPROJECT_PEP621:
            folder = self.root / f"candidate-{self.counter}"
            folder.mkdir()
            path = folder / "pyproject.toml"
        else:
            folder = (self.root / self.manifest_rel).parent
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / f".depfresh-candidate-{self.counter}-{self.manifest_name}"
        path.write_text(self._strip_direct_refs(text), encoding="utf-8")
        return path

    def _strip_direct_refs(self, text: str) -> str:
        if self.fmt == DependencyFormat.PYPROJECT_PEP621:
            return strip_pyproject_direct_refs(text) if self.ignore_direct_references else text
        lines = parse_lines(text)
        direct = [line for line in lines if line.kind == "direct"]
        if direct and not self.ignore_direct_references:
            refs = [d.requirement or d.code for d in direct]
            raise DirectReferenceError(self.manifest_name, refs)
        physical = text.splitlines(keepends=True)
        drop = {i for d in direct for i in range(d.start, d.end + 1)}
        return "".join(line for i, line in enumerate(physical) if i not in drop)

    def runtime_pins(self) -> dict[str, str]:
        """The resolution without any extra (where a transitive floor belongs)."""
        return self.extra_pins(None)

    def extra_pins(self, extra: str | None) -> dict[str, str]:
        """The resolution of the original manifest with only *extra* (``None``: none)."""
        if extra not in self._extra_pins:
            saved = self.options
            self.options = RemediationOptions(env=saved.env, extras=(extra,) if extra else ())
            try:
                self._extra_pins[extra] = self.compile(self.write(self.original.text)).pins
            except CommandError:
                self._extra_pins[extra] = {}
            finally:
                self.options = saved
        return self._extra_pins[extra]

    def compile(
        self,
        manifest: Path,
        *,
        preferences: str | None = None,
        lowest_direct: bool = False,
        record: bool = False,
    ) -> Resolution:
        """``uv pip compile`` *manifest* for the deploy platform.

        Raises:
            CommandError: If the requirements cannot be resolved.
            PrivateIndexError: If a non-PyPI index cannot be reached.
        """
        env = self.options.env
        args = [
            "pip", "compile", str(manifest),
            "--python-platform", env.platform,
            "--python-version", env.python_minor,
            "--no-header", "--annotation-style", "line", "--emit-index-annotation",
        ]
        if self.fmt == DependencyFormat.PYPROJECT_PEP621:
            if self.options.all_extras:
                args.append("--all-extras")
            for extra in self.options.extras:
                args += ["--extra", extra]
        output_file: Path | None = None
        if preferences is not None:
            self.counter += 1
            output_file = self.root / f"preferences-{self.counter}.txt"
            output_file.write_text(preferences, encoding="utf-8")
            args += ["-o", str(output_file)]
        if lowest_direct:
            args += ["--resolution", "lowest-direct"]
        if record:
            self.commands.append(
                "uv " + " ".join(a if a != str(manifest) else self.manifest_name for a in args)
            )
        try:
            result = run([self.uv, *args], cwd=self.target_dir, env=uv_env())
        except CommandError as exc:
            _raise_if_private_index(exc)
            raise
        text = output_file.read_text(encoding="utf-8") if output_file else result.stdout
        return parse_compile_output(text)

    def hashes(self, pins: dict[str, str]) -> dict[str, list[str]]:
        """``--hash`` values for exact pins (all distributions of each release)."""
        if not pins:
            return {}
        self.counter += 1
        path = self.root / f"hashes-{self.counter}.in"
        path.write_text("".join(f"{n}=={v}\n" for n, v in sorted(pins.items())))
        result = run(
            [self.uv, "pip", "compile", str(path), "--no-deps", "--generate-hashes",
             "--no-header", "--no-annotate", "--universal"],
            cwd=self.target_dir, env=uv_env(),
        )
        hashes: dict[str, list[str]] = {}
        current: str | None = None
        for line in result.stdout.splitlines():
            stripped = line.strip().rstrip("\\").strip()
            if stripped.startswith("--hash="):
                if current:
                    hashes.setdefault(current, []).append(stripped[len("--hash="):])
            elif stripped and not stripped.startswith("#"):
                try:
                    current = normalise(Requirement(stripped).name)
                except InvalidRequirement:
                    current = None
        return hashes


def _raise_if_private_index(exc: CommandError) -> None:
    for token in exc.stderr.replace("`", " ").split():
        if token.startswith(("http://", "https://")) and not is_pypi_index(token) and (
            "Failed to fetch" in exc.stderr or "error sending request" in exc.stderr
        ):
            raise PrivateIndexError(token.rstrip(":/") + "/", exc.stderr) from exc


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------


@dataclass
class PipOutcome:
    """Everything a resolved-mode run found and changed."""

    baseline: Resolution
    final: Resolution
    pre_vulns: list[Vulnerability]
    post_vulns: list[Vulnerability]
    plans: dict[str, FixPlan]
    failures: dict[str, str]
    new_text: str
    changed: bool
    resolution_check: str
    commands: list[str]
    notes: list[str]
    not_audited: list[str]
    gate: ImportGate
    direct_refs: list[str]
    original_text: str = ""
    audited_count: int | None = None
    other_index: dict[str, str] = field(default_factory=dict)

    def baseline_text_lines(self) -> list[str]:
        return self.original_text.splitlines(keepends=True)


def remediate_pip(
    *,
    uv: str,
    target_dir: Path,
    manifest: Path,
    fmt: DependencyFormat,
    work_dir: Path,
    auditor: Auditor,
    options: RemediationOptions,
    sources: AdvisorySources,
    venv_name: str,
    ignore_direct_references: bool,
    audit_only: bool = False,
) -> PipOutcome:
    """Audit and (unless *audit_only*) remediate a build-time-resolved manifest."""
    if fmt == DependencyFormat.PYPROJECT_PEP621:
        check_static_dependencies(tomlkit.parse(manifest.read_text(encoding="utf-8")).unwrap(),
                                  manifest)
    ws = PipWorkspace(uv, target_dir, manifest, fmt, work_dir, options, ignore_direct_references)
    original = ws.original.text
    doc = open_document(fmt, original, options)
    direct_refs = list(doc.direct_refs)
    if fmt == DependencyFormat.PYPROJECT_PEP621:
        direct_refs += source_direct_refs(manifest, doc.listed())
    elif ws.tree is not None:
        direct_refs = list(ws.tree.direct)
    if direct_refs and not ignore_direct_references:
        raise DirectReferenceError(str(manifest), direct_refs)

    baseline = ws.compile(ws.write(original), record=True)
    private = baseline.private(ws.scope)
    not_audited = [f"{n}=={baseline.pins[n]} (private index {url}; not audited)"
                   for n, url in sorted(private.items())]
    not_audited += [f"{ref} (direct reference)" for ref in baseline.direct_refs]
    log.info(
        "Resolved %s for %s/%s: %d packages (%d not audited)",
        manifest.name, options.env.platform, options.env.python_version,
        len(baseline.pins), len(not_audited),
    )
    audited = baseline.public_pins(ws.scope)
    other_index = baseline.other_index(ws.scope)
    pre_vulns = auditor.audit(audited, "pre-upgrade")
    gate = ImportGate(enabled=options.import_check and not audit_only, target_dir=target_dir)
    notes: list[str] = []
    if other_index:
        notes.append(other_index_note(other_index))
        log.warning("%s", notes[-1])

    if audit_only:
        return PipOutcome(
            baseline=baseline, final=baseline, pre_vulns=pre_vulns, post_vulns=pre_vulns,
            plans=plan(pre_vulns, baseline.pins, options, sources, private), failures={},
            new_text=original, changed=False, resolution_check="",
            commands=ws.commands, notes=notes, not_audited=not_audited, gate=gate,
            direct_refs=direct_refs, original_text=original, audited_count=len(audited),
            other_index=other_index,
        )

    venv = work_dir / venv_name
    venv_python: str | None = None
    if gate.enabled:
        venv_python = _install_for_imports(ws, venv, ws.write(original), gate, baseline=True)

    plans: dict[str, FixPlan] = {}
    failures: dict[str, str] = {}
    hashed = isinstance(doc, RequirementsDocument) and any(e.hashed for e in doc.all_entries)
    edits: dict[str, str] = {}        # listed package -> new specifier
    additions: dict[str, tuple[str, str]] = {}  # unlisted package -> (specifier, comment)
    current, current_vulns = baseline, pre_vulns
    attempted: dict[str, str] = {}

    def rounds(considered: Callable[[list[Vulnerability]], list[Vulnerability]]) -> None:
        nonlocal current, current_vulns
        for round_no in range(1, options.max_rounds + 1):
            new_plans = plan(considered(current_vulns), current.pins, options, sources, private)
            record_plans(plans, new_plans)
            targets = {n: p.target for n, p in new_plans.items()
                       if p.status == "fix" and p.target and attempted.get(n) != p.target}
            if not targets:
                return
            log.info("Round %d: fixing %s", round_no,
                     ", ".join(f"{n}>={v}" for n, v in sorted(targets.items())))
            attempted.update(targets)
            _plan_edits(ws, doc, fmt, original, baseline, current, targets, new_plans, edits,
                        additions, failures, options, notes)
            text = _render(fmt, original, options, edits, additions, ws)
            try:
                current = ws.compile(ws.write(text))
                if hashed and _pin_new_dependencies(
                    fmt, text, options, baseline, current, additions,
                ):
                    text = _render(fmt, original, options, edits, additions, ws)
                    current = ws.compile(ws.write(text))
            except CommandError as exc:
                notes.append(f"Edited manifest does not resolve: {_first_line(exc.stderr)}")
                return
            current_vulns = auditor.audit(current.public_pins(ws.scope),
                                          f"post-upgrade-{round_no}")
            if not considered(current_vulns):
                return

    # The advisory database first, exactly as a run without --repo-advisories;
    # then the repository advisories, kept only if they leave no more database
    # findings than that.
    rounds(database_findings)
    if any(v.from_repository for v in current_vulns):
        before = len(database_findings(current_vulns))
        saved = (dict(edits), dict(additions), current, current_vulns, snapshot_plans(plans),
                 dict(failures), list(notes))
        rounds(list)
        after = len(database_findings(current_vulns))
        if after > before:
            tried = dict(plans)
            kept_edits, kept_additions, current, current_vulns, kept_plans, kept_failures, \
                kept_notes = saved
            edits.clear()
            edits.update(kept_edits)
            additions.clear()
            additions.update(kept_additions)
            plans.clear()
            plans.update(kept_plans)
            failures.clear()
            failures.update(kept_failures)
            notes[:] = kept_notes
            reason = (f"Not applied: fixing the repository advisories left {after} database "
                      f"advisories instead of {before}")
            keep_repository_findings_open(plans, tried, failures, current_vulns, reason)
            notes.append(f"Repository advisories were not fixed: their fixes left {after} "
                         f"database advisories instead of {before}")
            log.warning("%s", notes[-1])

    new_text = _render(fmt, original, options, edits, additions, ws)
    changed = new_text != original
    resolution_check = ""
    final = current
    listed = doc.listed()
    for name, spec in sorted(edits.items()):
        ws.commands.append(f"# {ws.manifest_name}: {name} {listed.get(name) or '(any)'} -> {spec}")
    for name, (spec, comment) in sorted(additions.items()):
        ws.commands.append(f"# {ws.manifest_name}: add {name}{spec}  # {comment}")
    if changed:
        try:
            final = ws.compile(ws.write(new_text), record=True)
            resolution_check = f"passed ({len(final.pins)} packages)"
        except CommandError as exc:
            resolution_check = f"failed: {_first_line(exc.stderr)}"
    if changed and gate.enabled and gate.baseline is not None and venv_python:
        # A fresh venv: installing over the baseline would keep packages the
        # new set no longer installs, and hide the imports that need them.
        _install_for_imports(ws, venv.with_name(f"{venv.name}-after"), ws.write(new_text), gate,
                             baseline=False)

    return PipOutcome(
        baseline=baseline, final=final, pre_vulns=pre_vulns, post_vulns=current_vulns,
        plans=plans, failures=failures, new_text=new_text, changed=changed,
        resolution_check=resolution_check, commands=ws.commands, notes=notes,
        not_audited=not_audited, gate=gate, direct_refs=direct_refs,
        original_text=original, audited_count=len(audited), other_index=other_index,
    )


def _pin_new_dependencies(
    fmt: DependencyFormat,
    text: str,
    options: RemediationOptions,
    baseline: Resolution,
    current: Resolution,
    additions: dict[str, tuple[str, str]],
) -> bool:
    """Hash-checking files must list every package: pin what a fixed release now needs.

    pip's ``--require-hashes`` mode refuses to install anything the file does
    not pin and hash, so a dependency that only the fixed release brings in
    (aiohttp 3.10 needs aiohappyeyeballs) is added as a hashed ``==`` pin.

    Returns:
        True when *additions* changed.
    """
    listed = set(open_document(fmt, text, options).listed()) | set(additions)
    new = {
        name: version for name, version in current.pins.items()
        if name not in listed and name not in baseline.pins
    }
    for name, version in sorted(new.items()):
        parents = ", ".join(sorted(current.via.get(name) or [])) or "the fixed releases"
        additions[name] = (f"=={version}", f"depfresh: required by {parents}")
    return bool(new)


def _first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:300]
    return "no output"


def _render(
    fmt: DependencyFormat,
    original: str,
    options: RemediationOptions,
    edits: dict[str, str],
    additions: dict[str, tuple[str, str]],
    ws: PipWorkspace,
) -> str:
    """Apply *edits* and *additions* to a fresh copy of the original manifest."""
    doc = open_document(fmt, original, options)
    entries = doc.entries if isinstance(doc, RequirementsDocument) else {}
    hashed = any(e.hashed for e in entries.values())
    pins_to_hash = {
        name: spec[2:] for name, spec in edits.items()
        if hashed and spec.startswith("==") and name in entries and entries[name].hashed
    }
    hashes = ws.hashes(pins_to_hash) if pins_to_hash else {}
    for name, spec in edits.items():
        if name in doc.listed():
            doc.set_spec(name, spec, hashes.get(name))
    add_hashes = ws.hashes({
        name: spec[2:] for name, (spec, _) in additions.items() if spec.startswith("==")
    }) if hashed else {}
    for name, (spec, comment) in sorted(additions.items()):
        if isinstance(doc, PyprojectDocument):
            doc.append(f"{name}{spec}  # {comment}", extra=_extra_for(name, ws, options))
        elif hashed and name in add_hashes:
            digests = add_hashes[name]
            doc.append(f"{name}{spec} \\" if digests else f"{name}{spec}")
            for j, digest in enumerate(digests):
                doc.append(f"    --hash={digest}" + (" \\" if j < len(digests) - 1 else ""))
            doc.append(f"    # {comment}")
        else:
            doc.append(f"{name}{spec}  # {comment}")
    return doc.render()


def _extra_for(name: str, ws: PipWorkspace, options: RemediationOptions) -> str | None:
    """Where a transitive floor goes in pyproject.toml.

    ``[project].dependencies`` when the runtime set pulls the package (or
    nothing selected does), otherwise the first selected extra, in the order
    the file declares them, whose own resolution pulls it.
    """
    if not (options.extras or options.all_extras) or name in ws.runtime_pins():
        return None
    declared = list(tomlkit.parse(ws.original.text).unwrap().get("project", {})
                    .get("optional-dependencies", {}))
    selected = [g for g in declared if options.all_extras or g in options.extras]
    return next((g for g in selected if name in ws.extra_pins(g)), None)


def _plan_edits(
    ws: PipWorkspace,
    doc: RequirementsDocument | PyprojectDocument,
    fmt: DependencyFormat,
    original: str,
    baseline: Resolution,
    current: Resolution,
    targets: dict[str, str],
    plans: dict[str, FixPlan],
    edits: dict[str, str],
    additions: dict[str, tuple[str, str]],
    failures: dict[str, str],
    options: RemediationOptions,
    notes: list[str],
) -> None:
    """Choose the manifest edits for *targets*, with minimal co-upgrades if needed."""
    check_unambiguous(doc, targets)
    listed = doc.listed()

    def edits_for(names: Iterable[str]) -> tuple[dict[str, str], dict[str, tuple[str, str]]]:
        e = dict(edits)
        a = dict(additions)
        for name in names:
            version = targets[name]
            advisory = ", ".join(sorted({v.ghsa or v.cve for v in plans[name].vulns}))
            if name in listed:
                spec = listed[name]
                e[name] = f"=={version}" if _is_pin(spec) else admit_version(spec, version)
            else:
                # pip's hash-checking mode accepts only hashed == pins
                op = "==" if fmt == DependencyFormat.REQUIREMENTS_HASHED else ">="
                a[name] = (f"{op}{version}", f"depfresh: {advisory}")
        return e, a

    def attempt(names: set[str]) -> str:
        """Fix *names*: ``""`` when the edits are taken, otherwise why not."""
        candidate_edits, candidate_adds = edits_for(names)
        text = _render(fmt, original, options, candidate_edits, candidate_adds, ws)
        try:
            trial = ws.compile(ws.write(text), preferences=current.text, lowest_direct=True)
        except CommandError:
            log.info("Pins in %s block %s; looking for minimal co-upgrades", ws.manifest_name,
                     ", ".join(sorted(names)))
        else:
            problem = cobump_problem(current.pins, trial.pins, names, options)
            if not problem:
                edits.update(candidate_edits)
                additions.update(candidate_adds)
                return ""
            log.info("Fixing %s %s; looking for other co-upgrades",
                     ", ".join(sorted(names)), problem)
        label = ", ".join(f"{n} {targets[n]}" for n in sorted(names))
        return _with_cobumps(ws, fmt, original, current, listed, names, candidate_edits,
                             candidate_adds, options, edits, additions, label)

    if not attempt(set(targets)):
        return
    for name in sorted(targets):
        why = attempt({name})
        if why:
            failures[name] = why
            log.warning("%s", why)


def _is_pin(spec: str) -> bool:
    clauses = [c.strip() for c in spec.split(",") if c.strip()]
    return len(clauses) == 1 and clauses[0].startswith("==") and "*" not in clauses[0]


def _with_cobumps(
    ws: PipWorkspace,
    fmt: DependencyFormat,
    original: str,
    current: Resolution,
    listed: dict[str, str],
    fixing: set[str],
    candidate_edits: dict[str, str],
    candidate_adds: dict[str, tuple[str, str]],
    options: RemediationOptions,
    edits: dict[str, str],
    additions: dict[str, tuple[str, str]],
    label: str,
) -> str:
    """Relax the other pins to floors, prefer every current version, take the lowest moves.

    Pins of ``--keep-version`` packages stay pinned.  *label* names the fixes
    (``"starlette 0.53.0"``) in the reason.

    Returns:
        ``""`` when the edits are taken, otherwise why no co-upgrade works.
    """
    kept = {normalise(p) for p in options.keep_version or []}
    relaxed = dict(candidate_edits)
    for name, spec in listed.items():
        if name not in relaxed and _is_pin(spec) and name not in kept:
            relaxed[name] = f">={spec[2:]}"
    text = _render(fmt, original, options, relaxed, candidate_adds, ws)
    try:
        trial = ws.compile(ws.write(text), preferences=current.text, lowest_direct=True)
    except CommandError:
        pinned_kept = sorted(n for n in kept if n in listed and n not in fixing)
        return (
            f"No resolution fixes {label} on {options.env.platform}: the other requirements "
            "cannot move to a compatible version"
            + (f" (--keep-version keeps {', '.join(pinned_kept)})" if pinned_kept else "")
        )
    problem = cobump_problem(current.pins, trial.pins, fixing, options)
    if problem:
        return f"Fixing {label} {problem}"
    moved, _, _, _ = diff_sets(current.pins, trial.pins, set())
    cobumps = [c for c in moved if c.name not in fixing]
    new_edits = dict(candidate_edits)
    check_unambiguous(open_document(fmt, original, options), (c.name for c in cobumps))
    for change in cobumps:
        if change.name in listed and _is_pin(listed[change.name]):
            new_edits[change.name] = f"=={change.new_version}"
    edits.update(new_edits)
    additions.update(candidate_adds)
    return ""


def _install_for_imports(
    ws: PipWorkspace, venv: Path, manifest: Path, gate: ImportGate, *, baseline: bool,
) -> str | None:
    """Install *manifest* on this host into a new venv at *venv* and run the import check."""
    try:
        python = create_venv(ws.uv, venv, ws.options.env.python_version)
        args = [ws.uv, "pip", "install", "-r", str(manifest), "--python", python]
        if ws.fmt == DependencyFormat.PYPROJECT_PEP621:
            if ws.options.all_extras:
                args.append("--all-extras")
            for extra in ws.options.extras:
                args += ["--extra", extra]
        run(args, cwd=ws.target_dir, env=uv_env())
    except DepfreshError as exc:
        if baseline:
            gate.enabled = False
            gate.notes.append(f"Import check skipped: the baseline does not install here ({exc})")
            log.warning("%s", gate.notes[-1])
            return None
        gate.blocked = f"the remediated set does not install on this host: {exc}"
        gate.after = ImportCheck()
        log.error("%s", gate.blocked)
        return None
    if baseline:
        gate.baseline = gate.check(python, "baseline")
    else:
        gate.after = gate.check(python, "upgraded")
    return python


def changes_of(outcome: PipOutcome) -> tuple[
    list[PackageChange], list[PackageChange], list[str], list[PackageChange],
]:
    """Version changes between the baseline and final resolutions."""
    vulnerable = {normalise(v.package) for v in outcome.pre_vulns}
    return diff_sets(outcome.baseline.pins, outcome.final.pins, vulnerable)
