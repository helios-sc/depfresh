"""Lock-aware remediation for uv projects (``pyproject.toml`` + ``uv.lock``).

What ships from a uv project is the lock (``uv sync --frozen``), not a fresh
resolution of ``pyproject.toml``.  So depfresh:

1. exports the shipped set: ``uv export --frozen --no-emit-project
   --no-hashes`` with the chosen groups/extras (default ``--no-dev``), and
   evaluates its markers for the deploy platform;
2. audits it with pip-audit and plans the lowest fixing release per
   vulnerable package (:mod:`depfresh.advisories`);
3. applies the plan with ``uv lock --upgrade-package <pkg>==<fix>`` in a
   scratch copy, one package at a time if the combined update fails, and
   re-exports and re-audits;
4. checks the result with ``uv lock --check``.

The write-back is the updated ``uv.lock``.  ``pyproject.toml`` only changes
when a direct dependency's own constraint excludes the fix.

Everything runs in a scratch copy of the project, so a dry run or a failure
never touches the target.  uv reads the project's own index configuration
(``[[tool.uv.index]]``, ``[tool.uv.sources]``), so a private package is only
ever resolved against its private index; if that index is unreachable, uv
fails and so does depfresh.
"""

from __future__ import annotations

import difflib
import logging
import shutil
import sys
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tomlkit
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from depfresh.advisories import AdvisorySources, FixPlan, TargetEnv, evaluate_marker
from depfresh.constraints import admit_version, normalise
from depfresh.exceptions import CommandError, DepfreshError, PrivateIndexError
from depfresh.models import ImportCheck, PackageChange, Vulnerability
from depfresh.remediation import (
    Auditor,
    ImportGate,
    RemediationOptions,
    diff_sets,
    disallowed_majors,
    plan,
)
from depfresh.uv import run, uv_env

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[import-not-found]

log = logging.getLogger("depfresh")

_PYPI_HOSTS = {"pypi.org", "pypi.python.org", "files.pythonhosted.org"}

#: Files a single (non-workspace) uv project needs to lock and export.
_PROJECT_FILES = ("pyproject.toml", "uv.lock", "uv.toml", ".python-version")

_COPY_IGNORE = shutil.ignore_patterns(
    ".git", ".venv*", "venv*", "node_modules", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".tox", "reports",
)


def is_pypi_index(url: str | None) -> bool:
    """True for the public PyPI index (``https://pypi.org/simple`` and mirrors of its host)."""
    if not url:
        return False
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    return host in _PYPI_HOSTS


@dataclass(frozen=True)
class LockedPackage:
    """One ``[[package]]`` entry of ``uv.lock``."""

    name: str
    version: str
    source: dict[str, Any]

    @property
    def kind(self) -> str:
        """``"registry"``, ``"git"``, ``"path"``, ``"editable"``, ``"virtual"``…"""
        return next(iter(self.source), "unknown")

    @property
    def registry(self) -> str | None:
        """The index URL for registry packages."""
        value = self.source.get("registry")
        return str(value) if value is not None else None


def read_lock(path: Path) -> tuple[int | None, list[LockedPackage]]:
    """Parse ``uv.lock``: ``(revision, packages)``.

    Raises:
        DepfreshError: If the file is not valid TOML.
    """
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise DepfreshError(f"{path}: not a readable uv.lock ({exc})") from exc
    packages = [
        LockedPackage(
            name=normalise(str(entry.get("name", ""))),
            version=str(entry.get("version", "")),
            source=dict(entry.get("source") or {}),
        )
        for entry in data.get("package", [])
        if isinstance(entry, dict)
    ]
    revision = data.get("revision")
    return (int(revision) if isinstance(revision, int) else None), packages


def lock_version_changes(
    before: list[LockedPackage], after: list[LockedPackage],
) -> list[PackageChange]:
    """Every package whose locked versions differ between two lock files."""
    def versions(pkgs: list[LockedPackage]) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for p in pkgs:
            out.setdefault(p.name, set()).add(p.version)
        return out

    a, b = versions(before), versions(after)
    changes = []
    for name in sorted(set(a) | set(b)):
        va, vb = a.get(name, set()), b.get(name, set())
        if va != vb:
            changes.append(PackageChange(
                name,
                ", ".join(sorted(va - vb or va)) or "(new)",
                ", ".join(sorted(vb - va or vb)) or "(removed)",
            ))
    return changes


@dataclass
class ShippedSet:
    """The exported lock, evaluated for the deploy platform.

    Attributes:
        pins: PyPI packages that ship, ``{name: version}`` (audited).
        private: Packages from another index, ``{name: version}`` (not audited,
            never looked up on PyPI).
        not_audited: Human-readable lines for everything not audited.
    """

    pins: dict[str, str] = field(default_factory=dict)
    private: dict[str, str] = field(default_factory=dict)
    not_audited: list[str] = field(default_factory=list)


def shipped_set(export_text: str, env: TargetEnv, locked: list[LockedPackage]) -> ShippedSet:
    """Parse ``uv export`` output into the set that ships on *env*."""
    sources = {(p.name, p.version): p for p in locked}
    result = ShippedSet()
    for raw in export_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            # -e ./member, --index-url …: local code or options, never audited
            if line.startswith(("-e ", "--editable")):
                result.not_audited.append(f"{line} (local)")
            continue
        try:
            req = Requirement(line)
        except InvalidRequirement:
            result.not_audited.append(f"{line} (unparseable)")
            continue
        if not evaluate_marker(str(req.marker) if req.marker else None, env):
            continue
        name = normalise(req.name)
        if req.url:
            result.not_audited.append(f"{name} @ {req.url} (direct reference)")
            continue
        pins = [s.version for s in req.specifier if s.operator in ("==", "===")]
        if not pins:
            result.not_audited.append(f"{line} (not pinned)")
            continue
        version = pins[0]
        locked_pkg = sources.get((name, version))
        if locked_pkg is not None and locked_pkg.kind != "registry":
            result.not_audited.append(f"{name}=={version} ({locked_pkg.kind} source)")
            continue
        if locked_pkg is not None and not is_pypi_index(locked_pkg.registry):
            result.private[name] = version
            result.not_audited.append(
                f"{name}=={version} (private index {locked_pkg.registry}; not audited)"
            )
            continue
        result.pins[name] = version
    return result


def group_args(options: RemediationOptions) -> list[str]:
    """Dependency-group and extra flags shared by ``uv export`` and ``uv sync``."""
    args: list[str] = []
    if options.all_groups:
        args.append("--all-groups")
    elif options.groups:
        args.append("--no-default-groups")
        for group in options.groups:
            args += ["--group", group]
    else:
        args.append("--no-dev")
    if options.all_extras:
        args.append("--all-extras")
    else:
        for extra in options.extras:
            args += ["--extra", extra]
    return args


def _needs_full_copy(pyproject: dict[str, Any]) -> bool:
    """Workspaces and path sources need more than pyproject.toml + uv.lock."""
    tool_uv = pyproject.get("tool", {}).get("uv", {})
    if "workspace" in tool_uv:
        return True
    for source in (tool_uv.get("sources") or {}).values():
        entries = source if isinstance(source, list) else [source]
        for entry in entries:
            if isinstance(entry, dict) and ("path" in entry or entry.get("workspace")):
                return True
    return False


class LockProject:
    """A scratch copy of a uv project that uv commands run against."""

    def __init__(self, uv: str, target_dir: Path, work_dir: Path) -> None:
        self.uv = uv
        self.target_dir = target_dir
        self.root = work_dir / "project"
        self.commands: list[str] = []
        pyproject = tomllib.loads((target_dir / "pyproject.toml").read_text(encoding="utf-8"))
        _check_static_dependencies(pyproject, target_dir / "pyproject.toml")
        if _needs_full_copy(pyproject):
            self._check_paths_inside(pyproject)
            shutil.copytree(target_dir, self.root, ignore=_COPY_IGNORE, symlinks=True)
        else:
            self.root.mkdir(parents=True)
            for name in _PROJECT_FILES:
                if (target_dir / name).is_file():
                    shutil.copy2(target_dir / name, self.root / name)

    def _check_paths_inside(self, pyproject: dict[str, Any]) -> None:
        sources = pyproject.get("tool", {}).get("uv", {}).get("sources") or {}
        for name, source in sources.items():
            entries = source if isinstance(source, list) else [source]
            for entry in entries:
                if not isinstance(entry, dict) or "path" not in entry:
                    continue
                path = (self.target_dir / str(entry["path"])).resolve()
                if not path.is_relative_to(self.target_dir.resolve()):
                    raise DepfreshError(
                        f"{name} is a path dependency outside the project ({entry['path']}); "
                        "lock-aware mode only supports paths inside the project directory"
                    )

    def _uv(self, args: list[str], *, check: bool = True, env: dict[str, str] | None = None,
            record: bool = False) -> Any:
        cmd = [self.uv, *args]
        if record:
            self.commands.append("uv " + " ".join(args))
        try:
            return run(cmd, cwd=self.root, check=check, env=uv_env(env))
        except CommandError as exc:
            raise _explain_index_failure(exc) from exc

    def export(self, options: RemediationOptions) -> str:
        """``uv export --frozen --no-emit-project --no-hashes`` for the chosen groups."""
        args = ["export", "--frozen", "--no-emit-project", "--no-hashes", "--no-header",
                "--no-annotate", "--format", "requirements.txt", *group_args(options)]
        return str(self._uv(args).stdout)

    def lock_upgrade(self, targets: dict[str, str]) -> tuple[bool, str]:
        """``uv lock --upgrade-package <pkg>==<version>…``: ``(ok, uv output)``."""
        args = ["lock"]
        for name, version in sorted(targets.items()):
            args += ["--upgrade-package", f"{name}=={version}"]
        self.commands.append("uv " + " ".join(args))
        result = run([self.uv, *args], cwd=self.root, check=False, env=uv_env())
        output = (result.stderr or "") + (result.stdout or "")
        if result.returncode != 0:
            _raise_if_index_unreachable(output)
        return result.returncode == 0, output

    def check(self) -> str:
        """``uv lock --check``: ``"passed"`` or ``"failed: <reason>"``."""
        self.commands.append("uv lock --check")
        result = run([self.uv, "lock", "--check"], cwd=self.root, check=False, env=uv_env())
        if result.returncode == 0:
            return "passed"
        _raise_if_index_unreachable(result.stderr or "")
        return "failed: " + _first_error_line(result.stderr or result.stdout)

    def sync(self, venv: Path, options: RemediationOptions, local: list[str]) -> str:
        """Install the locked set for this host into *venv*; returns its Python."""
        args = ["sync", "--frozen", "--no-install-project", "--no-install-workspace",
                "--python", options.env.python_version, *group_args(options)]
        for name in local:
            args += ["--no-install-package", name]
        self._uv(args, env={"UV_PROJECT_ENVIRONMENT": str(venv)})
        bin_dir = "Scripts" if sys.platform == "win32" else "bin"
        return str(venv / bin_dir / ("python.exe" if sys.platform == "win32" else "python"))

    @property
    def lock_path(self) -> Path:
        return self.root / "uv.lock"

    @property
    def pyproject_path(self) -> Path:
        return self.root / "pyproject.toml"


def _check_static_dependencies(pyproject: dict[str, Any], path: Path) -> None:
    """Refuse projects whose dependencies only a build backend can compute.

    uv would run the build backend (repository code, e.g. ``setup.py``) to
    learn them; depfresh never executes repository code.
    """
    dynamic = pyproject.get("project", {}).get("dynamic") or []
    blocked = sorted({"dependencies", "optional-dependencies"} & {str(d) for d in dynamic})
    if blocked:
        raise DepfreshError(
            f"{path}: {', '.join(blocked)} are dynamic, so uv would have to run the build "
            "backend (repository code) to read them. depfresh never executes repository "
            "code; declare them statically in [project]."
        )


def _first_error_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("error:", "×", "Because", "╰─▶")) or "No solution" in stripped:
            return stripped[:300]
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return (lines[0] if lines else "no output")[:300]


def _uv_failure_summary(output: str) -> str:
    """The resolver's explanation, squeezed onto one line for reports."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    keep = [line for line in lines if not line.startswith(("Using ", "Resolved ", "Updated "))]
    return " ".join(keep)[:600] or "uv lock failed"


def _raise_if_index_unreachable(output: str) -> None:
    """uv could not reach a non-PyPI index: fail clearly, never fall back."""
    for line in output.splitlines():
        if "Failed to fetch" not in line and "error sending request" not in line:
            continue
        for token in line.replace("`", " ").split():
            if token.startswith(("http://", "https://")) and not is_pypi_index(token):
                raise PrivateIndexError(token.rstrip(":"), output)


def _explain_index_failure(exc: CommandError) -> DepfreshError:
    try:
        _raise_if_index_unreachable(exc.stderr)
    except PrivateIndexError as private:
        return private
    return exc


# ---------------------------------------------------------------------------
# pyproject.toml constraint edits
# ---------------------------------------------------------------------------


def blocking_constraint(pyproject_text: str, package: str, target: str) -> str | None:
    """The direct requirement string of *package* that excludes *target*, if any."""
    data = tomllib.loads(pyproject_text)
    name = normalise(package)
    for dep in _all_dependency_strings(data):
        try:
            req = Requirement(dep)
        except InvalidRequirement:
            continue
        if normalise(req.name) != name or req.url:
            continue
        try:
            if not SpecifierSet(str(req.specifier)).contains(Version(target), prereleases=True):
                return dep
        except InvalidVersion:
            return None
    return None


def _all_dependency_strings(data: dict[str, Any]) -> list[str]:
    project = data.get("project", {})
    deps = [str(d) for d in project.get("dependencies", [])]
    for group in (project.get("optional-dependencies") or {}).values():
        deps += [str(d) for d in group]
    for group in (data.get("dependency-groups") or {}).values():
        deps += [str(d) for d in group if isinstance(d, str)]
    return deps


def admit_in_pyproject(pyproject_text: str, package: str, target: str) -> str:
    """Rewrite every direct requirement of *package* so that it admits *target*.

    Formatting, comments and the other requirements are preserved (tomlkit).
    """
    doc = tomlkit.parse(pyproject_text)
    name = normalise(package)

    def rewrite(array: Any) -> None:
        for i, item in enumerate(array):
            if not isinstance(item, str):
                continue
            try:
                req = Requirement(str(item))
            except InvalidRequirement:
                continue
            if normalise(req.name) != name or req.url:
                continue
            extras = f"[{','.join(sorted(req.extras))}]" if req.extras else ""
            marker = f" ; {req.marker}" if req.marker else ""
            array[i] = f"{req.name}{extras}{admit_version(str(req.specifier), target)}{marker}"

    project: Any = doc.get("project", {})
    if "dependencies" in project:
        rewrite(project["dependencies"])
    for group in (project.get("optional-dependencies") or {}).values():
        rewrite(group)
    for group in (doc.get("dependency-groups") or {}).values():
        rewrite(group)
    return tomlkit.dumps(doc)


# ---------------------------------------------------------------------------
# The remediation run
# ---------------------------------------------------------------------------


@dataclass
class LockOutcome:
    """Everything a lock-aware run found and changed, for the result and reports."""

    baseline: ShippedSet
    final: ShippedSet
    pre_vulns: list[Vulnerability]
    post_vulns: list[Vulnerability]
    plans: dict[str, FixPlan]
    failures: dict[str, str]
    lock_changes: list[PackageChange]
    lock_check: str
    revision_before: int | None
    revision_after: int | None
    new_lock: bytes | None
    new_pyproject: bytes | None
    pyproject_diff: str
    commands: list[str]
    notes: list[str]
    gate: ImportGate


def remediate_lock(
    *,
    uv: str,
    target_dir: Path,
    work_dir: Path,
    auditor: Auditor,
    options: RemediationOptions,
    sources: AdvisorySources,
    venv_name: str,
    audit_only: bool = False,
) -> LockOutcome:
    """Audit and (unless *audit_only*) remediate the uv project in *target_dir*."""
    project = LockProject(uv, target_dir, work_dir)
    revision_before, locked_before = read_lock(project.lock_path)
    local = sorted(p.name for p in locked_before if p.kind in ("path", "editable", "directory"))

    baseline = shipped_set(project.export(options), options.env, locked_before)
    log.info(
        "Locked set for %s/%s: %d audited packages, %d not audited",
        options.env.platform, options.env.python_version,
        len(baseline.pins), len(baseline.not_audited),
    )
    pre_vulns = auditor.audit(baseline.pins, "pre-upgrade")
    gate = ImportGate(enabled=options.import_check and not audit_only, target_dir=target_dir)
    venv = work_dir / venv_name

    plans: dict[str, FixPlan] = {}
    failures: dict[str, str] = {}
    notes: list[str] = []
    current = baseline
    current_vulns = pre_vulns
    pyproject_before = project.pyproject_path.read_text(encoding="utf-8")

    if audit_only:
        plans = plan(pre_vulns, baseline.pins, options, sources, baseline.private)
        return LockOutcome(
            baseline=baseline, final=baseline, pre_vulns=pre_vulns, post_vulns=pre_vulns,
            plans=plans, failures={}, lock_changes=[], lock_check="",
            revision_before=revision_before, revision_after=revision_before, new_lock=None,
            new_pyproject=None, pyproject_diff="", commands=project.commands, notes=notes,
            gate=gate,
        )

    if gate.enabled:
        _baseline_imports(gate, project, venv, options, local)

    attempted: dict[str, str] = {}
    for round_no in range(1, options.max_rounds + 1):
        new_plans = plan(current_vulns, current.pins, options, sources, current.private)
        for name, p in new_plans.items():
            if name not in plans or p.status == "fix":
                plans[name] = p
        targets = {
            name: p.target for name, p in new_plans.items()
            if p.status == "fix" and p.target and attempted.get(name) != p.target
        }
        if not targets:
            break
        log.info("Round %d: upgrading %s", round_no,
                 ", ".join(f"{n}=={v}" for n, v in sorted(targets.items())))
        _apply_targets(project, targets, baseline, options, failures, notes)
        attempted.update(targets)
        current = shipped_set(project.export(options), options.env, read_lock(project.lock_path)[1])
        current_vulns = auditor.audit(current.pins, f"post-upgrade-{round_no}")
        if not current_vulns:
            break

    post_vulns = current_vulns
    revision_after, locked_after = read_lock(project.lock_path)
    lock_changes = lock_version_changes(locked_before, locked_after)
    lock_check = project.check()

    if gate.enabled:
        _after_imports(gate, project, venv, options, local)

    pyproject_after = project.pyproject_path.read_text(encoding="utf-8")
    pyproject_diff = "".join(difflib.unified_diff(
        pyproject_before.splitlines(keepends=True), pyproject_after.splitlines(keepends=True),
        fromfile="a/pyproject.toml", tofile="b/pyproject.toml",
    ))
    if revision_before != revision_after and lock_changes:
        notes.append(
            f"uv rewrote uv.lock from revision {revision_before} to {revision_after}; "
            "readers need a uv that supports it"
        )
    return LockOutcome(
        baseline=baseline,
        final=current,
        pre_vulns=pre_vulns,
        post_vulns=post_vulns,
        plans=plans,
        failures=failures,
        lock_changes=lock_changes,
        lock_check=lock_check,
        revision_before=revision_before,
        revision_after=revision_after,
        new_lock=project.lock_path.read_bytes() if lock_changes else None,
        new_pyproject=pyproject_after.encode("utf-8") if pyproject_diff else None,
        pyproject_diff=pyproject_diff,
        commands=project.commands,
        notes=notes,
        gate=gate,
    )


def _apply_targets(
    project: LockProject,
    targets: dict[str, str],
    baseline: ShippedSet,
    options: RemediationOptions,
    failures: dict[str, str],
    notes: list[str],
) -> None:
    """Lock *targets* together; on failure (or a disallowed major), one at a time."""
    snapshot_lock = project.lock_path.read_bytes()
    snapshot_pyproject = project.pyproject_path.read_bytes()
    ok, _ = project.lock_upgrade(targets)
    if ok and not _disallowed_cobumps(project, baseline, targets, options):
        return
    project.lock_path.write_bytes(snapshot_lock)
    project.pyproject_path.write_bytes(snapshot_pyproject)
    log.info("Combined update failed or crossed an unapproved major; trying one at a time")
    for name, version in sorted(targets.items()):
        _apply_one(project, name, version, baseline, options, failures, notes)


def _apply_one(
    project: LockProject,
    name: str,
    version: str,
    baseline: ShippedSet,
    options: RemediationOptions,
    failures: dict[str, str],
    notes: list[str],
) -> None:
    snapshot_lock = project.lock_path.read_bytes()
    snapshot_pyproject = project.pyproject_path.read_bytes()
    ok, output = project.lock_upgrade({name: version})
    if not ok:
        text = project.pyproject_path.read_text(encoding="utf-8")
        blocker = blocking_constraint(text, name, version)
        if blocker is not None:
            project.pyproject_path.write_text(
                admit_in_pyproject(text, name, version), encoding="utf-8",
            )
            log.info("%s: direct constraint %r excludes %s; raising it", name, blocker, version)
            ok, output = project.lock_upgrade({name: version})
            if ok:
                notes.append(
                    f"pyproject.toml: `{blocker}` excluded the fix {name} {version}, so the "
                    "constraint was raised"
                )
    if ok:
        majors = _disallowed_cobumps(project, baseline, {name: version}, options)
        if not majors:
            return
        output = "requires a major co-upgrade of " + ", ".join(
            f"{c.name} {c.old_version}→{c.new_version}" for c in majors
        ) + f"; re-run with --allow-major {name} " + " ".join(c.name for c in majors)
    project.lock_path.write_bytes(snapshot_lock)
    project.pyproject_path.write_bytes(snapshot_pyproject)
    failures[name] = f"uv could not lock {name}=={version}: {_uv_failure_summary(output)}"
    log.warning("%s", failures[name])


def _disallowed_cobumps(
    project: LockProject,
    baseline: ShippedSet,
    targets: dict[str, str],
    options: RemediationOptions,
) -> list[PackageChange]:
    """Packages other than *targets* that the update moved across a major version."""
    try:
        after = shipped_set(project.export(options), options.env, read_lock(project.lock_path)[1])
    except CommandError:
        return []
    changed, _, _, _ = diff_sets(baseline.pins, after.pins, set())
    others = [c for c in changed if c.name not in targets]
    return disallowed_majors(others, options.allow_major)


def _baseline_imports(
    gate: ImportGate, project: LockProject, venv: Path, options: RemediationOptions,
    local: list[str],
) -> None:
    try:
        python = project.sync(venv, options, local)
    except DepfreshError as exc:
        gate.enabled = False
        gate.notes.append(f"Import check skipped: the locked set does not install here ({exc})")
        log.warning("%s", gate.notes[-1])
        return
    gate.baseline = gate.check(python, "baseline")


def _after_imports(
    gate: ImportGate, project: LockProject, venv: Path, options: RemediationOptions,
    local: list[str],
) -> None:
    try:
        python = project.sync(venv, options, local)
    except DepfreshError as exc:
        gate.blocked = f"the remediated lock does not install on this host: {exc}"
        gate.after = ImportCheck()
        log.error("%s", gate.blocked)
        return
    gate.after = gate.check(python, "upgraded")
