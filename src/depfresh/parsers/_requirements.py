"""Handlers for requirements.txt (simple and hashed) and requirements.in."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from depfresh.constraints import normalise
from depfresh.models import DependencyInspection, DependencySpec
from depfresh.parsers._helpers import (
    _dependency_from_requirement,
    _extract_version_from_specifier,
    _format_requirement,
    _update_specifier_string,
)
from depfresh.textio import read_text, read_text_file, write_text_like

log = logging.getLogger("depfresh")


# ---------------------------------------------------------------------------
# Requirements (simple) handler
# ---------------------------------------------------------------------------

class RequirementsSimpleHandler:
    """Handler for plain ``requirements.txt`` (``name==version``)."""

    is_pinned = True

    def parse(self, path: Path) -> dict[str, str]:
        return {
            dep.name: dep.version
            for dep in self.inspect(path).registry
        }

    def inspect(self, path: Path) -> DependencyInspection:
        return _inspect_requirements_file(path)

    def write(self, pkgs: dict[str, str], path: Path, **kwargs: Any) -> None:
        """Update the listed requirements to the versions in *pkgs*, in place.

        Only lines of packages in *pkgs* whose version changes are touched: a
        pin moves (``==``), a floor is raised (``>=``); comments, markers,
        ordering, unlisted packages and every other line stay as they are.
        A file that does not exist yet is written as sorted ``name==version``
        lines.
        """
        if not path.exists():
            lines = [name if ver == "*" else f"{name}=={ver}" for name, ver in sorted(pkgs.items())]
            path.write_text("\n".join(lines) + "\n")
            log.debug("Wrote requirements: %s (%d packages)", path, len(lines))
            return
        from depfresh.constraints import admit_version
        from depfresh.pipmode import RequirementsDocument

        original = read_text_file(path)
        doc = RequirementsDocument(original.text)
        changed = 0
        for name, spec in doc.listed().items():
            new_ver = pkgs.get(name)
            if not new_ver or new_ver == "*":
                continue
            pinned = spec.startswith("==") and "," not in spec and "*" not in spec
            if pinned:
                if spec[2:] == new_ver:
                    continue
                new_spec = f"=={new_ver}"
            elif _admits(spec, new_ver):
                continue  # a floor that already admits the version is left alone
            else:
                new_spec = admit_version(spec, new_ver)
            doc.set_spec(name, new_spec)
            changed += 1
        write_text_like(path, doc.render(), original)
        log.debug("Updated %d requirement line(s) in %s", changed, path)


def _admits(spec: str, version: str) -> bool:
    """True when the specifier *spec* already allows *version*."""
    from packaging.specifiers import InvalidSpecifier, SpecifierSet
    from packaging.version import InvalidVersion

    try:
        return SpecifierSet(spec).contains(version, prereleases=True)
    except (InvalidSpecifier, InvalidVersion):
        return True


# ---------------------------------------------------------------------------
# Requirements (hashed / pip-compile) handler
# ---------------------------------------------------------------------------

class RequirementsHashedHandler:
    """Handler for pip-compile format with ``--hash=`` directives."""

    is_pinned = True

    def parse(self, path: Path) -> dict[str, str]:
        return RequirementsSimpleHandler().parse(path)

    def inspect(self, path: Path) -> DependencyInspection:
        return _inspect_requirements_file(path)

    def write(self, pkgs: dict[str, str], path: Path, **kwargs: Any) -> None:
        uv: str = kwargs["uv"]
        python_version: str = kwargs["python_version"]

        from depfresh.uv import compile_hashed

        compile_hashed(uv, pkgs, path, python_version)


# ---------------------------------------------------------------------------
# Requirements.in handler
# ---------------------------------------------------------------------------

class RequirementsInHandler:
    """Handler for pip-tools / uv input files (``requirements.in``).

    These files contain *unpinned* specifiers (``flask>=2.0``, ``requests``).
    ``is_pinned`` is ``False`` — callers should freeze after install to get
    the real "before" versions.
    """

    is_pinned = False

    def parse(self, path: Path) -> dict[str, str]:
        return {
            dep.name: dep.version
            for dep in self.inspect(path).registry
        }

    def inspect(self, path: Path) -> DependencyInspection:
        return _inspect_requirements_file(path)

    def write(self, pkgs: dict[str, str], path: Path, **kwargs: Any) -> None:
        """Re-write the ``.in`` file, updating version lower-bounds.

        Preserves comments and non-requirement lines.  For requirement
        lines, updates the version specifier with ``>=new_version``.
        """
        original = read_text_file(path)
        original_lines = original.text.splitlines()
        new_lines: list[str] = []

        for line in original_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                new_lines.append(line)
                continue
            try:
                req = Requirement(stripped)
            except InvalidRequirement:
                new_lines.append(line)
                continue

            name = normalise(req.name)
            if name in pkgs and pkgs[name] != "*":
                new_ver = pkgs[name]
                old_ver = _extract_version_from_specifier(req.specifier)
                if old_ver != "*":
                    old_m = re.match(r"^(\d+)\.", old_ver)
                    new_m = re.match(r"^(\d+)\.", new_ver)
                    if old_m and new_m and int(new_m.group(1)) > int(old_m.group(1)):
                        log.warning(
                            "%s: lower bound bumped across a major version "
                            "(%s \u2192 %s) \u2014 review before committing",
                            req.name, old_ver, new_ver,
                        )
                new_lines.append(
                    _format_requirement(req, _update_specifier_string(str(req.specifier), new_ver))
                )
            else:
                new_lines.append(line)

        write_text_like(path, "\n".join(new_lines) + "\n", original)
        log.debug("Wrote requirements.in: %s (%d packages)", path, len(pkgs))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_PIP_DIRECTIVE_PATTERNS: dict[str, str] = {
    "-r ": "File inclusion (-r) is not followed \u2014 "
           "dependencies from the referenced file will not be processed",
    "--requirement ": "File inclusion (--requirement) is not followed \u2014 "
                      "dependencies from the referenced file will not be processed",
    "-c ": "Constraint file (-c) is not applied \u2014 "
           "constraints from the referenced file will not be enforced",
    "--constraint ": "Constraint file (--constraint) is not applied \u2014 "
                     "constraints from the referenced file will not be enforced",
    "--index-url ": "Custom index (--index-url) is ignored \u2014 "
                    "depfresh uses the default PyPI index (or uv\u2019s configured index)",
    "--extra-index-url ": "Extra index (--extra-index-url) is ignored \u2014 "
                          "packages from this index may not be found",
    "--find-links ": "Find-links directive is ignored",
    "--trusted-host ": "Trusted-host directive is ignored",
    "--no-binary ": "no-binary directive is ignored",
    "--only-binary ": "only-binary directive is ignored",
}


def _inspect_requirements_file(path: Path) -> DependencyInspection:
    """Inspect a requirements-style file line-by-line."""
    inspection = DependencyInspection()
    lines = _merge_continuation_lines(read_text(path).splitlines())

    for stripped in lines:
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(("-e ", "--editable ", "git+")):
            inspection.direct_references.append(DependencySpec(
                name="",
                version="",
                requirement="",
                raw=stripped,
                source_kind="direct-reference",
                group="runtime",
                is_runtime=True,
            ))
            continue
        if stripped.startswith("-"):
            _warn_pip_directive(stripped, path)
            continue
        base = stripped.split(" --hash=", 1)[0].strip()
        if not base or base.startswith("--hash="):
            continue
        try:
            req = Requirement(base)
        except InvalidRequirement:
            continue
        dep = _dependency_from_requirement(
            req,
            raw=base,
            group="runtime",
            is_runtime=True,
        )
        if dep.source_kind == "direct-reference":
            inspection.direct_references.append(dep)
        else:
            inspection.registry.append(dep)
    return inspection


def _warn_pip_directive(line: str, path: Path) -> None:
    """Emit a warning when a pip directive is silently skipped."""
    for prefix, message in _PIP_DIRECTIVE_PATTERNS.items():
        if line.startswith(prefix) or line.startswith("-" + prefix.lstrip("-")):
            log.warning("%s: %s: %s", path.name, message, line)
            return
    log.debug("%s: skipping unsupported pip option: %s", path.name, line)


def _merge_continuation_lines(raw_lines: list[str]) -> list[str]:
    """Merge lines joined by trailing backslash (``\\``) into single lines."""
    merged: list[str] = []
    buf = ""
    for raw_line in raw_lines:
        stripped = raw_line.rstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1].strip() + " "
        else:
            buf += stripped.strip()
            if buf:
                merged.append(buf)
            buf = ""
    if buf.strip():
        merged.append(buf.strip())
    return merged
