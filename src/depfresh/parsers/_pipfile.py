"""Handler for pipenv Pipfile format."""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path
from typing import Any, cast

import tomlkit

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[import-not-found]

from depfresh.constraints import normalise
from depfresh.models import DependencyInspection, DependencyScope, DependencySpec
from depfresh.parsers._helpers import (
    _build_grouped_dependency,
    _parse_grouped_version,
    _update_specifier_string,
)

log = logging.getLogger("depfresh")


# ---------------------------------------------------------------------------
# Pipfile handler
# ---------------------------------------------------------------------------

class PipfileHandler:
    """Handler for pipenv ``Pipfile``."""

    is_pinned = False

    def parse(self, path: Path) -> dict[str, str]:
        return {
            dep.name: dep.version
            for dep in self.inspect(path).registry
        }

    def inspect(self, path: Path) -> DependencyInspection:
        data = tomllib.loads(path.read_text())
        inspection = DependencyInspection()

        for section in ("packages", "dev-packages"):
            is_runtime = section == "packages"
            group = "runtime" if is_runtime else "dev"
            for name, value in data.get(section, {}).items():
                _append_pipfile_dependency(
                    inspection,
                    name=str(name),
                    value=value,
                    group=group,
                    is_runtime=is_runtime,
                )

        return inspection

    def write(self, pkgs: dict[str, str], path: Path, **kwargs: Any) -> None:
        doc = tomlkit.parse(path.read_text())
        dependency_scope: DependencyScope = kwargs.get("dependency_scope", "all")

        sections = ("packages", "dev-packages") if dependency_scope == "all" else ("packages",)
        for section in sections:
            if section not in doc:
                continue
            section_table = cast(Any, doc[section])
            for name in section_table:
                norm = normalise(name)
                if norm not in pkgs:
                    continue
                new_ver = pkgs[norm]
                value = section_table[name]
                if isinstance(value, str):
                    if value == "*":
                        pass  # leave as wildcard
                    elif re.match(r"^[><=!~]", value):
                        section_table[name] = _update_specifier_string(value, new_ver)
                    else:
                        section_table[name] = new_ver
                elif isinstance(value, dict):
                    ver_str = value.get("version", "")
                    if isinstance(ver_str, str):
                        if ver_str == "*":
                            pass
                        elif re.match(r"^[><=!~]", ver_str):
                            value["version"] = _update_specifier_string(ver_str, new_ver)
                        else:
                            value["version"] = new_ver

        path.write_text(tomlkit.dumps(doc))
        log.debug("Wrote Pipfile: %s", path)


# ---------------------------------------------------------------------------
# Pipfile helpers
# ---------------------------------------------------------------------------

def _append_pipfile_dependency(
    inspection: DependencyInspection,
    *,
    name: str,
    value: Any,
    group: str,
    is_runtime: bool,
) -> None:
    """Convert a Pipfile dependency declaration into structured metadata."""
    dep = _build_pipfile_dependency(name, value, group=group, is_runtime=is_runtime)
    if dep is None:
        return
    if dep.source_kind == "direct-reference":
        inspection.direct_references.append(dep)
    else:
        inspection.registry.append(dep)


def _build_pipfile_dependency(
    name: str,
    value: Any,
    *,
    group: str,
    is_runtime: bool,
) -> DependencySpec | None:
    """Build a Pipfile dependency spec for install planning."""
    return _build_grouped_dependency(
        name, value,
        group=group,
        is_runtime=is_runtime,
        direct_ref_keys=("git", "path", "ref"),
        translate_constraint=_translate_pipfile_constraint,
    )


def _translate_pipfile_constraint(value: str) -> str:
    """Translate a Pipfile constraint into a pip-compatible specifier."""
    cleaned = value.strip()
    if not cleaned or cleaned == "*":
        return ""
    if re.match(r"^[><=!~]", cleaned):
        return cleaned
    return f"=={cleaned}"


def _parse_pipfile_version(value: Any) -> str | None:
    """Extract a version string from a Pipfile dependency value."""
    return _parse_grouped_version(
        value, direct_ref_keys=("git", "path", "ref"), strip_pattern=r"^[><=!~]+\s*",
    )
