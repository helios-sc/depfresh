"""Handlers for pyproject.toml — PEP 621 and Poetry formats."""

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
    import tomli as tomllib

from packaging.requirements import InvalidRequirement, Requirement

from depfresh.constraints import normalise
from depfresh.models import DependencyInspection, DependencyScope, DependencySpec
from depfresh.parsers._helpers import (
    _build_grouped_dependency,
    _dependency_from_requirement,
    _format_requirement,
    _numeric_version_parts,
    _parse_grouped_version,
    _update_specifier_string,
)

log = logging.getLogger("depfresh")


# ---------------------------------------------------------------------------
# pyproject.toml — PEP 621 handler
# ---------------------------------------------------------------------------

class PyprojectPEP621Handler:
    """Handler for ``pyproject.toml`` with PEP 621 ``[project.dependencies]``."""

    is_pinned = False

    def parse(self, path: Path) -> dict[str, str]:
        return {
            dep.name: dep.version
            for dep in self.inspect(path).registry
        }

    def inspect(self, path: Path) -> DependencyInspection:
        data = tomllib.loads(path.read_text())
        inspection = DependencyInspection()

        for dep_str in data.get("project", {}).get("dependencies", []):
            _append_pep508_dependency(
                inspection,
                dep_str,
                group="runtime",
                is_runtime=True,
            )

        optional_groups = data.get("project", {}).get("optional-dependencies", {})
        for group_name, group_deps in optional_groups.items():
            for dep_str in group_deps:
                _append_pep508_dependency(
                    inspection,
                    dep_str,
                    group=str(group_name),
                    is_runtime=False,
                )

        return inspection

    def write(self, pkgs: dict[str, str], path: Path, **kwargs: Any) -> None:
        doc = tomlkit.parse(path.read_text())
        dependency_scope: DependencyScope = kwargs.get("dependency_scope", "all")

        if "project" in doc:
            project = cast(Any, doc["project"])
            if "dependencies" in project:
                project["dependencies"] = _update_pep508_list(project["dependencies"], pkgs)

            if dependency_scope == "all" and "optional-dependencies" in project:
                optional_deps = cast(Any, project["optional-dependencies"])
                for group in optional_deps:
                    optional_deps[group] = _update_pep508_list(optional_deps[group], pkgs)

        path.write_text(tomlkit.dumps(doc))
        log.debug("Wrote pyproject.toml (PEP 621): %s", path)


# ---------------------------------------------------------------------------
# pyproject.toml — Poetry handler
# ---------------------------------------------------------------------------

class PyprojectPoetryHandler:
    """Handler for ``pyproject.toml`` with ``[tool.poetry.dependencies]``."""

    is_pinned = False

    def parse(self, path: Path) -> dict[str, str]:
        return {
            dep.name: dep.version
            for dep in self.inspect(path).registry
        }

    def inspect(self, path: Path) -> DependencyInspection:
        data = tomllib.loads(path.read_text())
        inspection = DependencyInspection()

        poetry = data.get("tool", {}).get("poetry", {})

        for name, value in poetry.get("dependencies", {}).items():
            if normalise(name) == "python":
                continue
            _append_poetry_dependency(
                inspection,
                name=str(name),
                value=value,
                group="runtime",
                is_runtime=True,
            )

        for group_name, group_data in poetry.get("group", {}).items():
            for name, value in group_data.get("dependencies", {}).items():
                if normalise(name) == "python":
                    continue
                _append_poetry_dependency(
                    inspection,
                    name=str(name),
                    value=value,
                    group=str(group_name),
                    is_runtime=False,
                )

        return inspection

    def write(self, pkgs: dict[str, str], path: Path, **kwargs: Any) -> None:
        doc = tomlkit.parse(path.read_text())
        dependency_scope: DependencyScope = kwargs.get("dependency_scope", "all")

        tool = cast(Any, doc.get("tool", {}))
        poetry = cast(Any, tool.get("poetry", {}))

        if "dependencies" in poetry:
            _update_poetry_deps(poetry["dependencies"], pkgs)

        if dependency_scope == "all":
            for group_data in cast(Any, poetry.get("group", {})).values():
                if "dependencies" in group_data:
                    _update_poetry_deps(group_data["dependencies"], pkgs)

        path.write_text(tomlkit.dumps(doc))
        log.debug("Wrote pyproject.toml (Poetry): %s", path)


# ---------------------------------------------------------------------------
# PEP 621 helpers
# ---------------------------------------------------------------------------

def _append_pep508_dependency(
    inspection: DependencyInspection,
    dep_str: str,
    *,
    group: str,
    is_runtime: bool,
) -> None:
    """Parse a PEP 508 string into the inspection structure."""
    try:
        req = Requirement(dep_str)
    except InvalidRequirement:
        return
    dep = _dependency_from_requirement(req, raw=dep_str, group=group, is_runtime=is_runtime)
    if dep.source_kind == "direct-reference":
        inspection.direct_references.append(dep)
    else:
        inspection.registry.append(dep)


def _update_pep508_list(dep_list: Any, pkgs: dict[str, str]) -> Any:
    """Update versions in a tomlkit array in-place, preserving formatting."""
    for i, dep_str in enumerate(dep_list):
        try:
            req = Requirement(str(dep_str))
        except InvalidRequirement:
            continue
        if req.url:
            continue
        name = normalise(req.name)
        if name in pkgs:
            new_ver = pkgs[name]
            dep_list[i] = _format_requirement(
                req,
                _update_specifier_string(str(req.specifier), new_ver),
            )
    return dep_list


# ---------------------------------------------------------------------------
# Poetry helpers
# ---------------------------------------------------------------------------

def _append_poetry_dependency(
    inspection: DependencyInspection,
    *,
    name: str,
    value: Any,
    group: str,
    is_runtime: bool,
) -> None:
    """Convert a Poetry dependency declaration into structured metadata."""
    dep = _build_poetry_dependency(name, value, group=group, is_runtime=is_runtime)
    if dep is None:
        return
    if dep.source_kind == "direct-reference":
        inspection.direct_references.append(dep)
    else:
        inspection.registry.append(dep)


def _build_poetry_dependency(
    name: str,
    value: Any,
    *,
    group: str,
    is_runtime: bool,
) -> DependencySpec | None:
    """Build a Poetry dependency spec for install planning."""
    return _build_grouped_dependency(
        name, value,
        group=group,
        is_runtime=is_runtime,
        direct_ref_keys=("git", "path", "url"),
        translate_constraint=_translate_poetry_constraint,
        extract_markers=_poetry_marker_extractor,
    )


def _poetry_marker_extractor(value: dict[str, Any]) -> list[str]:
    """Extract Poetry-specific markers (``python =`` key)."""
    markers: list[str] = []
    python_value = value.get("python")
    if isinstance(python_value, str) and python_value.strip():
        py_marker = _poetry_python_constraint_to_marker(python_value)
        if py_marker:
            markers.append(py_marker)
    return markers


def _translate_poetry_constraint(value: str) -> str:
    """Translate Poetry's version syntax into a pip-compatible specifier."""
    cleaned = value.strip()
    if not cleaned or cleaned == "*":
        return ""
    if cleaned.startswith("^"):
        return _caret_to_range(cleaned[1:].strip())
    if cleaned.startswith("~"):
        return _tilde_to_range(cleaned[1:].strip())
    if re.match(r"^[><=!]", cleaned):
        return cleaned
    return f"=={cleaned}"


def _caret_to_range(version: str) -> str:
    """Translate a caret constraint into ``>=,<`` form."""
    parts = _numeric_version_parts(version)
    if not parts:
        return f"=={version}"
    lower = version
    if parts[0] != 0:
        upper = f"{parts[0] + 1}.0"
    elif len(parts) > 1 and parts[1] != 0:
        upper = f"0.{parts[1] + 1}.0"
    elif len(parts) > 2:
        upper = f"0.0.{parts[2] + 1}"
    else:
        upper = "0.1.0"
    return f">={lower},<{upper}"


def _tilde_to_range(version: str) -> str:
    """Translate a tilde constraint into ``>=,<`` form."""
    parts = _numeric_version_parts(version)
    if not parts:
        return f"=={version}"
    lower = version
    if len(parts) <= 1:
        upper = f"{parts[0] + 1}.0"
    else:
        upper = f"{parts[0]}.{parts[1] + 1}.0"
    return f">={lower},<{upper}"


def _poetry_python_constraint_to_marker(value: str) -> str | None:
    """Translate Poetry's ``python =`` constraint into a marker expression."""
    specifier = _translate_poetry_constraint(value)
    if not specifier:
        return None
    tokens = [token.strip() for token in specifier.split(",") if token.strip()]
    markers: list[str] = []
    for token in tokens:
        match = re.match(r"^(>=|<=|==|!=|>|<)\s*([^\s,;]+)$", token)
        if match:
            markers.append(f'python_version {match.group(1)} "{match.group(2)}"')
    if not markers:
        return None
    return " and ".join(markers)


def _update_poetry_deps(deps_table: Any, pkgs: dict[str, str]) -> None:
    """Update a Poetry dependencies table in-place with versions from *pkgs*."""
    for name in list(deps_table):
        if normalise(name) == "python":
            continue
        norm = normalise(name)
        if norm not in pkgs:
            continue
        new_ver = pkgs[norm]
        value = deps_table[name]
        if isinstance(value, str):
            if value == "*":
                pass
            elif value.startswith("^"):
                deps_table[name] = f"^{new_ver}"
            elif value.startswith("~"):
                deps_table[name] = f"~{new_ver}"
            elif re.match(r"^[><=!]", value):
                deps_table[name] = _update_specifier_string(value, new_ver)
            else:
                # Bare version like "2.3.0"
                deps_table[name] = new_ver
        elif isinstance(value, dict) and "version" in value:
            old_ver_str = value["version"]
            if isinstance(old_ver_str, str):
                if old_ver_str.startswith("^"):
                    value["version"] = f"^{new_ver}"
                elif old_ver_str.startswith("~"):
                    value["version"] = f"~{new_ver}"
                elif old_ver_str == "*":
                    pass
                else:
                    value["version"] = _update_specifier_string(old_ver_str, new_ver)


def _parse_poetry_version(value: Any) -> str | None:
    """Extract a version string from a Poetry dependency value."""
    return _parse_grouped_version(
        value, direct_ref_keys=("git", "path", "url"), strip_pattern=r"^[~^]=?\s*",
    )
