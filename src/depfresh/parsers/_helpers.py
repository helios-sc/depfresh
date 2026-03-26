"""Shared helpers for dependency parsing and version manipulation."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from typing import Any, cast

from packaging.requirements import InvalidRequirement, Requirement

from depfresh.constraints import normalise
from depfresh.models import DependencySpec

log = logging.getLogger("depfresh")

_ConstraintTranslator = Callable[[str], str]
_MarkerExtractor = Callable[[dict[str, Any]], list[str]]


# ---------------------------------------------------------------------------
# Version / specifier helpers
# ---------------------------------------------------------------------------

def _extract_version_from_specifier(specifier: Any) -> str:
    """Extract a single version string from a PEP 440 specifier set.

    Returns the pinned version for ``==``, the lower bound for ``>=``,
    or ``"*"`` when no version constraint is present.
    """
    specs = list(specifier)
    if not specs:
        return "*"

    # Prefer == pin
    for spec in specs:
        if spec.operator == "==":
            return cast(str, spec.version)

    # Fallback to lower-bound
    for spec in specs:
        if spec.operator in (">=", "~="):
            return cast(str, spec.version)

    # Last resort: use the first specifier's version
    return cast(str, specs[0].version)


def _format_requirement(req: Requirement, specifier: str) -> str:
    """Render a requirement preserving extras and markers."""
    extras = f"[{','.join(sorted(req.extras))}]" if req.extras else ""
    marker = f" ; {req.marker}" if req.marker else ""
    return f"{req.name}{extras}{specifier}{marker}"


def _update_specifier_string(specifier: str, new_ver: str) -> str:
    """Update the primary version in a specifier string while preserving upper bounds."""
    tokens = [token.strip() for token in specifier.split(",") if token.strip()]
    if not tokens:
        return f">={new_ver}"

    for index, token in enumerate(tokens):
        match = re.match(r"^(===|==|~=|>=|<=|>|<|!=)\s*([^\s,;]+)$", token)
        if not match:
            continue
        op = match.group(1)
        if op in {"==", "~=", ">=", ">"}:
            tokens[index] = f"{op}{new_ver}"
            return ",".join(tokens)

    tokens.insert(0, f">={new_ver}")
    return ",".join(tokens)


def _extract_version_from_requirement_string(requirement: str) -> str:
    """Extract depfresh's planning version from a requirement string."""
    try:
        req = Requirement(requirement)
    except InvalidRequirement:
        return "*"
    return _extract_version_from_specifier(req.specifier)


def _numeric_version_parts(version: str) -> list[int]:
    """Return numeric version parts until the first non-numeric segment."""
    parts: list[int] = []
    for part in version.split("."):
        if part.isdigit():
            parts.append(int(part))
        else:
            break
    return parts


# ---------------------------------------------------------------------------
# Dependency building helpers
# ---------------------------------------------------------------------------

def _dependency_from_requirement(
    req: Requirement,
    *,
    raw: str,
    group: str,
    is_runtime: bool,
) -> DependencySpec:
    """Convert a packaging requirement into a structured dependency."""
    requirement = _format_requirement(req, str(req.specifier))
    return DependencySpec(
        name=normalise(req.name),
        version=_extract_version_from_specifier(req.specifier),
        requirement=requirement,
        raw=raw,
        source_kind="direct-reference" if req.url else "registry",
        group=group,
        is_runtime=is_runtime,
    )


def _build_requirement_string(
    name: str,
    specifier: str,
    *,
    extras: tuple[str, ...] = (),
    marker: str | None = None,
) -> str:
    """Build a requirement line suitable for a temporary requirements file."""
    extras_str = f"[{','.join(extras)}]" if extras else ""
    marker_str = f" ; {marker}" if marker else ""
    return f"{name}{extras_str}{specifier}{marker_str}"


def _combine_markers(markers: list[str]) -> str | None:
    """Combine marker fragments into a single marker expression."""
    clean = [marker.strip() for marker in markers if marker.strip()]
    if not clean:
        return None
    if len(clean) == 1:
        return clean[0]
    return " and ".join(f"({marker})" for marker in clean)


def _build_grouped_dependency(
    name: str,
    value: Any,
    *,
    group: str,
    is_runtime: bool,
    direct_ref_keys: tuple[str, ...],
    translate_constraint: _ConstraintTranslator,
    extract_markers: _MarkerExtractor | None = None,
) -> DependencySpec | None:
    """Build a dependency spec for grouped formats (Poetry / Pipfile).

    Parameters
    ----------
    direct_ref_keys:
        Dictionary keys that indicate a non-registry (direct) dependency.
    translate_constraint:
        Callable that converts a format-specific version string to a pip
        specifier.
    extract_markers:
        Optional callable that extracts additional marker strings from a
        dict-style dependency value.
    """
    norm_name = normalise(name)
    extras: tuple[str, ...] = ()
    markers: list[str] = []

    if isinstance(value, str):
        specifier = translate_constraint(value)
        raw = value
    elif isinstance(value, dict):
        if any(k in value for k in direct_ref_keys):
            raw_bits = [
                f"{key}={value[key]!r}" for key in direct_ref_keys if key in value
            ]
            return DependencySpec(
                name=norm_name,
                version="",
                requirement="",
                raw=f"{name}: {', '.join(raw_bits)}",
                source_kind="direct-reference",
                group=group,
                is_runtime=is_runtime,
            )
        extras_value = value.get("extras", [])
        if isinstance(extras_value, list):
            extras = tuple(str(extra) for extra in extras_value)
        markers_value = value.get("markers")
        if isinstance(markers_value, str) and markers_value.strip():
            markers.append(markers_value.strip())
        if extract_markers:
            markers.extend(extract_markers(value))
        specifier = translate_constraint(str(value.get("version", "*")))
        raw = str(value)
    else:
        return None

    requirement = _build_requirement_string(
        name,
        specifier,
        extras=extras,
        marker=_combine_markers(markers),
    )
    version = _extract_version_from_requirement_string(requirement)
    return DependencySpec(
        name=norm_name,
        version=version,
        requirement=requirement,
        raw=raw,
        group=group,
        is_runtime=is_runtime,
    )


# ---------------------------------------------------------------------------
# Grouped version parsing
# ---------------------------------------------------------------------------

def _parse_grouped_version(
    value: Any,
    *,
    direct_ref_keys: tuple[str, ...],
    strip_pattern: str,
) -> str | None:
    """Extract a version string from a grouped-format dependency value.

    Returns ``None`` for direct-reference dependencies that should be skipped.
    """
    if isinstance(value, str):
        if value == "*":
            return "*"
        cleaned = re.sub(strip_pattern, "", value).strip()
        parts = cleaned.split(",")
        first = re.sub(r"^[><=!]+\s*", "", parts[0]).strip()
        return first if first else "*"
    if isinstance(value, dict):
        if any(k in value for k in direct_ref_keys):
            return None
        ver_str = value.get("version")
        if ver_str is None:
            return None
        return _parse_grouped_version(
            cast(object, ver_str),
            direct_ref_keys=direct_ref_keys,
            strip_pattern=strip_pattern,
        )
    return None


def _parse_pep508(dep_str: str) -> tuple[str | None, str]:
    """Parse a PEP 508 dependency string, returning ``(normalised_name, version)``.

    Returns ``(None, "")`` for URL-based deps (``pkg @ https://...``).
    """
    try:
        req = Requirement(dep_str)
    except InvalidRequirement:
        return None, ""
    if req.url:
        return None, ""
    name = normalise(req.name)
    version = _extract_version_from_specifier(req.specifier)
    return name, version
