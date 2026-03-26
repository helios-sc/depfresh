"""Package name normalisation, version constraint building, and upgrade diagnostics."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from depfresh.models import PackageChange, Vulnerability

log = logging.getLogger("depfresh")


def normalise(name: str) -> str:
    """Normalise a Python package name (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def build_constraints(
    pkgs: dict[str, str],
    *,
    allow_major: list[str] | None = None,
    keep_version: list[str] | None = None,
) -> list[str]:
    """Build upgrade constraint lines.

    Parameters
    ----------
    pkgs:
        ``{normalised_name: version}`` of current packages.
    allow_major:
        ``None`` → minor/patch only.
        ``[]`` (empty) → uncapped for all packages.
        ``["urllib3", ...]`` → uncapped for named packages only.
    keep_version:
        Named packages are pinned to their current version exactly.
        Takes precedence over *allow_major*.
    """
    major_set = {normalise(p) for p in allow_major} if allow_major else set()
    keep_set = {normalise(p) for p in keep_version} if keep_version else set()
    allow_all = allow_major is not None and len(allow_major) == 0

    pkg_names = set(pkgs)
    for name in major_set - pkg_names:
        log.warning("--allow-major package %r not found in dependencies (typo?)", name)
    for name in keep_set - pkg_names:
        log.warning("--keep-version package %r not found in dependencies (typo?)", name)

    constraints: list[str] = []
    for name, version in sorted(pkgs.items()):
        if name in keep_set:
            constraints.append(f"{name}=={version}")
        elif allow_all or name in major_set:
            constraints.append(f"{name}>={version}")
        else:
            m = re.match(r"^(\d+)\.", version)
            if m:
                major = int(m.group(1))
                constraints.append(f"{name}>={version},<{major + 1}.0")
            else:
                constraints.append(f"{name}=={version}")
    return constraints


def compute_changes(
    old_pkgs: dict[str, str],
    new_pkgs: dict[str, str],
    vuln_packages: set[str],
) -> tuple[list[PackageChange], list[PackageChange], list[str]]:
    """Compare old and new package sets. Returns ``(upgraded, new_deps, unchanged)``."""
    from depfresh.models import PackageChange

    upgraded: list[PackageChange] = []
    new_deps: list[PackageChange] = []
    unchanged: list[str] = []

    for name, new_ver in sorted(new_pkgs.items()):
        if name in old_pkgs:
            old_ver = old_pkgs[name]
            if old_ver != new_ver:
                upgraded.append(PackageChange(
                    name=name,
                    old_version=old_ver,
                    new_version=new_ver,
                    is_security_fix=name in vuln_packages,
                ))
            else:
                unchanged.append(f"{name}=={old_ver}")
        else:
            new_deps.append(PackageChange(
                name=name, old_version="(new)", new_version=new_ver,
            ))

    return upgraded, new_deps, unchanged


def diagnose_remaining(
    vulns: list[Vulnerability],
    old_pkgs: dict[str, str],
    *,
    allow_major: list[str] | None = None,
    keep_version: list[str] | None = None,
) -> list[str]:
    """Explain *why* each post-upgrade vulnerability was not fixed.

    Returns a list of human-readable reason strings, one per vulnerability
    in the same order as *vulns*.
    """
    major_set = {normalise(p) for p in allow_major} if allow_major else set()
    keep_set = {normalise(p) for p in keep_version} if keep_version else set()
    allow_all = allow_major is not None and len(allow_major) == 0

    reasons: list[str] = []
    for v in vulns:
        norm = normalise(v.package)

        # 1. Pinned by --keep-version
        if norm in keep_set:
            reasons.append("Pinned to current version via --keep-version")
            continue

        # 2. Parse fix version (take the first one if comma-separated)
        fix_str = v.fix_versions.split(",")[0].strip()
        fix_major_match = re.match(r"^(\d+)\.", fix_str)
        if not fix_str or not fix_major_match:
            reasons.append("No fix version available yet")
            continue

        fix_major = int(fix_major_match.group(1))

        # 3. Get current major version
        current_ver = old_pkgs.get(norm, v.version)
        cur_major_match = re.match(r"^(\d+)\.", current_ver)
        if not cur_major_match:
            reasons.append("Could not determine current major version")
            continue

        cur_major = int(cur_major_match.group(1))

        # 4. Compare
        if fix_major > cur_major:
            if allow_all or norm in major_set:
                reasons.append(
                    f"Major upgrade allowed ({cur_major}\u2192{fix_major}) "
                    f"but could not resolve (possible dependency conflict)"
                )
            else:
                reasons.append(
                    f"Requires major upgrade ({cur_major}\u2192{fix_major}). "
                    f"Use --allow-major {v.package}"
                )
        else:
            reasons.append(
                "Fix is within version constraints but could not be "
                "resolved (possible dependency conflict)"
            )

    return reasons


def format_allow_major(allow_major: list[str] | None) -> str:
    """Human-readable description of the allow-major setting."""
    if allow_major is None:
        return "no (minor/patch only)"
    elif len(allow_major) == 0:
        return "yes (all packages)"
    else:
        return f"selective ({', '.join(allow_major)})"


def format_keep_version(keep_version: list[str] | None) -> str:
    """Human-readable description of the keep-version setting."""
    if not keep_version:
        return "none"
    return ", ".join(keep_version)
