"""Package name normalisation, version constraint building, and upgrade diagnostics."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from packaging.version import Version

    from depfresh.models import PackageChange, Vulnerability

log = logging.getLogger("depfresh")


def normalise(name: str) -> str:
    """Normalise a Python package name (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower()


#: First release component at or above which a version is treated as a
#: calendar version (certifi 2026.10.19, pytz 2026.1, tzdata 2025.3).  Moving
#: between years is a data refresh, not an API break.
CALVER_MIN_MAJOR = 1900


def is_calver(version: str) -> bool:
    """True for calendar versions such as ``2026.10.19`` (major >= 1900)."""
    m = re.match(r"^(\d+)", version)
    return m is not None and int(m.group(1)) >= CALVER_MIN_MAJOR


def classify_bump(old: str, new: str) -> str:
    """Classify a version change for reports and the major-upgrade policy.

    Returns one of ``"same"``, ``"patch"``, ``"minor"``, ``"0.x-minor"`` (a
    minor bump of a 0.x release, which may break), ``"major"``, ``"calver"``
    (between calendar versions), ``"downgrade"``, ``"new"``/``"removed"``
    (when one side is missing) or ``"unknown"`` when a version does not parse.
    """
    from packaging.version import InvalidVersion, Version

    if not old or old == "(new)":
        return "new"
    if not new or new == "(removed)":
        return "removed"
    try:
        a, b = Version(old), Version(new)
    except InvalidVersion:
        return "unknown"
    if a == b:
        return "same"
    if b < a:
        return "downgrade"
    if is_calver(old) and is_calver(new):
        return "calver"
    if b.major > a.major:
        return "major"
    if b.minor > a.minor:
        return "0.x-minor" if a.major == 0 else "minor"
    return "patch"


def admit_version(specifier: str, target: str) -> str:
    """Rewrite a PEP 440 *specifier* so that it admits *target* as its floor.

    Used to raise a floor for a security fix while keeping the rest of the
    user's intent.  Upper bounds are never dropped: a bound that excludes
    *target* is lifted only as far as *target* needs, at the bound's own
    granularity, epochs included.

    * an exact pin (``==X``/``===X``) becomes ``==target``;
    * floors (``>=``, ``>``) give way to ``>=target``;
    * ``~=X.Y.Z`` (``>=X.Y.Z, ==X.Y.*``) becomes ``~=target`` when *target*
      has as many release components, ``>=target,==<prefix>.*`` otherwise,
      with the prefix taken from *target*;
    * a wildcard ``==X.Y.*`` is kept, or moved to *target*'s ``X.Y``;
    * ``<V`` and ``<=V`` that admit *target* are kept; otherwise ``<V`` moves
      to the next value after *target* with as many components as ``V``
      (``<6.22`` → ``<6.26`` for 6.25.0, ``<47`` → ``<51`` for 50.0.2) and
      ``<=V`` becomes ``<=target``;
    * ``!=`` exclusions are kept unless they exclude *target*;
    * a specifier with no floor gains ``>=target``.

    Examples::

        admit_version("==2.6.3", "2.8.0")        -> "==2.8.0"
        admit_version(">=2.10.0", "3.17.1")      -> ">=3.17.1"
        admit_version(">=6.21,<7", "6.25.0")     -> ">=6.25.0,<7"
        admit_version(">=6.21,<6.22", "6.25.0")  -> ">=6.25.0,<6.26"
        admit_version(">=41,<47", "50.0.2")      -> ">=50.0.2,<51"
        admit_version("~=2.31.0", "2.32.1")      -> "~=2.32.1"
        admit_version("==2.31.*", "2.32.1")      -> ">=2.32.1,==2.32.*"
        admit_version("", "2.8.0")               -> ">=2.8.0"
    """
    from packaging.specifiers import InvalidSpecifier, Specifier
    from packaging.version import InvalidVersion, Version

    tv = Version(target)
    floor = f">={target}"
    kept: list[str] = []
    for clause in (c.strip() for c in specifier.split(",") if c.strip()):
        try:
            spec = Specifier(clause)
            op, ver = spec.operator, spec.version
            if op in ("==", "===") and not ver.endswith(".*"):
                return f"=={target}"
            if op in (">=", ">"):
                continue
            if op == "~=":
                width = len(Version(ver).release)
                if width == len(tv.release) and tv.local is None:
                    floor = ""
                    kept.append(f"~={target}")
                else:
                    kept.append(f"=={_prefix(tv, width - 1)}.*")
            elif op in ("==", "!=") and ver.endswith(".*"):
                if op == "!=":
                    if spec.contains(tv, prereleases=True):
                        kept.append(clause)
                elif spec.contains(tv, prereleases=True):
                    kept.append(clause)
                else:
                    kept.append(f"=={_prefix(tv, len(Version(ver[:-2]).release))}.*")
            elif spec.contains(tv, prereleases=True):
                kept.append(clause)
            elif op == "<":
                kept.append(f"<{_next_after(tv, len(Version(ver).release))}")
            elif op == "<=":
                kept.append(f"<={target}")
            # "!=target" excludes the fix itself: dropped.
        except (InvalidSpecifier, InvalidVersion):
            kept.append(clause)
    out = [floor] if floor else []
    for clause in kept:
        if clause not in out:
            out.append(clause)
    return ",".join(out)


def _epoch(version: Version) -> str:
    return f"{version.epoch}!" if version.epoch else ""


def _prefix(version: Version, width: int) -> str:
    """The first *width* release components of *version* (zero-padded), with its epoch."""
    release = [*version.release[:width], *([0] * max(0, width - len(version.release)))]
    return _epoch(version) + ".".join(str(part) for part in release)


def _next_after(version: Version, width: int) -> str:
    """The smallest *width*-component version above *version*: ``2.32.1``, 2 → ``2.33``."""
    release = [*version.release[:width], *([0] * max(0, width - len(version.release)))]
    release[-1] += 1
    return _epoch(version) + ".".join(str(part) for part in release)


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
