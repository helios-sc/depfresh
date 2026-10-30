"""Plan minimal security fixes: the lowest release that clears every advisory.

pip-audit says *which* installed versions are vulnerable, but its
``fix_versions`` keep only the last OSV ``affected`` range of each record:
for fastmcp 3.4.2 it reports 4.1.2 even though the advisory is also fixed
in 3.4.10, and ``last_affected`` ranges (no ``fixed`` event) come back with
no fix at all.  The planner therefore reads the complete OSV records of each
vulnerable package and walks its PyPI releases upwards, returning the lowest
release that no advisory affects, preferring the current major version.

Packages from a non-PyPI index are never looked up here (see
:func:`plan_fixes`), so a private package name is never sent to public PyPI.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from packaging.markers import InvalidMarker, Marker, UndefinedComparison, UndefinedEnvironmentName
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from depfresh.constraints import classify_bump, is_calver, normalise
from depfresh.models import Vulnerability

log = logging.getLogger("depfresh")

#: The deploy platform depfresh resolves for unless told otherwise.
DEFAULT_PLATFORM = "x86_64-unknown-linux-gnu"

OSV_API = "https://api.osv.dev"
PYPI_API = "https://pypi.org"

_LINUX_X86 = {"sys_platform": "linux", "platform_system": "Linux",
              "platform_machine": "x86_64", "os_name": "posix"}
_LINUX_ARM = {**_LINUX_X86, "platform_machine": "aarch64"}
_MAC_ARM = {"sys_platform": "darwin", "platform_system": "Darwin",
            "platform_machine": "arm64", "os_name": "posix"}
_MAC_X86 = {**_MAC_ARM, "platform_machine": "x86_64"}
_WINDOWS = {"sys_platform": "win32", "platform_system": "Windows",
            "platform_machine": "AMD64", "os_name": "nt"}

#: Marker values for the ``uv pip compile --python-platform`` targets.
_PLATFORM_MARKERS: dict[str, dict[str, str]] = {
    "linux": _LINUX_X86,
    "x86_64-unknown-linux-gnu": _LINUX_X86,
    "x86_64-unknown-linux-musl": _LINUX_X86,
    "aarch64-unknown-linux-gnu": _LINUX_ARM,
    "aarch64-unknown-linux-musl": _LINUX_ARM,
    "macos": _MAC_ARM,
    "aarch64-apple-darwin": _MAC_ARM,
    "x86_64-apple-darwin": _MAC_X86,
    "windows": _WINDOWS,
    "x86_64-pc-windows-msvc": _WINDOWS,
}


def supported_platforms() -> list[str]:
    """Platform names accepted by :class:`TargetEnv`."""
    return sorted(_PLATFORM_MARKERS) + ["x86_64-manylinux_*", "aarch64-manylinux_*"]


@dataclass(frozen=True)
class TargetEnv:
    """The interpreter and platform a dependency set is resolved and audited for.

    Attributes:
        python_version: ``"3.11"`` or a full ``"3.11.18"``.
        platform: A ``uv pip compile --python-platform`` target triple.
    """

    python_version: str
    platform: str = DEFAULT_PLATFORM

    def __post_init__(self) -> None:
        self.platform_markers()  # validate early

    def platform_markers(self) -> dict[str, str]:
        """Return the ``sys_platform``/``platform_machine``… marker values."""
        name = self.platform.lower()
        if name in _PLATFORM_MARKERS:
            return dict(_PLATFORM_MARKERS[name])
        if name.startswith("x86_64-manylinux"):
            return dict(_LINUX_X86)
        if name.startswith("aarch64-manylinux"):
            return dict(_LINUX_ARM)
        raise ValueError(
            f"Unsupported platform {self.platform!r}; use one of "
            f"{', '.join(supported_platforms())}"
        )

    @property
    def python_minor(self) -> str:
        """``"3.11"`` for ``"3.11.18"``."""
        return ".".join(self.python_version.split(".")[:2])

    @property
    def python_full(self) -> str:
        """The full version, ``X.Y.0`` when only ``X.Y`` was given."""
        parts = self.python_version.split(".")
        return self.python_version if len(parts) >= 3 else f"{self.python_minor}.0"

    def marker_environment(self) -> dict[str, str]:
        """The PEP 508 marker environment of a CPython on this platform."""
        env = {
            "implementation_name": "cpython",
            "implementation_version": self.python_full,
            "platform_python_implementation": "CPython",
            "platform_release": "",
            "platform_version": "",
            "python_full_version": self.python_full,
            "python_version": self.python_minor,
            "extra": "",
        }
        env.update(self.platform_markers())
        return env

    def accepts_requires_python(self, requires_python: str | None) -> bool:
        """True when a release's ``Requires-Python`` admits this interpreter.

        With only ``X.Y`` known, any patch release of ``X.Y`` counts, so
        ``>=3.11.4`` is accepted for ``3.11``.
        """
        if not requires_python:
            return True
        try:
            spec = SpecifierSet(requires_python)
        except InvalidSpecifier:
            return True
        if len(self.python_version.split(".")) >= 3:
            return spec.contains(self.python_version, prereleases=True)
        return any(
            spec.contains(f"{self.python_minor}.{patch}", prereleases=True)
            for patch in (0, 100)
        )


def evaluate_marker(marker: str | None, env: TargetEnv) -> bool:
    """Evaluate a PEP 508 marker for *env*; a missing marker is always true.

    An unparseable marker counts as true: the package is kept (and audited)
    rather than silently dropped.
    """
    if not marker or not marker.strip():
        return True
    try:
        return Marker(marker).evaluate(env.marker_environment())
    except (InvalidMarker, UndefinedComparison, UndefinedEnvironmentName):
        log.debug("Could not evaluate marker %r; keeping the package", marker)
        return True


# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Release:
    """One release of a package on PyPI."""

    version: Version
    yanked: bool = False
    requires_python: tuple[str | None, ...] = (None,)

    def supports(self, env: TargetEnv) -> bool:
        """True when at least one file of the release admits *env*'s Python."""
        return any(env.accepts_requires_python(rp) for rp in self.requires_python)


class AdvisorySources(Protocol):
    """Where the planner reads advisories and releases from (mocked in tests)."""

    def osv_records(self, package: str, version: str) -> list[dict[str, Any]]:
        """Full OSV records of the advisories affecting *package* at *version*."""
        ...

    def releases(self, package: str) -> list[Release]:
        """Every release of *package* on PyPI (yanked ones flagged)."""
        ...


class AdvisoryLookupError(Exception):
    """Raised by sources when an advisory or release lookup fails."""


class OnlineSources:
    """OSV (``/v1/query``) and the PyPI JSON API over HTTPS, cached per run."""

    def __init__(
        self,
        *,
        osv_api: str = OSV_API,
        pypi_api: str = PYPI_API,
        timeout: float = 30.0,
        user_agent: str = "depfresh",
    ) -> None:
        self._osv_api = osv_api.rstrip("/")
        self._pypi_api = pypi_api.rstrip("/")
        self._timeout = timeout
        self._headers = {"User-Agent": user_agent, "Accept": "application/json"}
        self._osv_cache: dict[tuple[str, str], list[dict[str, Any]]] = {}
        self._release_cache: dict[str, list[Release]] = {}

    def _request(self, url: str, payload: dict[str, Any] | None = None) -> Any:
        data = json.dumps(payload).encode() if payload is not None else None
        headers = dict(self._headers)
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                return json.loads(response.read())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            raise AdvisoryLookupError(f"{url}: {exc}") from exc

    def osv_records(self, package: str, version: str) -> list[dict[str, Any]]:
        key = (normalise(package), version)
        if key in self._osv_cache:
            return self._osv_cache[key]
        records: list[dict[str, Any]] = []
        payload: dict[str, Any] = {
            "package": {"name": package, "ecosystem": "PyPI"}, "version": version,
        }
        for _ in range(20):  # page limit
            data = self._request(f"{self._osv_api}/v1/query", payload)
            records.extend(v for v in data.get("vulns", []) if isinstance(v, dict))
            token = data.get("next_page_token")
            if not token:
                break
            payload = {**payload, "page_token": token}
        self._osv_cache[key] = records
        return records

    def releases(self, package: str) -> list[Release]:
        name = normalise(package)
        if name in self._release_cache:
            return self._release_cache[name]
        quoted = urllib.parse.quote(name)
        data = self._request(f"{self._pypi_api}/pypi/{quoted}/json")
        releases: list[Release] = []
        for raw_version, files in (data.get("releases") or {}).items():
            if not files:
                continue
            try:
                version = Version(raw_version)
            except InvalidVersion:
                continue
            usable = [f for f in files if isinstance(f, dict) and not f.get("yanked")]
            releases.append(Release(
                version=version,
                yanked=not usable,
                requires_python=tuple(f.get("requires_python") for f in usable) or (None,),
            ))
        releases.sort(key=lambda r: r.version)
        self._release_cache[name] = releases
        return releases


# ---------------------------------------------------------------------------
# OSV range evaluation
# ---------------------------------------------------------------------------


def _parse_version(value: object) -> Version | None:
    try:
        return Version(str(value))
    except InvalidVersion:
        return None


def range_affects(events: list[dict[str, Any]], version: Version) -> bool:
    """Evaluate one OSV ``ECOSYSTEM``/``SEMVER`` range for *version*.

    Follows the OSV schema: events sorted by version, ``introduced`` opens
    the range, ``fixed`` closes it at that version, ``last_affected`` closes
    it after that version.
    """
    points: list[tuple[Version, int, str]] = []
    order = {"introduced": 0, "last_affected": 1, "fixed": 2, "limit": 3}
    for event in events:
        for kind, raw in event.items():
            if kind not in order:
                continue
            parsed = (
                Version("0") if kind == "introduced" and str(raw) == "0" else _parse_version(raw)
            )
            if parsed is not None:
                points.append((parsed, order[kind], kind))
    affected = False
    for point, _, kind in sorted(points):
        if kind == "introduced" and version >= point:
            affected = True
        elif kind == "fixed" and version >= point:
            affected = False
        elif kind == "last_affected" and version > point:
            affected = False
        elif kind == "limit" and version >= point:
            affected = False
    return affected


def record_affects(record: Mapping[str, Any], package: str, version: Version) -> bool:
    """True when the OSV *record* says *package* at *version* is affected.

    Every ``affected`` entry of the package counts (OSV often splits one
    advisory into one entry per release line), through its ranges or its
    explicit ``versions`` list.
    """
    name = normalise(package)
    for affected in record.get("affected") or []:
        pkg = affected.get("package") or {}
        if str(pkg.get("ecosystem", "")).lower() != "pypi":
            continue
        if normalise(str(pkg.get("name", ""))) != name:
            continue
        for listed in affected.get("versions") or []:
            if _parse_version(listed) == version:
                return True
        for rng in affected.get("ranges") or []:
            if str(rng.get("type", "")).upper() in ("ECOSYSTEM", "SEMVER") and range_affects(
                list(rng.get("events") or []), version,
            ):
                return True
    return False


def fixed_events(record: Mapping[str, Any], package: str) -> list[Version]:
    """Every ``fixed`` version of *package* in an OSV record (all ranges)."""
    name = normalise(package)
    found: list[Version] = []
    for affected in record.get("affected") or []:
        pkg = affected.get("package") or {}
        if normalise(str(pkg.get("name", ""))) != name:
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                parsed = _parse_version(event.get("fixed")) if "fixed" in event else None
                if parsed is not None:
                    found.append(parsed)
    return found


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------

PlanStatus = Literal["fix", "needs-major", "kept", "no-fix", "private"]


@dataclass
class FixPlan:
    """What to do about one vulnerable package.

    Attributes:
        package: Normalised package name.
        current: Version that is installed (or locked) now.
        vulns: The advisories affecting *current*.
        status: ``"fix"`` (move to *target*), ``"needs-major"`` (the only fix
            crosses a major version and that is not allowed), ``"kept"``
            (``--keep-version``), ``"no-fix"`` or ``"private"`` (from a
            non-PyPI index, not looked up).
        target: The release to move to when *status* is ``"fix"``.
        lowest_fix: The lowest release clear of every advisory, any major.
        kind: :func:`~depfresh.constraints.classify_bump` of current → target
            (or → *lowest_fix* when no target).
        reason: Human-readable explanation for reports.
        approximate: True when the plan fell back to pip-audit's fix versions
            because OSV or PyPI could not be read.
    """

    package: str
    current: str
    vulns: list[Vulnerability] = field(default_factory=list)
    status: PlanStatus = "no-fix"
    target: str | None = None
    lowest_fix: str | None = None
    kind: str = ""
    reason: str = ""
    approximate: bool = False


def major_allowed(package: str, allow_major: list[str] | None) -> bool:
    """``None`` → no majors, ``[]`` → every package, otherwise the named packages."""
    if allow_major is None:
        return False
    if not allow_major:
        return True
    return normalise(package) in {normalise(p) for p in allow_major}


def _group_vulns(vulns: Iterable[Vulnerability]) -> dict[str, list[Vulnerability]]:
    grouped: dict[str, list[Vulnerability]] = {}
    for v in vulns:
        grouped.setdefault(normalise(v.package), []).append(v)
    return grouped


def plan_fixes(
    vulns: list[Vulnerability],
    current: Mapping[str, str],
    *,
    env: TargetEnv,
    sources: AdvisorySources,
    allow_major: list[str] | None = None,
    keep_version: list[str] | None = None,
    private: Iterable[str] = (),
) -> dict[str, FixPlan]:
    """Plan the minimal fix for every vulnerable package.

    Args:
        vulns: Deduplicated audit findings.
        current: ``{normalised_name: version}`` of the audited set.
        env: Target interpreter; releases whose ``Requires-Python`` excludes
            it are skipped.
        sources: OSV/PyPI access (see :class:`OnlineSources`).
        allow_major: ``None`` → stay in the current major; ``[]`` → any
            package may cross a major; ``["pkg"]`` → only those.
        keep_version: Packages that must not move.
        private: Packages from a non-PyPI index: never looked up.

    Returns:
        ``{normalised_name: FixPlan}``.
    """
    keep = {normalise(p) for p in keep_version or []}
    private_set = {normalise(p) for p in private}
    grouped = _group_vulns(vulns)

    def plan_one(name: str) -> FixPlan:
        pkg_vulns = grouped[name]
        cur = current.get(name) or pkg_vulns[0].version
        plan = FixPlan(package=name, current=cur, vulns=pkg_vulns)
        if name in keep:
            plan.status, plan.reason = "kept", "Pinned to current version via --keep-version"
            return plan
        if name in private_set:
            plan.status = "private"
            plan.reason = "From a private index: not looked up on PyPI"
            return plan
        _plan_versions(plan, env=env, sources=sources, allow_major=allow_major)
        return plan

    names = sorted(grouped)
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(names)))) as pool:
        plans = list(pool.map(plan_one, names))
    return {p.package: p for p in plans}


def _plan_versions(
    plan: FixPlan,
    *,
    env: TargetEnv,
    sources: AdvisorySources,
    allow_major: list[str] | None,
) -> None:
    """Fill *plan*'s target/lowest_fix/status from OSV ranges and PyPI releases."""
    current = _parse_version(plan.current)
    if current is None:
        plan.reason = f"Cannot parse the current version {plan.current!r}"
        return

    try:
        records = sources.osv_records(plan.package, plan.current)
    except AdvisoryLookupError as exc:
        log.warning(
            "OSV lookup failed for %s (%s); using pip-audit fix versions", plan.package, exc,
        )
        records = []
        plan.approximate = True
    advisory_records = _records_by_advisory(plan.vulns, records)
    if any(not recs for recs in advisory_records):
        plan.approximate = plan.approximate or bool(records)

    def affected(version: Version) -> bool:
        for vuln, recs in zip(plan.vulns, advisory_records):
            if recs:
                if any(record_affects(r, plan.package, version) for r in recs):
                    return True
            elif _affected_by_fix_versions(vuln, current, version):
                return True
        return False

    try:
        releases = [r for r in sources.releases(plan.package) if not r.yanked]
    except AdvisoryLookupError as exc:
        log.warning("PyPI lookup failed for %s (%s); using advisory fix versions",
                    plan.package, exc)
        plan.approximate = True
        releases = [Release(v) for v in _advisory_fix_versions(plan, records)]

    candidates = [
        r.version for r in releases
        if r.version > current
        and (current.is_prerelease or not r.version.is_prerelease)
        and r.supports(env)
    ]
    # Candidates ascend, so the first unaffected one is the lowest fix; and if
    # it is already past the current major, every in-major release is affected.
    lowest = next((c for c in candidates if not affected(c)), None)
    same_major = lowest if lowest is not None and _same_major(current, lowest) else None

    plan.lowest_fix = str(lowest) if lowest else None
    if same_major is not None:
        plan.status, plan.target = "fix", str(same_major)
        plan.kind = classify_bump(plan.current, plan.target)
        plan.reason = f"Upgrade to {plan.target}, the lowest release that fixes every advisory"
    elif lowest is not None:
        plan.kind = classify_bump(plan.current, str(lowest))
        if major_allowed(plan.package, allow_major):
            plan.status, plan.target = "fix", str(lowest)
            plan.reason = (
                f"Upgrade to {plan.target} (MAJOR {current.major}→{lowest.major}, "
                "allowed by --allow-major): no fix exists in the current major"
            )
        else:
            plan.status = "needs-major"
            plan.reason = (
                f"Requires major upgrade ({current.major}→{lowest.major}, lowest fix "
                f"{lowest}). Use --allow-major {plan.package}"
            )
    else:
        plan.status = "no-fix"
        plan.reason = "No fixed release available yet"


def _same_major(current: Version, candidate: Version) -> bool:
    """Calendar versions never cross a "major"; otherwise compare the first component."""
    if is_calver(str(current)) and is_calver(str(candidate)):
        return True
    return candidate.major == current.major


def _records_by_advisory(
    vulns: list[Vulnerability], records: list[dict[str, Any]],
) -> list[list[dict[str, Any]]]:
    """For each finding, the OSV records that describe the same advisory."""
    result: list[list[dict[str, Any]]] = []
    for vuln in vulns:
        ids = set(vuln.ids)
        matched = [
            r for r in records
            if ids & {str(r.get("id", "")), *(str(a) for a in r.get("aliases") or [])}
        ]
        result.append(matched)
    return result


def _affected_by_fix_versions(vuln: Vulnerability, current: Version, version: Version) -> bool:
    """Fallback without OSV ranges: affected below the lowest fix above *current*."""
    fixes = sorted(
        v for v in (_parse_version(f.strip()) for f in vuln.fix_versions.split(",") if f.strip())
        if v is not None and v > current
    )
    if not fixes:
        return True
    return version < fixes[0]


def _advisory_fix_versions(plan: FixPlan, records: list[dict[str, Any]]) -> list[Version]:
    """Candidate releases when PyPI is unavailable: every known fixed version."""
    found: set[Version] = set()
    for record in records:
        found.update(fixed_events(record, plan.package))
    for vuln in plan.vulns:
        for raw in vuln.fix_versions.split(","):
            parsed = _parse_version(raw.strip())
            if parsed is not None:
                found.add(parsed)
    return sorted(found)
