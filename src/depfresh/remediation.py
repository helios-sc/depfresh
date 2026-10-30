"""Pieces shared by the minimal remediation modes (lock-aware and resolved).

Both modes follow the same loop: determine the set that ships, audit it,
plan the lowest fixing release for each vulnerable package, apply the plan
with uv, then determine and audit the set that would ship afterwards.  Only
*how* the shipped set is computed and changed differs (``uv export`` and
``uv lock --upgrade-package`` versus ``uv pip compile`` for the deploy
platform and line edits), which lives in :mod:`depfresh.lockmode` and
:mod:`depfresh.pipmode`.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from depfresh.advisories import (
    AdvisorySources,
    FixPlan,
    OnlineSources,
    TargetEnv,
    major_allowed,
    plan_fixes,
)
from depfresh.audit import run_audit, write_pinned_requirements
from depfresh.constraints import classify_bump, normalise
from depfresh.models import ImportCheck, PackageChange, PlannedFix, Vulnerability
from depfresh.repoadvisories import RepoAdvisoryChecker
from depfresh.verify import import_regressions, verify_imports

log = logging.getLogger("depfresh")


@dataclass
class RemediationOptions:
    """User choices that shape a minimal remediation run.

    Attributes:
        env: Deploy interpreter and platform.
        allow_major: ``None`` (stay in-major), ``[]`` (any package) or names.
        keep_version: Packages that must not move.
        dry_run: Plan and verify, but write nothing to the target.
        import_check: Compare imports before and after (installs both sets
            into a venv on this host).
        extras: Optional-dependency groups that ship.
        all_extras: Every optional-dependency group ships.
        groups: Dependency groups (PEP 735 / uv) that ship; lock mode only.
        all_groups: Every dependency group ships; lock mode only.
        max_rounds: Plan/apply/audit rounds before giving up on follow-up
            findings (a co-bumped package that is itself vulnerable…).
    """

    env: TargetEnv
    allow_major: list[str] | None = None
    keep_version: list[str] | None = None
    dry_run: bool = False
    import_check: bool = True
    extras: tuple[str, ...] = ()
    all_extras: bool = False
    groups: tuple[str, ...] = ()
    all_groups: bool = False
    max_rounds: int = 3


@dataclass
class Auditor:
    """Runs the pinned pip-audit tool over ``{name: version}`` sets.

    With *repo_check* (``--repo-advisories``) every audit also includes the
    GitHub repository advisories that are not in the Advisory DB yet.
    """

    tool_python: str
    work_dir: Path
    calls: int = 0
    repo_check: RepoAdvisoryChecker | None = None

    def audit(self, pins: Mapping[str, str], label: str) -> list[Vulnerability]:
        """Audit *pins* (already filtered for the target platform)."""
        self.calls += 1
        path = self.work_dir / f"audit-{self.calls}-{label}.txt"
        write_pinned_requirements(dict(pins), path)
        try:
            vulns = run_audit(self.tool_python, path, label)
        finally:
            path.unlink(missing_ok=True)
        if self.repo_check is not None:
            extra = self.repo_check.findings(pins, vulns)
            log.info("Repository advisories (%s): %d not yet in the Advisory DB", label, len(extra))
            vulns = vulns + extra
        return vulns

    def notes(self) -> list[str]:
        """What the repository-advisory pass covered, for reports."""
        if self.repo_check is None:
            return []
        note = (
            f"Repository advisories: checked {len(self.repo_check.repos_checked)} GitHub "
            "repositories of shipped packages"
        )
        if self.repo_check.unmapped:
            note += (
                f"; {len(self.repo_check.unmapped)} packages declare no GitHub repository "
                "and were not checked"
            )
        return [note]


@dataclass
class ImportGate:
    """Baseline and after import checks for one run."""

    enabled: bool
    target_dir: Path
    baseline: ImportCheck | None = None
    after: ImportCheck | None = None
    notes: list[str] = field(default_factory=list)
    blocked: str = ""

    def check(self, venv_python: str, label: str) -> ImportCheck:
        """Verify imports against *venv_python* (``label``: baseline or upgraded)."""
        return verify_imports(self.target_dir, venv_python, label=label)

    def regressions(self) -> dict[str, str]:
        """Modules that resolved in the baseline and fail after remediation."""
        if self.baseline is None or self.after is None:
            return {}
        return import_regressions(self.baseline, self.after)


def default_sources() -> AdvisorySources:
    """OSV and PyPI over HTTPS (honours ``HTTPS_PROXY``)."""
    from depfresh import __version__

    return OnlineSources(user_agent=f"depfresh/{__version__}")


def plan(
    vulns: list[Vulnerability],
    current: Mapping[str, str],
    options: RemediationOptions,
    sources: AdvisorySources,
    private: Iterable[str],
) -> dict[str, FixPlan]:
    """Plan fixes for *vulns* under *options* (see :func:`plan_fixes`)."""
    if not vulns:
        return {}
    return plan_fixes(
        vulns,
        current,
        env=options.env,
        sources=sources,
        allow_major=options.allow_major,
        keep_version=options.keep_version,
        private=private,
    )


def diff_sets(
    before: Mapping[str, str],
    after: Mapping[str, str],
    vulnerable: set[str],
) -> tuple[list[PackageChange], list[PackageChange], list[str], list[PackageChange]]:
    """Compare two ``{name: version}`` sets.

    Returns:
        ``(changed, added, unchanged, removed)``; ``changed`` entries are
        flagged as security fixes when the package was vulnerable before.
    """
    changed: list[PackageChange] = []
    added: list[PackageChange] = []
    unchanged: list[str] = []
    removed: list[PackageChange] = []
    for name in sorted(set(before) | set(after)):
        old, new = before.get(name), after.get(name)
        if old is None and new is not None:
            added.append(PackageChange(name, "(new)", new))
        elif new is None and old is not None:
            removed.append(PackageChange(name, old, "(removed)"))
        elif old != new and old is not None and new is not None:
            changed.append(PackageChange(name, old, new, is_security_fix=name in vulnerable))
        elif old is not None:
            unchanged.append(f"{name}=={old}")
    return changed, added, unchanged, removed


def disallowed_majors(
    changes: Iterable[PackageChange], allow_major: list[str] | None,
) -> list[PackageChange]:
    """Changes that cross a major version for a package --allow-major does not cover."""
    return [
        c for c in changes
        if classify_bump(c.old_version, c.new_version) == "major"
        and not major_allowed(c.name, allow_major)
    ]


def planned_fixes(
    plans: Mapping[str, FixPlan],
    final: Mapping[str, str],
    failures: Mapping[str, str],
    still_vulnerable: set[str],
    *,
    applied: bool,
) -> list[PlannedFix]:
    """Turn plans plus the outcome into report rows.

    Args:
        plans: Every plan made during the run (last plan per package wins).
        final: ``{name: version}`` after remediation.
        failures: ``{name: reason}`` for fixes uv could not apply.
        still_vulnerable: Packages that still have findings afterwards.
        applied: False for dry runs and audit-only runs.
    """
    rows: list[PlannedFix] = []
    for name, p in sorted(plans.items()):
        status: str = p.status
        reason = p.reason
        if p.status == "fix":
            if name in failures:
                status, reason = "blocked", failures[name]
            elif not applied:
                status = "planned"
            elif name in still_vulnerable:
                status = "blocked"
                reason = f"Moved to {final.get(name)}, still vulnerable; see remaining findings"
            else:
                status = "applied"
        rows.append(PlannedFix(
            package=name,
            current=p.current,
            target=p.target or p.lowest_fix,
            status=status,
            kind=p.kind,
            reason=reason + (" (approximate: OSV/PyPI unavailable)" if p.approximate else ""),
            advisories=sorted({v.ghsa or v.cve for v in p.vulns}),
            final=final.get(name),
        ))
    return rows


def remaining_reasons(
    post_vulns: list[Vulnerability],
    fixes: list[PlannedFix],
    explain: Callable[[str], str] | None = None,
) -> list[str]:
    """One reason per remaining finding, from the plan of its package."""
    by_name = {f.package: f for f in fixes}
    reasons: list[str] = []
    for v in post_vulns:
        fix = by_name.get(normalise(v.package))
        if fix is not None:
            reasons.append(fix.reason)
        elif explain is not None:
            reasons.append(explain(normalise(v.package)))
        else:
            reasons.append("Not planned (appeared after remediation); re-run depfresh")
    return reasons
