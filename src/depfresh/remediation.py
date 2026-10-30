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

import dataclasses
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
    #: Exact group/extra flags to export with (from the Dockerfile's ``uv sync``);
    #: ``None`` derives them from the fields above.
    uv_group_flags: tuple[str, ...] | None = None


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
        check = self.repo_check
        note = (
            f"Repository advisories: checked {len(check.repos_checked)} GitHub "
            "repositories of shipped packages"
        )
        if check.in_database:
            note += (f"; {len(check.in_database)} of their advisories are in the global "
                     "database already, so OSV's ranges apply to them")
        if check.unmapped:
            note += (
                f"; {len(check.unmapped)} packages declare no GitHub repository "
                "and were not checked"
            )
        notes = [note]
        for ghsa, what in sorted(check.unreadable.items()):
            notes.append(f"Check by hand: repository advisory {ghsa} ({what}) has a version "
                         "range depfresh cannot read")
        return notes


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


def introduced_findings(
    before: Iterable[Vulnerability], after: Iterable[Vulnerability],
) -> list[Vulnerability]:
    """Findings of *after* whose package did not have that advisory in *before*.

    A co-upgrade can move a package onto a release with an advisory of its
    own; such a result trades one vulnerability for another.
    """
    seen = {(normalise(v.package), i) for v in before for i in v.ids}
    return [v for v in after if not any((normalise(v.package), i) in seen for i in v.ids)]


def introduced_reason(introduced: list[Vulnerability]) -> str:
    """The write-back refusal for :func:`introduced_findings`."""
    listed = ", ".join(f"{v.package} {v.version} {v.ghsa or v.cve}" for v in introduced[:5])
    more = f" and {len(introduced) - 5} more" if len(introduced) > 5 else ""
    return (f"the changes bring in {len(introduced)} advisories that were not there before "
            f"({listed}{more})")


def database_findings(vulns: Iterable[Vulnerability]) -> list[Vulnerability]:
    """The findings of the advisory database (everything but repository advisories)."""
    return [v for v in vulns if not v.from_repository]


def record_plans(plans: dict[str, FixPlan], new_plans: Mapping[str, FixPlan]) -> None:
    """Merge one round's plans into the run's (one plan per package, for the report).

    A later fix plan of a package that already moved keeps the original
    version and advisories, so the row reads "from → final".  A later plan
    without a fix only adds the reasons of the advisories it leaves open.
    """
    for name, new in new_plans.items():
        old = plans.get(name)
        if old is None:
            plans[name] = new
        elif new.status == "fix":
            if old.status == "fix" and old.current != new.current:
                seen = {i for v in new.vulns for i in v.ids}
                new = dataclasses.replace(
                    new,
                    current=old.current,
                    vulns=[*(v for v in old.vulns if not seen & set(v.ids)), *new.vulns],
                    kind=classify_bump(old.current, new.target or ""),
                    open_advisories={**{k: w for k, w in old.open_advisories.items()
                                        if k not in seen}, **new.open_advisories},
                )
            plans[name] = new
        else:
            for vid, why in new.open_advisories.items():
                old.open_advisories.setdefault(vid, why)


def snapshot_plans(plans: Mapping[str, FixPlan]) -> dict[str, FixPlan]:
    """A copy of *plans* that later merges cannot change."""
    return {n: dataclasses.replace(p, open_advisories=dict(p.open_advisories))
            for n, p in plans.items()}


def keep_repository_findings_open(
    plans: dict[str, FixPlan],
    tried: Mapping[str, FixPlan],
    failures: dict[str, str],
    remaining: Iterable[Vulnerability],
    reason: str,
) -> None:
    """After reverting the repository step: say why each repository finding stays."""
    for v in remaining:
        if not v.from_repository:
            continue
        name = normalise(v.package)
        if name in plans:
            for vid in v.ids:
                plans[name].open_advisories[vid] = reason
        elif name in tried:
            plans[name] = tried[name]
            failures[name] = reason


def cobump_problem(
    before: Mapping[str, str],
    after: Mapping[str, str],
    fixing: Iterable[str],
    options: RemediationOptions,
) -> str:
    """Why an update that fixes *fixing* cannot stand, or ``""`` when it can.

    Packages other than *fixing* that moved (co-upgrades) must not be named by
    ``--keep-version`` and must not cross a major that ``--allow-major`` does
    not cover.  Both modes apply this to every trial, the first one included.
    """
    targets = {normalise(n) for n in fixing}
    changed, _, _, _ = diff_sets(before, after, set())
    others = [c for c in changed if c.name not in targets]
    kept_names = {normalise(p) for p in options.keep_version or []}
    kept = [c for c in others if c.name in kept_names]
    majors = disallowed_majors([c for c in others if c.name not in kept_names],
                               options.allow_major)
    problems: list[str] = []
    if kept:
        problems.append(f"moves {_moves(kept)}, which --keep-version keeps")
    if majors:
        names = " ".join(sorted(targets | {c.name for c in majors}))
        problems.append(f"requires a major co-upgrade of {_moves(majors)}; "
                        f"re-run with --allow-major {names}")
    return "; ".join(problems)


def _moves(changes: Iterable[PackageChange]) -> str:
    return ", ".join(f"{c.name} {c.old_version}→{c.new_version}" for c in changes)


def planned_fixes(
    plans: Mapping[str, FixPlan],
    final: Mapping[str, str],
    failures: Mapping[str, str],
    remaining: Iterable[Vulnerability],
    *,
    applied: bool,
) -> list[PlannedFix]:
    """Turn plans plus the outcome into report rows.

    Args:
        plans: Every plan made during the run (last plan per package wins).
        final: ``{name: version}`` after remediation.
        failures: ``{name: reason}`` for fixes uv could not apply.
        remaining: The findings left afterwards.  A fix counts as applied when
            only the advisories its plan left open remain.
        applied: False for dry runs and audit-only runs.
    """
    unexpected: set[str] = set()
    for v in remaining:
        name = normalise(v.package)
        known = plans[name].open_advisories if name in plans else {}
        if not any(i in known for i in v.ids):
            unexpected.add(name)
    rows: list[PlannedFix] = []
    for name, p in sorted(plans.items()):
        status: str = p.status
        reason = p.reason
        if p.status == "fix":
            if name in failures:
                status, reason = "blocked", failures[name]
            elif not applied:
                status = "planned"
            elif name in unexpected:
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
            open_advisories=dict(p.open_advisories),
        ))
    return rows


def remaining_reasons(
    post_vulns: list[Vulnerability],
    fixes: list[PlannedFix],
    explain: Callable[[str], str] | None = None,
) -> list[str]:
    """One reason per remaining finding: its own when its plan left it open."""
    by_name = {f.package: f for f in fixes}
    reasons: list[str] = []
    for v in post_vulns:
        fix = by_name.get(normalise(v.package))
        if fix is not None:
            own = next((fix.open_advisories[i] for i in v.ids if i in fix.open_advisories), None)
            reasons.append(own if own is not None else fix.reason)
        elif explain is not None:
            reasons.append(explain(normalise(v.package)))
        else:
            reasons.append("Not planned (appeared after remediation); re-run depfresh")
    return reasons
