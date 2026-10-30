"""Report writers — log files, markdown, and requirements output."""

from __future__ import annotations

import logging
from pathlib import Path

from depfresh.constraints import (
    classify_bump,
    format_allow_major,
    format_keep_version,
    normalise,
)
from depfresh.models import PlannedFix, UpgradeResult
from depfresh.uv import compile_hashed

log = logging.getLogger("depfresh")


# ---------------------------------------------------------------------------
# Requirements writers
# ---------------------------------------------------------------------------

def write_requirements(pkgs: dict[str, str], path: Path) -> None:
    """Write sorted requirements in simple ``name==version`` format."""
    lines = [f"{name}=={ver}" for name, ver in sorted(pkgs.items())]
    path.write_text("\n".join(lines) + "\n")
    log.debug("Wrote requirements: %s (%d packages)", path, len(lines))


def write_requirements_hashed(
    uv: str, pkgs: dict[str, str], path: Path, python_version: str,
) -> None:
    """Write requirements in pip-compile format with hashes.

    Delegates to :func:`depfresh.uv.compile_hashed`.
    """
    compile_hashed(uv, pkgs, path, python_version)


# ---------------------------------------------------------------------------
# Log writer
# ---------------------------------------------------------------------------

def write_log(report: UpgradeResult, out_dir: Path, date_prefix: str) -> Path:
    """Write the detailed execution log."""
    path = out_dir / f"{date_prefix}_dependency_upgrade.log"
    sep = "=" * 80

    lines = [
        sep,
        f"DEPENDENCY UPGRADE LOG — {report.service_label}",
        f"Date: {report.date}",
        f"Tool: uv {report.uv_version} + pip-audit {report.pip_audit_version}",
        f"Python: {report.python_version}",
        f"Requirements: {report.requirements_path}",
        f"Dependency scope: {report.dependency_scope}",
        f"Ignore direct references: {'yes' if report.ignore_direct_references else 'no'}",
        f"Allow-major: {format_allow_major(report.allow_major)}",
        f"Keep-version: {format_keep_version(report.keep_version)}",
        f"Dry-run: {'yes' if report.dry_run else 'no'}",
        f"Mode: {report.mode} ({report.strategy})",
    ]
    if report.platform:
        lines.append(f"Target: {report.platform}, Python {report.python_version}")
    if report.extras:
        lines.append(f"Extras: {', '.join(report.extras)}")
    if report.groups:
        lines.append(f"Groups: {', '.join(report.groups)}")
    lines += [sep, "", "== PRE-UPGRADE VULNERABILITY AUDIT " + "=" * 44, ""]

    if report.pre_audit_vulns:
        lines.append(
            f"Found {len(report.pre_audit_vulns)} vulnerabilities in "
            f"{len({v.package for v in report.pre_audit_vulns})} packages:"
        )
        lines.append("")
        lines.append(f"{'Package':<25} {'Old Ver':<12} {'CVE':<18} {'Fix Versions':<20}")
        lines.append("-" * 75)
        for v in report.pre_audit_vulns:
            lines.append(f"{v.package:<25} {v.version:<12} {v.cve:<18} {v.fix_versions:<20}")
    else:
        lines.append("No vulnerabilities found.")

    if report.fixes:
        lines += ["", "", "== SECURITY FIXES " + "=" * 61, ""]
        for f in report.fixes:
            lines.append(
                f"  {f.package:<28} {f.current:<12} -> {(f.final or f.target or '-'):<12} "
                f"[{f.status}] {f.reason}"
            )
    if report.commands:
        lines += ["", "", "== COMMANDS " + "=" * 67, ""]
        lines += [f"  {c}" for c in report.commands]
    if report.lock_changes:
        lines += ["", "", "== UV.LOCK CHANGES " + "=" * 60, ""]
        for c in report.lock_changes:
            lines.append(f"  {c.name:<35} {c.old_version:<15} -> {c.new_version}")
    if report.lock_check:
        lines.append(f"uv lock --check: {report.lock_check}")
    if report.resolution_check:
        lines.append(f"Fresh resolution: {report.resolution_check}")
    if report.not_audited:
        lines += ["", "", "== NOT AUDITED " + "=" * 64, ""]
        lines += [f"  {line}" for line in report.not_audited]
    if report.notes:
        lines += ["", "", "== NOTES " + "=" * 70, ""]
        lines += [f"  {note}" for note in report.notes]

    lines += ["", "", "== UPGRADED PACKAGES " + "=" * 58, ""]
    lines.append(f"{'Package':<35} {'Old':<15} {'New':<15} {'Note'}")
    lines.append("-" * 80)
    for p in report.upgraded:
        note = "[SECURITY FIX]" if p.is_security_fix else ""
        lines.append(f"{p.name:<35} {p.old_version:<15} {p.new_version:<15} {note}")

    if report.new_deps:
        lines += ["", "", "== NEW TRANSITIVE DEPENDENCIES " + "=" * 48, ""]
        for p in report.new_deps:
            lines.append(f"  {p.name}=={p.new_version}")

    if report.direct_references_ignored:
        lines += ["", "", "== IGNORED DIRECT REFERENCES " + "=" * 49, ""]
        for raw in report.direct_references_ignored:
            lines.append(f"  {raw}")

    if report.unchanged:
        lines += ["", "", "== UNCHANGED PACKAGES " + "=" * 57, ""]
        for u in report.unchanged:
            lines.append(f"  {u}")

    lines += ["", "", "== POST-UPGRADE VULNERABILITY AUDIT " + "=" * 43, ""]
    if report.post_audit_vulns:
        lines.append(f"WARNING: {len(report.post_audit_vulns)} vulnerabilities remain:")
        lines.append("")
        lines.append(f"{'Package':<25} {'Version':<12} {'CVE':<18} {'Fix':<12} {'Reason'}")
        lines.append("-" * 100)
        for i, v in enumerate(report.post_audit_vulns):
            reason = (
                report.remaining_reasons[i]
                if i < len(report.remaining_reasons)
                else ""
            )
            lines.append(
                f"  {v.package:<23} {v.version:<12} {v.cve:<18} {v.fix_versions:<12} {reason}"
            )
    else:
        lines.append("No known vulnerabilities found.")

    # Import verification
    lines += ["", "", "== IMPORT VERIFICATION " + "=" * 56, ""]
    if report.import_check_baseline:
        base = report.import_check_baseline
        lines.append(
            f"Baseline (before upgrade): {len(base.verified)} resolved, "
            f"{len(base.failed)} unresolved"
        )
    if report.import_regressions:
        lines.append("")
        lines.append(
            f"REGRESSIONS ({len(report.import_regressions)}): resolved before the upgrade, "
            "fail after it. The dependency file was NOT written."
        )
        for mod, err in report.import_regressions.items():
            lines.append(f"  {mod}: {err}")
        lines.append("")
    if report.import_check:
        ic = report.import_check
        n_stdlib = ic.total_imports - len(ic.verified) - len(ic.failed) - len(ic.skipped_local)
        lines.append(
            f"Scanned {ic.files_scanned} Python files, found {ic.total_imports} unique imports "
            f"({len(ic.verified) + len(ic.failed)} third-party, "
            f"{len(ic.skipped_local)} local, {n_stdlib} stdlib)"
        )
        lines.append(
            f"Third-party: {len(ic.verified)} verified, {len(ic.failed)} FAILED"
        )
        if ic.failed:
            lines.append("")
            lines.append("FAILED IMPORTS:")
            for mod, err in ic.failed.items():
                lines.append(f"  {mod}: {err}")
        if ic.warnings:
            lines.append("")
            lines.append("DEPRECATION WARNINGS:")
            for mod, msgs in ic.warnings.items():
                for msg in msgs:
                    lines.append(f"  {mod}: {msg}")
        if not ic.failed and not ic.warnings:
            lines.append("")
            lines.append("All third-party imports verified successfully.")
        lines.append("")
        lines.append("Note: This verifies import resolution only.")
    else:
        lines.append("Import verification was not performed.")

    lines += [
        "", "", sep,
        "SUMMARY",
        sep,
        f"- Total packages: {report.original_count} -> {report.final_count}",
        f"- Packages upgraded: {len(report.upgraded)}",
        f"- New transitive dependencies: {len(report.new_deps)}",
        f"- Pre-upgrade vulnerabilities: {len(report.pre_audit_vulns)}",
        f"- Post-upgrade vulnerabilities: {len(report.post_audit_vulns)}",
        f"- Import regressions: {len(report.import_regressions)}",
        f"- Dependency file updated: {_write_back_status(report)}",
        sep,
    ]

    path.write_text("\n".join(lines) + "\n")
    log.debug("Wrote log: %s", path)
    return path


def _write_back_status(report: UpgradeResult) -> str:
    """One-line description of whether (and why not) the dependency file was written."""
    if report.dep_file_updated:
        return ", ".join(report.files_changed) or report.requirements_path
    if report.write_back_skipped:
        return f"no ({report.write_back_skipped})"
    if not report.files_changed and not report.manifest_diff:
        return "no (nothing to change)"
    return f"no ({'dry-run' if report.dry_run else 'not written'})"


def _write_state(report: UpgradeResult) -> str:
    """``written`` / ``not written (dry run)`` / ``not written: <reason>``."""
    if report.dep_file_updated:
        return "written"
    if report.write_back_skipped:
        return f"not written: {report.write_back_skipped}"
    return "not written (dry run)" if report.dry_run else "not written"


# ---------------------------------------------------------------------------
# Markdown writer
# ---------------------------------------------------------------------------

def write_markdown(report: UpgradeResult, out_dir: Path, date_prefix: str) -> Path:
    """Write the PR-ready markdown report."""
    path = out_dir / f"{date_prefix}_DEPENDENCY_UPGRADE_PR.md"

    md: list[str] = []
    _md_header(md, report)
    _md_summary(md, report)
    _md_files_changed(md, report)
    if report.mode == "legacy":
        _md_steps(md, report)
    else:
        _md_commands(md, report)
    _md_fixes(md, report)
    _md_vulnerability_tables(md, report)
    _md_upgraded_packages(md, report)
    _md_new_deps(md, report)
    _md_not_audited(md, report)
    _md_ignored_direct_refs(md, report)
    _md_import_verification(md, report)
    _md_notes(md, report)
    _md_checklist(md, report)

    path.write_text("\n".join(md) + "\n")
    log.debug("Wrote markdown: %s", path)
    return path


def _md_table(md: list[str], headers: list[str], rows: list[list[str]]) -> None:
    """Append a markdown table to *md*."""
    md.append("| " + " | ".join(headers) + " |")
    md.append("|" + "|".join("---" for _ in headers) + "|")
    for row in rows:
        md.append("| " + " | ".join(row) + " |")


def _md_header(md: list[str], report: UpgradeResult) -> None:
    md.append(f"# Dependency Upgrade Report — {report.service_label}")
    md.append("")
    md.append(f"**Date:** {report.date}")
    md.append(f"**Service:** `{report.service_label}`")
    md.append(f"**Python:** {report.python_version}")
    if report.platform:
        md.append(f"**Target platform:** `{report.platform}`")
    md.append(f"**Mode:** {_mode_description(report)}")
    md.append(f"**Tool:** uv {report.uv_version} + pip-audit {report.pip_audit_version}")
    md.append(f"**Dependency scope:** `{report.dependency_scope}`")
    if report.extras:
        md.append(f"**Extras:** {', '.join(report.extras)}")
    if report.groups:
        md.append(f"**Dependency groups:** {', '.join(report.groups)}")
    md.append(
        f"**Ignore direct references:** "
        f"{'yes' if report.ignore_direct_references else 'no'}"
    )
    md.append(f"**Allow-major:** {format_allow_major(report.allow_major)}")
    md.append(f"**Keep-version:** {format_keep_version(report.keep_version)}")
    md.append(f"**Dry-run:** {'yes' if report.dry_run else 'no'}")
    md.append("")
    md.append("---")
    md.append("")


def _md_summary(md: list[str], report: UpgradeResult) -> None:
    """Describe what actually changed, not what the settings allowed."""
    md.append("## Summary")
    md.append("")
    md.append(f"{_change_summary(report)} Dependency file: {_write_back_status(report)}.")
    md.append("")
    md.append(
        f"Detected **{len(report.pre_audit_vulns)}** known vulnerabilities before the upgrade "
        f"and **{len(report.post_audit_vulns)}** after the upgrade."
    )
    md.append("")
    if report.not_audited:
        if report.audited_count == 0:
            md.append(f"**Nothing was audited:** none of the {len(report.not_audited)} shipped "
                      "packages could be audited (see Not Audited below).")
        else:
            md.append(f"**{len(report.not_audited)} shipped packages were not audited** "
                      "(private index, local or direct references; see Not Audited below).")
        md.append("")
    if report.other_index:
        urls = ", ".join(f"`{u}`" for u in sorted(set(report.other_index.values())))
        md.append(f"**{len(report.other_index)} audited packages come from {urls}, not PyPI:** "
                  "they were audited by name against the public advisory database. Only "
                  "packages pinned to an index with `[tool.uv.sources]`, or served by an "
                  "explicit index, count as private.")
        md.append("")
    if report.write_back_skipped:
        md.append(
            f"**Nothing was written** ({report.write_back_skipped}): the files on disk still "
            f"have the {len(report.pre_audit_vulns)} vulnerabilities found before the run, "
            "and the changes below are planned only."
        )
        md.append("")
    elif report.dry_run and (report.files_changed or report.manifest_diff):
        md.append("**Dry run:** nothing was written; the changes below are planned only.")
        md.append("")
    md.append("---")
    md.append("")


def _change_summary(report: UpgradeResult) -> str:
    """One sentence: how many packages moved, and which crossed a major or went down."""
    if not report.upgraded and not report.new_deps:
        return "No package versions changed."
    kinds = {p.name: classify_bump(p.old_version, p.new_version) for p in report.upgraded}
    majors = sorted(name for name, kind in kinds.items() if kind == "major")
    downgrades = sorted(name for name, kind in kinds.items() if kind == "downgrade")
    parts = [f"**{len(report.upgraded)}** package(s) changed version"]
    if majors:
        parts.append(f"**{len(majors)} across a major version** ({', '.join(majors)})")
    elif report.upgraded:
        parts.append("none across a major version")
    if downgrades:
        parts.append(f"**{len(downgrades)} downgraded** ({', '.join(downgrades)})")
    if report.new_deps:
        parts.append(f"{len(report.new_deps)} new transitive dependencies")
    return "; ".join(parts) + "."


def _mode_description(report: UpgradeResult) -> str:
    if report.mode == "lock":
        return "lock-aware (audits and fixes `uv.lock`), vulnerable packages only"
    if report.mode in ("requirements", "pyproject"):
        return (
            f"resolved for the deploy platform ({report.requirements_path}), "
            "vulnerable packages only"
        )
    return "latest (every package upgraded within its bounds, resolved on this machine)"


def _md_files_changed(md: list[str], report: UpgradeResult) -> None:
    """Show the dependency-file changes exactly as written (or as they would be)."""
    md.append("## Files Changed")
    md.append("")
    state = _write_state(report)
    if report.mode == "lock":
        if report.lock_changes:
            md.append(
                f"`uv.lock` ({state}): {len(report.lock_changes)} package version(s) change, "
                "across every group and platform in the lock:"
            )
            md.append("")
            _md_table(
                md,
                ["Package", "Locked before", "Locked after", "Bump"],
                [
                    [c.name, c.old_version, c.new_version,
                     _bump_label(c.old_version, c.new_version)]
                    for c in report.lock_changes
                ],
            )
        else:
            md.append("`uv.lock`: no changes.")
        md.append("")
        if report.manifest_diff:
            md.append(f"`pyproject.toml` ({state}):")
            md.append("")
            md.append("```diff")
            md.append(report.manifest_diff.rstrip("\n"))
            md.append("```")
        else:
            md.append("`pyproject.toml`: no changes.")
        md.append("")
        md.append("---")
        md.append("")
        return
    if not report.manifest_diff:
        md.append(f"`{report.requirements_path}`: no changes.")
    else:
        if not report.dep_file_updated:
            md.append(f"`{report.requirements_path}` ({state}); the change would be:")
            md.append("")
        md.append("```diff")
        md.append(report.manifest_diff.rstrip("\n"))
        md.append("```")
    md.append("")
    md.append("---")
    md.append("")


def _bump_label(old: str, new: str) -> str:
    """Bump kind, upper-cased when it crosses a major version."""
    kind = classify_bump(old.split(",")[0].strip(), new.split(",")[0].strip())
    return "**MAJOR**" if kind == "major" else kind


def _md_commands(md: list[str], report: UpgradeResult) -> None:
    """Steps of a minimal run: the commands that produced the changes."""
    md.append("## Steps Performed")
    md.append("")
    if report.mode == "lock":
        md.append(
            "1. Exported the locked set that ships and evaluated its markers for "
            f"`{report.platform}` / Python {report.python_version}:"
        )
        md.append("   `uv export --frozen --no-emit-project --no-hashes "
                  + _group_flags(report) + "`")
    else:
        md.append(
            f"1. Resolved `{report.requirements_path}` for the deploy platform: "
            f"`uv pip compile --python-platform {report.platform} "
            f"--python-version {report.python_version}`"
        )
    md.append(
        f"2. Audited it: `pip-audit -r <pinned set> --no-deps --disable-pip -s osv` "
        f"({len(report.pre_audit_vulns)} advisories)."
    )
    md.append(
        "3. Planned, for each vulnerable package, the lowest release that fixes every advisory "
        "that has a fix (OSV affected ranges, PyPI releases)."
    )
    md.append("4. Applied the plan:")
    md.append("")
    md.append("```bash")
    md.extend(report.commands or ["# nothing to change"])
    md.append("```")
    md.append("")
    md.append(
        f"5. Re-audited what would ship: **{len(report.post_audit_vulns)}** advisories remain."
    )
    md.append("")
    md.append("---")
    md.append("")


def _group_flags(report: UpgradeResult) -> str:
    if report.groups and report.groups[0].startswith("(Dockerfile: uv sync "):
        text = report.groups[0][len("(Dockerfile: uv sync "):].rstrip(")")
        return "" if text == "default groups" else text
    flags = []
    if report.groups == ["(all)"]:
        flags.append("--all-groups")
    elif report.groups and report.groups != ["(no dev)"]:
        flags.append("--no-default-groups " + " ".join(f"--group {g}" for g in report.groups))
    else:
        flags.append("--no-dev")
    if report.extras == ["(all)"]:
        flags.append("--all-extras")
    else:
        flags += [f"--extra {e}" for e in report.extras]
    return " ".join(flags)


def _md_fixes(md: list[str], report: UpgradeResult) -> None:
    """One row per vulnerable package: plan, outcome and why."""
    if not report.fixes:
        return
    md.append(f"## Security Fixes ({len(report.fixes)} vulnerable packages)")
    md.append("")
    _md_table(
        md,
        ["Package", "From", "To", "Bump", "Advisories", "Status", "Note"],
        [
            [
                f.package,
                f.current,
                _fix_to(f),
                _bump_label(f.current, _fix_to(f)) if _fix_to(f) != "-" else "-",
                ", ".join(f.advisories[:6]) + (f" (+{len(f.advisories) - 6})"
                                               if len(f.advisories) > 6 else ""),
                f.status,
                f.reason.replace("|", "/"),
            ]
            for f in report.fixes
        ],
    )
    md.append("")
    md.append("---")
    md.append("")


def _fix_to(fix: PlannedFix) -> str:
    """The version a fix moved to, or (not applied) the version it would need."""
    if fix.status == "applied" and fix.final:
        return fix.final
    return fix.target or "-"


def _md_not_audited(md: list[str], report: UpgradeResult) -> None:
    if not report.not_audited:
        return
    md.append(f"## Not Audited ({len(report.not_audited)})")
    md.append("")
    for line in report.not_audited:
        md.append(f"- `{line}`")
    md.append("")
    md.append("---")
    md.append("")


def _md_notes(md: list[str], report: UpgradeResult) -> None:
    if not report.notes:
        return
    md.append("## Notes")
    md.append("")
    for note in report.notes:
        md.append(f"- {note}")
    md.append("")
    md.append("---")
    md.append("")


def _md_steps(md: list[str], report: UpgradeResult) -> None:
    md.append("## Steps Performed")
    md.append("")
    md.append("### 1. Created clean uv virtual environment")
    md.append("```bash")
    md.append(f"uv venv {report.venv_name} --python {report.python_version}")
    md.append("# depfresh installs the project dependencies into the temporary environment")
    md.append("```")
    md.append("")
    md.append("### 2. Ran initial vulnerability audit (pip-audit)")
    md.append("```bash")
    md.append("pip-audit -r <pinned-requirements> --no-deps --disable-pip -s osv --format json")
    md.append("```")
    md.append(f"**Result:** {len(report.pre_audit_vulns)} known vulnerabilities found.")
    md.append("")
    md.append("### 3. Upgraded all packages")
    md.append("```bash")
    md.append("# Generated constraints: package>=current_major.0,<next_major.0")
    md.append(
        f"uv pip install --upgrade -r upgrade_constraints.txt "
        f"--python {report.venv_name}/bin/python"
    )
    md.append("```")
    md.append("")
    md.append("### 4. Updated the dependency file")
    md.append("```bash")
    if report.dep_file_updated:
        md.append(
            f"# depfresh wrote the upgraded dependency set back to {report.requirements_path}"
        )
    else:
        md.append(f"# depfresh did not modify {report.requirements_path}")
    md.append("```")
    md.append("")
    md.append("### 5. Ran post-upgrade vulnerability audit")
    md.append("```bash")
    md.append("pip-audit -r <pinned-requirements> --no-deps --disable-pip -s osv --format json")
    md.append("```")
    remaining = len(report.post_audit_vulns)
    if remaining == 0:
        md.append("**Result: No known vulnerabilities found.**")
    else:
        md.append(f"**Result: {remaining} vulnerabilities remain.**")
    md.append("")
    md.append("---")
    md.append("")


def _md_vulnerability_tables(md: list[str], report: UpgradeResult) -> None:
    if report.pre_audit_vulns:
        md.append(
            "## Vulnerabilities Detected Before Upgrade "
            f"({len(report.pre_audit_vulns)} total)"
        )
        md.append("")
        vuln_fix_map = {f.package: _fix_to(f) for f in report.fixes}
        vuln_fix_map.update({
            normalise(p.name): p.new_version
            for p in report.upgraded if p.is_security_fix
        })
        _md_table(
            md,
            ["Package", "Old Version", "New Version", "CVE", "GHSA"],
            [
                [
                    v.package, v.version,
                    vuln_fix_map.get(normalise(v.package), v.fix_versions or "-"), v.cve,
                    v.ghsa if v.ghsa != v.cve else "",
                ]
                for v in report.pre_audit_vulns
            ],
        )
        md.append("")
        md.append("---")
        md.append("")

    if report.post_audit_vulns:
        md.append(f"## Remaining Vulnerabilities ({len(report.post_audit_vulns)})")
        md.append("")
        _md_table(
            md,
            ["Package", "Version", "CVE", "Fix Versions", "Reason"],
            [
                [
                    v.package, v.version, v.cve, v.fix_versions,
                    report.remaining_reasons[i] if i < len(report.remaining_reasons) else "",
                ]
                for i, v in enumerate(report.post_audit_vulns)
            ],
        )
        md.append("")
        md.append("---")
        md.append("")


def _md_upgraded_packages(md: list[str], report: UpgradeResult) -> None:
    md.append("## All Upgraded Packages")
    md.append("")
    if report.mode == "legacy":
        _md_table(
            md,
            ["Package", "Old Version", "New Version"],
            [[p.name, p.old_version, p.new_version] for p in report.upgraded],
        )
    else:
        md.append(
            "Version changes in the shipped set. Packages without an advisory moved only "
            "because a fix required it."
        )
        md.append("")
        _md_table(
            md,
            ["Package", "Old Version", "New Version", "Bump", "Why"],
            [
                [p.name, p.old_version, p.new_version,
                 _bump_label(p.old_version, p.new_version),
                 "security fix" if p.is_security_fix else "required by a fix"]
                for p in report.upgraded
            ],
        )
    md.append("")
    md.append("---")
    md.append("")


def _md_new_deps(md: list[str], report: UpgradeResult) -> None:
    if not report.new_deps:
        return
    md.append("## New Transitive Dependencies")
    md.append("")
    _md_table(
        md,
        ["Package", "Version"],
        [[p.name, p.new_version] for p in report.new_deps],
    )
    md.append("")
    md.append("---")
    md.append("")


def _md_ignored_direct_refs(md: list[str], report: UpgradeResult) -> None:
    if not report.direct_references_ignored:
        return
    md.append("## Ignored Direct References")
    md.append("")
    for raw in report.direct_references_ignored:
        md.append(f"- `{raw}`")
    md.append("")
    md.append("---")
    md.append("")


def _md_import_verification(md: list[str], report: UpgradeResult) -> None:
    if not report.import_check:
        return
    ic = report.import_check
    n_stdlib = ic.total_imports - len(ic.verified) - len(ic.failed) - len(ic.skipped_local)
    md.append("## Import Verification")
    md.append("")
    md.append(
        f"Scanned **{ic.files_scanned}** Python files, "
        f"found **{ic.total_imports}** unique imports."
    )
    md.append("")
    if report.import_check_baseline:
        base = report.import_check_baseline
        md.append(
            f"Before the upgrade, {len(base.verified)} third-party imports resolved and "
            f"{len(base.failed)} did not; only imports that resolved before and fail after "
            "count as regressions."
        )
        md.append("")
    if report.import_regressions:
        md.append(
            f"### Regressions ({len(report.import_regressions)}): "
            "the dependency file was not written"
        )
        md.append("")
        _md_table(
            md,
            ["Module", "Error after the upgrade"],
            [[f"`{mod}`", err] for mod, err in report.import_regressions.items()],
        )
        md.append("")
    _md_table(
        md,
        ["Category", "Count"],
        [
            ["Third-party verified", str(len(ic.verified))],
            ["Third-party failed", str(len(ic.failed))],
            ["Local (skipped)", str(len(ic.skipped_local))],
            ["Stdlib (skipped)", str(n_stdlib)],
        ],
    )
    md.append("")
    if ic.failed:
        md.append("### Failed Imports")
        md.append("")
        _md_table(
            md,
            ["Module", "Error"],
            [[f"`{mod}`", err] for mod, err in ic.failed.items()],
        )
        md.append("")
    if ic.warnings:
        md.append("### Deprecation Warnings")
        md.append("")
        _md_table(
            md,
            ["Package", "Warning"],
            [[f"`{mod}`", msg] for mod, msgs in ic.warnings.items() for msg in msgs],
        )
        md.append("")
    md.append(
        "> This verifies import resolution only. "
        "Run the test suite for full API compatibility validation."
    )
    md.append("")
    md.append("---")
    md.append("")


def _md_checklist(md: list[str], report: UpgradeResult) -> None:
    remaining = len(report.post_audit_vulns)
    md.append("## Verification Checklist")
    md.append("")
    if report.mode == "lock":
        md.append(
            f"- [x] Exported {report.original_count} shipped packages from `uv.lock` for "
            f"`{report.platform}`, Python {report.python_version}"
        )
    elif report.mode in ("requirements", "pyproject"):
        md.append(
            f"- [x] Resolved {report.original_count} packages from `{report.requirements_path}` "
            f"for `{report.platform}`, Python {report.python_version}"
        )
    else:
        md.append(f"- [x] `uv` environment created with Python {report.python_version}")
        md.append(
            f"- [x] All {report.original_count} original packages installed successfully"
        )
    md.append(
        f"- [x] Pre-upgrade audit: {len(report.pre_audit_vulns)} vulnerabilities identified"
    )
    if report.mode == "legacy":
        md.append("- [x] Selected packages upgraded within configured version bounds")
    else:
        moved = {p.name for p in report.upgraded}
        vulnerable = {normalise(v.package) for v in report.pre_audit_vulns}
        md.append(
            f"- [x] Only vulnerable packages moved ({len(moved & vulnerable)}), plus "
            f"{len(moved - vulnerable)} required co-upgrade(s)"
        )
        majors = [p.name for p in report.upgraded
                  if classify_bump(p.old_version, p.new_version) == "major"]
        if majors:
            md.append(f"- [ ] Review the major version changes: {', '.join(sorted(majors))}")
    if report.lock_check:
        mark = "x" if report.lock_check == "passed" else " "
        md.append(f"- [{mark}] `uv lock --check`: {report.lock_check}")
    if report.resolution_check:
        mark = "x" if report.resolution_check.startswith("passed") else " "
        md.append(f"- [{mark}] Fresh resolution for `{report.platform}`: {report.resolution_check}")
    if report.dep_file_updated:
        md.append(f"- [x] Dependency file updated ({report.final_count} packages)")
    else:
        md.append(f"- [ ] Dependency file updated: {_write_back_status(report)}")
    if remaining == 0:
        md.append("- [x] Post-upgrade audit: **0 vulnerabilities found**")
    else:
        md.append(f"- [ ] Post-upgrade audit: **{remaining} vulnerabilities remain**")
    if report.import_check:
        ic = report.import_check
        if report.import_regressions:
            md.append(
                f"- [ ] Import verification: **{len(report.import_regressions)} regressions** "
                f"(see Import Verification section)"
            )
        elif ic.failed:
            md.append(
                f"- [x] Import verification: no regressions "
                f"({len(ic.failed)} imports were already unresolved before the upgrade)"
                if report.import_check_baseline
                else f"- [ ] Import verification: **{len(ic.failed)} imports failed** "
                f"(see Import Verification section)"
            )
        else:
            md.append(
                f"- [x] Import verification: **{len(ic.verified)}** "
                f"third-party imports verified"
            )
    if report.direct_references_ignored:
        md.append(
            f"- [ ] Direct references skipped: **{len(report.direct_references_ignored)}** "
            f"(review before release)"
        )
