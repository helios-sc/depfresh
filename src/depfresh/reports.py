"""Report writers — log files, markdown, and requirements output."""

from __future__ import annotations

import logging
from pathlib import Path

from depfresh.constraints import format_allow_major, format_keep_version, normalise
from depfresh.models import UpgradeResult
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
        sep, "",
        "== PRE-UPGRADE VULNERABILITY AUDIT " + "=" * 44, "",
    ]

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
        (
            f"- Dependency file updated: {report.requirements_path}"
            if report.dep_file_updated
            else f"- Dependency file updated: no ({'dry-run' if report.dry_run else 'not written'})"
        ),
        sep,
    ]

    path.write_text("\n".join(lines) + "\n")
    log.debug("Wrote log: %s", path)
    return path


# ---------------------------------------------------------------------------
# Markdown writer
# ---------------------------------------------------------------------------

def write_markdown(report: UpgradeResult, out_dir: Path, date_prefix: str) -> Path:
    """Write the PR-ready markdown report."""
    path = out_dir / f"{date_prefix}_DEPENDENCY_UPGRADE_PR.md"

    md: list[str] = []
    _md_header(md, report)
    _md_summary(md, report)
    _md_steps(md, report)
    _md_vulnerability_tables(md, report)
    _md_upgraded_packages(md, report)
    _md_new_deps(md, report)
    _md_ignored_direct_refs(md, report)
    _md_import_verification(md, report)
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
    md.append(f"**Tool:** uv {report.uv_version} + pip-audit {report.pip_audit_version}")
    md.append(f"**Dependency scope:** `{report.dependency_scope}`")
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
    md.append("## Summary")
    md.append("")
    if report.allow_major is None:
        upgrade_desc = "**minor/patch** versions (no major version changes)"
    elif len(report.allow_major) == 0:
        upgrade_desc = "**available** versions (including major upgrades)"
    else:
        upgrade_desc = (
            f"**available** versions (major upgrades for: "
            f"{', '.join(report.allow_major)}; minor/patch for the rest)"
        )
    md.append(
        f"Upgraded Python dependencies to their latest {upgrade_desc}. "
        f"Detected **{len(report.pre_audit_vulns)}** known vulnerabilities before the upgrade "
        f"and **{len(report.post_audit_vulns)}** after the upgrade."
    )
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
    md.append("pip-audit -r <temp-requirements> --format json")
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
    md.append("pip-audit -r <temp-requirements> --format json")
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
        vuln_fix_map = {
            normalise(p.name): p.new_version
            for p in report.upgraded if p.is_security_fix
        }
        _md_table(
            md,
            ["Package", "Old Version", "New Version", "CVE"],
            [
                [
                    v.package, v.version,
                    vuln_fix_map.get(normalise(v.package), v.fix_versions), v.cve,
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
    _md_table(
        md,
        ["Package", "Old Version", "New Version"],
        [[p.name, p.old_version, p.new_version] for p in report.upgraded],
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
    md.append(f"- [x] `uv` environment created with Python {report.python_version}")
    md.append(
        f"- [x] All {report.original_count} original packages installed successfully"
    )
    md.append(
        f"- [x] Pre-upgrade audit: {len(report.pre_audit_vulns)} vulnerabilities identified"
    )
    md.append("- [x] Selected packages upgraded within configured version bounds")
    if report.dep_file_updated:
        md.append(f"- [x] Dependency file updated ({report.final_count} packages)")
    else:
        md.append(
            f"- [ ] Dependency file updated ({'dry-run' if report.dry_run else 'not written'})"
        )
    if remaining == 0:
        md.append("- [x] Post-upgrade audit: **0 vulnerabilities found**")
    else:
        md.append(f"- [ ] Post-upgrade audit: **{remaining} vulnerabilities remain**")
    if report.import_check:
        ic = report.import_check
        if ic.failed:
            md.append(
                f"- [ ] Import verification: **{len(ic.failed)} imports failed** "
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
