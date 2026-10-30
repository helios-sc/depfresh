"""Tests for report writers."""

from __future__ import annotations

from pathlib import Path

from depfresh.models import ImportCheck, PackageChange, UpgradeResult, Vulnerability
from depfresh.reports import write_log, write_markdown
from tests.helpers import make_result as _make_report


class TestWriteLog:
    def test_creates_log_file(self, tmp_path: Path) -> None:
        report = _make_report()
        path = write_log(report, tmp_path, "2026-01-15")
        assert path.exists()
        assert path.name == "2026-01-15_dependency_upgrade.log"

    def test_contains_header(self, tmp_path: Path) -> None:
        report = _make_report(date="2026-01-15")
        path = write_log(report, tmp_path, "2026-01-15")
        content = path.read_text()
        assert "test_service" in content
        assert "2026-01-15" in content

    def test_contains_vulnerability_info(self, tmp_path: Path) -> None:
        report = _make_report(
            pre_audit_vulns=[
                Vulnerability("urllib3", "2.0.4", "CVE-2023-001", "2.0.6", "desc")
            ],
        )
        path = write_log(report, tmp_path, "2026-01-15")
        content = path.read_text()
        assert "CVE-2023-001" in content
        assert "urllib3" in content

    def test_contains_upgraded_packages(self, tmp_path: Path) -> None:
        report = _make_report(
            upgraded=[PackageChange("flask", "2.3.0", "2.4.0")],
        )
        path = write_log(report, tmp_path, "2026-01-15")
        content = path.read_text()
        assert "flask" in content
        assert "2.3.0" in content
        assert "2.4.0" in content

    def test_contains_import_check(self, tmp_path: Path) -> None:
        report = _make_report(
            import_check=ImportCheck(
                files_scanned=50,
                total_imports=100,
                verified=["flask", "requests"],
                failed={},
            ),
        )
        path = write_log(report, tmp_path, "2026-01-15")
        content = path.read_text()
        assert "50" in content
        assert "verified" in content.lower()


class TestWriteMarkdown:
    def test_creates_markdown_file(self, tmp_path: Path) -> None:
        report = _make_report()
        path = write_markdown(report, tmp_path, "2026-01-15")
        assert path.exists()
        assert path.name == "2026-01-15_DEPENDENCY_UPGRADE_PR.md"

    def test_contains_tables(self, tmp_path: Path) -> None:
        report = _make_report(
            upgraded=[PackageChange("flask", "2.3.0", "2.4.0")],
        )
        path = write_markdown(report, tmp_path, "2026-01-15")
        content = path.read_text()
        assert "| flask | 2.3.0 | 2.4.0 |" in content

    def test_contains_checklist(self, tmp_path: Path) -> None:
        report = _make_report()
        path = write_markdown(report, tmp_path, "2026-01-15")
        content = path.read_text()
        assert "- [x]" in content

    def test_remaining_vulns_unchecked(self, tmp_path: Path) -> None:
        report = _make_report(
            post_audit_vulns=[
                Vulnerability("urllib3", "2.0.4", "CVE-2023-001", "2.0.6", "desc")
            ],
        )
        path = write_markdown(report, tmp_path, "2026-01-15")
        content = path.read_text()
        assert "- [ ] Post-upgrade audit" in content

    def test_remaining_vulns_show_reason(self, tmp_path: Path) -> None:
        report = _make_report(
            post_audit_vulns=[
                Vulnerability("black", "23.12.1", "CVE-2026-001", "26.3.1", "desc")
            ],
            remaining_reasons=["Requires major upgrade (23→26). Use --allow-major black"],
        )
        path = write_markdown(report, tmp_path, "2026-01-15")
        content = path.read_text()
        assert "| Reason |" in content
        assert "major upgrade" in content.lower()

    def test_remaining_vulns_reason_in_log(self, tmp_path: Path) -> None:
        report = _make_report(
            post_audit_vulns=[
                Vulnerability("black", "23.12.1", "CVE-2026-001", "26.3.1", "desc")
            ],
            remaining_reasons=["Requires major upgrade (23→26). Use --allow-major black"],
        )
        path = write_log(report, tmp_path, "2026-01-15")
        content = path.read_text()
        assert "Reason" in content
        assert "major upgrade" in content.lower()


class TestImportRegressionReporting:
    def _report(self) -> UpgradeResult:
        return _make_report(
            import_check_baseline=ImportCheck(verified=["fastmcp", "fastmcp.tools.tool"]),
            import_check=ImportCheck(
                verified=["fastmcp"],
                failed={"fastmcp.tools.tool": "No module named 'fastmcp.tools.tool'"},
            ),
            import_regressions={"fastmcp.tools.tool": "No module named 'fastmcp.tools.tool'"},
            write_back_skipped="1 import(s) resolved before the upgrade and fail after it",
        )

    def test_markdown_lists_regressions_and_unwritten_file(self, tmp_path: Path) -> None:
        report = self._report()
        content = write_markdown(report, tmp_path, "2026-01-15").read_text()
        assert "Regressions (1)" in content
        assert "`fastmcp.tools.tool`" in content
        assert "- [ ] Dependency file updated: no (1 import(s)" in content
        assert "- [ ] Import verification: **1 regressions**" in content

    def test_log_lists_regressions(self, tmp_path: Path) -> None:
        report = self._report()
        content = write_log(report, tmp_path, "2026-01-15").read_text()
        assert "REGRESSIONS (1)" in content
        assert "Import regressions: 1" in content



class TestAccurateSummary:
    """The PR text said "no major version changes" while the manifest changed."""

    def test_reports_majors_that_actually_happened(self, tmp_path: Path) -> None:
        report = _make_report(
            upgraded=[
                PackageChange("cryptography", "46.0.6", "50.0.2", is_security_fix=True),
                PackageChange("idna", "3.11", "3.15"),
            ],
        )
        content = write_markdown(report, tmp_path, "2026-01-15").read_text()
        assert "1 across a major version** (cryptography)" in content
        assert "no major version changes" not in content

    def test_reports_downgrades(self, tmp_path: Path) -> None:
        report = _make_report(
            upgraded=[PackageChange("google-cloud-storage", "3.17.1", "2.19.0")],
        )
        content = write_markdown(report, tmp_path, "2026-01-15").read_text()
        assert "1 downgraded** (google-cloud-storage)" in content

    def test_manifest_diff_is_shown_even_without_version_changes(self, tmp_path: Path) -> None:
        diff = (
            "--- a/pyproject.toml\n+++ b/pyproject.toml\n@@ -1 +1 @@\n"
            '-    "fastapi>=0.115",\n+    "fastapi>=0.162.0",\n'
        )
        report = _make_report(
            requirements_path="pyproject.toml", manifest_diff=diff, dep_file_updated=True,
        )
        content = write_markdown(report, tmp_path, "2026-01-15").read_text()
        assert "No package versions changed." in content
        assert "## Files Changed" in content
        assert '+    "fastapi>=0.162.0",' in content

    def test_unwritten_diff_is_labelled(self, tmp_path: Path) -> None:
        report = _make_report(manifest_diff="-a\n+b\n", dry_run=True)
        content = write_markdown(report, tmp_path, "2026-01-15").read_text()
        assert "(not written (dry run)); the change would be:" in content
