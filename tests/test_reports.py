"""Tests for report writers."""

from __future__ import annotations

from pathlib import Path

from depfresh.models import ImportCheck, PackageChange, Vulnerability
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
