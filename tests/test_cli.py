"""Tests for CLI argument parsing and argument-to-upgrade wiring."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from depfresh.cli import _setup_logging, main
from depfresh.exceptions import DepfreshError
from depfresh.models import UpgradeResult
from depfresh.parsers import _FORMAT_CHOICES
from tests.helpers import make_result as _make_result

# ---------------------------------------------------------------------------
# Help / meta
# ---------------------------------------------------------------------------


class TestHelp:
    def test_help_flag_exits_zero(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "depfresh" in out
        assert "--dry-run" in out
        assert "--allow-major" in out
        assert "--dep-file" in out
        assert "--format" in out

    def test_invalid_format_rejected(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["/tmp", "--format", "not-a-real-format"])
        assert exc_info.value.code == 2  # argparse error

    def test_format_choices_match_enum(self) -> None:
        from depfresh.parsers import DependencyFormat

        assert set(_FORMAT_CHOICES) == {f.value for f in DependencyFormat}

    def test_no_args_exits_with_error(self) -> None:
        """Omitting target_dir must fail (argparse error)."""
        with pytest.raises(SystemExit) as exc_info:
            main([])
        assert exc_info.value.code == 2


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


class TestExitCodes:
    def test_missing_target_exits_1(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["/nonexistent/path/that/does/not/exist"])
        assert exc_info.value.code == 1

    def test_depfresh_error_exits_1(self) -> None:
        with patch("depfresh.cli.upgrade", side_effect=DepfreshError("boom")):
            with pytest.raises(SystemExit) as exc_info:
                main(["/some/path"])
        assert exc_info.value.code == 1

    def test_depfresh_error_message_on_stderr(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with patch("depfresh.cli.upgrade", side_effect=DepfreshError("boom")):
            with pytest.raises(SystemExit):
                main(["/some/path"])
        assert "boom" in capsys.readouterr().err

    def test_clean_run_returns_normally(self) -> None:
        """A run with no remaining vulns should return without calling sys.exit."""
        result = _make_result()
        with patch("depfresh.cli.upgrade", return_value=result):
            main(["/some/path"])  # must not raise

    def test_remaining_vulns_exits_2(self) -> None:
        from depfresh.models import Vulnerability

        vuln = Vulnerability(
            package="foo", version="1.0", cve="CVE-2024-1234",
            fix_versions="2.0", description="bad"
        )
        result = _make_result(post_audit_vulns=[vuln])
        with patch("depfresh.cli.upgrade", return_value=result):
            with pytest.raises(SystemExit) as exc_info:
                main(["/some/path"])
        assert exc_info.value.code == 2


# ---------------------------------------------------------------------------
# Argument wiring — each flag reaches upgrade() correctly
# ---------------------------------------------------------------------------


class TestArgumentWiring:
    """Verify that CLI flags are forwarded to upgrade() with the right values."""

    def _run(self, argv: list[str]) -> MagicMock:
        """Run main() with a mocked upgrade() and return the mock."""
        result = _make_result()
        mock_upgrade = MagicMock(return_value=result)
        with patch("depfresh.cli.upgrade", mock_upgrade):
            try:
                main(argv)
            except SystemExit:
                pass
        return mock_upgrade

    def test_target_dir_passed(self) -> None:
        mock = self._run(["/my/project"])
        mock.assert_called_once()
        assert mock.call_args.kwargs["target"] == "/my/project"

    def test_dry_run_flag(self) -> None:
        mock = self._run(["/p", "--dry-run"])
        assert mock.call_args.kwargs["dry_run"] is True

    def test_dependency_scope_flag(self) -> None:
        mock = self._run(["/p", "--dependency-scope", "all"])
        assert mock.call_args.kwargs["dependency_scope"] == "all"

    def test_dependency_scope_default_runtime(self) -> None:
        mock = self._run(["/p"])
        assert mock.call_args.kwargs["dependency_scope"] == "runtime"

    def test_ignore_direct_references_flag(self) -> None:
        mock = self._run(["/p", "--ignore-direct-references"])
        assert mock.call_args.kwargs["ignore_direct_references"] is True

    def test_ignore_direct_references_default_false(self) -> None:
        mock = self._run(["/p"])
        assert mock.call_args.kwargs["ignore_direct_references"] is False

    def test_dry_run_default_false(self) -> None:
        mock = self._run(["/p"])
        assert mock.call_args.kwargs["dry_run"] is False

    def test_python_version(self) -> None:
        mock = self._run(["/p", "--python", "3.12"])
        assert mock.call_args.kwargs["python"] == "3.12"

    def test_python_version_default(self) -> None:
        mock = self._run(["/p"])
        assert mock.call_args.kwargs["python"] == "3.11"

    def test_allow_major_all(self) -> None:
        """--allow-major with no packages means allow all (empty list)."""
        mock = self._run(["/p", "--allow-major"])
        assert mock.call_args.kwargs["allow_major"] == []

    def test_allow_major_specific_packages(self) -> None:
        mock = self._run(["/p", "--allow-major", "urllib3", "cryptography"])
        assert mock.call_args.kwargs["allow_major"] == ["urllib3", "cryptography"]

    def test_allow_major_default_none(self) -> None:
        mock = self._run(["/p"])
        assert mock.call_args.kwargs["allow_major"] is None

    def test_keep_version(self) -> None:
        mock = self._run(["/p", "--keep-version", "crewai", "litellm"])
        assert mock.call_args.kwargs["keep_version"] == ["crewai", "litellm"]

    def test_keep_version_default_none(self) -> None:
        mock = self._run(["/p"])
        assert mock.call_args.kwargs["keep_version"] is None

    def test_dep_file(self) -> None:
        mock = self._run(["/p", "--dep-file", "pyproject.toml"])
        assert mock.call_args.kwargs["dep_file"] == "pyproject.toml"

    def test_dep_file_default_none(self) -> None:
        mock = self._run(["/p"])
        assert mock.call_args.kwargs["dep_file"] is None

    def test_format_flag(self) -> None:
        mock = self._run(["/p", "--format", "pyproject-poetry"])
        assert mock.call_args.kwargs["fmt"] == "pyproject-poetry"

    def test_format_default_none(self) -> None:
        mock = self._run(["/p"])
        assert mock.call_args.kwargs["fmt"] is None

    def test_label_flag(self) -> None:
        mock = self._run(["/p", "--label", "my_service"])
        assert mock.call_args.kwargs["label"] == "my_service"

    def test_label_default_none(self) -> None:
        mock = self._run(["/p"])
        assert mock.call_args.kwargs["label"] is None

    def test_reports_dir(self) -> None:
        mock = self._run(["/p", "--reports-dir", "./artifacts"])
        assert mock.call_args.kwargs["reports_dir"] == "./artifacts"

    def test_reports_dir_default_none(self) -> None:
        mock = self._run(["/p"])
        assert mock.call_args.kwargs["reports_dir"] is None

    def test_venv_name(self) -> None:
        mock = self._run(["/p", "--venv", "my-venv"])
        assert mock.call_args.kwargs["venv_name"] == "my-venv"

    def test_venv_name_default(self) -> None:
        mock = self._run(["/p"])
        assert mock.call_args.kwargs["venv_name"] == ".venv-upgrade"



# ---------------------------------------------------------------------------
# Stdout output
# ---------------------------------------------------------------------------


class TestOutput:
    def _run_capture(self, result: UpgradeResult) -> str:
        with patch("depfresh.cli.upgrade", return_value=result):
            try:
                main(["/p"])
            except SystemExit:
                pass
        return ""  # stdout checked via capsys in individual tests

    def test_summary_shows_label(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = _make_result(service_label="my_service")
        with patch("depfresh.cli.upgrade", return_value=result):
            try:
                main(["/p"])
            except SystemExit:
                pass
        assert "my_service" in capsys.readouterr().out

    def test_summary_shows_package_counts(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = _make_result(original_count=15, final_count=16)
        with patch("depfresh.cli.upgrade", return_value=result):
            try:
                main(["/p"])
            except SystemExit:
                pass
        out = capsys.readouterr().out
        assert "15" in out
        assert "16" in out

    def test_summary_shows_scope(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = _make_result(dependency_scope="all")
        with patch("depfresh.cli.upgrade", return_value=result):
            try:
                main(["/p"])
            except SystemExit:
                pass
        assert "all" in capsys.readouterr().out

    def test_clean_run_message(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = _make_result()
        with patch("depfresh.cli.upgrade", return_value=result):
            try:
                main(["/p"])
            except SystemExit:
                pass
        assert "All vulnerabilities resolved" in capsys.readouterr().out

    def test_vuln_warning_in_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        from depfresh.models import Vulnerability

        vuln = Vulnerability(
            package="foo", version="1.0", cve="CVE-2024-1234",
            fix_versions="2.0", description="bad"
        )
        result = _make_result(post_audit_vulns=[vuln])
        with patch("depfresh.cli.upgrade", return_value=result):
            with pytest.raises(SystemExit):
                main(["/p"])
        assert "WARNING" in capsys.readouterr().out

    def test_log_path_shown_when_present(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = _make_result(log_path="/reports/run.log")
        with patch("depfresh.cli.upgrade", return_value=result):
            try:
                main(["/p"])
            except SystemExit:
                pass
        assert "/reports/run.log" in capsys.readouterr().out

    def test_report_path_shown_when_present(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = _make_result(markdown_path="/reports/PR.md")
        with patch("depfresh.cli.upgrade", return_value=result):
            try:
                main(["/p"])
            except SystemExit:
                pass
        assert "/reports/PR.md" in capsys.readouterr().out

    def test_ignored_direct_refs_shown_when_present(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = _make_result(direct_references_ignored=["pkg @ https://example.com/pkg-1.0.tar.gz"])
        with patch("depfresh.cli.upgrade", return_value=result):
            try:
                main(["/p"])
            except SystemExit:
                pass
        assert "Direct refs" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------


class TestLogging:
    def test_verbose_flag_enables_debug(self) -> None:
        import logging

        _setup_logging(verbose=True)
        logger = logging.getLogger("depfresh")
        assert logger.level == logging.DEBUG

    def test_default_logging_is_info(self) -> None:
        import logging

        _setup_logging(verbose=False)
        logger = logging.getLogger("depfresh")
        assert logger.level == logging.INFO
