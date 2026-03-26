"""Tests for uv module — binary discovery and venv management."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from depfresh.exceptions import CommandError, UvNotFoundError
from depfresh.uv import (
    cleanup_venv,
    create_venv,
    find_uv,
    freeze,
    get_uv_version,
    installed_names,
    run,
)


class TestRun:
    def test_captures_stdout(self) -> None:
        result = run([sys.executable, "-c", "print('hello')"])
        assert "hello" in result.stdout

    def test_raises_command_error_on_nonzero(self) -> None:
        with pytest.raises(CommandError):
            run([sys.executable, "-c", "import sys; sys.exit(1)"])

    def test_check_false_does_not_raise(self) -> None:
        result = run([sys.executable, "-c", "import sys; sys.exit(1)"], check=False)
        assert result.returncode != 0

    def test_returns_completed_process(self) -> None:
        result = run([sys.executable, "--version"])
        assert result.returncode == 0


class TestFindUv:
    def test_returns_path_when_found(self) -> None:
        with patch("depfresh.uv.shutil.which", return_value="/usr/local/bin/uv"):
            assert find_uv() == "/usr/local/bin/uv"

    def test_raises_when_not_found(self) -> None:
        with patch("depfresh.uv.shutil.which", return_value=None):
            with pytest.raises(UvNotFoundError):
                find_uv()


class TestGetUvVersion:
    def test_parses_version_string(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "uv 0.4.10\n"
        with patch("depfresh.uv.run", return_value=mock_result):
            assert get_uv_version("/usr/bin/uv") == "0.4.10"

    def test_returns_unknown_on_failure(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        with patch("depfresh.uv.run", return_value=mock_result):
            assert get_uv_version("/usr/bin/uv") == "unknown"


class TestCreateVenv:
    def test_returns_correct_python_path(self, tmp_path: Path) -> None:
        venv_path = tmp_path / ".venv-test"
        mock_result = MagicMock()
        mock_result.stdout = "Python 3.11.5\n"
        with patch("depfresh.uv.run", return_value=mock_result):
            result = create_venv("/usr/bin/uv", venv_path, "3.11")
        if sys.platform == "win32":
            assert result.endswith("python.exe")
        else:
            assert result == str(venv_path / "bin" / "python")

    def test_removes_existing_venv(self, tmp_path: Path) -> None:
        venv_path = tmp_path / ".venv-test"
        venv_path.mkdir()
        marker = venv_path / "marker.txt"
        marker.write_text("existing")
        mock_result = MagicMock()
        mock_result.stdout = "Python 3.11.0\n"
        with patch("depfresh.uv.run", return_value=mock_result):
            create_venv("/usr/bin/uv", venv_path, "3.11")
        assert not marker.exists()


class TestCleanupVenv:
    def test_removes_existing_venv(self, tmp_path: Path) -> None:
        venv_path = tmp_path / ".venv-cleanup"
        venv_path.mkdir()
        cleanup_venv(venv_path)
        assert not venv_path.exists()

    def test_no_error_when_missing(self, tmp_path: Path) -> None:
        venv_path = tmp_path / ".venv-nonexistent"
        cleanup_venv(venv_path)  # must not raise


class TestInstalledNames:
    def test_parses_freeze_output(self) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "Flask==2.3.0\nRequests==2.31.0\npip==23.0\n"
        with patch("depfresh.uv.run", return_value=mock_result):
            names = installed_names("/usr/bin/uv", "/path/to/python")
        assert "flask" in names
        assert "requests" in names

    def test_normalises_names(self) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "My_Package==1.0.0\n"
        with patch("depfresh.uv.run", return_value=mock_result):
            names = installed_names("/usr/bin/uv", "/path/to/python")
        assert "my-package" in names

    def test_empty_output(self) -> None:
        mock_result = MagicMock()
        mock_result.stdout = ""
        with patch("depfresh.uv.run", return_value=mock_result):
            names = installed_names("/usr/bin/uv", "/path/to/python")
        assert names == frozenset()


class TestFreeze:
    def test_excludes_static_audit_tools(self) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "flask==2.3.0\npip-audit==2.7.0\npip==23.0\nrequests==2.31.0\n"
        with patch("depfresh.uv.run", return_value=mock_result):
            pkgs = freeze("/usr/bin/uv", "/path/to/python")
        assert "flask" in pkgs
        assert "requests" in pkgs
        assert "pip-audit" not in pkgs
        assert "pip" not in pkgs

    def test_extra_exclude(self) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "flask==2.3.0\ncustomtool==1.0.0\n"
        with patch("depfresh.uv.run", return_value=mock_result):
            pkgs = freeze("/usr/bin/uv", "/path/to/python", extra_exclude=frozenset({"customtool"}))
        assert "flask" in pkgs
        assert "customtool" not in pkgs

    def test_normalises_package_names(self) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "My_Package==1.0.0\n"
        with patch("depfresh.uv.run", return_value=mock_result):
            pkgs = freeze("/usr/bin/uv", "/path/to/python")
        assert "my-package" in pkgs

    def test_skips_blank_and_comment_lines(self) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "\n# comment\nflask==2.3.0\n"
        with patch("depfresh.uv.run", return_value=mock_result):
            pkgs = freeze("/usr/bin/uv", "/path/to/python")
        assert "flask" in pkgs
        assert len(pkgs) == 1

    def test_returns_correct_versions(self) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "flask==2.3.0\nrequests==2.31.0\n"
        with patch("depfresh.uv.run", return_value=mock_result):
            pkgs = freeze("/usr/bin/uv", "/path/to/python")
        assert pkgs["flask"] == "2.3.0"
        assert pkgs["requests"] == "2.31.0"
