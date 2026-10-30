"""Tests for uv module — binary discovery and venv management."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from depfresh.exceptions import CommandError, UvNotFoundError, UvVersionError
from depfresh.uv import (
    MIN_UV_VERSION,
    UV_ENV_VAR,
    cleanup_venv,
    create_venv,
    find_uv,
    freeze,
    get_uv_version,
    installed_names,
    run,
    uv_version_ok,
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


def _fake_uv(directory: Path, version: str) -> Path:
    """Create an executable that prints ``uv <version>`` like the real binary."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "uv"
    path.write_text(f"#!/bin/sh\necho 'uv {version} (fake)'\n")
    path.chmod(0o755)
    return path


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell shims")
class TestFindUv:
    @pytest.fixture(autouse=True)
    def _isolate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(UV_ENV_VAR, raising=False)
        # Do not pick up a uv installed next to the test interpreter.
        monkeypatch.setattr("depfresh.uv.sysconfig.get_path", lambda _name: "/nonexistent")
        monkeypatch.setattr("depfresh.uv.sys.executable", "/nonexistent/python")

    def test_returns_new_enough_uv_on_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        uv = _fake_uv(tmp_path / "bin", "0.13.6")
        monkeypatch.setenv("PATH", str(tmp_path / "bin"))
        assert find_uv() == str(uv)

    def test_skips_an_old_uv_earlier_on_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """uv 0.6.17 on PATH cannot read lock revision 3: never use it silently."""
        _fake_uv(tmp_path / "old", "0.6.17")
        new = _fake_uv(tmp_path / "new", "0.13.6")
        monkeypatch.setenv("PATH", f"{tmp_path / 'old'}{os.pathsep}{tmp_path / 'new'}")
        assert find_uv() == str(new)

    def test_only_old_uv_raises_version_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _fake_uv(tmp_path / "old", "0.6.17")
        monkeypatch.setenv("PATH", str(tmp_path / "old"))
        with pytest.raises(UvVersionError, match=r"0\.6\.17") as exc_info:
            find_uv()
        assert MIN_UV_VERSION in str(exc_info.value)

    def test_explicit_binary_is_used_and_checked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        old = _fake_uv(tmp_path / "old", "0.6.17")
        _fake_uv(tmp_path / "new", "0.13.6")
        monkeypatch.setenv("PATH", str(tmp_path / "new"))
        with pytest.raises(UvVersionError):
            find_uv(str(old))  # never silently replaced by the PATH one

    def test_env_var_selects_the_binary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        chosen = _fake_uv(tmp_path / "chosen", "0.10.0")
        _fake_uv(tmp_path / "path", "0.13.6")
        monkeypatch.setenv("PATH", str(tmp_path / "path"))
        monkeypatch.setenv(UV_ENV_VAR, str(chosen))
        assert find_uv() == str(chosen)

    def test_missing_explicit_binary_raises_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(UvNotFoundError, match="not found"):
            find_uv(str(tmp_path / "nope" / "uv"))

    def test_raises_when_not_found(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("PATH", str(tmp_path / "empty"))
        with pytest.raises(UvNotFoundError):
            find_uv()


class TestUvVersionOk:
    @pytest.mark.parametrize(
        ("version", "ok"),
        [("0.13.6", True), (MIN_UV_VERSION, True), ("0.6.17", False), ("unknown", False)],
    )
    def test_threshold(self, version: str, ok: bool) -> None:
        assert uv_version_ok(version) is ok


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
    def test_keeps_packages_pip_audit_also_uses(self) -> None:
        """pip-audit runs from its own env, so rich/msgpack/platformdirs are project packages."""
        mock_result = MagicMock()
        mock_result.stdout = "flask==2.3.0\nmsgpack==1.0.5\nplatformdirs==4.2.0\nrich==13.7.0\n"
        with patch("depfresh.uv.run", return_value=mock_result):
            pkgs = freeze("/usr/bin/uv", "/path/to/python")
        assert pkgs == {
            "flask": "2.3.0", "msgpack": "1.0.5", "platformdirs": "4.2.0", "rich": "13.7.0",
        }

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
