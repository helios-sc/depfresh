"""Tests for upgrade module — orchestration, helpers, and public API."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from depfresh.exceptions import (
    CommandError,
    DirectReferenceError,
    RequirementsNotFoundError,
    TargetNotFoundError,
)
from depfresh.models import DependencySpec, ImportCheck, UpgradeResult, Vulnerability
from depfresh.parsers import PyprojectPEP621Handler
from depfresh.upgrade import (
    _audit_only_legacy,
    _resolve_dep_file,
    _run_audit_with_temp,
    _setup_venv,
    audit_only,
    derive_label,
    upgrade,
)

# depfresh.__init__ binds the upgrade() function to the name "upgrade",
# shadowing the depfresh.upgrade submodule.  On Python <3.12,
# mock.patch("depfresh.upgrade.X") resolves to the function and fails.
# Access the real module through sys.modules instead.
_upgrade_mod = sys.modules["depfresh.upgrade"]

# ---------------------------------------------------------------------------
# derive_label
# ---------------------------------------------------------------------------


class TestDeriveLabel:
    def test_returns_directory_name(self, tmp_path: Path) -> None:
        label = derive_label(tmp_path)
        assert tmp_path.name in label

    def test_uses_git_root_as_boundary(self, tmp_path: Path) -> None:
        repo = tmp_path / "myapp"
        repo.mkdir()
        (tmp_path / ".git").mkdir()
        label = derive_label(repo)
        assert "myapp" in label

    def test_uses_src_as_boundary(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        src = project / "src"
        service = src / "jobs"
        service.mkdir(parents=True)
        label = derive_label(service)
        assert "jobs" in label

    def test_non_existent_path_accepted(self, tmp_path: Path) -> None:
        # derive_label only does path manipulation, no existence check
        label = derive_label(tmp_path / "fake")
        assert "fake" in label


# ---------------------------------------------------------------------------
# _resolve_dep_file
# ---------------------------------------------------------------------------


class TestResolvDepFile:
    def test_raises_when_explicit_file_missing(self, tmp_path: Path) -> None:
        with pytest.raises(RequirementsNotFoundError):
            _resolve_dep_file(tmp_path, "missing.txt", None)

    def test_raises_when_no_dep_file_found(self, tmp_path: Path) -> None:
        with pytest.raises(RequirementsNotFoundError):
            _resolve_dep_file(tmp_path, None, None)

    def test_finds_requirements_txt(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.3.0\n")
        path, fmt, handler = _resolve_dep_file(tmp_path, None, None)
        assert path == req
        assert "requirements" in fmt.value

    def test_explicit_file_takes_priority(self, tmp_path: Path) -> None:
        custom = tmp_path / "custom.txt"
        custom.write_text("flask==2.3.0\n")
        path, _, _ = _resolve_dep_file(tmp_path, "custom.txt", None)
        assert path == custom

    def test_fmt_overrides_detection(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.3.0\n")
        _, fmt, _ = _resolve_dep_file(tmp_path, None, "requirements-simple")
        assert fmt.value == "requirements-simple"



# ---------------------------------------------------------------------------
# _run_audit_with_temp
# ---------------------------------------------------------------------------


class TestRunAuditWithTemp:
    def test_calls_run_audit_and_returns_vulns(self, tmp_path: Path) -> None:
        vuln = Vulnerability("urllib3", "2.0.0", "CVE-2023-001", "2.0.6", "desc")
        pkgs = {"urllib3": "2.0.0"}
        with patch.object(_upgrade_mod, "run_audit", return_value=[vuln]) as mock_audit:
            result = _run_audit_with_temp("/venv/bin/python", tmp_path, pkgs, "test")
        assert result == [vuln]
        assert mock_audit.called

    def test_temp_file_is_deleted_on_success(self, tmp_path: Path) -> None:
        with patch.object(_upgrade_mod, "run_audit", return_value=[]):
            _run_audit_with_temp("/venv/bin/python", tmp_path, {"flask": "2.3.0"}, "test")
        # Temp file must not remain after successful run
        remaining = list(tmp_path.glob(".depfresh_audit_*.tmp"))
        assert remaining == []

    def test_temp_file_is_deleted_on_error(self, tmp_path: Path) -> None:
        with patch.object(_upgrade_mod, "run_audit", side_effect=RuntimeError("boom")):
            with pytest.raises(RuntimeError):
                _run_audit_with_temp("/venv/bin/python", tmp_path, {"flask": "2.3.0"}, "test")
        remaining = list(tmp_path.glob(".depfresh_audit_*.tmp"))
        assert remaining == []

    def test_label_used_in_temp_filename(self, tmp_path: Path) -> None:
        """The temp file name includes the label so pre/post files don't collide."""
        seen_paths: list[Path] = []

        def capture_path(venv_python: str, req_path: Path, label: str) -> list[Vulnerability]:
            seen_paths.append(req_path)
            return []

        with patch.object(_upgrade_mod, "run_audit", side_effect=capture_path):
            _run_audit_with_temp("/venv/bin/python", tmp_path, {"flask": "2.3.0"}, "pre-upgrade")

        assert len(seen_paths) == 1
        assert "pre-upgrade" in seen_paths[0].name

    def test_pid_included_in_temp_filename(self, tmp_path: Path) -> None:
        """The temp file name includes the PID for process-level isolation."""
        seen_paths: list[Path] = []

        def capture_path(venv_python: str, req_path: Path, label: str) -> list[Vulnerability]:
            seen_paths.append(req_path)
            return []

        with patch.object(_upgrade_mod, "run_audit", side_effect=capture_path):
            _run_audit_with_temp("/venv/bin/python", tmp_path, {"flask": "2.3.0"}, "test")

        assert len(seen_paths) == 1
        assert str(os.getpid()) in seen_paths[0].name


# ---------------------------------------------------------------------------
# upgrade() — validation
# ---------------------------------------------------------------------------


class TestUpgradeValidation:
    def test_raises_target_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(TargetNotFoundError):
            upgrade(tmp_path / "nonexistent")

    def test_raises_requirements_not_found_empty_dir(self, tmp_path: Path) -> None:
        with pytest.raises(RequirementsNotFoundError):
            upgrade(tmp_path)

    def test_raises_requirements_not_found_explicit_missing(self, tmp_path: Path) -> None:
        with pytest.raises(RequirementsNotFoundError):
            upgrade(tmp_path, dep_file="missing.txt")

    def test_direct_reference_fails_closed_by_default(self, tmp_path: Path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            '[project]\n'
            'dependencies = ["flask>=2.3.0", "demo @ https://example.com/demo-1.0.tar.gz"]\n'
        )
        with pytest.raises(DirectReferenceError):
            upgrade(tmp_path)


# ---------------------------------------------------------------------------
# upgrade() — happy path with mocked externals
# ---------------------------------------------------------------------------


def _mock_venv_python(tmp_path: Path) -> str:
    return str(tmp_path / ".venv-upgrade" / "bin" / "python")


def _make_setup_venv_mock(
    tmp_path: Path,
    old_pkgs: dict[str, str] | None = None,
) -> MagicMock:
    return MagicMock(
        return_value=(
            _mock_venv_python(tmp_path),
            "3.11.5",
            old_pkgs or {"flask": "2.3.0"},
        )
    )


_AUDIT_TOOL = ("/tool/bin/python", "2.10.1")


class TestUpgradeHappyPath:
    @pytest.fixture()
    def req_file(self, tmp_path: Path) -> Path:
        r = tmp_path / "requirements.txt"
        r.write_text("flask==2.3.0\nrequests==2.28.0\n")
        return r

    def test_returns_upgrade_result(self, tmp_path: Path, req_file: Path) -> None:
        setup_mock = _make_setup_venv_mock(tmp_path, old_pkgs={"flask": "2.3.0"})
        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.4.0"),
            patch.object(_upgrade_mod, "_setup_venv", setup_mock),
            patch.object(_upgrade_mod, "install_pip_audit", return_value=_AUDIT_TOOL),
            patch.object(_upgrade_mod, "_run_audit_with_temp", return_value=[]),
            patch.object(_upgrade_mod, "build_constraints", return_value=["flask>=2.3.0,<3"]),
            patch.object(_upgrade_mod, "install_packages"),
            patch.object(_upgrade_mod, "freeze", return_value={"flask": "2.4.0"}),
            patch.object(_upgrade_mod, "verify_imports", return_value=ImportCheck()),
            patch.object(_upgrade_mod, "write_log", return_value=tmp_path / "log.txt"),
            patch.object(_upgrade_mod, "write_markdown", return_value=tmp_path / "pr.md"),
            patch.object(_upgrade_mod, "cleanup_venv"),
        ):
            result = upgrade(tmp_path, strategy="latest", label="test", reports_dir=tmp_path)
        assert isinstance(result, UpgradeResult)
        assert result.service_label == "test"

    def test_dry_run_does_not_modify_dep_file(self, tmp_path: Path, req_file: Path) -> None:
        original_content = req_file.read_text()
        setup_mock = _make_setup_venv_mock(tmp_path, old_pkgs={"flask": "2.3.0"})
        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.4.0"),
            patch.object(_upgrade_mod, "_setup_venv", setup_mock),
            patch.object(_upgrade_mod, "install_pip_audit", return_value=_AUDIT_TOOL),
            patch.object(_upgrade_mod, "_run_audit_with_temp", return_value=[]),
            patch.object(_upgrade_mod, "build_constraints", return_value=[]),
            patch.object(_upgrade_mod, "install_packages"),
            patch.object(_upgrade_mod, "freeze", return_value={"flask": "2.4.0"}),
            patch.object(_upgrade_mod, "verify_imports", return_value=ImportCheck()),
            patch.object(_upgrade_mod, "write_log", return_value=tmp_path / "log.txt"),
            patch.object(_upgrade_mod, "write_markdown", return_value=tmp_path / "pr.md"),
            patch.object(_upgrade_mod, "cleanup_venv"),
        ):
            upgrade(tmp_path, strategy="latest", dry_run=True, label="test", reports_dir=tmp_path)
        assert req_file.read_text() == original_content

    def test_dry_run_reports_the_diff_it_would_write(
        self, tmp_path: Path, req_file: Path,
    ) -> None:
        original_content = req_file.read_text()
        setup_mock = _make_setup_venv_mock(
            tmp_path, old_pkgs={"flask": "2.3.0", "requests": "2.28.0"},
        )
        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.9.0"),
            patch.object(_upgrade_mod, "_setup_venv", setup_mock),
            patch.object(_upgrade_mod, "install_pip_audit", return_value=_AUDIT_TOOL),
            patch.object(_upgrade_mod, "_run_audit_with_temp", return_value=[]),
            patch.object(_upgrade_mod, "build_constraints", return_value=[]),
            patch.object(_upgrade_mod, "install_packages"),
            patch.object(
                _upgrade_mod, "freeze", return_value={"flask": "2.3.3", "requests": "2.28.0"},
            ),
            patch.object(_upgrade_mod, "verify_imports", return_value=ImportCheck()),
            patch.object(_upgrade_mod, "write_log", return_value=tmp_path / "log.txt"),
            patch.object(_upgrade_mod, "write_markdown", return_value=tmp_path / "pr.md"),
        ):
            result = upgrade(
                tmp_path, strategy="latest", dry_run=True, label="test", reports_dir=tmp_path,
            )
        assert req_file.read_text() == original_content
        assert "-flask==2.3.0" in result.manifest_diff
        assert "+flask==2.3.3" in result.manifest_diff
        assert result.dep_file_updated is False

    def test_pre_vulns_appear_in_result(self, tmp_path: Path, req_file: Path) -> None:
        vuln = Vulnerability("urllib3", "2.0.0", "CVE-2023-001", "2.0.6", "desc")
        setup_mock = _make_setup_venv_mock(tmp_path, old_pkgs={"urllib3": "2.0.0"})
        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.4.0"),
            patch.object(_upgrade_mod, "_setup_venv", setup_mock),
            patch.object(_upgrade_mod, "install_pip_audit", return_value=_AUDIT_TOOL),
            patch.object(_upgrade_mod, "_run_audit_with_temp", side_effect=[[vuln], []]),
            patch.object(_upgrade_mod, "build_constraints", return_value=[]),
            patch.object(_upgrade_mod, "install_packages"),
            patch.object(_upgrade_mod, "freeze", return_value={"urllib3": "2.0.6"}),
            patch.object(_upgrade_mod, "verify_imports", return_value=ImportCheck()),
            patch.object(_upgrade_mod, "write_log", return_value=tmp_path / "log.txt"),
            patch.object(_upgrade_mod, "write_markdown", return_value=tmp_path / "pr.md"),
            patch.object(_upgrade_mod, "cleanup_venv"),
        ):
            result = upgrade(tmp_path, strategy="latest", label="test", reports_dir=tmp_path)
        assert len(result.pre_audit_vulns) == 1
        assert result.pre_audit_vulns[0].cve == "CVE-2023-001"

    def test_cleanup_venv_called_even_on_error(self, tmp_path: Path, req_file: Path) -> None:
        """venv must be cleaned up even when an error occurs inside the try block."""
        setup_mock = _make_setup_venv_mock(tmp_path)
        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.4.0"),
            patch.object(_upgrade_mod, "_setup_venv", setup_mock),
            patch.object(_upgrade_mod, "install_pip_audit", return_value=_AUDIT_TOOL),
            patch.object(
                _upgrade_mod, "_run_audit_with_temp", side_effect=RuntimeError("audit boom"),
            ),
            patch.object(_upgrade_mod, "cleanup_venv") as mock_cleanup,
        ):
            with pytest.raises(RuntimeError, match="audit boom"):
                upgrade(tmp_path, strategy="latest", label="test", reports_dir=tmp_path)
        mock_cleanup.assert_called_once()

    def test_post_vulns_appear_in_result(self, tmp_path: Path, req_file: Path) -> None:
        vuln = Vulnerability("cryptography", "40.0.0", "CVE-2024-001", "41.0.0", "desc")
        setup_mock = _make_setup_venv_mock(tmp_path)
        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.4.0"),
            patch.object(_upgrade_mod, "_setup_venv", setup_mock),
            patch.object(_upgrade_mod, "install_pip_audit", return_value=_AUDIT_TOOL),
            patch.object(_upgrade_mod, "_run_audit_with_temp", side_effect=[[], [vuln]]),
            patch.object(_upgrade_mod, "build_constraints", return_value=[]),
            patch.object(_upgrade_mod, "install_packages"),
            patch.object(_upgrade_mod, "freeze", return_value={"cryptography": "40.0.0"}),
            patch.object(_upgrade_mod, "verify_imports", return_value=ImportCheck()),
            patch.object(_upgrade_mod, "write_log", return_value=tmp_path / "log.txt"),
            patch.object(_upgrade_mod, "write_markdown", return_value=tmp_path / "pr.md"),
            patch.object(_upgrade_mod, "cleanup_venv"),
        ):
            result = upgrade(tmp_path, strategy="latest", label="test", reports_dir=tmp_path)
        assert len(result.post_audit_vulns) == 1
        assert result.post_audit_vulns[0].cve == "CVE-2024-001"

    def test_install_failure_bubbles_up_and_does_not_write_dep_file(
        self, tmp_path: Path, req_file: Path,
    ) -> None:
        original_content = req_file.read_text()
        setup_mock = _make_setup_venv_mock(tmp_path, old_pkgs={"flask": "2.3.0"})
        error = CommandError(["uv", "pip", "install"], 1, "resolution failed")

        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.4.0"),
            patch.object(_upgrade_mod, "_setup_venv", setup_mock),
            patch.object(_upgrade_mod, "install_pip_audit", return_value=_AUDIT_TOOL),
            patch.object(_upgrade_mod, "_run_audit_with_temp", return_value=[]),
            patch.object(_upgrade_mod, "build_constraints", return_value=[]),
            patch.object(_upgrade_mod, "verify_imports", return_value=ImportCheck()),
            patch.object(_upgrade_mod, "install_packages", side_effect=error),
            patch.object(_upgrade_mod, "cleanup_venv"),
        ):
            with pytest.raises(CommandError, match="resolution failed"):
                upgrade(tmp_path, strategy="latest", label="test", reports_dir=tmp_path)

        assert req_file.read_text() == original_content

    def test_runtime_scope_excludes_optional_dependencies(self, tmp_path: Path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[project]\n"
            'dependencies = ["flask>=2.3.0"]\n'
            "[project.optional-dependencies]\n"
            'dev = ["pytest>=8.0"]\n'
        )
        setup_mock = _make_setup_venv_mock(tmp_path, old_pkgs={"flask": "2.3.0"})
        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.4.0"),
            patch.object(_upgrade_mod, "_setup_venv", setup_mock),
            patch.object(_upgrade_mod, "install_pip_audit", return_value=_AUDIT_TOOL),
            patch.object(_upgrade_mod, "_run_audit_with_temp", return_value=[]),
            patch.object(_upgrade_mod, "build_constraints", return_value=[]),
            patch.object(_upgrade_mod, "install_packages"),
            patch.object(_upgrade_mod, "freeze", return_value={"flask": "2.4.0"}),
            patch.object(_upgrade_mod, "verify_imports", return_value=ImportCheck()),
            patch.object(_upgrade_mod, "write_log", return_value=tmp_path / "log.txt"),
            patch.object(_upgrade_mod, "write_markdown", return_value=tmp_path / "pr.md"),
            patch.object(_upgrade_mod, "cleanup_venv"),
        ):
            upgrade(tmp_path, strategy="latest", label="test", reports_dir=tmp_path)

        install_deps = setup_mock.call_args.args[5]
        old_pkgs = setup_mock.call_args.args[6]
        assert [dep.name for dep in install_deps] == ["flask"]
        assert old_pkgs == {"flask": "2.3.0"}

    def test_all_scope_includes_optional_dependencies(self, tmp_path: Path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[project]\n"
            'dependencies = ["flask>=2.3.0"]\n'
            "[project.optional-dependencies]\n"
            'dev = ["pytest>=8.0"]\n'
        )
        setup_mock = _make_setup_venv_mock(tmp_path, old_pkgs={"flask": "2.3.0", "pytest": "8.0.0"})
        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.4.0"),
            patch.object(_upgrade_mod, "_setup_venv", setup_mock),
            patch.object(_upgrade_mod, "install_pip_audit", return_value=_AUDIT_TOOL),
            patch.object(_upgrade_mod, "_run_audit_with_temp", return_value=[]),
            patch.object(_upgrade_mod, "build_constraints", return_value=[]),
            patch.object(_upgrade_mod, "install_packages"),
            patch.object(
                _upgrade_mod, "freeze", return_value={"flask": "2.4.0", "pytest": "8.1.0"},
            ),
            patch.object(_upgrade_mod, "verify_imports", return_value=ImportCheck()),
            patch.object(_upgrade_mod, "write_log", return_value=tmp_path / "log.txt"),
            patch.object(_upgrade_mod, "write_markdown", return_value=tmp_path / "pr.md"),
            patch.object(_upgrade_mod, "cleanup_venv"),
        ):
            upgrade(
                tmp_path, strategy="latest", label="test", reports_dir=tmp_path,
                dependency_scope="all",
            )

        install_deps = setup_mock.call_args.args[5]
        old_pkgs = setup_mock.call_args.args[6]
        assert {dep.name for dep in install_deps} == {"flask", "pytest"}
        assert old_pkgs == {"flask": "2.3.0", "pytest": "8.0"}

    def test_ignore_direct_references_skips_selected_direct_refs(self, tmp_path: Path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[project]\n"
            'dependencies = ["flask>=2.3.0", "demo @ https://example.com/demo-1.0.tar.gz"]\n'
        )
        setup_mock = _make_setup_venv_mock(tmp_path, old_pkgs={"flask": "2.3.0"})
        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.4.0"),
            patch.object(_upgrade_mod, "_setup_venv", setup_mock),
            patch.object(_upgrade_mod, "install_pip_audit", return_value=_AUDIT_TOOL),
            patch.object(_upgrade_mod, "_run_audit_with_temp", return_value=[]),
            patch.object(_upgrade_mod, "build_constraints", return_value=[]),
            patch.object(_upgrade_mod, "install_packages"),
            patch.object(_upgrade_mod, "freeze", return_value={"flask": "2.4.0"}),
            patch.object(_upgrade_mod, "verify_imports", return_value=ImportCheck()),
            patch.object(_upgrade_mod, "write_log", return_value=tmp_path / "log.txt"),
            patch.object(_upgrade_mod, "write_markdown", return_value=tmp_path / "pr.md"),
            patch.object(_upgrade_mod, "cleanup_venv"),
        ):
            result = upgrade(
                tmp_path,
                label="test",
                reports_dir=tmp_path,
                ignore_direct_references=True,
                strategy="latest",
            )

        install_deps = setup_mock.call_args.args[5]
        assert [dep.name for dep in install_deps] == ["flask"]
        assert result.direct_references_ignored == ["demo @ https://example.com/demo-1.0.tar.gz"]


class TestImportRegressionGate:
    """The write-back must not run when imports regress against the baseline."""

    @staticmethod
    def _run(tmp_path: Path, checks: list[ImportCheck], dry_run: bool = False) -> UpgradeResult:
        setup_mock = _make_setup_venv_mock(tmp_path, old_pkgs={"fastmcp": "3.4.7"})
        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.9.0"),
            patch.object(_upgrade_mod, "_setup_venv", setup_mock),
            patch.object(_upgrade_mod, "install_pip_audit", return_value=_AUDIT_TOOL),
            patch.object(_upgrade_mod, "_run_audit_with_temp", return_value=[]),
            patch.object(_upgrade_mod, "build_constraints", return_value=[]),
            patch.object(_upgrade_mod, "install_packages"),
            patch.object(_upgrade_mod, "freeze", return_value={"fastmcp": "4.1.4"}),
            patch.object(_upgrade_mod, "verify_imports", side_effect=checks),
            patch.object(_upgrade_mod, "write_log", return_value=tmp_path / "log.txt"),
            patch.object(_upgrade_mod, "write_markdown", return_value=tmp_path / "pr.md"),
        ):
            return upgrade(
                tmp_path, label="test", reports_dir=tmp_path, dry_run=dry_run,
                allow_major=[], strategy="latest",
            )

    def test_regression_blocks_write_back(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("fastmcp==3.4.7\n")
        baseline = ImportCheck(verified=["fastmcp", "fastmcp.tools.tool"])
        after = ImportCheck(
            verified=["fastmcp"],
            failed={"fastmcp.tools.tool": "No module named 'fastmcp.tools.tool'"},
        )
        result = self._run(tmp_path, [baseline, after])

        assert result.import_regressions == {
            "fastmcp.tools.tool": "No module named 'fastmcp.tools.tool'",
        }
        assert result.dep_file_updated is False
        assert "import" in result.write_back_skipped
        assert req.read_text() == "fastmcp==3.4.7\n"

    def test_failures_already_present_in_baseline_do_not_block(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("fastmcp==3.4.7\n")
        missing = {"pytest": "No module named 'pytest'"}
        baseline = ImportCheck(verified=["fastmcp"], failed=dict(missing))
        after = ImportCheck(verified=["fastmcp"], failed=dict(missing))
        result = self._run(tmp_path, [baseline, after])

        assert result.import_regressions == {}
        assert result.dep_file_updated is True
        assert "fastmcp==4.1.4" in req.read_text()


class TestSubprojectPyproject:
    """--dep-file sub/pyproject.toml without a lock: resolved mode on that subproject."""

    ROOT = '[project]\nname = "root-app"\nversion = "1"\ndependencies = ["six==1.17.0"]\n'
    SUB = '[project]\nname = "sub-app"\nversion = "1"\ndependencies = ["idna==3.6"]\n'

    def _tree(self, tmp_path: Path) -> Path:
        target = tmp_path / "repo"
        (target / "sub").mkdir(parents=True)
        (target / "pyproject.toml").write_text(self.ROOT)
        (target / "sub" / "pyproject.toml").write_text(self.SUB)
        return target

    def test_uv_runs_in_the_subproject(self, tmp_path: Path) -> None:
        from depfresh.advisories import TargetEnv
        from depfresh.parsers import DependencyFormat
        from depfresh.pipmode import PipWorkspace
        from depfresh.remediation import RemediationOptions

        sub = self._tree(tmp_path) / "sub"
        ws = PipWorkspace("/usr/bin/uv", sub, sub / "pyproject.toml",
                          DependencyFormat.PYPROJECT_PEP621, tmp_path / "work",
                          RemediationOptions(env=TargetEnv("3.12")),
                          ignore_direct_references=False)
        result = MagicMock(stdout="idna==3.6  # via sub-app\n", stderr="")
        with patch("depfresh.pipmode.run", return_value=result) as mock:
            ws.compile(ws.write(self.SUB))
        assert mock.call_args.kwargs["cwd"] == sub.resolve()

    def test_writes_only_the_subproject(self, tmp_path: Path) -> None:
        from depfresh.pipmode import PipOutcome, Resolution
        from depfresh.remediation import ImportGate

        target = self._tree(tmp_path)
        sub = target / "sub"
        new_text = self.SUB.replace("idna==3.6", "idna==3.15")
        outcome = PipOutcome(
            baseline=Resolution(pins={"idna": "3.6"}), final=Resolution(pins={"idna": "3.15"}),
            pre_vulns=[Vulnerability("idna", "3.6", "GHSA-x", "3.15", "")], post_vulns=[],
            plans={}, failures={}, new_text=new_text, changed=True,
            resolution_check="passed", commands=[], notes=[], not_audited=[],
            gate=ImportGate(False, sub), direct_refs=[], original_text=self.SUB,
        )
        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.13.6"),
            patch.object(_upgrade_mod, "install_pip_audit", return_value=_AUDIT_TOOL),
            patch.object(_upgrade_mod, "remediate_pip", return_value=outcome) as mock,
        ):
            result = upgrade(target, dep_file="sub/pyproject.toml", python="3.12",
                             reports_dir=tmp_path / "reports")
        assert mock.call_args.kwargs["target_dir"] == sub
        assert (sub / "pyproject.toml").read_text() == new_text
        assert (target / "pyproject.toml").read_text() == self.ROOT
        assert result.requirements_path == "sub/pyproject.toml"
        assert result.files_changed == ["sub/pyproject.toml"]

    def test_dep_file_outside_the_target_is_refused(self, tmp_path: Path) -> None:
        from depfresh.exceptions import DepfreshError

        target = self._tree(tmp_path)
        (tmp_path / "other").mkdir()
        (tmp_path / "other" / "pyproject.toml").write_text(self.SUB)
        with pytest.raises(DepfreshError, match="outside"):
            upgrade(target / "sub", dep_file="../../other/pyproject.toml", python="3.12")

    def test_requirements_file_is_checked_against_its_own_pyproject(
        self, tmp_path: Path,
    ) -> None:
        from depfresh.indexes import PrivateSourceError

        target = self._tree(tmp_path)
        (target / "sub" / "pyproject.toml").write_text(
            self.SUB + '[[tool.uv.index]]\nname = "internal"\n'
            'url = "https://us-east1-python.pkg.dev/acme/python/simple/"\n'
            '[tool.uv.sources]\nprivate-widget = { index = "internal" }\n'
        )
        (target / "sub" / "requirements.txt").write_text("private-widget==0.1.0\n")
        with (
            patch.object(_upgrade_mod, "find_uv") as find_uv,
            pytest.raises(PrivateSourceError, match="private-widget"),
        ):
            upgrade(target, dep_file="sub/requirements.txt", python="3.12")
        assert not find_uv.called


# ---------------------------------------------------------------------------
# audit_only() — validation and happy path
# ---------------------------------------------------------------------------


class TestAuditOnly:
    def test_raises_target_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(TargetNotFoundError):
            audit_only(tmp_path / "nonexistent")

    def test_raises_requirements_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(RequirementsNotFoundError):
            audit_only(tmp_path)

    @staticmethod
    def _outcome(pins: dict[str, str], vulns: list[Vulnerability]) -> MagicMock:
        from depfresh.pipmode import PipOutcome, Resolution
        from depfresh.remediation import ImportGate

        resolution = Resolution(pins=pins)
        return MagicMock(return_value=PipOutcome(
            baseline=resolution, final=resolution, pre_vulns=vulns, post_vulns=vulns,
            plans={}, failures={}, new_text="", changed=False, resolution_check="",
            commands=[], notes=[], not_audited=[], gate=ImportGate(False, Path(".")),
            direct_refs=[],
        ))

    def test_returns_upgrade_result(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("flask==2.3.0\n")
        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.9.0"),
            patch.object(_upgrade_mod, "install_pip_audit", return_value=_AUDIT_TOOL),
            patch.object(_upgrade_mod, "remediate_pip",
                         self._outcome({"flask": "2.3.0"}, [])) as mock,
        ):
            result = audit_only(tmp_path)
        assert isinstance(result, UpgradeResult)
        assert result.post_audit_vulns == []
        assert result.mode == "requirements"
        assert mock.call_args.kwargs["audit_only"] is True

    def test_vulnerabilities_placed_in_pre_audit_vulns(self, tmp_path: Path) -> None:
        """audit_only stores findings in pre_audit_vulns (no upgrade, no post)."""
        (tmp_path / "requirements.txt").write_text("urllib3==2.0.0\n")
        vuln = Vulnerability("urllib3", "2.0.0", "CVE-2023-001", "2.0.6", "desc")
        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.9.0"),
            patch.object(_upgrade_mod, "install_pip_audit", return_value=_AUDIT_TOOL),
            patch.object(_upgrade_mod, "remediate_pip",
                         self._outcome({"urllib3": "2.0.0"}, [vuln])),
        ):
            result = audit_only(tmp_path)
        assert len(result.pre_audit_vulns) == 1
        assert result.pre_audit_vulns[0].package == "urllib3"
        assert result.post_audit_vulns == []

    def test_work_dir_removed_even_on_error(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("flask==2.3.0\n")
        work = tmp_path / "work"
        work.mkdir()
        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.9.0"),
            patch.object(_upgrade_mod.tempfile, "mkdtemp", return_value=str(work)),
            patch.object(_upgrade_mod, "install_pip_audit", return_value=_AUDIT_TOOL),
            patch.object(_upgrade_mod, "remediate_pip", side_effect=RuntimeError("boom")),
        ):
            with pytest.raises(RuntimeError):
                audit_only(tmp_path)
        assert not work.exists()

    def test_legacy_audit_cleans_up_on_error(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("flask==2.3.0\n")
        setup_mock = MagicMock(return_value=("/venv/bin/python", "3.11.5", {"flask": "2.3.0"}))
        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.4.0"),
            patch.object(_upgrade_mod, "_setup_venv", setup_mock),
            patch.object(_upgrade_mod, "install_pip_audit", return_value=_AUDIT_TOOL),
            patch.object(_upgrade_mod, "_run_audit_with_temp", side_effect=RuntimeError("boom")),
            patch.object(_upgrade_mod, "cleanup_venv") as mock_cleanup,
        ):
            with pytest.raises(RuntimeError):
                _audit_only_legacy(
                    tmp_path, dep_file=None, fmt=None, python="3.11", venv_name=".venv-audit",
                    dependency_scope="runtime", ignore_direct_references=False, uv_binary=None,
                )
        mock_cleanup.assert_called_once()

    def test_pip_audit_runs_from_an_isolated_tool_env(self, tmp_path: Path) -> None:
        """pip-audit is never installed into the project venv.

        Earlier releases installed pip-audit next to the project's packages and
        then dropped pip-audit's dependencies (rich, msgpack, platformdirs…)
        from the frozen set, which also hid the project's own copies of those
        packages from the audit.
        """
        req_file = tmp_path / "requirements.in"
        req_file.write_text("flask\nmsgpack\n")  # unpinned — triggers freeze inside _setup_venv

        freeze_mock = MagicMock(return_value={"flask": "2.3.0", "msgpack": "1.0.5"})
        audit_mock = MagicMock(return_value=[])
        install_tool = MagicMock(return_value=_AUDIT_TOOL)
        installed_into: list[str] = []

        def install_capture(uv: str, venv_python: str, req_path: Path) -> None:
            installed_into.append(venv_python)

        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.4.0"),
            patch.object(_upgrade_mod, "create_venv", return_value="/venv/bin/python"),
            patch.object(_upgrade_mod, "install_requirements", side_effect=install_capture),
            patch.object(_upgrade_mod, "install_pip_audit", install_tool),
            patch.object(_upgrade_mod, "freeze", freeze_mock),
            patch.object(_upgrade_mod, "run", return_value=MagicMock(stdout="Python 3.11.5\n")),
            patch.object(_upgrade_mod, "_run_audit_with_temp", audit_mock),
        ):
            _audit_only_legacy(
                tmp_path, dep_file=None, fmt=None, python="3.11", venv_name=".venv-audit",
                dependency_scope="runtime", ignore_direct_references=False, uv_binary=None,
            )

        # The tool env lives in depfresh's work dir, not in the project venv.
        tool_dir = install_tool.call_args.args[1]
        assert tool_dir.name == ".pip-audit-tool"
        assert installed_into == ["/venv/bin/python"]
        # Every frozen package is audited, msgpack included, with the tool interpreter.
        assert audit_mock.call_args.args[0] == "/tool/bin/python"
        assert audit_mock.call_args.args[2] == {"flask": "2.3.0", "msgpack": "1.0.5"}

    def test_work_dir_removed_when_install_fails(self, tmp_path: Path) -> None:
        """An install failure before the audit must not leave a venv behind."""
        (tmp_path / "requirements.txt").write_text("flask==2.3.0\n")
        created: list[Path] = []

        def fake_create(uv: str, venv_path: Path, python: str) -> str:
            venv_path.mkdir(parents=True)
            created.append(venv_path)
            return str(venv_path / "bin" / "python")

        error = CommandError(["uv", "pip", "install"], 1, "no solution")
        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.4.0"),
            patch.object(_upgrade_mod, "create_venv", side_effect=fake_create),
            patch.object(_upgrade_mod, "install_requirements", side_effect=error),
        ):
            with pytest.raises(CommandError):
                upgrade(tmp_path, strategy="latest", label="test", reports_dir=tmp_path / "reports")

        assert created, "venv should have been created before the failure"
        assert not created[0].exists()
        assert not created[0].parent.exists()  # the whole work dir is gone
        assert not list(tmp_path.glob(".venv-upgrade*"))


class TestSetupVenv:
    def test_non_pinned_formats_install_wildcards(self, tmp_path: Path) -> None:
        req_file = tmp_path / "pyproject.toml"
        req_file.write_text("[project]\ndependencies = []\n")
        seen: dict[str, str | bool] = {"content": "", "exists_during_install": False}

        def install_capture(uv: str, venv_python: str, req_path: Path) -> None:
            seen["content"] = req_path.read_text()
            seen["exists_during_install"] = req_path.exists()

        with (
            patch.object(_upgrade_mod, "create_venv", return_value="/venv/bin/python"),
            patch.object(_upgrade_mod, "install_requirements", side_effect=install_capture),
            patch.object(
                _upgrade_mod, "freeze", return_value={"flask": "2.4.0", "requests": "2.32.0"},
            ),
            patch.object(_upgrade_mod, "run", return_value=MagicMock(stdout="Python 3.11.5\n")),
        ):
            _setup_venv_result = _setup_venv(
                "/usr/bin/uv",
                tmp_path,
                tmp_path / ".venv-upgrade",
                "3.11",
                PyprojectPEP621Handler(),
                [
                    DependencySpec(
                        name="flask",
                        version="*",
                        requirement="flask",
                        raw="flask",
                    ),
                    DependencySpec(
                        name="requests",
                        version="2.31.0",
                        requirement="requests==2.31.0",
                        raw="requests==2.31.0",
                    ),
                ],
                {"flask": "*", "requests": "2.31.0"},
                req_file,
                False,
            )

        temp_req = tmp_path / ".depfresh_install.tmp"
        assert "flask\n" in str(seen["content"])
        assert "requests==2.31.0" in str(seen["content"])
        assert seen["exists_during_install"] is True
        assert not temp_req.exists()
        assert _setup_venv_result[2]["flask"] == "2.4.0"
