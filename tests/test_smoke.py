"""Release smoke tests — build wheel, install, run with real uv and pip-audit.

These tests require:
- ``uv`` on PATH
- Network access to PyPI

Run explicitly with::

    pytest -m smoke

They are excluded from the default ``pytest`` run.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.smoke

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_PYTHON_VERSION = f"{sys.version_info.major}.{sys.version_info.minor}"


def _has_uv() -> bool:
    return shutil.which("uv") is not None


@pytest.fixture(scope="module")
def installed_venv(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, str, str]:
    """Build the wheel, install it into a fresh venv.

    Returns ``(venv_dir, python_path, depfresh_bin)``.
    """
    uv = shutil.which("uv")
    assert uv is not None

    # -- Build wheel ----------------------------------------------------------
    dist_dir = tmp_path_factory.mktemp("dist")
    result = subprocess.run(
        [uv, "build", "--wheel", "--out-dir", str(dist_dir)],
        cwd=str(_PROJECT_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"uv build failed:\n{result.stderr}"

    wheels = list(dist_dir.glob("*.whl"))
    assert len(wheels) == 1, f"Expected 1 wheel, found {len(wheels)}: {wheels}"

    # -- Create venv and install wheel ----------------------------------------
    venv_dir = tmp_path_factory.mktemp("smoke-venv")
    subprocess.run(
        [uv, "venv", str(venv_dir), "--python", _PYTHON_VERSION],
        check=True,
        capture_output=True,
        timeout=60,
    )

    if sys.platform == "win32":
        python = str(venv_dir / "Scripts" / "python.exe")
        depfresh_bin = str(venv_dir / "Scripts" / "depfresh")
    else:
        python = str(venv_dir / "bin" / "python")
        depfresh_bin = str(venv_dir / "bin" / "depfresh")

    subprocess.run(
        [uv, "pip", "install", str(wheels[0]), "--python", python],
        check=True,
        capture_output=True,
        timeout=120,
    )

    return venv_dir, python, depfresh_bin


# ---------------------------------------------------------------------------
# Wheel packaging tests
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _has_uv(), reason="uv not installed")
class TestWheelPackaging:
    """Verify the built wheel installs cleanly and the entry point works."""

    def test_depfresh_help(self, installed_venv: tuple[Path, str, str]) -> None:
        """``depfresh --help`` must exit 0 and show usage text."""
        _, _, depfresh_bin = installed_venv
        result = subprocess.run(
            [depfresh_bin, "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert "depfresh" in result.stdout
        assert "--dry-run" in result.stdout
        assert "--allow-major" in result.stdout

    def test_version_importable(self, installed_venv: tuple[Path, str, str]) -> None:
        """The installed package must expose ``__version__``."""
        _, python, _ = installed_venv
        result = subprocess.run(
            [python, "-c", "from depfresh import __version__; print(__version__)"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert result.stdout.strip(), "Expected a non-empty version string"

    def test_public_api_importable(self, installed_venv: tuple[Path, str, str]) -> None:
        """All public API names must be importable from the installed wheel."""
        _, python, _ = installed_venv
        result = subprocess.run(
            [
                python,
                "-c",
                (
                    "from depfresh import upgrade, audit_only, "
                    "UpgradeResult, Vulnerability, PackageChange, ImportCheck; "
                    "print('ok')"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"Import failed:\n{result.stderr}"
        assert result.stdout.strip() == "ok"


# ---------------------------------------------------------------------------
# Live integration test
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _has_uv(), reason="uv not installed")
class TestLiveIntegration:
    """Run depfresh for real against a tiny project with actual uv and pip-audit."""

    def test_dry_run_upgrade_with_real_tools(
        self,
        installed_venv: tuple[Path, str, str],
        tmp_path: Path,
    ) -> None:
        """Full dry-run upgrade: venv creation, audit, upgrade, report generation.

        Uses a minimal requirements.txt so the run finishes quickly.
        Accepts exit 0 (all clean) or 2 (vulns remain) — both mean the
        tool ran to completion.  Only exit 1 (error) is a failure.
        """
        _, _, depfresh_bin = installed_venv

        # Create a tiny sample project
        project_dir = tmp_path / "sample_project"
        project_dir.mkdir()
        (project_dir / "requirements.txt").write_text(
            "idna==3.6\npackaging==23.1\n"
        )

        reports_dir = tmp_path / "reports"

        result = subprocess.run(
            [
                depfresh_bin,
                str(project_dir),
                "--dry-run",
                "--python",
                _PYTHON_VERSION,
                "--reports-dir",
                str(reports_dir),
                "--label",
                "smoke_test",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        assert result.returncode in (0, 2), (
            f"depfresh failed (exit {result.returncode}):\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )

        # Verify stdout summary was printed
        assert "depfresh" in result.stdout
        assert "Upgraded:" in result.stdout

        # Verify reports were generated
        report_dir = reports_dir / "smoke_test"
        assert report_dir.is_dir(), f"Report dir not created: {report_dir}"

        md_files = list(report_dir.glob("*_DEPENDENCY_UPGRADE_PR.md"))
        assert md_files, "No markdown report generated"

        log_files = list(report_dir.glob("*_dependency_upgrade.log"))
        assert log_files, "No log file generated"

        # Verify report content is non-trivial
        md_content = md_files[0].read_text()
        assert "## Summary" in md_content
        assert "## All Upgraded Packages" in md_content
        assert "## Verification Checklist" in md_content

        # Verify the original file was NOT modified (dry-run)
        assert (project_dir / "requirements.txt").read_text() == "idna==3.6\npackaging==23.1\n"


@pytest.mark.skipif(not _has_uv(), reason="uv not installed")
class TestLiveLockAware:
    """Lock-aware mode against a real uv project: the fix lands in uv.lock."""

    def test_fixes_a_vulnerable_lock(
        self,
        installed_venv: tuple[Path, str, str],
        tmp_path: Path,
    ) -> None:
        if sys.version_info >= (3, 11):
            import tomllib
        else:
            import tomli as tomllib
        from packaging.version import Version

        _, _, depfresh_bin = installed_venv
        uv = shutil.which("uv")
        assert uv is not None
        project = tmp_path / "lock_project"
        project.mkdir()
        pyproject = (
            '[project]\nname = "smoke-lock"\nversion = "0.1.0"\n'
            'requires-python = ">=3.10"\ndependencies = ["idna>=3.0"]\n\n'
            "[tool.uv]\npackage = false\n"
        )
        (project / "pyproject.toml").write_text(pyproject)
        for args in (["lock"], ["lock", "--upgrade-package", "idna==3.6"]):
            done = subprocess.run(
                [uv, *args], cwd=project, capture_output=True, text=True, timeout=120,
            )
            assert done.returncode == 0, done.stderr

        result = subprocess.run(
            [depfresh_bin, str(project), "--python", _PYTHON_VERSION,
             "--reports-dir", str(tmp_path / "reports"), "--label", "smoke_lock"],
            capture_output=True, text=True, timeout=600,
        )
        assert result.returncode == 0, f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        assert "Mode:         lock (minimal)" in result.stdout

        lock = tomllib.loads((project / "uv.lock").read_text())
        idna = next(p for p in lock["package"] if p["name"] == "idna")
        assert Version(idna["version"]) > Version("3.6")
        assert (project / "pyproject.toml").read_text() == pyproject
        check = subprocess.run(
            [uv, "lock", "--check"], cwd=project, capture_output=True, text=True, timeout=120,
        )
        assert check.returncode == 0, check.stderr


@pytest.mark.skipif(not _has_uv(), reason="uv not installed")
class TestLiveResolvedMode:
    """Minimal mode on a requirements file, resolved for linux/x86_64."""

    def test_moves_only_the_vulnerable_line(
        self,
        installed_venv: tuple[Path, str, str],
        tmp_path: Path,
    ) -> None:
        _, _, depfresh_bin = installed_venv
        project = tmp_path / "req_project"
        project.mkdir()
        original = "# service pins\nidna==3.6  # transitive of requests\nsix>=1.16\n"
        (project / "requirements.txt").write_text(original)

        result = subprocess.run(
            [depfresh_bin, str(project), "--python", _PYTHON_VERSION,
             "--reports-dir", str(tmp_path / "reports"), "--label", "smoke_resolved"],
            capture_output=True, text=True, timeout=600,
        )
        assert result.returncode in (0, 2), (
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
        assert "Target:       x86_64-unknown-linux-gnu" in result.stdout

        lines = (project / "requirements.txt").read_text().splitlines()
        assert lines[0] == "# service pins"
        assert lines[1].startswith("idna==") and lines[1] != "idna==3.6  # transitive of requests"
        assert lines[1].endswith("  # transitive of requests")
        assert lines[2] == "six>=1.16"
