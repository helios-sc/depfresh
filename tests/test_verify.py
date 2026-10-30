"""Tests for verify module — AST-based import extraction."""

from __future__ import annotations

import sys
import venv
from pathlib import Path
from unittest.mock import patch

import pytest

from depfresh.models import ImportCheck
from depfresh.verify import (
    _batch_import_check,
    _extract_imports,
    _find_local_modules,
    _get_stdlib_modules,
    import_regressions,
    site_dirs,
    verify_imports,
)


@pytest.fixture(scope="module")
def probe_venv(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, Path]:
    """A pip-less venv with a package whose import has a visible side effect.

    Returns ``(venv_python, marker_file)``.  ``sidefx`` writes *marker_file*
    when imported, so a check that imports anything is caught.
    """
    root = tmp_path_factory.mktemp("probe-venv")
    venv.create(root / "venv", with_pip=False, symlinks=sys.platform != "win32")
    bin_dir = "Scripts" if sys.platform == "win32" else "bin"
    python = root / "venv" / bin_dir / ("python.exe" if sys.platform == "win32" else "python")
    site = next((root / "venv").glob("lib/python*/site-packages"), None)
    if site is None:
        site = root / "venv" / "Lib" / "site-packages"
    marker = root / "imported.marker"
    pkg = site / "sidefx"
    (pkg / "tools").mkdir(parents=True)
    (pkg / "__init__.py").write_text(f"open({str(marker)!r}, 'w').write('imported')\n")
    (pkg / "tools" / "__init__.py").write_text("")
    (pkg / "tools" / "tool.py").write_text("raise RuntimeError('must not run')\n")
    (site / "flatmod.py").write_text("")
    # google.cloud-style nested namespace packages (no __init__.py anywhere)
    (site / "nsroot" / "inner").mkdir(parents=True)
    (site / "nsroot" / "inner" / "leaf.py").write_text("")
    return str(python), marker


class TestExtractImports:
    def test_extracts_imports(self, tmp_path: Path) -> None:
        py_file = tmp_path / "app.py"
        py_file.write_text(
            "import flask\n"
            "from requests import get\n"
            "import os\n"
        )
        imports, scanned = _extract_imports(tmp_path)
        assert scanned == 1
        assert "flask" in imports
        assert "requests" in imports
        assert "os" in imports

    def test_skips_relative_imports(self, tmp_path: Path) -> None:
        py_file = tmp_path / "app.py"
        py_file.write_text("from . import utils\nfrom .models import User\n")
        imports, _ = _extract_imports(tmp_path)
        assert "utils" not in imports
        assert "models" not in imports

    def test_skips_pycache(self, tmp_path: Path) -> None:
        cache_dir = tmp_path / "__pycache__"
        cache_dir.mkdir()
        (cache_dir / "app.cpython-311.py").write_text("import evil\n")
        (tmp_path / "real.py").write_text("import flask\n")
        imports, scanned = _extract_imports(tmp_path)
        assert scanned == 1
        assert "evil" not in imports

    def test_skips_venv(self, tmp_path: Path) -> None:
        venv_dir = tmp_path / ".venv"
        venv_dir.mkdir()
        (venv_dir / "some.py").write_text("import internal\n")
        (tmp_path / "app.py").write_text("import flask\n")
        imports, scanned = _extract_imports(tmp_path)
        assert scanned == 1
        assert "internal" not in imports

    def test_handles_syntax_errors(self, tmp_path: Path) -> None:
        (tmp_path / "bad.py").write_text("def broken(:\n")
        (tmp_path / "good.py").write_text("import flask\n")
        imports, scanned = _extract_imports(tmp_path)
        assert scanned == 1
        assert "flask" in imports


class TestFindLocalModules:
    def test_finds_directories(self, tmp_path: Path) -> None:
        (tmp_path / "myapp").mkdir()
        (tmp_path / "utils").mkdir()
        local = _find_local_modules(tmp_path)
        assert "myapp" in local
        assert "utils" in local

    def test_finds_python_files(self, tmp_path: Path) -> None:
        (tmp_path / "helpers.py").write_text("")
        local = _find_local_modules(tmp_path)
        assert "helpers" in local

    def test_includes_target_dir_name(self, tmp_path: Path) -> None:
        local = _find_local_modules(tmp_path)
        assert tmp_path.name in local

    def test_skips_hidden_dirs(self, tmp_path: Path) -> None:
        (tmp_path / ".hidden").mkdir()
        local = _find_local_modules(tmp_path)
        assert ".hidden" not in local

    def test_skips_venv_dirs(self, tmp_path: Path) -> None:
        (tmp_path / "venv").mkdir()
        (tmp_path / ".venv-test").mkdir()
        local = _find_local_modules(tmp_path)
        assert "venv" not in local
        assert ".venv-test" not in local

    def test_finds_modules_below_the_first_level(self, tmp_path: Path) -> None:
        """A project that puts src/ on sys.path imports its modules by bare name."""
        (tmp_path / "src" / "ops").mkdir(parents=True)
        (tmp_path / "src" / "db_client.py").write_text("")
        (tmp_path / "src" / "ops" / "geo_lookup.py").write_text("")
        local = _find_local_modules(tmp_path)
        assert {"db_client", "geo_lookup", "src", "ops"} <= local

    def test_ignores_modules_inside_virtualenvs(self, tmp_path: Path) -> None:
        site = tmp_path / ".venv" / "lib" / "python3.11" / "site-packages" / "requests"
        site.mkdir(parents=True)
        (site / "__init__.py").write_text("")
        vendored = tmp_path / "env" / "lib" / "site-packages" / "flask"
        vendored.mkdir(parents=True)
        (vendored / "__init__.py").write_text("")
        local = _find_local_modules(tmp_path)
        assert "requests" not in local
        assert "flask" not in local


class TestVerifyImports:
    def test_returns_verified_and_failed_third_party_imports(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("import flask\nimport requests\nimport os\n")

        with (
            patch("depfresh.verify._get_stdlib_modules", return_value={"os"}),
            patch(
                "depfresh.verify._batch_import_check",
                return_value=(
                    {"flask": None, "requests": "No module named 'requests'"},
                    {"flask": ["DeprecationWarning: old"]},
                ),
            ),
        ):
            result = verify_imports(tmp_path, "/venv/bin/python")

        assert result.verified == ["flask"]
        assert "requests" in result.failed
        assert "flask" in result.warnings

    def test_skips_local_and_stdlib_only_projects(self, tmp_path: Path) -> None:
        (tmp_path / "helpers.py").write_text("")
        (tmp_path / "app.py").write_text("import os\nimport helpers\n")

        with patch("depfresh.verify._get_stdlib_modules", return_value={"os"}):
            result = verify_imports(tmp_path, "/venv/bin/python")

        assert result.verified == []
        assert result.failed == {}
        assert "helpers" in result.skipped_local


class TestNothingRuns:
    """Locating modules runs only the standard library: no .pth hook, no cwd module."""

    @pytest.fixture()
    def hooked_venv(self, tmp_path: Path) -> tuple[str, Path, Path]:
        venv.create(tmp_path / "venv", with_pip=False, symlinks=sys.platform != "win32")
        bin_dir = "Scripts" if sys.platform == "win32" else "bin"
        python = tmp_path / "venv" / bin_dir / ("python.exe" if sys.platform == "win32"
                                                else "python")
        site = next((tmp_path / "venv").glob("lib/python*/site-packages"), None)
        site = site or tmp_path / "venv" / "Lib" / "site-packages"
        marker = tmp_path / "pth.marker"
        # a hook like setuptools' distutils-precedence.pth, and a plain path entry
        (site / "hook.pth").write_text(f"import os; open({str(marker)!r}, 'w').write('x')\n")
        extra = tmp_path / "extra-path"
        (extra / "viapth").mkdir(parents=True)
        (extra / "viapth" / "__init__.py").write_text("")
        (site / "paths.pth").write_text(f"# comment\n{extra}\n")
        return str(python), marker, site

    def test_pth_hooks_do_not_run_and_path_entries_count(
        self, hooked_venv: tuple[str, Path, Path],
    ) -> None:
        python, marker, site = hooked_venv
        results, _ = _batch_import_check(python, {"viapth", "json"})
        assert results == {"viapth": None, "json": None}
        assert not marker.exists(), "a .pth import hook ran during the import check"
        assert site_dirs(python) == [str(site.resolve())]

    def test_modules_in_the_working_directory_are_never_imported(
        self, hooked_venv: tuple[str, Path, Path], tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        python, marker, _ = hooked_venv
        project = tmp_path / "project"
        project.mkdir()
        cwd_marker = tmp_path / "cwd.marker"
        (project / "json.py").write_text(f"open({str(cwd_marker)!r}, 'w').write('x')\n")
        monkeypatch.chdir(project)
        assert "json" in _get_stdlib_modules(python)
        assert _batch_import_check(python, {"json"})[0] == {"json": None}
        assert not cwd_marker.exists(), "json.py from the working directory was imported"
        assert not marker.exists()


class TestBatchImportCheck:
    def test_missing_parent_fails_only_its_own_modules(self) -> None:
        """A dotted import of a missing package must not crash the whole batch."""
        results, _ = _batch_import_check(
            sys.executable, {"json", "json.decoder", "definitely_missing_pkg_xyz.sub"},
        )
        assert results["json"] is None
        assert results["json.decoder"] is None
        assert "definitely_missing_pkg_xyz" in str(results["definitely_missing_pkg_xyz.sub"])

    def test_missing_submodule_is_reported(self) -> None:
        results, _ = _batch_import_check(sys.executable, {"json.no_such_submodule"})
        assert "json.no_such_submodule" in str(results["json.no_such_submodule"])

    def test_resolves_dotted_names_without_importing(
        self, probe_venv: tuple[str, Path],
    ) -> None:
        python, marker = probe_venv
        results, warns = _batch_import_check(
            python, {"sidefx", "sidefx.tools.tool", "sidefx.tools.gone", "flatmod.sub"},
        )
        assert results["sidefx"] is None
        assert results["sidefx.tools.tool"] is None
        assert "sidefx.tools.gone" in str(results["sidefx.tools.gone"])
        assert "not a package" in str(results["flatmod.sub"])
        assert warns == {}
        assert not marker.exists(), "the check imported sidefx/__init__.py"

    def test_nested_namespace_packages(self, probe_venv: tuple[str, Path]) -> None:
        """google.cloud.*: PathFinder needs the parent in sys.modules; the check must not."""
        python, _ = probe_venv
        results, _ = _batch_import_check(
            python, {"nsroot", "nsroot.inner", "nsroot.inner.leaf", "nsroot.inner.gone"},
        )
        assert results["nsroot"] is None
        assert results["nsroot.inner"] is None
        assert results["nsroot.inner.leaf"] is None
        assert "nsroot.inner.gone" in str(results["nsroot.inner.gone"])


class TestImportRegressions:
    def test_reports_only_modules_that_resolved_before(self) -> None:
        baseline = ImportCheck(
            verified=["fastmcp", "fastmcp.tools.tool"],
            failed={"pytest": "No module named 'pytest'"},
        )
        after = ImportCheck(
            verified=["fastmcp"],
            failed={
                "fastmcp.tools.tool": "No module named 'fastmcp.tools.tool'",
                "pytest": "No module named 'pytest'",
            },
        )
        assert import_regressions(baseline, after) == {
            "fastmcp.tools.tool": "No module named 'fastmcp.tools.tool'",
        }

    def test_no_regressions_when_nothing_breaks(self) -> None:
        check = ImportCheck(verified=["flask"])
        assert import_regressions(check, check) == {}
