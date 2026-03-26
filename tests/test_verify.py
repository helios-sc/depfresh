"""Tests for verify module — AST-based import extraction."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from depfresh.verify import _extract_imports, _find_local_modules, verify_imports


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
