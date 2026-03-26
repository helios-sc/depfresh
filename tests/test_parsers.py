"""Tests for the parsers module — format detection, parsing, and writing."""

from __future__ import annotations

import logging
from pathlib import Path
from textwrap import dedent
from unittest.mock import MagicMock, patch

import pytest

from depfresh.exceptions import CommandError
from depfresh.parsers import (
    DependencyFormat,
    PipfileHandler,
    PyprojectPEP621Handler,
    PyprojectPoetryHandler,
    RequirementsHashedHandler,
    RequirementsInHandler,
    RequirementsSimpleHandler,
    _merge_continuation_lines,
    detect_dep_file,
    detect_format,
    get_handler,
)

# ===================================================================
# Auto-detection
# ===================================================================

class TestDetectFormat:
    def test_requirements_txt_simple(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.3.0\nrequests==2.31.0\n")
        assert detect_format(req) == DependencyFormat.REQUIREMENTS_SIMPLE

    def test_requirements_txt_hashed(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.3.0 --hash=sha256:abc123\n")
        assert detect_format(req) == DependencyFormat.REQUIREMENTS_HASHED

    def test_requirements_in(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.in"
        req.write_text("flask>=2.0\nrequests\n")
        assert detect_format(req) == DependencyFormat.REQUIREMENTS_IN

    def test_pipfile(self, tmp_path: Path) -> None:
        pf = tmp_path / "Pipfile"
        pf.write_text('[packages]\nflask = "==2.3.0"\n')
        assert detect_format(pf) == DependencyFormat.PIPFILE

    def test_pyproject_pep621(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [project]
            dependencies = ["flask>=2.3.0"]
        """))
        assert detect_format(pp) == DependencyFormat.PYPROJECT_PEP621

    def test_pyproject_poetry(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [tool.poetry.dependencies]
            python = "^3.10"
            flask = "^2.3.0"
        """))
        assert detect_format(pp) == DependencyFormat.PYPROJECT_POETRY

    def test_pyproject_both_prefers_pep621(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [project]
            dependencies = ["flask>=2.3.0"]

            [tool.poetry.dependencies]
            flask = "^2.3.0"
        """))
        assert detect_format(pp) == DependencyFormat.PYPROJECT_PEP621

    def test_pyproject_no_deps_raises(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [build-system]
            requires = ["hatchling"]
        """))
        with pytest.raises(ValueError, match="neither"):
            detect_format(pp)


class TestDetectDepFile:
    def test_finds_requirements_txt(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("flask==2.3.0\n")
        assert detect_dep_file(tmp_path).name == "requirements.txt"

    def test_finds_requirements_in(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.in").write_text("flask>=2.0\n")
        assert detect_dep_file(tmp_path).name == "requirements.in"

    def test_finds_pyproject_toml(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["flask>=2.3.0"]\n'
        )
        assert detect_dep_file(tmp_path).name == "pyproject.toml"

    def test_finds_pipfile(self, tmp_path: Path) -> None:
        (tmp_path / "Pipfile").write_text('[packages]\nflask = "*"\n')
        assert detect_dep_file(tmp_path).name == "Pipfile"

    def test_priority_requirements_txt_over_pyproject(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("flask==2.3.0\n")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["flask>=2.3.0"]\n'
        )
        assert detect_dep_file(tmp_path).name == "requirements.txt"

    def test_no_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="No dependency file"):
            detect_dep_file(tmp_path)


class TestGetHandler:
    @pytest.mark.parametrize("fmt", list(DependencyFormat))
    def test_returns_handler_for_each_format(self, fmt: DependencyFormat) -> None:
        handler = get_handler(fmt)
        assert hasattr(handler, "parse")
        assert hasattr(handler, "write")
        assert hasattr(handler, "is_pinned")


# ===================================================================
# Requirements.txt (simple) handler
# ===================================================================

class TestRequirementsSimple:
    def test_parse_basic(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text(dedent("""\
            flask==2.3.0
            requests==2.31.0
            urllib3==2.0.4
        """))
        handler = RequirementsSimpleHandler()
        result = handler.parse(req)
        assert result == {
            "flask": "2.3.0",
            "requests": "2.31.0",
            "urllib3": "2.0.4",
        }

    def test_parse_skips_comments_and_blanks(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text(dedent("""\
            # This is a comment
            flask==2.3.0

            # Another comment
            requests==2.31.0
        """))
        handler = RequirementsSimpleHandler()
        result = handler.parse(req)
        assert len(result) == 2

    def test_parse_skips_flags(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text(dedent("""\
            --index-url https://pypi.org/simple
            flask==2.3.0
            -e git+https://example.com#egg=foo
        """))
        handler = RequirementsSimpleHandler()
        result = handler.parse(req)
        assert result == {"flask": "2.3.0"}

    def test_parse_normalises_names(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("My_Package==1.0.0\nzope.interface==5.0\n")
        handler = RequirementsSimpleHandler()
        result = handler.parse(req)
        assert "my-package" in result
        assert "zope-interface" in result

    def test_write_sorted(self, tmp_path: Path) -> None:
        out = tmp_path / "requirements.txt"
        handler = RequirementsSimpleHandler()
        handler.write({"zlib": "1.0.0", "aiohttp": "3.9.0", "flask": "2.3.0"}, out)
        lines = out.read_text().strip().split("\n")
        assert lines == ["aiohttp==3.9.0", "flask==2.3.0", "zlib==1.0.0"]

    def test_is_pinned(self) -> None:
        assert RequirementsSimpleHandler().is_pinned is True


# ===================================================================
# Requirements.txt (hashed) handler
# ===================================================================

class TestRequirementsHashed:
    def test_parse_hashed_format(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text(dedent("""\
            certifi==2024.2.2 \\
                --hash=sha256:abc123 \\
                --hash=sha256:def456
                # via requests
            flask==2.3.0 \\
                --hash=sha256:aaa111
        """))
        handler = RequirementsHashedHandler()
        result = handler.parse(req)
        assert result == {"certifi": "2024.2.2", "flask": "2.3.0"}

    def test_is_pinned(self) -> None:
        assert RequirementsHashedHandler().is_pinned is True

    def test_write_fails_closed_when_hash_generation_fails(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        handler = RequirementsHashedHandler()
        mock_result = MagicMock(returncode=2, stderr="compile failed", stdout="")
        with patch("depfresh.uv.run", return_value=mock_result):
            with pytest.raises(CommandError):
                handler.write({"flask": "2.3.0"}, req, uv="/usr/bin/uv", python_version="3.11")


# ===================================================================
# Requirements.in handler
# ===================================================================

class TestRequirementsIn:
    def test_parse_pinned(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.in"
        req.write_text("flask==2.3.0\nrequests==2.31.0\n")
        handler = RequirementsInHandler()
        result = handler.parse(req)
        assert result == {"flask": "2.3.0", "requests": "2.31.0"}

    def test_parse_unpinned_gte(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.in"
        req.write_text("flask>=2.0\nrequests>=2.28\n")
        handler = RequirementsInHandler()
        result = handler.parse(req)
        assert result == {"flask": "2.0", "requests": "2.28"}

    def test_parse_bare_names(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.in"
        req.write_text("flask\nrequests\n")
        handler = RequirementsInHandler()
        result = handler.parse(req)
        assert result == {"flask": "*", "requests": "*"}

    def test_parse_extras(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.in"
        req.write_text("flask[async]>=2.3\n")
        handler = RequirementsInHandler()
        result = handler.parse(req)
        assert result == {"flask": "2.3"}

    def test_parse_tilde_equals(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.in"
        req.write_text("flask~=2.3.0\n")
        handler = RequirementsInHandler()
        result = handler.parse(req)
        assert result == {"flask": "2.3.0"}

    def test_parse_comments_and_blanks(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.in"
        req.write_text(dedent("""\
            # Core deps
            flask>=2.0

            # HTTP
            requests
        """))
        handler = RequirementsInHandler()
        result = handler.parse(req)
        assert len(result) == 2

    def test_parse_skips_includes(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.in"
        req.write_text(dedent("""\
            -r base.txt
            -c constraints.txt
            flask>=2.0
        """))
        handler = RequirementsInHandler()
        result = handler.parse(req)
        assert result == {"flask": "2.0"}

    def test_parse_markers(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.in"
        req.write_text('requests>=2.28 ; python_version>="3.8"\n')
        handler = RequirementsInHandler()
        result = handler.parse(req)
        assert result == {"requests": "2.28"}

    def test_write_updates_versions(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.in"
        req.write_text(dedent("""\
            # Core deps
            flask>=2.0
            requests
        """))
        handler = RequirementsInHandler()
        handler.write({"flask": "2.4.0", "requests": "2.31.0"}, req)
        content = req.read_text()
        assert "# Core deps" in content
        assert "flask>=2.4.0" in content
        assert "requests>=2.31.0" in content

    def test_write_preserves_extras(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.in"
        req.write_text("flask[async]>=2.3\n")
        handler = RequirementsInHandler()
        handler.write({"flask": "2.4.0"}, req)
        content = req.read_text()
        assert "flask[async]>=2.4.0" in content

    def test_write_preserves_markers(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.in"
        req.write_text('requests>=2.28 ; python_version>="3.8"\n')
        handler = RequirementsInHandler()
        handler.write({"requests": "2.31.0"}, req)
        content = req.read_text()
        assert "requests>=2.31.0" in content
        assert "python_version" in content

    def test_write_warns_on_major_bump(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        req = tmp_path / "requirements.in"
        req.write_text("flask>=2.0\n")
        handler = RequirementsInHandler()
        import logging
        with caplog.at_level(logging.WARNING, logger="depfresh"):
            handler.write({"flask": "3.1.0"}, req)
        assert any("major version" in r.message for r in caplog.records)
        assert "2.0" in caplog.text
        assert "3.1.0" in caplog.text

    def test_write_no_warn_same_major(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        req = tmp_path / "requirements.in"
        req.write_text("flask>=2.0\n")
        handler = RequirementsInHandler()
        import logging
        with caplog.at_level(logging.WARNING, logger="depfresh"):
            handler.write({"flask": "2.4.0"}, req)
        assert not any("major version" in r.message for r in caplog.records)

    def test_is_pinned(self) -> None:
        assert RequirementsInHandler().is_pinned is False


# ===================================================================
# pyproject.toml — PEP 621 handler
# ===================================================================

class TestPyprojectPEP621:
    def test_parse_project_dependencies(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [project]
            name = "myapp"
            dependencies = [
                "flask>=2.3.0",
                "requests==2.31.0",
                "urllib3>=2.0,<3.0",
            ]
        """))
        handler = PyprojectPEP621Handler()
        result = handler.parse(pp)
        assert result["flask"] == "2.3.0"
        assert result["requests"] == "2.31.0"
        assert result["urllib3"] == "2.0"

    def test_parse_optional_dependencies(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [project]
            name = "myapp"
            dependencies = ["flask>=2.3.0"]

            [project.optional-dependencies]
            dev = ["pytest>=7.0", "ruff>=0.1.0"]
            docs = ["sphinx>=6.0"]
        """))
        handler = PyprojectPEP621Handler()
        result = handler.parse(pp)
        assert result["flask"] == "2.3.0"
        assert result["pytest"] == "7.0"
        assert result["ruff"] == "0.1.0"
        assert result["sphinx"] == "6.0"

    def test_parse_bare_names(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [project]
            dependencies = ["flask"]
        """))
        handler = PyprojectPEP621Handler()
        result = handler.parse(pp)
        assert result == {"flask": "*"}

    def test_parse_extras(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [project]
            dependencies = ["flask[async]>=2.3.0"]
        """))
        handler = PyprojectPEP621Handler()
        result = handler.parse(pp)
        assert result["flask"] == "2.3.0"

    def test_parse_markers(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [project]
            dependencies = [
                "requests>=2.31.0",
                'colorama>=0.4 ; sys_platform=="win32"',
            ]
        """))
        handler = PyprojectPEP621Handler()
        result = handler.parse(pp)
        assert result["requests"] == "2.31.0"
        assert result["colorama"] == "0.4"

    def test_parse_url_deps_skipped(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [project]
            dependencies = [
                "flask>=2.3.0",
                "mypkg @ https://example.com/mypkg-1.0.tar.gz",
            ]
        """))
        handler = PyprojectPEP621Handler()
        result = handler.parse(pp)
        assert "flask" in result
        assert "mypkg" not in result

    def test_parse_tilde_equals(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [project]
            dependencies = ["flask~=2.3.0"]
        """))
        handler = PyprojectPEP621Handler()
        result = handler.parse(pp)
        assert result["flask"] == "2.3.0"

    def test_parse_no_project_section(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [build-system]
            requires = ["hatchling"]
        """))
        handler = PyprojectPEP621Handler()
        result = handler.parse(pp)
        assert result == {}

    def test_write_updates_versions(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [project]
            name = "myapp"
            dependencies = [
                "flask>=2.3.0",
                "requests==2.31.0",
            ]
        """))
        handler = PyprojectPEP621Handler()
        handler.write({"flask": "2.4.0", "requests": "2.32.0"}, pp)
        content = pp.read_text()
        assert "flask>=2.4.0" in content
        assert "requests==2.32.0" in content
        # Preserves project name
        assert 'name = "myapp"' in content

    def test_write_preserves_extras_and_valid_pep508_order(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [project]
            dependencies = ["flask[async]>=2.3.0"]
        """))
        handler = PyprojectPEP621Handler()
        handler.write({"flask": "2.4.0"}, pp)
        content = pp.read_text()
        assert "flask[async]>=2.4.0" in content

    def test_write_preserves_upper_bounds(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [project]
            dependencies = ["urllib3>=2.0,<3.0"]
        """))
        handler = PyprojectPEP621Handler()
        handler.write({"urllib3": "2.1.0"}, pp)
        content = pp.read_text()
        assert "urllib3" in content
        assert ">=2.1.0" in content
        assert "<3.0" in content

    def test_write_preserves_other_toml(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [build-system]
            requires = ["hatchling"]
            build-backend = "hatchling.build"

            [project]
            name = "myapp"
            dependencies = ["flask>=2.3.0"]

            [tool.ruff]
            line-length = 100
        """))
        handler = PyprojectPEP621Handler()
        handler.write({"flask": "2.4.0"}, pp)
        content = pp.read_text()
        assert "flask>=2.4.0" in content
        assert "hatchling" in content
        assert "line-length = 100" in content

    def test_write_updates_optional_deps(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [project]
            dependencies = ["flask>=2.3.0"]

            [project.optional-dependencies]
            dev = ["pytest>=7.0"]
        """))
        handler = PyprojectPEP621Handler()
        handler.write({"flask": "2.4.0", "pytest": "8.0.0"}, pp)
        content = pp.read_text()
        assert "flask>=2.4.0" in content
        assert "pytest>=8.0.0" in content

    def test_write_runtime_scope_leaves_optional_deps_unchanged(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [project]
            dependencies = ["flask>=2.3.0"]

            [project.optional-dependencies]
            dev = ["pytest>=7.0"]
        """))
        handler = PyprojectPEP621Handler()
        handler.write(
            {"flask": "2.4.0", "pytest": "8.0.0"},
            pp,
            dependency_scope="runtime",
        )
        content = pp.read_text()
        assert "flask>=2.4.0" in content
        assert "pytest>=7.0" in content

    def test_is_pinned(self) -> None:
        assert PyprojectPEP621Handler().is_pinned is False


# ===================================================================
# pyproject.toml — Poetry handler
# ===================================================================

class TestPyprojectPoetry:
    def test_parse_simple_caret(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [tool.poetry.dependencies]
            python = "^3.10"
            flask = "^2.3.0"
            requests = "^2.31.0"
        """))
        handler = PyprojectPoetryHandler()
        result = handler.parse(pp)
        assert result == {"flask": "2.3.0", "requests": "2.31.0"}
        assert "python" not in result

    def test_parse_tilde(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [tool.poetry.dependencies]
            flask = "~2.3"
        """))
        handler = PyprojectPoetryHandler()
        result = handler.parse(pp)
        assert result == {"flask": "2.3"}

    def test_parse_exact(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [tool.poetry.dependencies]
            flask = "2.3.0"
        """))
        handler = PyprojectPoetryHandler()
        result = handler.parse(pp)
        assert result == {"flask": "2.3.0"}

    def test_parse_star(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [tool.poetry.dependencies]
            flask = "*"
        """))
        handler = PyprojectPoetryHandler()
        result = handler.parse(pp)
        assert result == {"flask": "*"}

    def test_parse_table_form(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [tool.poetry.dependencies]
            flask = {version = "^2.3.0", optional = true}
        """))
        handler = PyprojectPoetryHandler()
        result = handler.parse(pp)
        assert result == {"flask": "2.3.0"}

    def test_parse_git_dep_skipped(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [tool.poetry.dependencies]
            flask = "^2.3.0"
            mypkg = {git = "https://github.com/org/mypkg.git"}
        """))
        handler = PyprojectPoetryHandler()
        result = handler.parse(pp)
        assert "flask" in result
        assert "mypkg" not in result

    def test_parse_path_dep_skipped(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [tool.poetry.dependencies]
            flask = "^2.3.0"
            local-pkg = {path = "../local-pkg"}
        """))
        handler = PyprojectPoetryHandler()
        result = handler.parse(pp)
        assert "flask" in result
        assert "local-pkg" not in result

    def test_parse_groups(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [tool.poetry.dependencies]
            flask = "^2.3.0"

            [tool.poetry.group.dev.dependencies]
            pytest = "^7.0"
            ruff = "^0.1.0"

            [tool.poetry.group.docs.dependencies]
            sphinx = "^6.0"
        """))
        handler = PyprojectPoetryHandler()
        result = handler.parse(pp)
        assert result["flask"] == "2.3.0"
        assert result["pytest"] == "7.0"
        assert result["ruff"] == "0.1.0"
        assert result["sphinx"] == "6.0"

    def test_parse_range_specifier(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [tool.poetry.dependencies]
            flask = ">=2.3,<3.0"
        """))
        handler = PyprojectPoetryHandler()
        result = handler.parse(pp)
        assert result == {"flask": "2.3"}

    def test_parse_normalises_names(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [tool.poetry.dependencies]
            My_Package = "^1.0.0"
        """))
        handler = PyprojectPoetryHandler()
        result = handler.parse(pp)
        assert "my-package" in result

    def test_write_preserves_caret(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [tool.poetry.dependencies]
            python = "^3.10"
            flask = "^2.3.0"
        """))
        handler = PyprojectPoetryHandler()
        handler.write({"flask": "2.4.0"}, pp)
        content = pp.read_text()
        assert 'flask = "^2.4.0"' in content
        # Python constraint untouched
        assert 'python = "^3.10"' in content

    def test_write_preserves_tilde(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [tool.poetry.dependencies]
            flask = "~2.3"
        """))
        handler = PyprojectPoetryHandler()
        handler.write({"flask": "2.4.0"}, pp)
        content = pp.read_text()
        assert 'flask = "~2.4.0"' in content

    def test_write_preserves_table_form(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [tool.poetry.dependencies]
            flask = {version = "^2.3.0", optional = true}
        """))
        handler = PyprojectPoetryHandler()
        handler.write({"flask": "2.4.0"}, pp)
        content = pp.read_text()
        assert "2.4.0" in content
        assert "optional" in content

    def test_write_preserves_star(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [tool.poetry.dependencies]
            flask = "*"
        """))
        handler = PyprojectPoetryHandler()
        handler.write({"flask": "2.4.0"}, pp)
        content = pp.read_text()
        assert 'flask = "*"' in content

    def test_write_updates_groups(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [tool.poetry.dependencies]
            flask = "^2.3.0"

            [tool.poetry.group.dev.dependencies]
            pytest = "^7.0"
        """))
        handler = PyprojectPoetryHandler()
        handler.write({"flask": "2.4.0", "pytest": "8.0.0"}, pp)
        content = pp.read_text()
        assert 'flask = "^2.4.0"' in content
        assert 'pytest = "^8.0.0"' in content

    def test_write_runtime_scope_leaves_poetry_groups_unchanged(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [tool.poetry.dependencies]
            flask = "^2.3.0"

            [tool.poetry.group.dev.dependencies]
            pytest = "^7.0"
        """))
        handler = PyprojectPoetryHandler()
        handler.write(
            {"flask": "2.4.0", "pytest": "8.0.0"},
            pp,
            dependency_scope="runtime",
        )
        content = pp.read_text()
        assert 'flask = "^2.4.0"' in content
        assert 'pytest = "^7.0"' in content

    def test_write_bare_version(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [tool.poetry.dependencies]
            flask = "2.3.0"
        """))
        handler = PyprojectPoetryHandler()
        handler.write({"flask": "2.4.0"}, pp)
        content = pp.read_text()
        assert 'flask = "2.4.0"' in content

    def test_is_pinned(self) -> None:
        assert PyprojectPoetryHandler().is_pinned is False


# ===================================================================
# Pipfile handler
# ===================================================================

class TestPipfile:
    def test_parse_star(self, tmp_path: Path) -> None:
        pf = tmp_path / "Pipfile"
        pf.write_text(dedent("""\
            [packages]
            flask = "*"
            requests = "*"
        """))
        handler = PipfileHandler()
        result = handler.parse(pf)
        assert result == {"flask": "*", "requests": "*"}

    def test_parse_pinned(self, tmp_path: Path) -> None:
        pf = tmp_path / "Pipfile"
        pf.write_text(dedent("""\
            [packages]
            flask = "==2.3.0"
            requests = "==2.31.0"
        """))
        handler = PipfileHandler()
        result = handler.parse(pf)
        assert result == {"flask": "2.3.0", "requests": "2.31.0"}

    def test_parse_range(self, tmp_path: Path) -> None:
        pf = tmp_path / "Pipfile"
        pf.write_text(dedent("""\
            [packages]
            flask = ">=2.3"
        """))
        handler = PipfileHandler()
        result = handler.parse(pf)
        assert result == {"flask": "2.3"}

    def test_parse_table_form(self, tmp_path: Path) -> None:
        pf = tmp_path / "Pipfile"
        pf.write_text(dedent("""\
            [packages]
            flask = {version = "==2.3.0", extras = ["security"]}
        """))
        handler = PipfileHandler()
        result = handler.parse(pf)
        assert result == {"flask": "2.3.0"}

    def test_parse_dev_packages(self, tmp_path: Path) -> None:
        pf = tmp_path / "Pipfile"
        pf.write_text(dedent("""\
            [packages]
            flask = "==2.3.0"

            [dev-packages]
            pytest = "==7.4.0"
            ruff = ">=0.1.0"
        """))
        handler = PipfileHandler()
        result = handler.parse(pf)
        assert result["flask"] == "2.3.0"
        assert result["pytest"] == "7.4.0"
        assert result["ruff"] == "0.1.0"

    def test_parse_skips_requires(self, tmp_path: Path) -> None:
        pf = tmp_path / "Pipfile"
        pf.write_text(dedent("""\
            [requires]
            python_version = "3.11"

            [packages]
            flask = "==2.3.0"
        """))
        handler = PipfileHandler()
        result = handler.parse(pf)
        assert result == {"flask": "2.3.0"}
        assert "python-version" not in result

    def test_parse_git_dep_skipped(self, tmp_path: Path) -> None:
        pf = tmp_path / "Pipfile"
        pf.write_text(dedent("""\
            [packages]
            flask = "==2.3.0"
            mypkg = {git = "https://github.com/org/mypkg.git", ref = "main"}
        """))
        handler = PipfileHandler()
        result = handler.parse(pf)
        assert "flask" in result
        assert "mypkg" not in result

    def test_parse_normalises_names(self, tmp_path: Path) -> None:
        pf = tmp_path / "Pipfile"
        pf.write_text(dedent("""\
            [packages]
            My_Package = "==1.0.0"
        """))
        handler = PipfileHandler()
        result = handler.parse(pf)
        assert "my-package" in result

    def test_write_updates_pinned(self, tmp_path: Path) -> None:
        pf = tmp_path / "Pipfile"
        pf.write_text(dedent("""\
            [packages]
            flask = "==2.3.0"
            requests = "==2.31.0"
        """))
        handler = PipfileHandler()
        handler.write({"flask": "2.4.0", "requests": "2.32.0"}, pf)
        content = pf.read_text()
        assert '"==2.4.0"' in content
        assert '"==2.32.0"' in content

    def test_write_updates_range(self, tmp_path: Path) -> None:
        pf = tmp_path / "Pipfile"
        pf.write_text(dedent("""\
            [packages]
            flask = ">=2.3,<3.0"
        """))
        handler = PipfileHandler()
        handler.write({"flask": "2.4.0"}, pf)
        content = pf.read_text()
        assert '">=2.4.0,<3.0"' in content

    def test_write_preserves_star(self, tmp_path: Path) -> None:
        pf = tmp_path / "Pipfile"
        pf.write_text(dedent("""\
            [packages]
            flask = "*"
        """))
        handler = PipfileHandler()
        handler.write({"flask": "2.4.0"}, pf)
        content = pf.read_text()
        assert '"*"' in content

    def test_write_updates_table_form(self, tmp_path: Path) -> None:
        pf = tmp_path / "Pipfile"
        pf.write_text(dedent("""\
            [packages]
            flask = {version = "==2.3.0", extras = ["security"]}
        """))
        handler = PipfileHandler()
        handler.write({"flask": "2.4.0"}, pf)
        content = pf.read_text()
        assert "2.4.0" in content
        assert "security" in content

    def test_write_preserves_dev_packages(self, tmp_path: Path) -> None:
        pf = tmp_path / "Pipfile"
        pf.write_text(dedent("""\
            [packages]
            flask = "==2.3.0"

            [dev-packages]
            pytest = "==7.4.0"
        """))
        handler = PipfileHandler()
        handler.write({"flask": "2.4.0", "pytest": "8.0.0"}, pf)
        content = pf.read_text()
        assert '"==2.4.0"' in content
        assert '"==8.0.0"' in content

    def test_write_runtime_scope_leaves_dev_packages_unchanged(self, tmp_path: Path) -> None:
        pf = tmp_path / "Pipfile"
        pf.write_text(dedent("""\
            [packages]
            flask = "==2.3.0"

            [dev-packages]
            pytest = "==7.4.0"
        """))
        handler = PipfileHandler()
        handler.write(
            {"flask": "2.4.0", "pytest": "8.0.0"},
            pf,
            dependency_scope="runtime",
        )
        content = pf.read_text()
        assert '"==2.4.0"' in content
        assert '"==7.4.0"' in content

    def test_is_pinned(self) -> None:
        assert PipfileHandler().is_pinned is False


# ===================================================================
# Roundtrip tests — parse then write produces valid output
# ===================================================================

class TestRoundtrip:
    def test_requirements_simple_roundtrip(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.3.0\nrequests==2.31.0\n")
        handler = RequirementsSimpleHandler()
        pkgs = handler.parse(req)
        handler.write(pkgs, req)
        result = handler.parse(req)
        assert result == pkgs

    def test_pyproject_pep621_roundtrip(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [project]
            name = "myapp"
            dependencies = [
                "flask>=2.3.0",
                "requests>=2.31.0",
            ]
        """))
        handler = PyprojectPEP621Handler()
        pkgs = handler.parse(pp)
        handler.write(pkgs, pp)
        result = handler.parse(pp)
        assert result == pkgs

    def test_pyproject_poetry_roundtrip(self, tmp_path: Path) -> None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(dedent("""\
            [tool.poetry.dependencies]
            python = "^3.10"
            flask = "^2.3.0"
            requests = "^2.31.0"
        """))
        handler = PyprojectPoetryHandler()
        pkgs = handler.parse(pp)
        handler.write(pkgs, pp)
        result = handler.parse(pp)
        assert result == pkgs

    def test_pipfile_roundtrip(self, tmp_path: Path) -> None:
        pf = tmp_path / "Pipfile"
        pf.write_text(dedent("""\
            [packages]
            flask = "==2.3.0"
            requests = "==2.31.0"
        """))
        handler = PipfileHandler()
        pkgs = handler.parse(pf)
        handler.write(pkgs, pf)
        result = handler.parse(pf)
        assert result == pkgs


# ===================================================================
# Backslash line continuation
# ===================================================================


class TestLineContinuation:
    def test_single_continuation(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("very-long-pkg>=1.0,\\\n    <2.0\n")
        handler = RequirementsSimpleHandler()
        result = handler.parse(req)
        assert "very-long-pkg" in result
        assert result["very-long-pkg"] == "1.0"

    def test_multiple_consecutive_continuations(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text(
            "multi-line-pkg>=1.0,\\\n"
            "    !=1.2.0,\\\n"
            "    <2.0\n"
        )
        handler = RequirementsSimpleHandler()
        result = handler.parse(req)
        assert "multi-line-pkg" in result
        assert result["multi-line-pkg"] == "1.0"

    def test_continuation_at_end_of_file_no_newline(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("trailing-pkg>=3.0,\\\n    <4.0")
        handler = RequirementsSimpleHandler()
        result = handler.parse(req)
        assert "trailing-pkg" in result
        assert result["trailing-pkg"] == "3.0"

    def test_merge_continuation_lines_directly(self) -> None:
        raw = ["very-long-pkg>=1.0,\\", "    <2.0"]
        merged = _merge_continuation_lines(raw)
        assert len(merged) == 1
        assert merged[0] == "very-long-pkg>=1.0, <2.0"


# ===================================================================
# Pip directive warnings
# ===================================================================


class TestPipDirectiveWarnings:
    def test_dash_r_warns(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("-r other.txt\nflask==2.3.0\n")
        handler = RequirementsSimpleHandler()
        with caplog.at_level(logging.WARNING, logger="depfresh"):
            result = handler.parse(req)
        assert any("-r" in rec.message for rec in caplog.records)
        assert "flask" in result

    def test_dash_c_warns(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("-c constraints.txt\nflask==2.3.0\n")
        handler = RequirementsSimpleHandler()
        with caplog.at_level(logging.WARNING, logger="depfresh"):
            handler.parse(req)
        assert any("-c" in rec.message for rec in caplog.records)

    def test_index_url_warns(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("--index-url https://pypi.example.com/simple\nflask==2.3.0\n")
        handler = RequirementsSimpleHandler()
        with caplog.at_level(logging.WARNING, logger="depfresh"):
            handler.parse(req)
        assert any("--index-url" in rec.message for rec in caplog.records)

    def test_extra_index_url_warns(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("--extra-index-url https://pypi.example.com/simple\nflask==2.3.0\n")
        handler = RequirementsSimpleHandler()
        with caplog.at_level(logging.WARNING, logger="depfresh"):
            handler.parse(req)
        assert any("--extra-index-url" in rec.message for rec in caplog.records)

    def test_editable_does_not_warn(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("-e git+https://github.com/user/repo.git#egg=mypkg\nflask==2.3.0\n")
        handler = RequirementsSimpleHandler()
        with caplog.at_level(logging.WARNING, logger="depfresh"):
            handler.parse(req)
        warning_messages = [rec.message for rec in caplog.records if rec.levelno >= logging.WARNING]
        assert not warning_messages

    def test_directives_dont_prevent_parsing(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text(
            "-r other.txt\n"
            "-c constraints.txt\n"
            "--index-url https://pypi.example.com/simple\n"
            "flask==2.3.0\n"
            "requests==2.31.0\n"
        )
        handler = RequirementsSimpleHandler()
        with caplog.at_level(logging.WARNING, logger="depfresh"):
            result = handler.parse(req)
        assert "flask" in result
        assert "requests" in result
