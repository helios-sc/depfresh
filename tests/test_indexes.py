"""Tests for private-index handling and never executing repository code."""

from __future__ import annotations

import sys
from pathlib import Path
from textwrap import dedent
from unittest.mock import patch

import pytest

from depfresh.cli import main
from depfresh.exceptions import DirectReferenceError
from depfresh.indexes import (
    PrivateSourceError,
    check_requirements_against_sources,
    foreign_sources,
    uv_source_indexes,
)
from depfresh.parsers import (
    DependencyFormat,
    RequirementsSimpleHandler,
    SetupPyError,
    SetupPyHandler,
    detect_format,
    read_setup_py,
)
from depfresh.upgrade import audit_only, upgrade

_upgrade_mod = sys.modules["depfresh.upgrade"]

PRIVATE = "https://us-east1-python.pkg.dev/acme/python/simple/"
PRIVATE_PYPROJECT = dedent(f"""\
    [project]
    name = "demo-api"
    version = "0.1.0"
    dependencies = ["fastapi>=0.115", "private-widget==0.1.0"]

    [[tool.uv.index]]
    name = "internal"
    url = "{PRIVATE}"
    explicit = true

    [tool.uv.sources]
    private-widget = {{ index = "internal" }}

    [tool.uv]
    package = false
""")


def _no_uv(*args: object, **kwargs: object) -> str:
    raise AssertionError("uv must not be looked up before the inputs are validated")


class TestUvSourceIndexes:
    def test_maps_packages_to_their_private_index(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(PRIVATE_PYPROJECT)
        assert uv_source_indexes(tmp_path / "pyproject.toml") == {"private-widget": PRIVATE}

    def test_ignores_git_and_path_sources(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(dedent("""\
            [project]
            name = "x"
            dependencies = []
            [tool.uv.sources]
            a = { git = "https://example.com/a.git" }
            b = { path = "libs/b" }
        """))
        assert uv_source_indexes(tmp_path / "pyproject.toml") == {}

    def test_missing_file(self, tmp_path: Path) -> None:
        assert uv_source_indexes(tmp_path / "pyproject.toml") == {}


class TestRequirementsAgainstSources:
    def test_private_package_in_a_requirements_file_is_refused(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(PRIVATE_PYPROJECT)
        with pytest.raises(PrivateSourceError, match="dependency confusion"):
            check_requirements_against_sources(
                {"private-widget", "six"}, tmp_path, "requirements.txt",
            )

    def test_unrelated_requirements_pass(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(PRIVATE_PYPROJECT)
        check_requirements_against_sources({"six"}, tmp_path, "requirements.txt")

    def test_upgrade_refuses_before_any_lookup(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(PRIVATE_PYPROJECT)
        (tmp_path / "requirements.txt").write_text("fastapi==0.129.0\nprivate-widget==0.1.0\n")
        with patch.object(_upgrade_mod, "find_uv", side_effect=_no_uv):
            with pytest.raises(PrivateSourceError):
                upgrade(tmp_path, dep_file="requirements.txt", reports_dir=tmp_path / "r")
            with pytest.raises(PrivateSourceError):
                audit_only(tmp_path, dep_file="requirements.txt")


class TestLatestStrategySources:
    def test_pyproject_with_private_index_is_refused(self, tmp_path: Path) -> None:
        """The synthesized install file of --strategy latest cannot honour uv.sources."""
        (tmp_path / "pyproject.toml").write_text(PRIVATE_PYPROJECT)
        with patch.object(_upgrade_mod, "find_uv", side_effect=_no_uv):
            with pytest.raises(PrivateSourceError, match="minimal strategy"):
                upgrade(tmp_path, strategy="latest", reports_dir=tmp_path / "r")

    def test_poetry_private_source(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(dedent("""\
            [tool.poetry.dependencies]
            python = "^3.11"
            internal = "^1.0"

            [[tool.poetry.source]]
            name = "corp"
            url = "https://pypi.corp.example/simple"
        """))
        assert foreign_sources(tmp_path / "pyproject.toml") == ["https://pypi.corp.example/simple"]
        with patch.object(_upgrade_mod, "find_uv", side_effect=_no_uv):
            with pytest.raises(PrivateSourceError):
                upgrade(tmp_path, strategy="latest", reports_dir=tmp_path / "r")

    def test_pipfile_pypi_source_is_fine(self, tmp_path: Path) -> None:
        (tmp_path / "Pipfile").write_text(
            '[[source]]\nurl = "https://pypi.org/simple"\nname = "pypi"\n\n[packages]\nsix = "*"\n'
        )
        assert foreign_sources(tmp_path / "Pipfile") == []


class TestSetupPyIsNeverExecuted:
    MARKER_SCRIPT = "open({marker!r}, 'w').write('executed')\n"

    def _write(self, tmp_path: Path, body: str) -> tuple[Path, Path]:
        marker = tmp_path / "executed.marker"
        path = tmp_path / "setup.py"
        path.write_text(self.MARKER_SCRIPT.format(marker=str(marker)) + body)
        return path, marker

    def test_literal_install_requires(self, tmp_path: Path) -> None:
        path, marker = self._write(tmp_path, dedent("""\
            from setuptools import setup
            REQUIRES = ["requests>=2.31", "idna==3.6"]
            setup(name="demo", install_requires=REQUIRES,
                  extras_require={"gcs": ["google-cloud-storage>=2.0"]})
        """))
        install, extras = read_setup_py(path)
        assert install == ["requests>=2.31", "idna==3.6"]
        assert extras == {"gcs": ["google-cloud-storage>=2.0"]}
        inspection = SetupPyHandler().inspect(path)
        assert [d.name for d in inspection.registry] == [
            "requests", "idna", "google-cloud-storage",
        ]
        assert inspection.registry[2].is_runtime is False
        assert not marker.exists()

    def test_a_script_without_setup_call_is_refused(self, tmp_path: Path) -> None:
        """A setup.py that pip-installs packages when it runs."""
        path, marker = self._write(tmp_path, dedent("""\
            import subprocess, sys
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'numpy'])
        """))
        with pytest.raises(SetupPyError, match="never executes setup.py"):
            read_setup_py(path)
        assert not marker.exists()

    def test_computed_requirements_are_refused(self, tmp_path: Path) -> None:
        path, _ = self._write(tmp_path, dedent("""\
            from setuptools import setup
            setup(install_requires=open("requirements.txt").read().split())
        """))
        with pytest.raises(SetupPyError, match="computed"):
            read_setup_py(path)

    def test_kwargs_are_refused(self, tmp_path: Path) -> None:
        path, _ = self._write(tmp_path, "from setuptools import setup\nsetup(**CONFIG)\n")
        with pytest.raises(SetupPyError):
            read_setup_py(path)

    def test_detection_and_no_write_back(self, tmp_path: Path) -> None:
        path, _ = self._write(tmp_path, "from setuptools import setup\nsetup()\n")
        assert detect_format(path) == DependencyFormat.SETUP_PY
        with pytest.raises(SetupPyError, match="does not edit setup.py"):
            SetupPyHandler().write({"idna": "3.15"}, path)

    def test_setup_cfg_is_refused(self, tmp_path: Path) -> None:
        cfg = tmp_path / "setup.cfg"
        cfg.write_text("[options]\ninstall_requires = requests\n")
        with pytest.raises(ValueError, match="setup.cfg"):
            detect_format(cfg)

    def test_cli_refuses_the_script_without_running_it(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str],
    ) -> None:
        path, marker = self._write(tmp_path, "import os\nos.system('echo hi')\n")
        with patch.object(_upgrade_mod, "find_uv", side_effect=_no_uv):
            with pytest.raises(SystemExit) as exc_info:
                main([str(tmp_path), "--dep-file", "setup.py"])
        assert exc_info.value.code == 1
        assert "never executes setup.py" in capsys.readouterr().err
        assert not marker.exists()

    def test_uv_only_sees_the_static_requirements(self, tmp_path: Path) -> None:
        path, marker = self._write(tmp_path, dedent("""\
            from setuptools import setup
            setup(install_requires=["idna==3.6"])
        """))
        seen: dict[str, object] = {}

        def fake_remediate(**kwargs: object) -> object:
            manifest = kwargs["manifest"]
            assert isinstance(manifest, Path)
            seen["name"] = manifest.name
            seen["text"] = manifest.read_text()
            seen["fmt"] = kwargs["fmt"]
            raise RuntimeError("stop here")

        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.13.6"),
            patch.object(_upgrade_mod, "install_pip_audit", return_value=("/t/python", "2.10.1")),
            patch.object(_upgrade_mod, "remediate_pip", side_effect=fake_remediate),
        ):
            with pytest.raises(RuntimeError, match="stop here"):
                upgrade(tmp_path, dep_file="setup.py", reports_dir=tmp_path / "r")
        assert seen == {
            "name": "setup.py.requirements.in", "text": "idna==3.6\n",
            "fmt": DependencyFormat.REQUIREMENTS_IN,
        }
        assert not marker.exists()


class TestLocalPathRequirements:
    @pytest.mark.parametrize(
        "line",
        ["./libs/shared", "/opt/wheels/demo-1.0-py3-none-any.whl",
         "https://example.com/demo-1.0.tar.gz", "file:///srv/demo", "../sibling"],
    )
    def test_paths_and_urls_are_direct_references(self, tmp_path: Path, line: str) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text(f"six==1.17.0\n{line}\n")
        inspection = RequirementsSimpleHandler().inspect(req)
        assert [d.name for d in inspection.registry] == ["six"]
        assert [d.raw for d in inspection.direct_references] == [line]

    def test_upgrade_fails_closed_instead_of_building_them(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("six==1.17.0\n./libs/shared\n")
        with patch.object(_upgrade_mod, "find_uv", side_effect=_no_uv):
            with pytest.raises(DirectReferenceError):
                upgrade(tmp_path, reports_dir=tmp_path / "r")
            with pytest.raises(DirectReferenceError):
                upgrade(tmp_path, strategy="latest", reports_dir=tmp_path / "r")
