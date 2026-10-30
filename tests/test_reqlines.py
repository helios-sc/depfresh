"""Tests for reqlines — every requirements line classified, includes followed, fail closed."""

from __future__ import annotations

import sys
from pathlib import Path
from textwrap import dedent
from unittest.mock import MagicMock, patch

import pytest

from depfresh.advisories import TargetEnv
from depfresh.exceptions import DepfreshError, DirectReferenceError
from depfresh.lockmode import check_static_project
from depfresh.parsers import DependencyFormat, RequirementsSimpleHandler
from depfresh.pipmode import PipWorkspace, strip_pyproject_direct_refs
from depfresh.remediation import RemediationOptions
from depfresh.reqlines import (
    IncludeOutsideTargetError,
    classify,
    inspect_tree,
    logical_lines,
    parse_lines,
)
from depfresh.upgrade import audit_only, upgrade

_upgrade_mod = sys.modules["depfresh.upgrade"]
ENV = TargetEnv("3.11")


def _no_uv(*args: object, **kwargs: object) -> str:
    raise AssertionError("uv must not be looked up before the inputs are validated")


class TestClassify:
    @pytest.mark.parametrize(
        ("line", "detail"),
        [
            ("-e .", "editable"),
            ("-e=./pkg", "editable"),
            ("-e\t./pkg", "editable"),
            ("--editable ./pkg", "editable"),
            ("--editable=git+https://example.com/x.git#egg=x", "editable"),
            ("-e git+ssh://git@example.com/acme/x.git#egg=x", "editable"),
            ("git+https://example.com/acme/x.git@v1#egg=x", "VCS"),
            ("git+ssh://git@example.com/acme/x.git", "VCS"),
            ("hg+https://example.com/x", "VCS"),
            ("demo @ https://example.com/demo-1.0.tar.gz", "URL"),
            ("demo @ file:///abs/path", "URL"),
            ("https://example.com/demo-1.0.tar.gz", "URL"),
            ("file:../x", "URL"),
            ("./pkg", "local path"),
            ("../sibling", "local path"),
            ("pkg/", "local path"),
            ("libs/core", "local path"),
            ("libs/common[extra]", "local path"),
            ("src/mypkg", "local path"),
            ("vendor/mypkg-1.0.tar.gz", "local path"),
            ("~/x", "local path"),
            ("/opt/wheels/demo-1.0-py3-none-any.whl", "local path"),
            ("C:\\wheels\\demo", "local path"),
            ("mypkg-1.0.tar.gz", "archive"),
            ("demo-1.0-py3-none-any.whl", "archive"),
            ("demo.zip", "archive"),
            ("-f ./wheels", "local find-links"),
            ("--find-links=/srv/wheels", "local find-links"),
            ("not a requirement at all!", "unparseable"),
        ],
    )
    def test_direct_forms(self, line: str, detail: str) -> None:
        kind, _, got, _ = classify(line)
        assert (kind, got) == ("direct", detail)

    @pytest.mark.parametrize(
        "line",
        [
            "six==1.17.0",
            "Django>=4.2,<5",
            'pywin32==306 ; sys_platform == "win32"',
            "uvicorn[standard]>=0.32",
            "requests==2.32.0 --hash=sha256:abc",
            "zope.interface==5.0",
        ],
    )
    def test_registry_lines(self, line: str) -> None:
        assert classify(line)[0] == "registry"

    @pytest.mark.parametrize(
        ("line", "path", "kind"),
        [
            ("-r base.txt", "base.txt", "requirement"),
            ("-rbase.txt", "base.txt", "requirement"),
            ("--requirement=reqs/base.txt", "reqs/base.txt", "requirement"),
            ("-c constraints.txt", "constraints.txt", "constraint"),
            ("--constraint constraints.txt", "constraints.txt", "constraint"),
        ],
    )
    def test_includes(self, line: str, path: str, kind: str) -> None:
        assert classify(line) == ("include", "", path, kind)

    @pytest.mark.parametrize(
        "line",
        ["--index-url https://pypi.example.com/simple", "-f https://example.com/wheels",
         "--no-binary :all:", "--pre"],
    )
    def test_options(self, line: str) -> None:
        assert classify(line)[0] == "option"


class TestLogicalLines:
    def test_continuations_join(self) -> None:
        text = "requests \\\n    >=2.0\nsix==1.16\n"
        assert list(logical_lines(text)) == [(0, 1, "requests     >=2.0"), (2, 2, "six==1.16")]

    def test_comment_ending_in_backslash_does_not_swallow_the_next_line(self) -> None:
        """pip: a line holding a comment never continues."""
        text = (
            "# windows path C:\\tools\\\nrequests==2.25.0\n"
            "idna==2.10  # see C:\\notes\\\nsix==1\n"
        )
        kinds = [(line.kind, line.code) for line in parse_lines(text)]
        assert kinds == [
            ("comment", ""),
            ("registry", "requests==2.25.0"),
            ("registry", "idna==2.10"),
            ("registry", "six==1"),
        ]


class TestInspectTree:
    @staticmethod
    def _project(tmp_path: Path) -> Path:
        (tmp_path / "requirements").mkdir()
        (tmp_path / "requirements" / "base.txt").write_text("six==1.17.0\n-c constraints.txt\n")
        (tmp_path / "requirements" / "constraints.txt").write_text("idna<4\n")
        (tmp_path / "requirements.txt").write_text("-r requirements/base.txt\nflask==3.0.0\n")
        return tmp_path / "requirements.txt"

    def test_follows_includes_recursively(self, tmp_path: Path) -> None:
        tree = inspect_tree(self._project(tmp_path), tmp_path)
        assert [str(tree.relative(p)) for p in tree.files] == [
            "requirements.txt", "requirements/base.txt", "requirements/constraints.txt",
        ]
        assert tree.registry == {"flask", "six", "idna"}
        assert tree.direct == []

    def test_reports_direct_lines_of_included_files(self, tmp_path: Path) -> None:
        """`-r requirements/base.txt` with `-e .` inside would build the project."""
        manifest = self._project(tmp_path)
        (tmp_path / "requirements" / "base.txt").write_text("six==1.17.0\n-e .\n")
        tree = inspect_tree(manifest, tmp_path)
        assert tree.direct == ["requirements/base.txt: -e . (editable)"]

    def test_include_outside_the_target_is_refused(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        (tmp_path / "shared.txt").write_text("six\n")
        (project / "requirements.txt").write_text("-r ../shared.txt\n")
        with pytest.raises(IncludeOutsideTargetError, match="outside"):
            inspect_tree(project / "requirements.txt", project)

    def test_missing_include_is_refused(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("-r missing.txt\n")
        with pytest.raises(IncludeOutsideTargetError, match="does not exist"):
            inspect_tree(tmp_path / "requirements.txt", tmp_path)

    def test_copy_to_drops_direct_lines_everywhere(self, tmp_path: Path) -> None:
        manifest = self._project(tmp_path)
        (tmp_path / "requirements" / "base.txt").write_text(
            "six==1.17.0\n-e .\ngit+ssh://git@example.com/acme/x.git\nmypkg-1.0.tar.gz\n"
        )
        copy = inspect_tree(manifest, tmp_path).copy_to(tmp_path / "scratch", strip=True)
        assert copy == tmp_path / "scratch" / "requirements.txt"
        assert (tmp_path / "scratch" / "requirements" / "base.txt").read_text() == "six==1.17.0\n"


class TestFailClosedInEveryMode:
    """No uv call may see a local path, archive, VCS or URL line of the target."""

    @staticmethod
    def _project(tmp_path: Path) -> Path:
        (tmp_path / "requirements").mkdir()
        (tmp_path / "requirements" / "base.txt").write_text("six==1.17.0\n-e .\n")
        (tmp_path / "requirements.txt").write_text("-r requirements/base.txt\nflask==3.0.0\n")
        (tmp_path / "setup.py").write_text("raise SystemExit('must never run')\n")
        return tmp_path

    @pytest.mark.parametrize("strategy", ["minimal", "latest"])
    def test_upgrade_refuses_before_uv(self, tmp_path: Path, strategy: str) -> None:
        project = self._project(tmp_path)
        with patch.object(_upgrade_mod, "find_uv", side_effect=_no_uv):
            with pytest.raises(DirectReferenceError, match="requirements/base.txt: -e ."):
                upgrade(project, strategy=strategy, reports_dir=tmp_path / "r")  # type: ignore[arg-type]

    def test_audit_only_refuses_before_uv(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        with patch.object(_upgrade_mod, "find_uv", side_effect=_no_uv):
            with pytest.raises(DirectReferenceError):
                audit_only(project)

    @pytest.mark.parametrize(
        "line",
        ["git+https://example.com/acme/x.git@v1#egg=x", "git+ssh://git@example.com/acme/x.git",
         "mypkg-1.0.tar.gz", "libs/core", "-e=./x"],
    )
    def test_audit_only_refuses_vcs_and_archives(self, tmp_path: Path, line: str) -> None:
        (tmp_path / "requirements.txt").write_text(f"six==1.17.0\n{line}\n")
        with patch.object(_upgrade_mod, "find_uv", side_effect=_no_uv):
            with pytest.raises(DirectReferenceError):
                audit_only(tmp_path)

    def test_ignored_direct_lines_never_reach_uv(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        (project / "requirements.txt").write_text(
            "-r requirements/base.txt\nflask==3.0.0\ngit+ssh://git@example.com/acme/x.git\n"
            "mypkg-1.0.tar.gz\n"
        )
        ws = PipWorkspace("/usr/bin/uv", project, project / "requirements.txt",
                          DependencyFormat.REQUIREMENTS_SIMPLE, tmp_path / "work",
                          RemediationOptions(env=ENV), ignore_direct_references=True)
        candidate = ws.write((project / "requirements.txt").read_text())
        assert candidate.read_text() == "-r requirements/base.txt\nflask==3.0.0\n"
        assert (ws.root / "requirements" / "base.txt").read_text() == "six==1.17.0\n"

    def test_workspace_refuses_without_the_flag(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        with pytest.raises(DirectReferenceError):
            PipWorkspace("/usr/bin/uv", project, project / "requirements.txt",
                         DependencyFormat.REQUIREMENTS_SIMPLE, tmp_path / "work",
                         RemediationOptions(env=ENV), ignore_direct_references=False)

    def test_latest_installs_a_sanitized_copy(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        seen: dict[str, str] = {}

        def capture(uv: str, venv_python: str, req_path: Path) -> None:
            seen["path"] = str(req_path)
            seen["base"] = (req_path.parent / "requirements" / "base.txt").read_text()
            raise RuntimeError("stop")

        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.13.6"),
            patch.object(_upgrade_mod, "create_venv", return_value="/venv/bin/python"),
            patch.object(_upgrade_mod, "install_requirements", side_effect=capture),
        ):
            with pytest.raises(RuntimeError, match="stop"):
                upgrade(project, strategy="latest", ignore_direct_references=True,
                        reports_dir=tmp_path / "r")
        assert not seen["path"].startswith(str(project))
        assert seen["base"] == "six==1.17.0\n"

    def test_parser_inspection_lists_paths_as_direct(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("six==1.17.0\npkg/\n-e=./x\nmypkg-1.0.tar.gz\n")
        inspection = RequirementsSimpleHandler().inspect(req)
        assert [d.name for d in inspection.registry] == ["six"]
        assert [d.raw for d in inspection.direct_references] == ["pkg/", "-e=./x",
                                                                 "mypkg-1.0.tar.gz"]


class TestPyprojectSources:
    PYPROJECT = dedent("""\
        [project]
        name = "demo-api"
        version = "1.0"
        dependencies = ["six", "core-lib", "tool"]

        [tool.uv.sources]
        core-lib = { path = "libs/core" }
        tool = { git = "https://example.com/acme/tool.git" }
    """)

    def test_path_and_vcs_sources_fail_closed(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(self.PYPROJECT)
        with patch.object(_upgrade_mod, "find_uv", side_effect=_no_uv):
            with pytest.raises(DirectReferenceError, match=r"core-lib \(\[tool.uv.sources\]"):
                upgrade(tmp_path, reports_dir=tmp_path / "r")

    def test_ignored_sources_are_dropped_from_candidates(self) -> None:
        if sys.version_info >= (3, 11):
            import tomllib
        else:
            import tomli as tomllib
        data = tomllib.loads(strip_pyproject_direct_refs(self.PYPROJECT))
        assert data["project"]["dependencies"] == ["six"]

    def test_latest_refuses_any_source(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(self.PYPROJECT)
        with patch.object(_upgrade_mod, "find_uv", side_effect=_no_uv):
            with pytest.raises(DepfreshError, match="minimal strategy"):
                upgrade(tmp_path, strategy="latest", ignore_direct_references=True,
                        reports_dir=tmp_path / "r")


class TestStaticLockProject:
    @staticmethod
    def _pyproject(directory: Path, body: str) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "pyproject.toml").write_text(body)

    def test_static_project_with_static_path_dependency(self, tmp_path: Path) -> None:
        self._pyproject(tmp_path, dedent("""\
            [project]
            name = "demo-api"
            version = "1.0"
            dependencies = ["core-lib"]
            [tool.uv.sources]
            core-lib = { path = "libs/core" }
        """))
        self._pyproject(tmp_path / "libs" / "core",
                        '[project]\nname = "core-lib"\nversion = "0.1"\ndependencies = []\n')
        check_static_project(tmp_path)

    def test_dynamic_version_is_refused(self, tmp_path: Path) -> None:
        """uv lock builds the project to learn a dynamic version, even with package = false."""
        self._pyproject(tmp_path, '[project]\nname = "x"\ndynamic = ["version"]\n'
                                  'dependencies = []\n[tool.uv]\npackage = false\n')
        with pytest.raises(DepfreshError, match="version are dynamic"):
            check_static_project(tmp_path)

    def test_setup_py_only_path_dependency_is_refused(self, tmp_path: Path) -> None:
        self._pyproject(tmp_path, '[project]\nname = "x"\nversion = "1"\ndependencies = ["lib"]\n'
                                  '[tool.uv.sources]\nlib = { path = "lib" }\n')
        (tmp_path / "lib").mkdir()
        (tmp_path / "lib" / "setup.py").write_text("raise SystemExit\n")
        with pytest.raises(DepfreshError, match="no pyproject.toml"):
            check_static_project(tmp_path)

    def test_dynamic_workspace_member_is_refused(self, tmp_path: Path) -> None:
        self._pyproject(tmp_path, '[project]\nname = "root"\nversion = "1"\ndependencies = []\n'
                                  '[tool.uv.workspace]\nmembers = ["packages/*"]\n')
        self._pyproject(tmp_path / "packages" / "a",
                        '[project]\nname = "a"\nversion = "1"\ndynamic = ["dependencies"]\n')
        with pytest.raises(DepfreshError, match="dependencies are dynamic"):
            check_static_project(tmp_path)

    def test_wheel_path_dependency_is_fine(self, tmp_path: Path) -> None:
        self._pyproject(tmp_path, '[project]\nname = "x"\nversion = "1"\ndependencies = ["w"]\n'
                                  '[tool.uv.sources]\n'
                                  'w = { path = "wheels/w-1.0-py3-none-any.whl" }\n')
        (tmp_path / "wheels").mkdir()
        (tmp_path / "wheels" / "w-1.0-py3-none-any.whl").write_bytes(b"")
        check_static_project(tmp_path)

    def test_upgrade_refuses_before_uv(self, tmp_path: Path) -> None:
        self._pyproject(tmp_path, '[project]\nname = "x"\ndynamic = ["version"]\n'
                                  'dependencies = ["six"]\n')
        (tmp_path / "uv.lock").write_text("version = 1\n")
        with patch.object(_upgrade_mod, "find_uv", side_effect=_no_uv):
            with pytest.raises(DepfreshError, match="never executes repository code"):
                upgrade(tmp_path, reports_dir=tmp_path / "r")


def test_mocked_compile_never_sees_direct_lines(tmp_path: Path) -> None:
    """The uv command line only ever names scratch copies."""
    (tmp_path / "requirements.txt").write_text("six==1.17.0\n")
    ws = PipWorkspace("/usr/bin/uv", tmp_path, tmp_path / "requirements.txt",
                      DependencyFormat.REQUIREMENTS_SIMPLE, tmp_path / "work",
                      RemediationOptions(env=ENV), ignore_direct_references=False)
    result = MagicMock(stdout="six==1.17.0  # via -r requirements.txt\n", stderr="")
    with patch("depfresh.pipmode.run", return_value=result) as mock:
        ws.compile(ws.write("six==1.17.0\n"))
    manifest_arg = Path(mock.call_args.args[0][3])
    assert manifest_arg.is_relative_to(tmp_path / "work")
