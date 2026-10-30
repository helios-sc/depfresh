"""Tests for lockmode — lock-aware audit and remediation of uv projects."""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from textwrap import dedent
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from depfresh.advisories import Release, TargetEnv
from depfresh.exceptions import CommandError, DepfreshError, PrivateIndexError
from depfresh.indexes import PrivateScope
from depfresh.lockmode import (
    LockOutcome,
    LockProject,
    _raise_if_index_unreachable,
    admit_in_pyproject,
    blocking_constraint,
    group_args,
    is_pypi_index,
    lock_version_changes,
    read_lock,
    remediate_lock,
    shipped_set,
)
from depfresh.models import ImportCheck, UpgradeResult, Vulnerability
from depfresh.remediation import RemediationOptions
from depfresh.upgrade import upgrade
from tests.helpers import MixedAuditor, MixedSources, TwoSourceAuditor, TwoSourceSources

_upgrade_mod = sys.modules["depfresh.upgrade"]

PYPI = "https://pypi.org/simple"
PRIVATE = "https://us-east1-python.pkg.dev/acme/python/simple/"


def _lock_text(packages: dict[str, str], sources: dict[str, dict[str, str]] | None = None,
               revision: int = 3) -> str:
    sources = sources or {}
    out = [f"version = 1\nrevision = {revision}\nrequires-python = \">=3.11\"\n"]
    for name, version in sorted(packages.items()):
        source = sources.get(name, {"registry": PYPI})
        key, value = next(iter(source.items()))
        out.append(
            f'\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
            f'source = {{ {key} = "{value}" }}\n'
        )
    return "".join(out)


ENV = TargetEnv("3.12")


class TestShippedSet:
    def test_evaluates_markers_for_the_deploy_platform(self) -> None:
        text = dedent("""\
            anyio==4.13.0
            colorama==0.4.6 ; sys_platform == 'win32'
            jeepney==0.9.0 ; sys_platform == 'linux'
            pywin32==312 ; sys_platform == 'win32'
            uvloop==0.22.1 ; platform_python_implementation != 'PyPy' and sys_platform != 'win32'
        """)
        locked = read_lock_from(text_packages={
            "anyio": "4.13.0", "colorama": "0.4.6", "jeepney": "0.9.0", "pywin32": "312",
            "uvloop": "0.22.1",
        })
        result = shipped_set(text, ENV, locked)
        assert result.pins == {"anyio": "4.13.0", "jeepney": "0.9.0", "uvloop": "0.22.1"}

    def test_pinned_private_packages_are_not_audited(self) -> None:
        locked = read_lock_from(
            text_packages={"private-widget": "0.1.0", "six": "1.17.0"},
            sources={"private-widget": {"registry": PRIVATE}},
        )
        scope = PrivateScope(pinned={"private-widget": PRIVATE})
        result = shipped_set("private-widget==0.1.0\nsix==1.17.0\n", ENV, locked, scope)
        assert result.pins == {"six": "1.17.0"}
        assert result.private == {"private-widget": "0.1.0"}
        assert any("private index" in line for line in result.not_audited)
        assert result.other_index == {}

    def test_explicit_index_packages_are_not_audited(self) -> None:
        locked = read_lock_from(
            text_packages={"private-widget": "0.1.0"},
            sources={"private-widget": {"registry": PRIVATE}},
        )
        scope = PrivateScope(explicit={PRIVATE.rstrip("/").lower()})
        result = shipped_set("private-widget==0.1.0\n", ENV, locked, scope)
        assert (result.pins, result.private) == ({}, {"private-widget": "0.1.0"})

    def test_a_mirror_as_default_index_is_audited_and_named(self) -> None:
        """A non-PyPI default index serves public packages: they are audited."""
        mirror = "https://mirror.example/api/pypi/simple"
        locked = read_lock_from(
            text_packages={"six": "1.17.0", "idna": "3.11"},
            sources={"six": {"registry": mirror}, "idna": {"registry": mirror}},
        )
        result = shipped_set("idna==3.11\nsix==1.17.0\n", ENV, locked)
        assert result.pins == {"idna": "3.11", "six": "1.17.0"}
        assert result.private == {}
        assert result.not_audited == []
        assert result.other_index == {"idna": mirror, "six": mirror}

    def test_local_and_git_sources_are_reported(self) -> None:
        locked = read_lock_from(
            text_packages={"tool": "1.0.0"}, sources={"tool": {"git": "https://example/x.git"}},
        )
        text = "-e ./libs/member\ntool==1.0.0\nother @ https://example.com/other.whl\n"
        result = shipped_set(text, ENV, locked)
        assert result.pins == {}
        assert len(result.not_audited) == 3


def read_lock_from(
    text_packages: dict[str, str], sources: dict[str, dict[str, str]] | None = None,
) -> list[Any]:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "uv.lock"
        path.write_text(_lock_text(text_packages, sources))
        return read_lock(path)[1]


class TestLockParsing:
    def test_revision_and_sources(self, tmp_path: Path) -> None:
        path = tmp_path / "uv.lock"
        path.write_text(_lock_text({"Six": "1.17.0"}, revision=2))
        revision, packages = read_lock(path)
        assert revision == 2
        assert packages[0].name == "six"
        assert packages[0].registry == PYPI

    def test_version_changes(self) -> None:
        before = read_lock_from({"a": "1.0", "b": "2.0", "c": "1.0"})
        after = read_lock_from({"a": "1.1", "b": "2.0", "d": "0.1"})
        changes = {c.name: (c.old_version, c.new_version)
                   for c in lock_version_changes(before, after)}
        assert changes == {"a": ("1.0", "1.1"), "c": ("1.0", "(removed)"), "d": ("(new)", "0.1")}

    def test_unreadable_lock(self, tmp_path: Path) -> None:
        path = tmp_path / "uv.lock"
        path.write_text("not = [toml")
        with pytest.raises(DepfreshError, match="not a readable uv.lock"):
            read_lock(path)


class TestGroupArgs:
    @pytest.mark.parametrize(
        ("kwargs", "expected"),
        [
            ({}, ["--no-dev"]),
            ({"groups": ("prod",)}, ["--no-default-groups", "--group", "prod"]),
            ({"all_groups": True}, ["--all-groups"]),
            ({"extras": ("full", "gcs")}, ["--no-dev", "--extra", "full", "--extra", "gcs"]),
            ({"all_extras": True}, ["--no-dev", "--all-extras"]),
        ],
    )
    def test_flags(self, kwargs: dict[str, Any], expected: list[str]) -> None:
        assert group_args(RemediationOptions(env=ENV, **kwargs)) == expected


class TestDockerfileGroups:
    """`RUN uv sync --frozen --extra gcs` ships the gcs extra: export it."""

    def test_flags_are_used_verbatim(self) -> None:
        options = RemediationOptions(env=ENV, uv_group_flags=("--no-dev", "--extra", "gcs"))
        assert group_args(options) == ["--no-dev", "--extra", "gcs"]

    def test_plain_uv_sync_exports_the_default_groups(self) -> None:
        assert group_args(RemediationOptions(env=ENV, uv_group_flags=())) == []

    def test_upgrade_exports_what_the_dockerfile_installs(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        (project / "pyproject.toml").write_text(
            '[project]\nname = "x"\nversion = "1"\ndependencies = ["six"]\n'
            '[project.optional-dependencies]\ngcs = ["google-cloud-storage"]\n'
        )
        (project / "uv.lock").write_text(_lock_text({"six": "1.17.0"}))
        (project / "Dockerfile").write_text("FROM python:3.12\nRUN uv sync --frozen --extra gcs\n")
        seen: dict[str, Any] = {}

        def fake(**kwargs: Any) -> None:
            seen["options"] = kwargs["options"]
            raise RuntimeError("stop")

        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.13.6"),
            patch.object(_upgrade_mod, "install_pip_audit",
                         return_value=("/tool/bin/python", "2.10.1")),
            patch.object(_upgrade_mod, "remediate_lock", side_effect=fake),
        ):
            with pytest.raises(RuntimeError, match="stop"):
                upgrade(project, reports_dir=tmp_path / "r")
        assert group_args(seen["options"]) == ["--extra", "gcs"]
        assert seen["options"].extras == ("gcs",)


class TestIndexes:
    def test_pypi_hosts(self) -> None:
        assert is_pypi_index("https://pypi.org/simple")
        assert not is_pypi_index(PRIVATE)
        assert not is_pypi_index(None)

    def test_unreachable_private_index_fails_clearly(self) -> None:
        output = (
            "error: Request failed after 3 retries\n"
            f"  Caused by: Failed to fetch: `{PRIVATE}private-widget/`\n"
        )
        with pytest.raises(PrivateIndexError) as exc_info:
            _raise_if_index_unreachable(output)
        assert "us-east1-python.pkg.dev" in str(exc_info.value)
        assert "does not fall back to public PyPI" in str(exc_info.value)

    def test_pypi_fetch_errors_are_not_private_index_errors(self) -> None:
        _raise_if_index_unreachable("Failed to fetch: `https://pypi.org/simple/six/`")


class TestConstraintEdits:
    PYPROJECT = dedent("""\
        [project]
        name = "demo"
        dependencies = [
            # crypto is capped for an old reason
            "cryptography>=41,<47",
            "fastapi>=0.115",
        ]

        [dependency-groups]
        dev = ["pytest>=8"]
    """)

    def test_finds_a_blocking_constraint(self) -> None:
        assert blocking_constraint(self.PYPROJECT, "cryptography", "50.0.2") == (
            "cryptography>=41,<47"
        )
        assert blocking_constraint(self.PYPROJECT, "fastapi", "0.133.0") is None

    def test_raises_only_the_blocking_requirement(self) -> None:
        text = admit_in_pyproject(self.PYPROJECT, "cryptography", "50.0.2")
        assert '"cryptography>=50.0.2,<51"' in text
        assert '"fastapi>=0.115"' in text
        assert "# crypto is capped for an old reason" in text

    def test_dynamic_dependencies_are_refused(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "x"\nversion = "1"\ndynamic = ["dependencies"]\n'
        )
        (tmp_path / "uv.lock").write_text(_lock_text({}))
        with pytest.raises(DepfreshError, match="never executes repository code"):
            LockProject("/usr/bin/uv", tmp_path, tmp_path / "work")

    def test_path_dependency_outside_the_project_is_refused(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        (project / "pyproject.toml").write_text(dedent("""\
            [project]
            name = "x"
            version = "1"
            dependencies = ["lib"]

            [tool.uv.sources]
            lib = { path = "../lib" }
        """))
        (project / "uv.lock").write_text(_lock_text({}))
        with pytest.raises(DepfreshError, match="outside the project"):
            LockProject("/usr/bin/uv", project, tmp_path / "work")

    def test_single_project_copies_only_what_uv_needs(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        (project / "src").mkdir(parents=True)
        (project / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = []\n')
        (project / "uv.lock").write_text(_lock_text({}))
        (project / ".python-version").write_text("3.12\n")
        (project / "src" / "app.py").write_text("")
        scratch = LockProject("/usr/bin/uv", project, tmp_path / "work").root
        assert sorted(p.name for p in scratch.iterdir()) == [
            ".python-version", "pyproject.toml", "uv.lock",
        ]


# ---------------------------------------------------------------------------
# remediate_lock with a fake project
# ---------------------------------------------------------------------------


class FakeProject:
    """Stands in for LockProject: a shipped set, a lock file and resolver rules.

    ``rules`` maps ``pkg==version`` to the co-upgrades uv would make, or to
    ``None`` when uv cannot lock that version at all.
    """

    def __init__(self, root: Path, versions: dict[str, str],
                 rules: dict[str, dict[str, str] | None], pyproject: str,
                 registry: str = PYPI) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.versions = dict(versions)
        self.rules = rules
        self.registry = registry
        self.commands: list[str] = []
        self.pyproject_path.write_text(pyproject)
        self._write_lock()
        self.lock_calls: list[dict[str, str]] = []
        self.scope = PrivateScope()

    @property
    def lock_path(self) -> Path:
        return self.root / "uv.lock"

    @property
    def pyproject_path(self) -> Path:
        return self.root / "pyproject.toml"

    def _write_lock(self) -> None:
        sources = {name: {"registry": self.registry} for name in self.versions}
        self.lock_path.write_text(_lock_text(self.versions, sources))

    def export(self, options: RemediationOptions) -> str:
        self.versions = {p.name: p.version for p in read_lock(self.lock_path)[1]}
        return "".join(f"{n}=={v}\n" for n, v in sorted(self.versions.items()))

    def lock_upgrade(self, targets: dict[str, str]) -> tuple[bool, str]:
        self.lock_calls.append(dict(targets))
        self.versions = {p.name: p.version for p in read_lock(self.lock_path)[1]}
        pyproject = self.pyproject_path.read_text()
        new = dict(self.versions)
        for name, version in targets.items():
            key = f"{name}=={version}"
            rule = self.rules.get(key, {})
            if rule is None:
                return False, f"error: No solution found when resolving {key}"
            if blocking_constraint(pyproject, name, version):
                return False, f"Because you require {name}<47 and {key}, unsatisfiable"
            new[name] = version
            new.update(rule)
        self.versions = new
        self._write_lock()
        return True, "Resolved"

    def check(self) -> str:
        return "passed"

    def sync(self, venv: Path, options: RemediationOptions, local: list[str]) -> str:
        return str(venv / "bin" / "python")


class FakeAuditor:
    def __init__(self, vulnerable: dict[str, set[str]]) -> None:
        self.vulnerable = vulnerable
        self.audited: list[dict[str, str]] = []

    def audit(self, pins: dict[str, str], label: str) -> list[Vulnerability]:
        self.audited.append(dict(pins))
        return [
            Vulnerability(name, version, f"GHSA-{name}", "", "")
            for name, version in sorted(pins.items())
            if version in self.vulnerable.get(name, set())
        ]


class FakeSources:
    def __init__(self, fixes: dict[str, str], releases: dict[str, list[str]]) -> None:
        self.fixes = fixes
        self._releases = releases

    def osv_records(self, package: str, version: str) -> list[dict[str, Any]]:
        return [{
            "id": f"GHSA-{package}",
            "affected": [{
                "package": {"name": package, "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": self.fixes[package]}]}],
            }],
        }]

    def releases(self, package: str) -> list[Release]:
        from packaging.version import Version

        return [Release(Version(v)) for v in self._releases[package]]


PYPROJECT = '[project]\nname = "demo"\ndependencies = ["aiohttp>=3.9", "cryptography>=41"]\n'


def _run(
    tmp_path: Path,
    project_factory: Callable[[Path], FakeProject],
    auditor: FakeAuditor,
    sources: FakeSources,
    **option_kwargs: Any,
) -> tuple[LockOutcome, FakeProject]:
    created: list[FakeProject] = []

    def factory(uv: str, target_dir: Path, work_dir: Path,
                context_dir: Path | None = None) -> FakeProject:
        created.append(project_factory(work_dir / "project"))
        return created[-1]

    options = RemediationOptions(env=ENV, import_check=False, **option_kwargs)
    with patch("depfresh.lockmode.LockProject", side_effect=factory):
        outcome = remediate_lock(
            uv="/usr/bin/uv", target_dir=tmp_path, work_dir=tmp_path / "work",
            auditor=auditor,  # type: ignore[arg-type]
            options=options, sources=sources, venv_name=".venv-upgrade",
        )
    return outcome, created[0]


class TestRemediateLock:
    BASE = {"aiohttp": "3.14.1", "yarl": "1.24.2", "cryptography": "48.0.1", "six": "1.17.0"}
    RELEASES = {
        "aiohttp": ["3.14.1", "3.14.4", "3.14.5"],
        "cryptography": ["48.0.1", "50.0.0"],
        "yarl": ["1.24.2", "1.25.1"],
    }

    def test_upgrades_only_vulnerable_packages_and_their_co_upgrades(
        self, tmp_path: Path,
    ) -> None:
        """aiohttp 3.14.4 forces yarl 1.25.1; six is not touched."""
        auditor = FakeAuditor({"aiohttp": {"3.14.1"}})
        sources = FakeSources({"aiohttp": "3.14.4"}, self.RELEASES)
        outcome, project = _run(
            tmp_path,
            lambda root: FakeProject(root, self.BASE, {"aiohttp==3.14.4": {"yarl": "1.25.1"}},
                                     PYPROJECT),
            auditor, sources,
        )
        assert project.lock_calls == [{"aiohttp": "3.14.4"}]
        assert outcome.final.pins == {**self.BASE, "aiohttp": "3.14.4", "yarl": "1.25.1"}
        assert outcome.post_vulns == []
        assert outcome.lock_check == "passed"
        assert outcome.new_lock is not None
        assert outcome.new_pyproject is None
        assert {c.name for c in outcome.lock_changes} == {"aiohttp", "yarl"}

    def test_major_fix_is_planned_but_not_applied_without_permission(
        self, tmp_path: Path,
    ) -> None:
        auditor = FakeAuditor({"cryptography": {"48.0.1"}})
        sources = FakeSources({"cryptography": "50.0.0"}, self.RELEASES)
        outcome, project = _run(
            tmp_path, lambda root: FakeProject(root, self.BASE, {}, PYPROJECT), auditor, sources,
        )
        assert project.lock_calls == []
        assert outcome.plans["cryptography"].status == "needs-major"
        assert outcome.new_lock is None
        assert len(outcome.post_vulns) == 1

    def test_failed_combined_update_falls_back_to_one_at_a_time(self, tmp_path: Path) -> None:
        auditor = FakeAuditor({"aiohttp": {"3.14.1"}, "cryptography": {"48.0.1"}})
        sources = FakeSources({"aiohttp": "3.14.4", "cryptography": "50.0.0"}, self.RELEASES)
        outcome, project = _run(
            tmp_path,
            lambda root: FakeProject(root, self.BASE, {"cryptography==50.0.0": None}, PYPROJECT),
            auditor, sources, allow_major=["cryptography"],
        )
        assert project.lock_calls == [
            {"aiohttp": "3.14.4", "cryptography": "50.0.0"},
            {"aiohttp": "3.14.4"},
            {"cryptography": "50.0.0"},
        ]
        assert outcome.final.pins["aiohttp"] == "3.14.4"
        assert outcome.final.pins["cryptography"] == "48.0.1"
        assert "uv could not lock cryptography==50.0.0" in outcome.failures["cryptography"]

    def test_direct_constraint_blocking_the_fix_is_raised(self, tmp_path: Path) -> None:
        pyproject = '[project]\nname = "demo"\ndependencies = ["cryptography>=41,<49"]\n'
        auditor = FakeAuditor({"cryptography": {"48.0.1"}})
        sources = FakeSources({"cryptography": "50.0.0"}, self.RELEASES)
        outcome, _ = _run(
            tmp_path, lambda root: FakeProject(root, self.BASE, {}, pyproject),
            auditor, sources, allow_major=[],
        )
        assert outcome.final.pins["cryptography"] == "50.0.0"
        assert outcome.new_pyproject is not None
        assert '"cryptography>=50.0.0,<51"' in outcome.new_pyproject.decode()
        assert "+" in outcome.pyproject_diff
        assert any("excluded the fix" in note for note in outcome.notes)

    def test_a_crlf_pyproject_stays_crlf(self, tmp_path: Path) -> None:
        pyproject = ('[project]\r\nname = "demo"\r\n'
                     'dependencies = [\r\n    "cryptography>=41,<49",\r\n]\r\n')
        outcome, _ = _run(
            tmp_path, lambda root: FakeProject(root, self.BASE, {}, pyproject),
            FakeAuditor({"cryptography": {"48.0.1"}}),
            FakeSources({"cryptography": "50.0.0"}, self.RELEASES), allow_major=[],
        )
        assert outcome.new_pyproject is not None
        text = outcome.new_pyproject.decode()
        assert '"cryptography>=50.0.0,<51"' in text
        assert text.count("\r\n") == text.count("\n") == 5

    def test_unapproved_major_co_upgrade_is_reverted(self, tmp_path: Path) -> None:
        auditor = FakeAuditor({"aiohttp": {"3.14.1"}})
        sources = FakeSources({"aiohttp": "3.14.4"}, self.RELEASES)
        outcome, _ = _run(
            tmp_path,
            lambda root: FakeProject(root, self.BASE, {"aiohttp==3.14.4": {"six": "2.0.0"}},
                                     PYPROJECT),
            auditor, sources,
        )
        assert outcome.final.pins == self.BASE
        assert "--allow-major aiohttp six" in outcome.failures["aiohttp"]

    def test_an_advisory_without_a_fix_does_not_block_the_other(self, tmp_path: Path) -> None:
        pyproject = '[project]\nname = "x"\ndependencies = ["demo>=2"]\n'
        outcome, project = _run(
            tmp_path, lambda root: FakeProject(root, {"demo": "2.0.0"}, {}, pyproject),
            MixedAuditor(), MixedSources(),  # type: ignore[arg-type]
        )
        assert project.lock_calls == [{"demo": "2.0.1"}]
        assert outcome.final.pins == {"demo": "2.0.1"}
        assert [v.cve for v in outcome.post_vulns] == ["GHSA-bbbb"]
        assert outcome.plans["demo"].open_advisories == {
            "GHSA-bbbb": "No fixed release available yet",
        }

    def test_a_mirror_default_index_is_audited_and_fixed(self, tmp_path: Path) -> None:
        mirror = "https://mirror.example/api/pypi/simple"
        auditor = FakeAuditor({"aiohttp": {"3.14.1"}})
        outcome, project = _run(
            tmp_path,
            lambda root: FakeProject(root, self.BASE, {"aiohttp==3.14.4": {}}, PYPROJECT,
                                     registry=mirror),
            auditor, FakeSources({"aiohttp": "3.14.4"}, self.RELEASES),
        )
        assert auditor.audited[0] == self.BASE
        assert project.lock_calls == [{"aiohttp": "3.14.4"}]
        assert outcome.post_vulns == []
        assert outcome.baseline.other_index == dict.fromkeys(self.BASE, mirror)
        assert any("not from PyPI" in note and mirror in note for note in outcome.notes)

    def test_pinned_private_package_is_never_audited_or_looked_up(
        self, tmp_path: Path,
    ) -> None:
        auditor = FakeAuditor({"private-widget": {"0.1.0"}})
        sources = FakeSources({}, {})

        def project(root: Path) -> FakeProject:
            made = FakeProject(root, {**self.BASE, "private-widget": "0.1.0"}, {}, PYPROJECT,
                               registry=PRIVATE)
            made.scope = PrivateScope(pinned={"private-widget": PRIVATE})
            return made

        outcome, _ = _run(tmp_path, project, auditor, sources)
        assert all("private-widget" not in pins for pins in auditor.audited)
        assert outcome.baseline.private == {"private-widget": "0.1.0"}
        assert outcome.pre_vulns == []

    def test_a_kept_package_is_never_co_upgraded(self, tmp_path: Path) -> None:
        auditor = FakeAuditor({"aiohttp": {"3.14.1"}})
        sources = FakeSources({"aiohttp": "3.14.4"}, self.RELEASES)
        outcome, project = _run(
            tmp_path,
            lambda root: FakeProject(root, self.BASE, {"aiohttp==3.14.4": {"yarl": "1.25.1"}},
                                     PYPROJECT),
            auditor, sources, keep_version=["yarl"],
        )
        assert outcome.final.pins == self.BASE
        assert outcome.new_lock is None
        assert outcome.failures["aiohttp"] == (
            "aiohttp==3.14.4 moves yarl 1.24.2→1.25.1, which --keep-version keeps"
        )

    REPO_RELEASES = {**RELEASES, "yarl": ["1.24.2", "1.25.1"], "six": ["1.17.0", "1.17.1"]}

    def test_repository_advisories_are_fixed_after_the_database(self, tmp_path: Path) -> None:
        auditor = TwoSourceAuditor({"aiohttp": {"3.14.1"}}, {"yarl": ("<1.25.1", "1.25.1")})
        sources = TwoSourceSources({"aiohttp": "3.14.4"}, self.REPO_RELEASES)
        outcome, project = _run(
            tmp_path, lambda root: FakeProject(root, self.BASE, {}, PYPROJECT), auditor, sources,
        )
        # the database fix first, exactly as without the flag; then the repository fix
        assert project.lock_calls == [{"aiohttp": "3.14.4"}, {"yarl": "1.25.1"}]
        assert outcome.final.pins == {**self.BASE, "aiohttp": "3.14.4", "yarl": "1.25.1"}
        assert outcome.post_vulns == []

    def test_repository_fixes_never_leave_more_database_findings(
        self, tmp_path: Path,
    ) -> None:
        """yarl's repository fix drags six onto a release with an unfixed database advisory."""
        auditor = TwoSourceAuditor({"aiohttp": {"3.14.1"}, "six": {"1.17.1"}},
                                   {"yarl": ("<1.25.1", "1.25.1")})
        sources = TwoSourceSources({"aiohttp": "3.14.4", "six": None}, self.REPO_RELEASES)
        outcome, project = _run(
            tmp_path,
            lambda root: FakeProject(root, self.BASE, {"yarl==1.25.1": {"six": "1.17.1"}},
                                     PYPROJECT),
            auditor, sources,
        )
        assert outcome.final.pins == {**self.BASE, "aiohttp": "3.14.4"}
        assert read_lock(project.lock_path)[1] == read_lock_from({**self.BASE,
                                                                  "aiohttp": "3.14.4"})
        assert [(v.package, v.from_repository) for v in outcome.post_vulns] == [("yarl", True)]
        assert outcome.failures["yarl"].startswith("Not applied: fixing the repository "
                                                   "advisories left 1 database advisories "
                                                   "instead of 0")
        assert any("Repository advisories were not fixed" in n for n in outcome.notes)

    def test_follow_up_round_for_a_vulnerable_co_upgrade(self, tmp_path: Path) -> None:
        auditor = FakeAuditor({"aiohttp": {"3.14.1"}, "yarl": {"1.24.9"}})
        sources = FakeSources({"aiohttp": "3.14.4", "yarl": "1.25.1"},
                              {**self.RELEASES, "yarl": ["1.24.9", "1.25.1"]})
        outcome, project = _run(
            tmp_path,
            lambda root: FakeProject(root, self.BASE, {"aiohttp==3.14.4": {"yarl": "1.24.9"}},
                                     PYPROJECT),
            auditor, sources,
        )
        assert project.lock_calls == [{"aiohttp": "3.14.4"}, {"yarl": "1.25.1"}]
        assert outcome.post_vulns == []


class TestUpgradeLockMode:
    """upgrade() on a uv project: write-back of uv.lock and its gates."""

    @staticmethod
    def _outcome(tmp_path: Path, *, lock_check: str = "passed",
                 regress: bool = False) -> LockOutcome:
        from depfresh.lockmode import ShippedSet
        from depfresh.remediation import ImportGate

        gate = ImportGate(enabled=True, target_dir=tmp_path)
        gate.baseline = ImportCheck(verified=["fastmcp", "fastmcp.tools.tool"])
        gate.after = ImportCheck(
            verified=["fastmcp"] if regress else ["fastmcp", "fastmcp.tools.tool"],
            failed={"fastmcp.tools.tool": "No module named 'fastmcp.tools.tool'"}
            if regress else {},
        )
        return LockOutcome(
            baseline=ShippedSet(pins={"fastmcp": "3.4.2"}),
            final=ShippedSet(pins={"fastmcp": "3.4.10"}),
            pre_vulns=[Vulnerability("fastmcp", "3.4.2", "GHSA-7xgj-8392-5q4r", "4.1.2", "")],
            post_vulns=[], plans={}, failures={}, lock_changes=[], lock_check=lock_check,
            revision_before=3, revision_after=5, new_lock=b"new lock\n", new_pyproject=None,
            pyproject_diff="", commands=["uv lock --upgrade-package fastmcp==3.4.10"],
            notes=[], gate=gate,
        )

    def _upgrade(self, tmp_path: Path, outcome: LockOutcome, **kwargs: Any) -> UpgradeResult:
        project = tmp_path / "proj"
        project.mkdir(exist_ok=True)
        (project / "pyproject.toml").write_text(
            '[project]\nname = "x"\ndependencies = ["fastmcp>=3.4.2"]\n'
        )
        (project / "uv.lock").write_text("old lock\n")
        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.13.6"),
            patch.object(_upgrade_mod, "install_pip_audit",
                         return_value=("/tool/bin/python", "2.10.1")),
            patch.object(_upgrade_mod, "remediate_lock", return_value=outcome) as mock,
        ):
            result = upgrade(project, label="x", reports_dir=tmp_path / "reports", **kwargs)
        assert mock.called
        return result

    def test_an_advisory_a_co_upgrade_brings_in_blocks_the_write_back(
        self, tmp_path: Path,
    ) -> None:
        outcome = self._outcome(tmp_path)
        outcome.post_vulns = [Vulnerability("six", "1.17.1", "GHSA-new", "", "")]
        result = self._upgrade(tmp_path, outcome, python="3.12")
        assert (tmp_path / "proj" / "uv.lock").read_text() == "old lock\n"
        assert result.write_back_skipped == (
            "the changes bring in 1 advisories that were not there before "
            "(six 1.17.1 GHSA-new)"
        )

    @pytest.mark.parametrize("dry_run", [False, True])
    def test_an_open_advisory_keeps_its_own_reason(self, tmp_path: Path, dry_run: bool) -> None:
        from depfresh.advisories import FixPlan

        outcome = self._outcome(tmp_path)
        outcome.pre_vulns.append(Vulnerability("fastmcp", "3.4.2", "GHSA-open", "", ""))
        outcome.post_vulns = [Vulnerability("fastmcp", "3.4.10", "GHSA-open", "", "")]
        outcome.plans = {"fastmcp": FixPlan(
            "fastmcp", "3.4.2", list(outcome.pre_vulns), status="fix", target="3.4.10",
            kind="patch", reason="Upgrade to 3.4.10; still open: GHSA-open",
            open_advisories={"GHSA-open": "No fixed release available yet"},
        )}
        result = self._upgrade(tmp_path, outcome, python="3.12", dry_run=dry_run)
        assert [f.status for f in result.fixes] == ["planned" if dry_run else "applied"]
        assert result.remaining_reasons == ["No fixed release available yet"]

    def test_writes_the_lock(self, tmp_path: Path) -> None:
        result = self._upgrade(tmp_path, self._outcome(tmp_path), python="3.12")
        assert (tmp_path / "proj" / "uv.lock").read_text() == "new lock\n"
        assert result.mode == "lock"
        assert result.dep_file_updated is True
        assert result.files_changed == ["uv.lock"]
        assert result.upgraded[0].name == "fastmcp"
        assert result.upgraded[0].is_security_fix is True

    def test_dry_run_writes_nothing(self, tmp_path: Path) -> None:
        result = self._upgrade(tmp_path, self._outcome(tmp_path), dry_run=True)
        assert (tmp_path / "proj" / "uv.lock").read_text() == "old lock\n"
        assert result.dep_file_updated is False

    def test_import_regression_blocks_the_lock(self, tmp_path: Path) -> None:
        result = self._upgrade(tmp_path, self._outcome(tmp_path, regress=True))
        assert (tmp_path / "proj" / "uv.lock").read_text() == "old lock\n"
        assert result.import_regressions
        assert "import" in result.write_back_skipped

    def test_failed_lock_check_blocks_the_lock(self, tmp_path: Path) -> None:
        result = self._upgrade(tmp_path, self._outcome(tmp_path, lock_check="failed: stale"))
        assert (tmp_path / "proj" / "uv.lock").read_text() == "old lock\n"
        assert "uv lock --check" in result.write_back_skipped

    @pytest.mark.parametrize("kind", ["lock check", "does not install"])
    def test_withheld_rows_say_planned_not_written(self, tmp_path: Path, kind: str) -> None:
        from depfresh.advisories import FixPlan

        outcome = self._outcome(
            tmp_path, lock_check="failed: stale" if kind == "lock check" else "passed",
        )
        if kind == "does not install":
            outcome.gate.blocked = "the remediated lock does not install on this host"
        outcome.plans = {"fastmcp": FixPlan(
            "fastmcp", "3.4.2", outcome.pre_vulns, status="fix", target="3.4.10",
            kind="patch", reason="Upgrade to 3.4.10",
        )}
        result = self._upgrade(tmp_path, outcome)
        assert [f.status for f in result.fixes] == ["planned, not written"]
        assert result.markdown_path is not None
        assert "**Nothing was written**" in Path(result.markdown_path).read_text()

    def test_withheld_write_back_exits_2_through_the_cli(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str],
    ) -> None:
        from depfresh.cli import main

        project = tmp_path / "proj"
        project.mkdir()
        (project / "pyproject.toml").write_text(
            '[project]\nname = "x"\nversion = "1"\ndependencies = ["fastmcp>=3.4.2"]\n'
        )
        (project / "uv.lock").write_text("old lock\n")
        outcome = self._outcome(tmp_path, lock_check="failed: stale")
        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.13.6"),
            patch.object(_upgrade_mod, "install_pip_audit",
                         return_value=("/tool/bin/python", "2.10.1")),
            patch.object(_upgrade_mod, "remediate_lock", return_value=outcome),
        ):
            with pytest.raises(SystemExit) as exc_info:
                main([str(project), "--reports-dir", str(tmp_path / "reports")])
        assert exc_info.value.code == 2
        assert "NOTHING WAS WRITTEN" in capsys.readouterr().out
        assert (project / "uv.lock").read_text() == "old lock\n"

    def test_markdown_lists_lock_changes(self, tmp_path: Path) -> None:
        outcome = self._outcome(tmp_path)
        from depfresh.models import PackageChange

        outcome.lock_changes = [PackageChange("fastmcp", "3.4.2", "3.4.10")]
        result = self._upgrade(tmp_path, outcome)
        assert result.markdown_path is not None
        content = Path(result.markdown_path).read_text()
        assert "`uv.lock` (written): 1 package version(s) change" in content
        assert "| fastmcp | 3.4.2 | 3.4.10 | patch |" in content
        assert "uv lock --upgrade-package fastmcp==3.4.10" in content
        assert "- [x] `uv lock --check`: passed" in content


class TestSubproject:
    """--dep-file sub/pyproject.toml works on that subproject, never on the root."""

    ROOT = '[project]\nname = "root-app"\nversion = "1"\ndependencies = ["six==1.17.0"]\n'
    SUB = '[project]\nname = "sub-app"\nversion = "1"\ndependencies = ["fastmcp>=3.4.2"]\n'

    def _tree(self, tmp_path: Path, *, root: bool = True) -> Path:
        target = tmp_path / "repo"
        (target / "services" / "api").mkdir(parents=True)
        if root:
            (target / "pyproject.toml").write_text(self.ROOT)
            (target / "uv.lock").write_text("root lock\n")
        (target / "uv.toml").write_text('index-url = "https://mirror.example/simple"\n')
        (target / "services" / ".python-version").write_text("3.12\n")
        (target / "services" / "api" / "pyproject.toml").write_text(self.SUB)
        (target / "services" / "api" / "uv.lock").write_text("sub lock\n")
        return target

    def test_scope_covers_workspace_members_and_settings(self, tmp_path: Path) -> None:
        from depfresh.lockmode import LockProject

        target = tmp_path / "ws"
        (target / "packages" / "core").mkdir(parents=True)
        (target / "pyproject.toml").write_text(
            '[project]\nname = "ws"\nversion = "1"\ndependencies = ["core"]\n'
            '[tool.uv.workspace]\nmembers = ["packages/*"]\n'
            '[tool.uv.sources]\ncore = { workspace = true }\n'
        )
        (target / "packages" / "core" / "pyproject.toml").write_text(
            '[project]\nname = "core"\nversion = "1"\ndependencies = ["private-widget"]\n'
            '[tool.uv.sources]\nprivate-widget = { index = "internal" }\n'
        )
        (target / "uv.toml").write_text(
            f'[[index]]\nname = "internal"\nurl = "{PRIVATE}"\nexplicit = true\n'
        )
        (target / "uv.lock").write_text(_lock_text({"six": "1.17.0"}))
        project = LockProject("/usr/bin/uv", target, tmp_path / "work")
        assert project.scope.pinned == {"private-widget": "internal"}
        assert project.scope.is_private("other", PRIVATE)

    def test_path_sources_get_a_full_copy_without_caches(self, tmp_path: Path) -> None:
        """Workspaces and path sources need the tree; VCS data, venvs and caches stay out."""
        from depfresh.lockmode import LockProject

        target = tmp_path / "proj"
        (target / "libs" / "core").mkdir(parents=True)
        (target / "pyproject.toml").write_text(
            '[project]\nname = "app"\nversion = "1"\ndependencies = ["core"]\n'
            '[tool.uv.sources]\ncore = { path = "libs/core" }\n'
        )
        (target / "libs" / "core" / "pyproject.toml").write_text(
            '[project]\nname = "core"\nversion = "1"\ndependencies = []\n'
        )
        (target / "uv.lock").write_text(_lock_text({"six": "1.17.0"}))
        for junk in (".git", ".venv", "node_modules", "reports", "src/__pycache__"):
            (target / junk).mkdir(parents=True)
            (target / junk / "x").write_text("")
        (target / "src" / "app.py").write_text("import core\n")
        project = LockProject("/usr/bin/uv", target, tmp_path / "work")
        copied = sorted(str(p.relative_to(project.root)) for p in project.root.rglob("*")
                        if p.is_file())
        assert copied == ["libs/core/pyproject.toml", "pyproject.toml", "src/app.py", "uv.lock"]

    def test_scratch_copy_keeps_the_settings_above_the_subproject(self, tmp_path: Path) -> None:
        from depfresh.lockmode import LockProject

        target = self._tree(tmp_path)
        project = LockProject("/usr/bin/uv", target / "services" / "api", tmp_path / "work",
                              context_dir=target)
        base = tmp_path / "work" / "project"
        assert project.root == base / "services" / "api"
        assert project.pyproject_path.read_text() == self.SUB
        assert project.lock_path.read_text() == "sub lock\n"
        assert (base / "uv.toml").is_file()
        assert (base / "pyproject.toml").read_text() == self.ROOT
        assert (base / "services" / ".python-version").is_file()
        assert not (base / "uv.lock").exists()

    @pytest.mark.parametrize("root", [True, False])
    def test_writes_only_the_subproject(self, tmp_path: Path, root: bool) -> None:
        target = self._tree(tmp_path, root=root)
        sub = target / "services" / "api"
        outcome = TestUpgradeLockMode._outcome(tmp_path)
        outcome.new_pyproject = b"new sub pyproject\n"
        outcome.pyproject_diff = "-old\n+new\n"
        with (
            patch.object(_upgrade_mod, "find_uv", return_value="/usr/bin/uv"),
            patch.object(_upgrade_mod, "get_uv_version", return_value="0.13.6"),
            patch.object(_upgrade_mod, "install_pip_audit",
                         return_value=("/tool/bin/python", "2.10.1")),
            patch.object(_upgrade_mod, "remediate_lock", return_value=outcome) as mock,
        ):
            result = upgrade(target, label="x", dep_file="services/api/pyproject.toml",
                             reports_dir=tmp_path / "reports", python="3.12")
        assert mock.call_args.kwargs["target_dir"] == sub
        assert mock.call_args.kwargs["context_dir"] == target
        assert (sub / "uv.lock").read_text() == "new lock\n"
        assert (sub / "pyproject.toml").read_text() == "new sub pyproject\n"
        if root:
            assert (target / "uv.lock").read_text() == "root lock\n"
            assert (target / "pyproject.toml").read_text() == self.ROOT
        assert result.requirements_path == "services/api/uv.lock"
        assert result.files_changed == ["services/api/uv.lock", "services/api/pyproject.toml"]

    def test_import_check_scans_the_subproject(self, tmp_path: Path) -> None:
        target = self._tree(tmp_path)
        sub = target / "services" / "api"
        made: list[tuple[Path, Path | None]] = []

        def factory(uv: str, project_dir: Path, work_dir: Path,
                    context_dir: Path | None = None) -> FakeProject:
            made.append((project_dir, context_dir))
            return FakeProject(work_dir / "project", {"fastmcp": "3.4.2"}, {}, self.SUB)

        with patch("depfresh.lockmode.LockProject", side_effect=factory):
            outcome = remediate_lock(
                uv="/usr/bin/uv", target_dir=sub, work_dir=tmp_path / "work",
                auditor=FakeAuditor({}),  # type: ignore[arg-type]
                options=RemediationOptions(env=ENV, import_check=False),
                sources=FakeSources({}, {}),  # type: ignore[arg-type]
                venv_name=".venv-upgrade", context_dir=target,
            )
        assert made == [(sub, target)]
        assert outcome.gate.target_dir == sub


class TestLatestStrategyOnALock:
    def test_is_refused(self, tmp_path: Path) -> None:
        """--strategy latest would rewrite pyproject.toml and leave uv.lock stale."""
        pyproject = '[project]\nname = "x"\nversion = "1"\ndependencies = ["six"]\n'
        (tmp_path / "pyproject.toml").write_text(pyproject)
        (tmp_path / "uv.lock").write_text("lock\n")
        with (
            patch.object(_upgrade_mod, "find_uv") as find_uv,
            pytest.raises(DepfreshError, match="the lock is what ships"),
        ):
            upgrade(tmp_path, strategy="latest", python="3.12")
        assert not find_uv.called
        assert (tmp_path / "pyproject.toml").read_text() == pyproject
        assert (tmp_path / "uv.lock").read_text() == "lock\n"


class TestWorkspaceMembers:
    """A workspace member ships from the workspace's lock: depfresh refuses it."""

    @staticmethod
    def _workspace(tmp_path: Path, workspace: str, member_lock: bool = False) -> Path:
        root = tmp_path / "ws"
        member = root / "packages" / "api"
        member.mkdir(parents=True)
        (root / "pyproject.toml").write_text(
            '[project]\nname = "ws"\nversion = "1"\ndependencies = []\n' + workspace
        )
        (root / "uv.lock").write_text("workspace lock\n")
        (member / "pyproject.toml").write_text(
            '[project]\nname = "api"\nversion = "1"\ndependencies = ["six"]\n'
        )
        if member_lock:
            (member / "uv.lock").write_text("stale member lock\n")
        return root

    @pytest.mark.parametrize(("workspace", "member"), [
        ('[tool.uv.workspace]\nmembers = ["packages/*"]\n', True),
        ('[tool.uv.workspace]\nmembers = ["packages/api"]\n', True),
        ('[tool.uv.workspace]\nmembers = ["packages/*"]\nexclude = ["packages/api"]\n', False),
        ('[tool.uv.workspace]\nmembers = ["libs/*"]\n', False),
        ("", False),
    ])
    def test_membership_follows_uv(self, tmp_path: Path, workspace: str, member: bool) -> None:
        from depfresh.lockmode import workspace_root_of

        root = self._workspace(tmp_path, workspace)
        found = workspace_root_of(root / "packages" / "api")
        assert found == (root.resolve() if member else None)

    def test_only_the_nearest_pyproject_counts(self, tmp_path: Path) -> None:
        """uv stops at the first pyproject.toml above the project, as here."""
        from depfresh.lockmode import workspace_root_of

        root = self._workspace(tmp_path, '[tool.uv.workspace]\nmembers = ["packages/**"]\n')
        (root / "packages" / "pyproject.toml").write_text(
            '[project]\nname = "group"\nversion = "1"\n'
        )
        assert workspace_root_of(root / "packages" / "api") is None

    @pytest.mark.parametrize("member_lock", [False, True])
    @pytest.mark.parametrize("how", ["dep-file", "target"])
    def test_member_runs_are_refused(self, tmp_path: Path, member_lock: bool, how: str) -> None:
        root = self._workspace(tmp_path, '[tool.uv.workspace]\nmembers = ["packages/*"]\n',
                               member_lock=member_lock)
        with (
            patch.object(_upgrade_mod, "find_uv") as find_uv,
            pytest.raises(DepfreshError, match="belongs to the uv workspace at"),
        ):
            if how == "dep-file":
                upgrade(root, dep_file="packages/api/pyproject.toml", python="3.12")
            else:
                upgrade(root / "packages" / "api", python="3.12")
        assert not find_uv.called
        assert (root / "uv.lock").read_text() == "workspace lock\n"


class TestLockProjectCommands:
    """The exact uv invocations, with uv mocked out."""

    @pytest.fixture()
    def project(self, tmp_path: Path) -> LockProject:
        target = tmp_path / "proj"
        target.mkdir()
        (target / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = []\n')
        (target / "uv.lock").write_text(_lock_text({}))
        return LockProject("/usr/bin/uv", target, tmp_path / "work")

    def test_export_command(self, project: LockProject) -> None:
        result = MagicMock(returncode=0, stdout="six==1.17.0\n", stderr="")
        with patch("depfresh.lockmode.run", return_value=result) as mock:
            assert project.export(RemediationOptions(env=ENV)) == "six==1.17.0\n"
        cmd = mock.call_args.args[0]
        assert cmd[:3] == ["/usr/bin/uv", "export", "--frozen"]
        for flag in ("--no-emit-project", "--no-hashes", "--no-dev"):
            assert flag in cmd
        assert mock.call_args.kwargs["cwd"] == project.root

    def test_lock_upgrade_command(self, project: LockProject) -> None:
        result = MagicMock(returncode=0, stdout="", stderr="Updated pyjwt v2.13.0 -> v2.15.0")
        with patch("depfresh.lockmode.run", return_value=result) as mock:
            ok, _ = project.lock_upgrade({"pyjwt": "2.15.0", "anyio": "4.14.2"})
        assert ok
        assert mock.call_args.args[0] == [
            "/usr/bin/uv", "lock",
            "--upgrade-package", "anyio==4.14.2", "--upgrade-package", "pyjwt==2.15.0",
        ]
        assert project.commands[-1].startswith("uv lock --upgrade-package anyio==4.14.2")

    def test_lock_upgrade_with_unreachable_private_index(self, project: LockProject) -> None:
        result = MagicMock(
            returncode=2, stdout="",
            stderr=f"error: Failed to fetch: `{PRIVATE}private-widget/`\n",
        )
        with patch("depfresh.lockmode.run", return_value=result):
            with pytest.raises(PrivateIndexError):
                project.lock_upgrade({"six": "1.17.0"})

    def test_sync_targets_a_scratch_env(self, project: LockProject, tmp_path: Path) -> None:
        with patch("depfresh.lockmode.run", return_value=MagicMock(returncode=0)) as mock:
            project.sync(tmp_path / "venv", RemediationOptions(env=ENV), ["member"])
        cmd = mock.call_args.args[0]
        assert "--no-install-project" in cmd and "--frozen" in cmd
        assert cmd[cmd.index("--no-install-package") + 1] == "member"
        assert mock.call_args.kwargs["env"]["UV_PROJECT_ENVIRONMENT"] == str(tmp_path / "venv")

    def test_export_failure_naming_a_private_index(self, project: LockProject) -> None:
        error = CommandError(["uv", "export"], 2, f"Failed to fetch: {PRIVATE}x/")
        with patch("depfresh.lockmode.run", side_effect=error):
            with pytest.raises(PrivateIndexError):
                project.export(RemediationOptions(env=ENV))
