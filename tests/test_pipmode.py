"""Tests for pipmode — resolved-mode remediation of requirements files and pyproject."""

from __future__ import annotations

import itertools
import sys
from pathlib import Path
from textwrap import dedent
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from depfresh.advisories import Release, TargetEnv
from depfresh.constraints import normalise
from depfresh.exceptions import CommandError, DirectReferenceError, PrivateIndexError
from depfresh.models import Vulnerability
from depfresh.parsers import DependencyFormat
from depfresh.pipmode import (
    AmbiguousRequirementError,
    PipWorkspace,
    PyprojectDocument,
    RequirementsDocument,
    Resolution,
    parse_compile_output,
    remediate_pip,
    split_requirement,
    strip_pyproject_direct_refs,
)
from depfresh.remediation import RemediationOptions
from depfresh.reqlines import parse_lines
from tests.helpers import MixedAuditor, MixedSources

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

ENV = TargetEnv("3.11")


class TestParseCompileOutput:
    def test_line_annotations_and_indexes(self) -> None:
        text = dedent("""\
            anyio==4.15.1             # via starlette
                # from https://pypi.org/simple
            fastapi==0.129.0          # via -r requirements.txt
                # from https://pypi.org/simple
            private-widget==0.1.0     # via demo (pyproject.toml)
                # from https://us-east1-python.pkg.dev/acme/python/simple/
            starlette==0.52.1         # via -r requirements.txt, fastapi
                # from https://pypi.org/simple
            tool @ git+https://example.com/tool.git
        """)
        result = parse_compile_output(text)
        assert result.pins["fastapi"] == "0.129.0"
        assert result.via["starlette"] == {"fastapi"}
        assert result.private() == {
            "private-widget": "https://us-east1-python.pkg.dev/acme/python/simple/",
        }
        assert "private-widget" not in result.public_pins()
        assert result.direct_refs == ["tool @ git+https://example.com/tool.git"]


class TestSplitRequirement:
    @pytest.mark.parametrize(
        ("code", "spec"),
        [
            ("grpcio==1.80.0", "==1.80.0"),
            ("google-cloud-storage>=2.10.0", ">=2.10.0"),
            ("uvicorn[standard] >= 0.32 ; python_version < '3.13'", ">= 0.32"),
            ("pandas", ""),
            ("pypdf>=6.21,<7", ">=6.21,<7"),
        ],
    )
    def test_spec_span(self, code: str, spec: str) -> None:
        split = split_requirement(code)
        assert split is not None
        assert code[split[1]:split[2]] == spec

    def test_url_requirement_is_not_editable(self) -> None:
        assert split_requirement("demo @ https://example.com/demo-1.0.tar.gz") is None


class TestRequirementsDocument:
    SERVICE = dedent("""\
        anthropic==0.86.0
        # keep the gRPC stack together
        grpcio==1.80.0  # pinned with grpcio-status
        docstring_parser==0.17.0
        pywin32==306 ; sys_platform == "win32"
        google-cloud-storage>=2.10.0
        pandas-gbq>=0.26.1
    """)

    def test_edits_only_the_requested_lines(self) -> None:
        doc = RequirementsDocument(self.SERVICE)
        doc.set_spec("grpcio", "==1.84.1")
        doc.set_spec("pandas-gbq", ">=0.30.0")
        lines = doc.render().splitlines()
        assert lines[2] == "grpcio==1.84.1  # pinned with grpcio-status"
        assert lines[6] == "pandas-gbq>=0.30.0"
        unchanged = [0, 1, 3, 4, 5]
        assert [lines[i] for i in unchanged] == [self.SERVICE.splitlines()[i] for i in unchanged]

    def test_listed_keeps_floors_as_floors(self) -> None:
        listed = RequirementsDocument(self.SERVICE).listed()
        assert listed["google-cloud-storage"] == ">=2.10.0"
        assert listed["docstring-parser"] == "==0.17.0"

    def test_marker_preserved(self) -> None:
        doc = RequirementsDocument(self.SERVICE)
        doc.set_spec("pywin32", "==311")
        assert 'pywin32==311 ; sys_platform == "win32"' in doc.render()

    def test_append_a_commented_floor(self) -> None:
        doc = RequirementsDocument("flask==2.3.0")  # no trailing newline
        doc.append("setuptools>=84.1.0  # depfresh: GHSA-h35f-9h28-mq5c")
        assert doc.render() == (
            "flask==2.3.0\nsetuptools>=84.1.0  # depfresh: GHSA-h35f-9h28-mq5c\n"
        )

    def test_crlf_line_endings(self) -> None:
        doc = RequirementsDocument("idna==3.11\r\nsix==1.17.0\r\n")
        doc.set_spec("idna", "==3.15")
        doc.append("urllib3>=2.8.0  # depfresh: GHSA-x")
        assert doc.render() == "idna==3.15\r\nsix==1.17.0\r\nurllib3>=2.8.0  # depfresh: GHSA-x\r\n"

    def test_direct_references(self) -> None:
        doc = RequirementsDocument(dedent("""\
            -e .
            -e git+https://example.com/a.git#egg=a
            ./libs/b
            c @ https://example.com/c-1.0.tar.gz
            --index-url https://pypi.org/simple
            -r base.txt
            d==1.0
        """))
        assert set(doc.listed()) == {"d"}
        assert len(doc.direct_refs) == 4

    def test_hashed_entries_get_new_hashes(self) -> None:
        text = dedent("""\
            click==8.3.1 \\
                --hash=sha256:aaa \\
                --hash=sha256:bbb
                # via -r requirements.in
            packaging==23.2 \\
                --hash=sha256:ccc \\
                --hash=sha256:ddd
                # via -r requirements.in
            zipp==3.20.0 \\
                --hash=sha256:eee
        """)
        doc = RequirementsDocument(text)
        doc.set_spec("click", "==8.3.2", ["sha256:111", "sha256:222", "sha256:333"])
        doc.set_spec("zipp", "==3.21.0", ["sha256:444"])
        assert doc.render() == dedent("""\
            click==8.3.2 \\
                --hash=sha256:111 \\
                --hash=sha256:222 \\
                --hash=sha256:333
                # via -r requirements.in
            packaging==23.2 \\
                --hash=sha256:ccc \\
                --hash=sha256:ddd
                # via -r requirements.in
            zipp==3.21.0 \\
                --hash=sha256:444
        """)


class TestPyprojectDocument:
    TEXT = dedent("""\
        [project]
        name = "demo"
        dependencies = [
            "pandas",
            # pdf parsing
            "pypdf>=6.21,<7",
        ]

        [project.optional-dependencies]
        gcs = ["google-cloud-storage>=2.0"]
        dev = ["pytest"]
    """)

    def test_rewrites_one_requirement_and_keeps_comments(self) -> None:
        doc = PyprojectDocument(self.TEXT, [], False)
        doc.set_spec("pypdf", ">=6.25.0,<7")
        out = doc.render()
        assert '"pypdf>=6.25.0,<7",' in out
        assert "# pdf parsing" in out
        assert '"pandas",' in out

    def test_selected_extras_only(self) -> None:
        assert "google-cloud-storage" in PyprojectDocument(self.TEXT, ["gcs"], False).listed()
        assert "google-cloud-storage" not in PyprojectDocument(self.TEXT, [], False).listed()
        assert "pytest" in PyprojectDocument(self.TEXT, [], True).listed()

    def test_appends_commented_floor_to_dependencies(self) -> None:
        doc = PyprojectDocument(self.TEXT, [], False)
        doc.append("urllib3>=2.8.0  # depfresh: GHSA-8988-9cw3-xx77")
        out = doc.render()
        assert '"urllib3>=2.8.0", # depfresh: GHSA-8988-9cw3-xx77' in out
        deps = tomllib.loads(out)["project"]["dependencies"]
        assert deps == ["pandas", "pypdf>=6.21,<7", "urllib3>=2.8.0"]

    def test_appends_into_an_extra(self) -> None:
        doc = PyprojectDocument(self.TEXT, ["gcs"], False)
        doc.append("protobuf>=6.33.5  # depfresh: GHSA-x", extra="gcs")
        data = tomllib.loads(doc.render())
        assert data["project"]["optional-dependencies"]["gcs"] == [
            "google-cloud-storage>=2.0", "protobuf>=6.33.5",
        ]


# ---------------------------------------------------------------------------
# remediate_pip with a fake resolver
# ---------------------------------------------------------------------------


class FakeResolver:
    """A tiny exhaustive resolver standing in for ``uv pip compile``.

    ``universe`` lists the versions of each package; ``requires`` maps
    ``(package, version)`` to its dependency specifiers.  Preferences and
    ``lowest_direct`` behave like uv's: a preferred version is kept whenever
    it fits, otherwise the highest (or, for listed packages, lowest) fit.
    """

    def __init__(self, universe: dict[str, list[str]],
                 requires: dict[tuple[str, str], dict[str, str]]) -> None:
        self.universe = universe
        self.requires = requires
        self.calls: list[dict[str, Any]] = []

    def __call__(self, ws: PipWorkspace, manifest: Path, *, preferences: str | None = None,
                 lowest_direct: bool = False, record: bool = False) -> Resolution:
        text = manifest.read_text()
        self.calls.append({"text": text, "preferences": preferences is not None,
                           "lowest": lowest_direct})
        direct: dict[str, SpecifierSet] = {}
        for line in parse_lines(text):
            if line.kind != "registry":
                continue
            req = Requirement(line.requirement)
            if req.marker is not None and not req.marker.evaluate(ENV.marker_environment()):
                continue
            name = normalise(req.name)
            direct[name] = direct.get(name, SpecifierSet()) & req.specifier
        prefs = parse_compile_output(preferences).pins if preferences else {}
        names = sorted(self.universe)

        def ordered(name: str) -> list[str]:
            versions = sorted(self.universe[name], key=Version)
            if not (lowest_direct and name in direct):
                versions.reverse()
            if name in prefs and prefs[name] in versions:
                versions.remove(prefs[name])
                versions.insert(0, prefs[name])
            return versions

        for combo in itertools.product(*(ordered(n) for n in names)):
            chosen = dict(zip(names, combo))
            reach: dict[str, set[str]] = {n: set() for n in direct}
            todo = list(direct)
            while todo:  # only packages the requirements actually pull in ship
                pkg = todo.pop()
                for dep in self.requires.get((pkg, chosen[pkg]), {}):
                    if dep not in reach:
                        reach[dep] = set()
                        todo.append(dep)
                    reach[dep].add(pkg)
            if all(Version(chosen[n]) in spec for n, spec in direct.items()) and all(
                Version(chosen[dep]) in SpecifierSet(spec)
                for (pkg, ver), deps in self.requires.items()
                if pkg in reach and chosen.get(pkg) == ver
                for dep, spec in deps.items()
            ):
                body = "".join(
                    f"{n}=={chosen[n]}  # via {', '.join(sorted(reach[n])) or '-r x'}\n"
                    "    # from https://pypi.org/simple\n"
                    for n in sorted(reach)
                )
                return parse_compile_output(body)
        raise CommandError(["uv", "pip", "compile"], 1, "error: No solution found")


class FakeAuditor:
    def __init__(self, vulnerable: dict[str, set[str]]) -> None:
        self.vulnerable = vulnerable

    def audit(self, pins: dict[str, str], label: str) -> list[Vulnerability]:
        return [Vulnerability(n, v, f"GHSA-{n}", "", "") for n, v in sorted(pins.items())
                if v in self.vulnerable.get(n, set())]


class FakeSources:
    def __init__(self, fixes: dict[str, str], universe: dict[str, list[str]]) -> None:
        self.fixes = fixes
        self.universe = universe

    def osv_records(self, package: str, version: str) -> list[dict[str, Any]]:
        return [{"id": f"GHSA-{package}", "affected": [{
            "package": {"name": package, "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": self.fixes[package]}]}],
        }]}]

    def releases(self, package: str) -> list[Release]:
        return [Release(Version(v)) for v in self.universe[package]]


def _remediate(
    tmp_path: Path,
    text: str,
    resolver: FakeResolver,
    vulnerable: dict[str, set[str]],
    fixes: dict[str, str],
    *,
    fmt: DependencyFormat = DependencyFormat.REQUIREMENTS_SIMPLE,
    name: str = "requirements.txt",
    auditor: Any = None,
    sources: Any = None,
    **option_kwargs: Any,
) -> Any:
    target = tmp_path / "proj"
    target.mkdir(exist_ok=True)
    manifest = target / name
    manifest.write_text(text)
    options = RemediationOptions(env=ENV, import_check=False, **option_kwargs)
    with patch.object(PipWorkspace, "compile", autospec=True, side_effect=resolver):
        return remediate_pip(
            uv="/usr/bin/uv", target_dir=target, manifest=manifest, fmt=fmt,
            work_dir=tmp_path / "work", auditor=auditor or FakeAuditor(vulnerable),
            options=options, sources=sources or FakeSources(fixes, resolver.universe),
            venv_name=".venv-upgrade", ignore_direct_references=False,
        )


class TestRemediatePip:
    def test_an_advisory_without_a_fix_does_not_block_the_other(self, tmp_path: Path) -> None:
        resolver = FakeResolver({"demo": ["2.0.0", "2.0.1", "2.1.0", "3.0.0"]}, {})
        outcome = _remediate(tmp_path, "demo==2.0.0\n", resolver, {}, {},
                             auditor=MixedAuditor(), sources=MixedSources())
        assert outcome.new_text == "demo==2.0.1\n"
        assert [v.cve for v in outcome.post_vulns] == ["GHSA-bbbb"]
        plan = outcome.plans["demo"]
        assert (plan.status, plan.target) == ("fix", "2.0.1")
        assert plan.open_advisories == {"GHSA-bbbb": "No fixed release available yet"}

    def test_floor_is_not_read_as_the_shipped_version(self, tmp_path: Path) -> None:
        """google-cloud-storage>=2.10.0 ships 3.17.1 and must stay there."""
        resolver = FakeResolver(
            {"urllib3": ["2.6.3", "2.8.0"], "google-cloud-storage": ["2.10.0", "2.19.0", "3.17.1"]},
            {},
        )
        text = "urllib3==2.6.3\ngoogle-cloud-storage>=2.10.0\n"
        outcome = _remediate(tmp_path, text, resolver, {"urllib3": {"2.6.3"}},
                             {"urllib3": "2.8.0"})
        assert outcome.baseline.pins["google-cloud-storage"] == "3.17.1"
        assert outcome.final.pins["google-cloud-storage"] == "3.17.1"
        assert outcome.new_text == "urllib3==2.8.0\ngoogle-cloud-storage>=2.10.0\n"
        assert outcome.post_vulns == []
        assert outcome.resolution_check.startswith("passed")

    def test_minimal_co_upgrade_of_a_blocking_pin(self, tmp_path: Path) -> None:
        """Starlette 1.x needs a newer FastAPI; take the lowest that works."""
        resolver = FakeResolver(
            {"fastapi": ["0.129.0", "0.133.0", "0.136.3", "0.162.0"],
             "starlette": ["0.52.1", "1.3.1", "1.10.0"]},
            {("fastapi", "0.129.0"): {"starlette": "<1.0"},
             ("fastapi", "0.133.0"): {"starlette": ">=0.40,<2"},
             ("fastapi", "0.136.3"): {"starlette": ">=0.40,<2"},
             ("fastapi", "0.162.0"): {"starlette": ">=1.5"}},
        )
        text = "fastapi==0.129.0\nstarlette==0.52.1\n"
        outcome = _remediate(tmp_path, text, resolver, {"starlette": {"0.52.1"}},
                             {"starlette": "1.3.1"}, allow_major=["starlette"])
        assert outcome.new_text == "fastapi==0.133.0\nstarlette==1.3.1\n"
        assert outcome.final.pins == {"fastapi": "0.133.0", "starlette": "1.3.1"}

    def test_major_co_upgrade_needs_permission(self, tmp_path: Path) -> None:
        resolver = FakeResolver(
            {"pyopenssl": ["25.3.0", "26.4.0"], "cryptography": ["46.0.5", "46.0.7"]},
            {("pyopenssl", "25.3.0"): {"cryptography": "<46.0.6"}},
        )
        text = "pyopenssl==25.3.0\ncryptography==46.0.5\n"
        outcome = _remediate(tmp_path, text, resolver, {"cryptography": {"46.0.5"}},
                             {"cryptography": "46.0.7"})
        assert outcome.new_text == text
        assert "cryptography" in outcome.failures

    def test_transitive_package_gets_a_commented_floor(self, tmp_path: Path) -> None:
        resolver = FakeResolver(
            {"requests": ["2.33.0"], "urllib3": ["2.6.3", "2.8.0"]},
            {("requests", "2.33.0"): {"urllib3": ">=1.21"}},
        )
        resolver_pref = FakeResolver(resolver.universe, resolver.requires)

        def biased(ws: PipWorkspace, manifest: Path, **kwargs: Any) -> Resolution:
            # an old build cache: the fresh resolution keeps urllib3 2.6.3 until a floor says no
            if "urllib3" not in manifest.read_text():
                kwargs["preferences"] = "urllib3==2.6.3\n"
            return resolver_pref(ws, manifest, **kwargs)

        biased.universe = resolver.universe  # type: ignore[attr-defined]
        outcome = _remediate(tmp_path, "requests==2.33.0\n", biased,  # type: ignore[arg-type]
                             {"urllib3": {"2.6.3"}}, {"urllib3": "2.8.0"})
        assert outcome.new_text == "requests==2.33.0\nurllib3>=2.8.0  # depfresh: GHSA-urllib3\n"

    def test_pyproject_cap_is_raised_in_place(self, tmp_path: Path) -> None:
        """A cap that keeps the vulnerable release is lifted to the next major only."""
        resolver = FakeResolver({"pypdf": ["6.21.0", "6.25.0", "7.0.0"]}, {})
        text = '[project]\nname = "x"\ndependencies = [\n    "pypdf>=6.21,<6.22",\n]\n'

        def capped(ws: PipWorkspace, manifest: Path, **kwargs: Any) -> Resolution:
            from depfresh.pipmode import PyprojectDocument

            listed = PyprojectDocument(manifest.read_text(), [], False).listed()
            req_file = manifest.with_name("as-requirements.txt")
            req_file.write_text("".join(f"{n}{s}\n" for n, s in listed.items()))
            return resolver(ws, req_file, **kwargs)

        capped.universe = resolver.universe  # type: ignore[attr-defined]
        outcome = _remediate(tmp_path, text, capped,  # type: ignore[arg-type]
                             {"pypdf": {"6.21.0"}}, {"pypdf": "6.25.0"},
                             fmt=DependencyFormat.PYPROJECT_PEP621, name="pyproject.toml")
        assert '"pypdf>=6.25.0,<7",' in outcome.new_text

    def test_direct_references_fail_closed(self, tmp_path: Path) -> None:
        resolver = FakeResolver({"six": ["1.17.0"]}, {})
        with pytest.raises(DirectReferenceError):
            _remediate(tmp_path, "six==1.17.0\n-e git+https://example.com/x.git#egg=x\n",
                       resolver, {}, {})

    def test_nothing_vulnerable_changes_nothing(self, tmp_path: Path) -> None:
        resolver = FakeResolver({"six": ["1.17.0"]}, {})
        outcome = _remediate(tmp_path, "six==1.17.0\n", resolver, {}, {})
        assert outcome.changed is False
        assert outcome.resolution_check == ""


class TestPipWorkspace:
    @pytest.fixture()
    def workspace(self, tmp_path: Path) -> PipWorkspace:
        target = tmp_path / "proj"
        (target / "reqs").mkdir(parents=True)
        (target / "reqs" / "base.txt").write_text("six==1.17.0\n")
        (target / "requirements.txt").write_text("-r reqs/base.txt\nidna==3.11\n")
        return PipWorkspace(
            "/usr/bin/uv", target, target / "requirements.txt",
            DependencyFormat.REQUIREMENTS_SIMPLE, tmp_path / "work",
            RemediationOptions(env=ENV), ignore_direct_references=False,
        )

    def test_includes_are_mirrored(self, workspace: PipWorkspace) -> None:
        assert (workspace.root / "reqs" / "base.txt").read_text() == "six==1.17.0\n"
        candidate = workspace.write("-r reqs/base.txt\nidna==3.15\n")
        assert (candidate.parent / "reqs" / "base.txt").is_file()

    def test_compile_targets_the_deploy_platform(self, workspace: PipWorkspace) -> None:
        result = MagicMock(stdout="idna==3.11  # via -r requirements.txt\n", stderr="")
        with patch("depfresh.pipmode.run", return_value=result) as mock:
            resolution = workspace.compile(workspace.write("idna==3.11\n"), record=True)
        cmd = mock.call_args.args[0]
        assert cmd[:3] == ["/usr/bin/uv", "pip", "compile"]
        assert cmd[cmd.index("--python-platform") + 1] == "x86_64-unknown-linux-gnu"
        assert cmd[cmd.index("--python-version") + 1] == "3.11"
        assert "--emit-index-annotation" in cmd
        assert mock.call_args.kwargs["cwd"] == workspace.target_dir
        assert resolution.pins == {"idna": "3.11"}
        assert workspace.commands[-1].startswith("uv pip compile requirements.txt")

    def test_unreachable_private_index(self, workspace: PipWorkspace) -> None:
        error = CommandError(
            ["uv"], 2,
            "error: Request failed after 3 retries\n  cause: Failed to fetch: "
            "http://127.0.0.1:9/simple/depfresh-private-probe/\n",
        )
        with patch("depfresh.pipmode.run", side_effect=error):
            with pytest.raises(PrivateIndexError, match="does not fall back to public PyPI"):
                workspace.compile(workspace.write("idna==3.11\n"))

    def test_include_outside_the_target_is_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "proj"
        target.mkdir()
        (tmp_path / "shared.txt").write_text("six==1.17.0\n")
        (target / "requirements.txt").write_text("-r ../shared.txt\n")
        with pytest.raises(Exception, match="outside"):
            PipWorkspace("/usr/bin/uv", target, target / "requirements.txt",
                         DependencyFormat.REQUIREMENTS_SIMPLE, tmp_path / "work",
                         RemediationOptions(env=ENV), ignore_direct_references=False)


class TestIgnoredDirectReferences:
    def test_pyproject_url_requirements_are_dropped_for_resolution(self) -> None:
        text = dedent("""\
            [project]
            name = "x"
            dependencies = ["flask>=2.3.0", "demo @ https://example.com/demo-1.0.tar.gz"]

            [project.optional-dependencies]
            extra = ["other @ git+https://example.com/other.git", "six"]
        """)
        data = tomllib.loads(strip_pyproject_direct_refs(text))
        assert data["project"]["dependencies"] == ["flask>=2.3.0"]
        assert data["project"]["optional-dependencies"]["extra"] == ["six"]

    def test_requirements_direct_refs_are_dropped_for_resolution(self, tmp_path: Path) -> None:
        target = tmp_path / "proj"
        target.mkdir()
        text = "six==1.17.0\n-e git+https://example.com/x.git#egg=x\n./local/pkg\n"
        (target / "requirements.txt").write_text(text)
        ws = PipWorkspace("/usr/bin/uv", target, target / "requirements.txt",
                          DependencyFormat.REQUIREMENTS_SIMPLE, tmp_path / "work",
                          RemediationOptions(env=ENV), ignore_direct_references=True)
        assert ws.write(text).read_text() == "six==1.17.0\n"



class TestMarkerSplitLines:
    """The same package on several lines: edit the one that applies, or refuse."""

    SPLIT = 'numpy==1.24.4; python_version < "3.9"\nnumpy==1.26.0; python_version >= "3.9"\n'

    def test_only_the_applicable_line_is_edited(self) -> None:
        doc = RequirementsDocument(self.SPLIT, env=ENV)
        assert doc.listed() == {"numpy": "==1.26.0"}
        doc.set_spec("numpy", "==1.26.4")
        assert doc.render() == (
            'numpy==1.24.4; python_version < "3.9"\nnumpy==1.26.4; python_version >= "3.9"\n'
        )

    def test_without_a_target_both_lines_apply(self) -> None:
        with pytest.raises(AmbiguousRequirementError, match="lines 1, 2"):
            RequirementsDocument(self.SPLIT).set_spec("numpy", "==1.26.4")

    def test_case_variants_are_ambiguous(self) -> None:
        doc = RequirementsDocument("Jinja2==3.1.2\njinja2==3.1.2\n", env=ENV)
        assert "jinja2" in doc.ambiguous
        assert "jinja2" not in doc.listed()
        with pytest.raises(AmbiguousRequirementError):
            doc.set_spec("jinja2", "==3.1.4")

    def test_remediation_edits_the_line_that_ships(self, tmp_path: Path) -> None:
        resolver = FakeResolver({"numpy": ["1.24.4", "1.26.0", "1.26.4"]}, {})
        outcome = _remediate(tmp_path, self.SPLIT, resolver, {"numpy": {"1.26.0"}},
                             {"numpy": "1.26.4"})
        assert outcome.new_text == (
            'numpy==1.24.4; python_version < "3.9"\nnumpy==1.26.4; python_version >= "3.9"\n'
        )
        assert outcome.post_vulns == []

    def test_remediation_refuses_an_ambiguous_package(self, tmp_path: Path) -> None:
        resolver = FakeResolver({"jinja2": ["3.1.2", "3.1.4"]}, {})
        with pytest.raises(AmbiguousRequirementError):
            _remediate(tmp_path, "Jinja2==3.1.2\njinja2==3.1.2\n", resolver,
                       {"jinja2": {"3.1.2"}}, {"jinja2": "3.1.4"})
        assert (tmp_path / "proj" / "requirements.txt").read_text() == (
            "Jinja2==3.1.2\njinja2==3.1.2\n"
        )

    def test_latest_strategy_refuses_an_ambiguous_package(self, tmp_path: Path) -> None:
        from depfresh.parsers import RequirementsSimpleHandler

        req = tmp_path / "requirements.txt"
        req.write_text("Jinja2==3.1.2\njinja2==3.1.2\nsix==1.16.0\n")
        with pytest.raises(AmbiguousRequirementError):
            RequirementsSimpleHandler().write({"jinja2": "3.1.4", "six": "1.17.0"}, req)
        assert req.read_text() == "Jinja2==3.1.2\njinja2==3.1.2\nsix==1.16.0\n"


class TestContinuationEdits:
    def test_spec_on_a_continuation_line(self) -> None:
        doc = RequirementsDocument("requests \\\n    >=2.0\nsix==1.16\n", env=ENV)
        doc.set_spec("requests", ">=2.32.0")
        assert doc.render() == "requests >=2.32.0\nsix==1.16\n"

    def test_marker_on_a_hash_continuation_line_is_kept(self) -> None:
        text = (
            "pywin32==306 \\\n"
            '    ; sys_platform == "linux" \\\n'
            "    --hash=sha256:aaa\n"
            "six==1.16.0 \\\n"
            "    --hash=sha256:ccc\n"
        )
        doc = RequirementsDocument(text, env=ENV)
        doc.set_spec("pywin32", "==311", ["sha256:new"])
        assert doc.render() == (
            'pywin32==311 ; sys_platform == "linux" \\\n'
            "    --hash=sha256:new\n"
            "six==1.16.0 \\\n"
            "    --hash=sha256:ccc\n"
        )

    def test_comment_ending_in_backslash_keeps_the_next_entry(self) -> None:
        text = (
            "requests==2.25.0 \\\n"
            "    --hash=sha256:aaa\n"
            "idna==2.10  # pinned, see C:\\notes\\\n"
            "urllib3==1.26.0 \\\n"
            "    --hash=sha256:bbb\n"
        )
        doc = RequirementsDocument(text, env=ENV)
        assert set(doc.listed()) == {"requests", "idna", "urllib3"}
        doc.set_spec("idna", "==3.7", ["sha256:new1"])
        assert doc.render() == (
            "requests==2.25.0 \\\n"
            "    --hash=sha256:aaa\n"
            "idna==3.7  # pinned, see C:\\notes\\\n"
            "urllib3==1.26.0 \\\n"
            "    --hash=sha256:bbb\n"
        )



class TestHashedNewDependencies:
    """pip --require-hashes needs every package pinned: a fix's new dependency too."""

    def test_new_dependency_is_pinned_with_hashes(self, tmp_path: Path) -> None:
        universe = {"aiohttp": ["3.9.0", "3.10.11"], "yarl": ["1.9.0"],
                    "aiohappyeyeballs": ["2.4.0"]}
        requires = {("aiohttp", "3.9.0"): {"yarl": ">=1.0"},
                    ("aiohttp", "3.10.11"): {"yarl": ">=1.0", "aiohappyeyeballs": ">=2.3"}}
        text = ("aiohttp==3.9.0 \\\n    --hash=sha256:old-a\n    # via -r requirements.in\n"
                "yarl==1.9.0 \\\n    --hash=sha256:old-y\n    # via aiohttp\n")

        def fake_hashes(ws: PipWorkspace, pins: dict[str, str]) -> dict[str, list[str]]:
            return {n: [f"sha256:{n}-{v}"] for n, v in pins.items()}

        with patch.object(PipWorkspace, "hashes", fake_hashes):
            outcome = _remediate(tmp_path, text, FakeResolver(universe, requires),
                                 {"aiohttp": {"3.9.0"}}, {"aiohttp": "3.10.11"},
                                 fmt=DependencyFormat.REQUIREMENTS_HASHED)
        assert outcome.new_text == (
            "aiohttp==3.10.11 \\\n    --hash=sha256:aiohttp-3.10.11\n"
            "    # via -r requirements.in\n"
            "yarl==1.9.0 \\\n    --hash=sha256:old-y\n    # via aiohttp\n"
            "aiohappyeyeballs==2.4.0 \\\n    --hash=sha256:aiohappyeyeballs-2.4.0\n"
            "    # depfresh: required by aiohttp\n"
        )
        # the file is complete for the final resolution
        listed = set(RequirementsDocument(outcome.new_text, env=ENV).listed())
        assert set(outcome.final.pins) <= listed
