"""End-to-end tests for the real depfresh workflow using fake uv/pip-audit shims."""

from __future__ import annotations

import os
import shutil
import stat
import sys
import textwrap
from pathlib import Path

import pytest
from packaging.version import Version

from depfresh.advisories import Release
from depfresh.cli import main
from depfresh.exceptions import RequirementsNotFoundError, TargetNotFoundError, UvNotFoundError
from depfresh.upgrade import audit_only, upgrade

_upgrade_mod = sys.modules["depfresh.upgrade"]

_FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "sample_projects"
_SAMPLE_CASES = [
    ("01_requirements_simple", "requirements.txt", "packaging==23.3"),
    ("02_requirements_hashed", "requirements.txt", "packaging==23.3"),
    ("03_requirements_in", "requirements.in", "packaging>=26.1"),
    ("04_pyproject_pep621", "pyproject.toml", '"packaging>=26.1"'),
    ("05_pyproject_poetry", "pyproject.toml", 'packaging = "^23.3"'),
    ("06_pipfile", "Pipfile", 'packaging = "==23.3"'),
]

_FAKE_UV = """\
#!/usr/bin/env python3
import json
import re
import stat
import sys
from pathlib import Path


AVAILABLE = {
    "click": ["8.3.1"],
    "packaging": ["23.2", "23.3", "25.0", "26.0", "26.1"],
    "pip-audit": ["2.8.0"],
    "pip-api": ["0.1.0"],
    "rich": ["13.9.4"],
}


def normalise(name: str) -> str:
    return name.replace("_", "-").replace(".", "-").lower()


def state_path_from_python(venv_python: str) -> Path:
    return Path(venv_python).resolve().parent.parent / ".depfresh_fake_state.json"


def load_state(venv_python: str) -> dict[str, object]:
    return json.loads(state_path_from_python(venv_python).read_text())


def save_state(venv_python: str, state: dict[str, object]) -> None:
    state_path_from_python(venv_python).write_text(json.dumps(state, indent=2, sort_keys=True))


def version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def parse_requirement(line: str) -> tuple[str, str]:
    base = line.split(";", 1)[0].strip()
    match = re.match(r"^([A-Za-z0-9_.-]+)(?:\\[[^\\]]+\\])?(.*)$", base)
    if match is None:
        raise SystemExit(f"Unsupported fake requirement line: {line!r}")
    return normalise(match.group(1)), match.group(2).strip()


def choose_version(
    name: str, specifier: str, lowest: bool = False, preferred: str | None = None,
) -> str:
    versions = AVAILABLE.get(name, ["1.0.0"])
    if preferred is not None and preferred in versions:
        # an existing output file is a preference, kept whenever it still fits
        try:
            return choose_version(name, f"{specifier},=={preferred}" if specifier else
                                  f"=={preferred}", lowest)
        except SystemExit:
            pass
    if not specifier:
        return versions[0] if lowest else versions[-1]

    tokens = [token.strip() for token in specifier.split(",") if token.strip()]
    exacts = {token[2:] for token in tokens if token.startswith("==")}
    if len(exacts) > 1:
        raise SystemExit(f"Conflicting pins for {name!r}: {sorted(exacts)}")
    exact = next(iter(exacts), None)
    if exact is not None:
        if any(
            token.startswith(">=") and version_tuple(exact) < version_tuple(token[2:])
            for token in tokens
        ):
            raise SystemExit(f"No fake version available for {name!r}: {specifier!r}")
        return exact

    def matches(version: str) -> bool:
        current = version_tuple(version)
        for token in tokens:
            if token.startswith(">=") and current < version_tuple(token[2:]):
                return False
            if (
                token.startswith("<")
                and not token.startswith("<=")
                and current >= version_tuple(token[1:])
            ):
                return False
        return True

    matches_found = [version for version in versions if matches(version)]
    if matches_found:
        return matches_found[0] if lowest else matches_found[-1]
    raise SystemExit(f"No fake version available for {name!r} with specifier {specifier!r}")


def iter_requirements(req_path: Path, extras: list[str] | None = None,
                      all_extras: bool = False) -> list[tuple[str, str]]:
    requirements: list[tuple[str, str]] = []
    if req_path.name == "pyproject.toml":
        try:
            import tomllib
        except ImportError:  # Python 3.10
            import tomli as tomllib

        project = tomllib.loads(req_path.read_text()).get("project", {})
        lines = list(project.get("dependencies", []))
        for group, deps in project.get("optional-dependencies", {}).items():
            if all_extras or group in (extras or []):
                lines += deps
        for line in lines:
            if " @ " not in line:
                requirements.append(parse_requirement(line))
        return requirements
    for raw_line in req_path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-") or line.startswith("--hash="):
            continue
        base = line.split(" --hash=", 1)[0].split("  #", 1)[0].rstrip("\\\\").strip()
        if not base or base.startswith("#") or base.startswith("--hash="):
            continue
        requirements.append(parse_requirement(base))
    return requirements


def write_fake_python(venv_root: Path, python_version: str) -> None:
    script = f'''#!/usr/bin/env python3
import json
import sys
from pathlib import Path

state_path = Path(__file__).resolve().parent.parent / ".depfresh_fake_state.json"
state = json.loads(state_path.read_text())

if sys.argv[1:] == ["--version"]:
    print("Python {python_version}.9")
    raise SystemExit(0)

argv = [arg for arg in sys.argv[1:] if arg not in ("-I", "-S")]
if argv[:2] == ["-m", "pip_audit"]:
    import os
    pip_audit = str(Path(__file__).resolve().parent / "pip-audit")
    os.execv(pip_audit, [pip_audit, *argv[2:]])

if len(argv) >= 2 and argv[0] == "-c":
    code = argv[1]
    if "stdlib_module_names" in code:
        print(json.dumps(["__future__", "json", "pathlib", "sys"]))
        raise SystemExit(0)
    if "find_spec" in code:
        modules = json.loads(argv[2])
        installed = set(state["packages"])
        results = {{}}
        for mod in modules:
            top = mod.split(".")[0]
            results[mod] = None if top in installed else f"No module named '{{mod}}'"
        print(json.dumps({{"results": results, "warnings": {{}}}}))
        raise SystemExit(0)

raise SystemExit(1)
'''
    python_path = venv_root / "bin" / "python"
    python_path.write_text(script)
    python_path.chmod(stat.S_IRWXU)


def write_fake_pip_audit(venv_root: Path) -> None:
    script = '''#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def normalise(name: str) -> str:
    return name.replace("_", "-").replace(".", "-").lower()


if "--version" in sys.argv:
    print("pip-audit 2.8.0")
    raise SystemExit(0)

req_index = sys.argv.index("-r") + 1
req_path = Path(sys.argv[req_index])
dependencies = []
has_vulns = False

for raw_line in req_path.read_text().splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#") or line.startswith("--hash="):
        continue
    base = line.split(" --hash=", 1)[0].rstrip(chr(92)).strip()
    if "==" not in base:
        continue
    name, version = base.split("==", 1)
    name = normalise(name)
    vulns = []
    if name == "packaging" and version.startswith("23.2"):
        vulns = [{
            "id": "PYSEC-2026-0001",
            "aliases": ["CVE-2026-0001"],
            "fix_versions": ["23.3"],
            "description": "Synthetic vulnerability used by the depfresh end-to-end tests.",
        }]
        has_vulns = True
    dependencies.append({"name": name, "version": version, "vulns": vulns})

print(json.dumps({"dependencies": dependencies, "fixes": []}))
raise SystemExit(1 if has_vulns else 0)
'''
    pip_audit_path = venv_root / "bin" / "pip-audit"
    pip_audit_path.write_text(script)
    pip_audit_path.chmod(stat.S_IRWXU)


def create_fake_venv(venv_root: Path, python_version: str) -> None:
    (venv_root / "bin").mkdir(parents=True, exist_ok=True)
    state = {
        "python_version": python_version,
        "packages": {},
    }
    state_path = venv_root / ".depfresh_fake_state.json"
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True))
    write_fake_python(venv_root, python_version)
    write_fake_pip_audit(venv_root)


def main() -> int:
    args = sys.argv[1:]
    if args == ["--version"]:
        print("uv 0.13.6 (fake)")
        return 0

    if args[:1] == ["venv"]:
        venv_root = Path(args[1])
        python_version = args[args.index("--python") + 1]
        venv_root.mkdir(parents=True, exist_ok=True)
        create_fake_venv(venv_root, python_version)
        return 0

    if args[:2] == ["pip", "freeze"]:
        venv_python = args[args.index("--python") + 1]
        state = load_state(venv_python)
        for name, version in sorted(state["packages"].items()):
            print(f"{name}=={version}")
        return 0

    if args[:2] == ["pip", "compile"]:
        input_path = Path(args[2])
        output_path = Path(args[args.index("-o") + 1]) if "-o" in args else None
        extras = [args[i + 1] for i, a in enumerate(args) if a == "--extra"]
        reqs = iter_requirements(input_path, extras, "--all-extras" in args)
        if "--generate-hashes" in args:
            bs = chr(92)
            lines = [
                "# This file was autogenerated by the depfresh fake uv test shim.",
            ]
            for package, specifier in reqs:
                version = choose_version(package, specifier)
                flat = package.replace("-", "")
                lines.append(f"{package}=={version} {bs}")
                lines.append(f"    --hash=sha256:deadbeef{flat}{version} {bs}")
                lines.append(f"    --hash=sha256:feedface{flat}{version}")
            text = chr(10).join(lines) + chr(10)
        else:
            preferences = {}
            if output_path is not None and output_path.exists():
                for package, specifier in iter_requirements(output_path):
                    preferences[package] = specifier.lstrip("=")
            merged = {}
            for package, specifier in reqs:
                merged[package] = ",".join(x for x in (merged.get(package), specifier) if x)
            lines = []
            for package, specifier in sorted(merged.items()):
                version = choose_version(
                    package, specifier, "lowest-direct" in args, preferences.get(package),
                )
                lines.append(f"{package}=={version}  # via -r {input_path.name}")
                if "--emit-index-annotation" in args:
                    lines.append("    # from https://pypi.org/simple")
            text = chr(10).join(lines) + chr(10)
        if output_path is not None:
            output_path.write_text(text)
        else:
            sys.stdout.write(text)
        return 0

    if args[:2] == ["pip", "install"]:
        venv_python = args[args.index("--python") + 1]
        state = load_state(venv_python)
        packages = dict(state["packages"])

        if any(arg.startswith("pip-audit") for arg in args):
            packages["pip-audit"] = "2.8.0"
            packages["pip-api"] = "0.1.0"
            packages["rich"] = "13.9.4"
            state["packages"] = packages
            save_state(venv_python, state)
            return 0

        req_path = Path(args[args.index("-r") + 1])
        extras = [args[i + 1] for i, a in enumerate(args) if a == "--extra"]
        for package, specifier in iter_requirements(req_path, extras, "--all-extras" in args):
            packages[package] = choose_version(package, specifier)
        state["packages"] = packages
        save_state(venv_python, state)
        return 0

    raise SystemExit(f"Unsupported fake uv invocation: {args!r}")


if __name__ == "__main__":
    raise SystemExit(main())
"""


def _write_executable(path: Path, content: str) -> None:
    path.write_text(textwrap.dedent(content))
    path.chmod(stat.S_IRWXU)


def _install_fake_uv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    uv_path = fake_bin / "uv"
    _write_executable(uv_path, _FAKE_UV)
    current_path = os.environ.get("PATH", os.defpath)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{current_path}")
    return uv_path


def _copy_sample_project(tmp_path: Path, case_name: str) -> Path:
    source = _FIXTURE_ROOT / case_name
    destination = tmp_path / case_name
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns("__pycache__", ".venv*", "reports*"),
    )
    return destination


@pytest.mark.parametrize(("case_name", "dep_file", "expected_text"), _SAMPLE_CASES)
def test_cli_end_to_end_on_sample_projects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case_name: str,
    dep_file: str,
    expected_text: str,
) -> None:
    _install_fake_uv(tmp_path, monkeypatch)
    project_dir = _copy_sample_project(tmp_path, case_name)
    reports_dir = tmp_path / "reports"

    main(
        [
            str(project_dir),
            "--label",
            case_name,
            "--reports-dir",
            str(reports_dir),
            "--python",
            "3.11",
            "--strategy",
            "latest",
        ]
    )

    dep_path = project_dir / dep_file
    content = dep_path.read_text()
    assert expected_text in content
    if case_name == "02_requirements_hashed":
        assert "--hash=" in content

    report_dir = reports_dir / case_name
    log_files = list(report_dir.glob("*_dependency_upgrade.log"))
    markdown_files = list(report_dir.glob("*_DEPENDENCY_UPGRADE_PR.md"))
    assert len(log_files) == 1
    assert len(markdown_files) == 1
    assert "Import Verification" in markdown_files[0].read_text()
    assert "No known vulnerabilities found." in log_files[0].read_text()


def test_audit_only_end_to_end_reports_initial_vulnerability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_uv(tmp_path, monkeypatch)
    _fake_advisories(monkeypatch)
    project_dir = _copy_sample_project(tmp_path, "01_requirements_simple")

    result = audit_only(project_dir)

    assert len(result.pre_audit_vulns) == 1
    assert result.pre_audit_vulns[0].package == "packaging"
    assert result.pre_audit_vulns[0].cve == "CVE-2026-0001"


def test_runtime_scope_excludes_optional_groups_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_uv(tmp_path, monkeypatch)
    project_dir = _copy_sample_project(tmp_path, "07_pyproject_pep621_optional")
    reports_dir = tmp_path / "reports"

    main(
        [
            str(project_dir),
            "--label",
            "07_pyproject_pep621_optional",
            "--reports-dir",
            str(reports_dir),
            "--python",
            "3.11",
            "--strategy",
            "latest",
        ]
    )

    content = (project_dir / "pyproject.toml").read_text()
    assert '"packaging>=23.2"' in content


def test_all_scope_includes_optional_groups(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_uv(tmp_path, monkeypatch)
    project_dir = _copy_sample_project(tmp_path, "07_pyproject_pep621_optional")
    reports_dir = tmp_path / "reports"

    main(
        [
            str(project_dir),
            "--label",
            "07_pyproject_pep621_optional",
            "--reports-dir",
            str(reports_dir),
            "--python",
            "3.11",
            "--dependency-scope",
            "all",
            "--strategy",
            "latest",
        ]
    )

    content = (project_dir / "pyproject.toml").read_text()
    assert '"packaging>=26.1"' in content


def test_direct_references_fail_closed_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_uv(tmp_path, monkeypatch)
    project_dir = _copy_sample_project(tmp_path, "08_pyproject_pep621_direct_ref")
    reports_dir = tmp_path / "reports"

    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                str(project_dir),
                "--label",
                "08_pyproject_pep621_direct_ref",
                "--reports-dir",
                str(reports_dir),
                "--python",
                "3.11",
            ]
        )

    assert exc_info.value.code == 1


def test_ignore_direct_references_flag_allows_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_uv(tmp_path, monkeypatch)
    project_dir = _copy_sample_project(tmp_path, "08_pyproject_pep621_direct_ref")
    reports_dir = tmp_path / "reports"

    main(
        [
            str(project_dir),
            "--label",
            "08_pyproject_pep621_direct_ref",
            "--reports-dir",
            str(reports_dir),
            "--python",
            "3.11",
            "--ignore-direct-references",
            "--strategy",
            "latest",
        ]
    )

    content = (project_dir / "pyproject.toml").read_text()
    assert "demo @ https://example.com/demo-1.0.tar.gz" in content
    report_dir = reports_dir / "08_pyproject_pep621_direct_ref"
    report = next(report_dir.glob("*_DEPENDENCY_UPGRADE_PR.md"))
    assert "Ignored Direct References" in report.read_text()


# ---------------------------------------------------------------------------
# Negative / failure-path E2E tests
# ---------------------------------------------------------------------------


def test_missing_uv_binary_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ``uv`` is not on PATH, upgrade() must raise UvNotFoundError."""
    project_dir = _copy_sample_project(tmp_path, "01_requirements_simple")
    # Set PATH to an empty directory so uv is not found
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    monkeypatch.setenv("PATH", str(empty_bin))

    with pytest.raises(UvNotFoundError):
        upgrade(project_dir)


def test_missing_target_dir_raises() -> None:
    """A non-existent target directory must raise TargetNotFoundError."""
    with pytest.raises(TargetNotFoundError):
        upgrade("/nonexistent/path/that/does/not/exist")


def test_empty_project_raises(tmp_path: Path) -> None:
    """A directory with no dependency files must raise RequirementsNotFoundError."""
    with pytest.raises(RequirementsNotFoundError):
        upgrade(tmp_path)


def test_cli_missing_uv_exits_1(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLI must exit(1) when uv is not available."""
    project_dir = _copy_sample_project(tmp_path, "01_requirements_simple")
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    monkeypatch.setenv("PATH", str(empty_bin))

    with pytest.raises(SystemExit) as exc_info:
        main([str(project_dir)])
    assert exc_info.value.code == 1


def test_resolution_failure_does_not_modify_dep_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When uv resolution fails, the original dependency file must be untouched."""
    _install_fake_uv(tmp_path, monkeypatch)
    project_dir = _copy_sample_project(tmp_path, "01_requirements_simple")
    dep_file = project_dir / "requirements.txt"
    original_content = dep_file.read_text()

    # Inject a package that the fake uv can't resolve
    dep_file.write_text(original_content + "nonexistent-pkg-xyz==99.99.99\n")

    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                str(project_dir),
                "--label", "fail_test",
                "--reports-dir", str(tmp_path / "reports"),
                "--python", "3.11",
                "--strategy", "latest",
            ]
        )

    assert exc_info.value.code == 1


def test_remaining_vulns_exit_code_2(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When vulnerabilities remain after upgrade, CLI must exit(2).

    This uses --keep-version to pin the vulnerable package so the vuln persists.
    """
    _install_fake_uv(tmp_path, monkeypatch)
    project_dir = _copy_sample_project(tmp_path, "01_requirements_simple")

    # Replace packaging version with the one that has a synthetic vulnerability
    dep_file = project_dir / "requirements.txt"
    dep_file.write_text("packaging==23.2\nclick==8.3.1\n")

    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                str(project_dir),
                "--label", "vuln_test",
                "--reports-dir", str(tmp_path / "reports"),
                "--python", "3.11",
                "--keep-version", "packaging",
                "--strategy", "latest",
            ]
        )

    assert exc_info.value.code == 2



# ---------------------------------------------------------------------------
# Minimal strategy (the default): resolved for the deploy platform
# ---------------------------------------------------------------------------


class _FakeAdvisories:
    """OSV/PyPI stand-in: packaging 23.2 is vulnerable, fixed in 23.3."""

    def osv_records(self, package: str, version: str) -> list[dict[str, object]]:
        if package != "packaging":
            return []
        return [{
            "id": "PYSEC-2026-0001",
            "aliases": ["CVE-2026-0001"],
            "affected": [{
                "package": {"name": "packaging", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM",
                            "events": [{"introduced": "23.2"}, {"fixed": "23.3"}]}],
            }],
        }]

    def releases(self, package: str) -> list[Release]:
        versions = {"packaging": ["23.2", "23.3", "25.0", "26.0", "26.1"]}.get(package, [])
        return [Release(Version(v)) for v in versions]


def _fake_advisories(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_upgrade_mod, "default_sources", _FakeAdvisories)


def _run_minimal(tmp_path: Path, project_dir: Path, *extra: str) -> int:
    try:
        main([str(project_dir), "--label", project_dir.name,
              "--reports-dir", str(tmp_path / "reports"), "--python", "3.11", *extra])
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def _markdown(tmp_path: Path, label: str) -> str:
    return next((tmp_path / "reports" / label).glob("*_DEPENDENCY_UPGRADE_PR.md")).read_text()


def test_minimal_moves_only_the_vulnerable_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_uv(tmp_path, monkeypatch)
    _fake_advisories(monkeypatch)
    project_dir = _copy_sample_project(tmp_path, "01_requirements_simple")

    assert _run_minimal(tmp_path, project_dir) == 0

    assert (project_dir / "requirements.txt").read_text() == "click==8.3.1\npackaging==23.3\n"
    report = _markdown(tmp_path, project_dir.name)
    assert "resolved for the deploy platform" in report
    assert "| packaging | 23.2 | 23.3 | minor |" in report
    assert "uv pip compile requirements.txt --python-platform x86_64-unknown-linux-gnu" in report


def test_minimal_regenerates_hashes_of_the_moved_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_uv(tmp_path, monkeypatch)
    _fake_advisories(monkeypatch)
    project_dir = _copy_sample_project(tmp_path, "02_requirements_hashed")
    original = (project_dir / "requirements.txt").read_text()

    assert _run_minimal(tmp_path, project_dir) == 0

    content = (project_dir / "requirements.txt").read_text()
    assert "packaging==23.3 \\\n    --hash=sha256:deadbeefpackaging23.3" in content
    assert "048fb0e9405036518eaaf48a55953c750c11e1a1b68e0dd1a9d62ed0c092cfc5" not in content
    # click's block and the header comments are untouched
    click_block = original.split("packaging==23.2")[0]
    assert content.startswith(click_block)


@pytest.mark.parametrize(
    ("case_name", "dep_file"),
    [("03_requirements_in", "requirements.in"), ("04_pyproject_pep621", "pyproject.toml")],
)
def test_minimal_leaves_floors_that_resolve_to_fixed_versions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case_name: str, dep_file: str,
) -> None:
    """packaging>=23.2 ships 26.1 today: the floor is not the version that ships."""
    _install_fake_uv(tmp_path, monkeypatch)
    _fake_advisories(monkeypatch)
    project_dir = _copy_sample_project(tmp_path, case_name)
    original = (project_dir / dep_file).read_text()

    assert _run_minimal(tmp_path, project_dir) == 0

    assert (project_dir / dep_file).read_text() == original
    assert "No package versions changed." in _markdown(tmp_path, project_dir.name)


def test_minimal_keep_version_exits_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_uv(tmp_path, monkeypatch)
    _fake_advisories(monkeypatch)
    project_dir = _copy_sample_project(tmp_path, "01_requirements_simple")

    assert _run_minimal(tmp_path, project_dir, "--keep-version", "packaging") == 2
    assert (project_dir / "requirements.txt").read_text() == "click==8.3.1\npackaging==23.2\n"


def test_minimal_audit_only_exits_2_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    _install_fake_uv(tmp_path, monkeypatch)
    _fake_advisories(monkeypatch)
    project_dir = _copy_sample_project(tmp_path, "01_requirements_simple")

    assert _run_minimal(tmp_path, project_dir, "--audit-only") == 2
    out = capsys.readouterr().out
    assert "packaging 23.2 -> 23.3 [planned]" in out
    assert (project_dir / "requirements.txt").read_text() == "click==8.3.1\npackaging==23.2\n"


def test_minimal_refuses_poetry_with_a_clear_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    _install_fake_uv(tmp_path, monkeypatch)
    project_dir = _copy_sample_project(tmp_path, "05_pyproject_poetry")

    assert _run_minimal(tmp_path, project_dir) == 1
    assert "--strategy latest" in capsys.readouterr().err


def test_minimal_direct_references_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_uv(tmp_path, monkeypatch)
    project_dir = _copy_sample_project(tmp_path, "08_pyproject_pep621_direct_ref")
    assert _run_minimal(tmp_path, project_dir) == 1
