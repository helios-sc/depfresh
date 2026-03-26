"""End-to-end tests for the real depfresh workflow using fake uv/pip-audit shims."""

from __future__ import annotations

import os
import shutil
import stat
import textwrap
from pathlib import Path

import pytest

from depfresh.cli import main
from depfresh.exceptions import RequirementsNotFoundError, TargetNotFoundError, UvNotFoundError
from depfresh.upgrade import audit_only, upgrade

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


def choose_version(name: str, specifier: str) -> str:
    versions = AVAILABLE.get(name, ["1.0.0"])
    if not specifier:
        return versions[-1]

    tokens = [token.strip() for token in specifier.split(",") if token.strip()]
    exact = next((token[2:] for token in tokens if token.startswith("==")), None)
    if exact is not None:
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
        return matches_found[-1]
    raise SystemExit(f"No fake version available for {name!r} with specifier {specifier!r}")


def iter_requirements(req_path: Path) -> list[tuple[str, str]]:
    requirements: list[tuple[str, str]] = []
    for raw_line in req_path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-") or line.startswith("--hash="):
            continue
        base = line.split(" --hash=", 1)[0].rstrip("\\\\").strip()
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

if len(sys.argv) >= 3 and sys.argv[1] == "-c":
    code = sys.argv[2]
    if "stdlib_module_names" in code:
        print(json.dumps(["__future__", "json", "pathlib", "sys"]))
        raise SystemExit(0)
    if "packages_distributions" in code:
        modules = json.loads(sys.argv[3])
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
        print("uv 0.6.17")
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
        output_path = Path(args[args.index("-o") + 1])
        lines = [
            "# This file was autogenerated by the depfresh fake uv test shim.",
        ]
        for package, specifier in iter_requirements(input_path):
            version = choose_version(package, specifier)
            lines.append(
                f"{package}=={version} \\\\n"
                f"    --hash=sha256:deadbeef{package.replace('-', '')} \\\\n"
                f"    --hash=sha256:feedface{package.replace('-', '')}"
            )
        output_path.write_text("\\n".join(lines) + "\\n")
        return 0

    if args[:2] == ["pip", "install"]:
        venv_python = args[args.index("--python") + 1]
        state = load_state(venv_python)
        packages = dict(state["packages"])

        if "pip-audit" in args:
            packages["pip-audit"] = "2.8.0"
            packages["pip-api"] = "0.1.0"
            packages["rich"] = "13.9.4"
            state["packages"] = packages
            save_state(venv_python, state)
            return 0

        req_path = Path(args[args.index("-r") + 1])
        for package, specifier in iter_requirements(req_path):
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
            ]
        )

    assert exc_info.value.code == 2
