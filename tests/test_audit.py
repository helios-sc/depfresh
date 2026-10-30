"""Tests for audit module — pip-audit JSON parsing."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from depfresh.audit import (
    PIP_AUDIT_REQUIREMENT,
    _parse_pip_audit_json,
    audit_command,
    install_pip_audit,
    run_audit,
    write_pinned_requirements,
)
from depfresh.exceptions import AuditError


class TestParsePipAuditJson:
    def test_parses_single_vulnerability(self) -> None:
        data = [
            {
                "name": "urllib3",
                "version": "2.0.4",
                "vulns": [
                    {
                        "id": "CVE-2023-43804",
                        "fix_versions": ["2.0.6"],
                        "description": "Improper handling of headers",
                    }
                ],
            }
        ]
        vulns = _parse_pip_audit_json(json.dumps(data))
        assert len(vulns) == 1
        assert vulns[0].package == "urllib3"
        assert vulns[0].version == "2.0.4"
        assert vulns[0].cve == "CVE-2023-43804"
        assert vulns[0].fix_versions == "2.0.6"
        assert "Improper" in vulns[0].description

    def test_parses_multiple_packages(self) -> None:
        data = [
            {
                "name": "urllib3",
                "version": "2.0.4",
                "vulns": [{"id": "CVE-2023-43804", "fix_versions": ["2.0.6"], "description": "A"}],
            },
            {
                "name": "certifi",
                "version": "2023.7",
                "vulns": [
                    {"id": "CVE-2023-37920", "fix_versions": ["2023.7.22"], "description": "B"},
                ],
            },
        ]
        vulns = _parse_pip_audit_json(json.dumps(data))
        assert len(vulns) == 2
        assert vulns[1].package == "certifi"

    def test_empty_output_returns_empty_list(self) -> None:
        assert _parse_pip_audit_json("") == []

    def test_invalid_json_returns_empty_list(self) -> None:
        assert _parse_pip_audit_json("No known vulnerabilities found") == []

    def test_no_vulnerabilities(self) -> None:
        data = [{"name": "flask", "version": "2.3.0", "vulns": []}]
        assert _parse_pip_audit_json(json.dumps(data)) == []

    def test_truncates_long_descriptions(self) -> None:
        long_desc = "A" * 200
        data = [
            {
                "name": "urllib3",
                "version": "2.0.4",
                "vulns": [
                    {"id": "CVE-2023-001", "fix_versions": ["2.0.6"], "description": long_desc},
                ],
            }
        ]
        vulns = _parse_pip_audit_json(json.dumps(data))
        assert len(vulns) == 1
        assert vulns[0].description.endswith("...")
        assert len(vulns[0].description) == 123  # 120 + "..."

    def test_multiple_fix_versions_joined(self) -> None:
        data = [
            {
                "name": "pkg",
                "version": "1.0.0",
                "vulns": [
                    {"id": "CVE-2023-001", "fix_versions": ["1.0.1", "2.0.0"], "description": "x"},
                ],
            }
        ]
        vulns = _parse_pip_audit_json(json.dumps(data))
        assert "1.0.1" in vulns[0].fix_versions
        assert "2.0.0" in vulns[0].fix_versions

    def test_package_with_multiple_cves(self) -> None:
        data = [
            {
                "name": "cryptography",
                "version": "40.0.0",
                "vulns": [
                    {"id": "CVE-2024-0001", "fix_versions": ["41.0.0"], "description": "A"},
                    {"id": "CVE-2024-0002", "fix_versions": ["41.0.0"], "description": "B"},
                ],
            }
        ]
        vulns = _parse_pip_audit_json(json.dumps(data))
        assert len(vulns) == 2
        cves = {v.cve for v in vulns}
        assert "CVE-2024-0001" in cves
        assert "CVE-2024-0002" in cves

    def test_empty_json_array(self) -> None:
        assert _parse_pip_audit_json("[]") == []

    # --- real pip-audit --format json envelope: {"dependencies": [...], "fixes": [...]} ---

    def test_parses_real_envelope_format(self) -> None:
        data = {
            "dependencies": [
                {
                    "name": "urllib3",
                    "version": "2.0.4",
                    "vulns": [
                        {
                            "id": "PYSEC-2023-192",
                            "fix_versions": ["1.26.17", "2.0.6"],
                            "aliases": ["CVE-2023-43804"],
                            "description": "Improper handling",
                        }
                    ],
                }
            ],
            "fixes": [],
        }
        vulns = _parse_pip_audit_json(json.dumps(data))
        assert len(vulns) == 1
        assert vulns[0].package == "urllib3"
        # CVE alias must be preferred over the primary PYSEC id
        assert vulns[0].cve == "CVE-2023-43804"
        assert "2.0.6" in vulns[0].fix_versions

    def test_falls_back_to_pysec_when_no_cve_alias(self) -> None:
        data = {
            "dependencies": [
                {
                    "name": "somelib",
                    "version": "1.0.0",
                    "vulns": [
                        {
                            "id": "PYSEC-2024-001",
                            "fix_versions": ["1.0.1"],
                            "aliases": ["GHSA-xxxx-yyyy-zzzz"],
                            "description": "No CVE assigned yet",
                        }
                    ],
                }
            ],
            "fixes": [],
        }
        vulns = _parse_pip_audit_json(json.dumps(data))
        assert len(vulns) == 1
        # No CVE alias → fall back to primary id
        assert vulns[0].cve == "PYSEC-2024-001"

    def test_real_envelope_no_vulns(self) -> None:
        data = {"dependencies": [{"name": "flask", "version": "2.3.0", "vulns": []}], "fixes": []}
        assert _parse_pip_audit_json(json.dumps(data)) == []

    def test_real_envelope_empty_dependencies(self) -> None:
        data = {"dependencies": [], "fixes": []}
        assert _parse_pip_audit_json(json.dumps(data)) == []


class TestAliasDeduplication:
    """OSV returns one advisory as several records; each advisory counts once."""

    @staticmethod
    def _payload(vulns: list[dict[str, object]]) -> str:
        return json.dumps({
            "dependencies": [{"name": "urllib3", "version": "2.6.3", "vulns": vulns}],
            "fixes": [],
        })

    def test_pysec_and_ghsa_records_of_one_advisory_merge(self) -> None:
        vulns = _parse_pip_audit_json(self._payload([
            {"id": "PYSEC-2026-141", "aliases": ["CVE-2026-44431", "GHSA-qccp-gfcp-xxvc"],
             "fix_versions": ["2.7.0"], "description": "a"},
            {"id": "GHSA-qccp-gfcp-xxvc", "aliases": ["CVE-2026-44431"],
             "fix_versions": ["2.7.0"], "description": "a"},
        ]))
        assert len(vulns) == 1
        assert vulns[0].cve == "CVE-2026-44431"
        assert vulns[0].ghsa == "GHSA-qccp-gfcp-xxvc"
        assert set(vulns[0].aliases) == {"PYSEC-2026-141", "GHSA-qccp-gfcp-xxvc"}

    def test_repeated_identical_records_merge(self) -> None:
        record = {"id": "PYSEC-2026-4175", "aliases": ["GHSA-8988-9cw3-xx77", "CVE-2026-97687"],
                  "fix_versions": ["2.8.0"], "description": "b"}
        vulns = _parse_pip_audit_json(self._payload([record, dict(record)]))
        assert len(vulns) == 1

    def test_distinct_advisories_stay_separate(self) -> None:
        vulns = _parse_pip_audit_json(self._payload([
            {"id": "PYSEC-1", "aliases": ["CVE-1"], "fix_versions": ["2.7.0"]},
            {"id": "PYSEC-2", "aliases": ["CVE-2"], "fix_versions": ["2.8.0"]},
        ]))
        assert sorted(v.cve for v in vulns) == ["CVE-1", "CVE-2"]

    def test_merged_fix_versions_are_the_union(self) -> None:
        vulns = _parse_pip_audit_json(self._payload([
            {"id": "GHSA-a", "aliases": ["CVE-9"], "fix_versions": ["2.10.0"]},
            {"id": "PYSEC-9", "aliases": ["CVE-9"], "fix_versions": ["2.9.0", "2.10.0"]},
        ]))
        assert len(vulns) == 1
        assert vulns[0].fix_versions == "2.9.0, 2.10.0"

    def test_record_linking_two_groups_merges_them(self) -> None:
        vulns = _parse_pip_audit_json(self._payload([
            {"id": "GHSA-x", "aliases": []},
            {"id": "PYSEC-y", "aliases": []},
            {"id": "OSV-z", "aliases": ["GHSA-x", "PYSEC-y"]},
        ]))
        assert len(vulns) == 1

    def test_same_advisory_in_two_packages_counts_per_package(self) -> None:
        data = {"dependencies": [
            {"name": "fastmcp", "version": "3.4.2",
             "vulns": [{"id": "GHSA-7xgj-8392-5q4r", "aliases": [], "fix_versions": ["4.1.2"]}]},
            {"name": "fastmcp-slim", "version": "3.4.2",
             "vulns": [{"id": "GHSA-7xgj-8392-5q4r", "aliases": [], "fix_versions": ["4.1.2"]}]},
        ]}
        vulns = _parse_pip_audit_json(json.dumps(data))
        assert [v.package for v in vulns] == ["fastmcp", "fastmcp-slim"]


class TestAuditCommand:
    def test_audits_exact_pins_without_resolving(self, tmp_path: Path) -> None:
        """--no-deps --disable-pip: pip-audit must not build its own resolver venv."""
        cmd = audit_command("/tool/bin/python", tmp_path / "pins.txt")
        assert cmd[:4] == ["/tool/bin/python", "-I", "-m", "pip_audit"]
        assert "--no-deps" in cmd
        assert "--disable-pip" in cmd

    def test_runs_isolated_from_an_empty_directory(self, tmp_path: Path) -> None:
        """Neither the caller's directory nor PYTHON* variables reach pip-audit's sys.path."""
        from depfresh.audit import _audit_file

        result = MagicMock(returncode=0, stdout='{"dependencies": []}', stderr="")
        with patch("depfresh.audit.run", return_value=result) as mock_run:
            _audit_file("/tool/bin/python", tmp_path / "pins.txt", "test")
        cmd, kwargs = mock_run.call_args.args[0], mock_run.call_args.kwargs
        assert cmd[1] == "-I"
        cwd = Path(kwargs["cwd"])
        assert cwd != Path.cwd() and not cwd.exists()  # a temporary, now removed, directory

    def test_uses_osv_service(self, tmp_path: Path) -> None:
        cmd = audit_command("/tool/bin/python", tmp_path / "pins.txt")
        assert cmd[cmd.index("-s") + 1] == "osv"

    def test_reads_the_given_requirements_file(self, tmp_path: Path) -> None:
        req = tmp_path / "pins.txt"
        cmd = audit_command("/tool/bin/python", req)
        assert cmd[cmd.index("-r") + 1] == str(req)


class TestInstallPipAudit:
    def test_pins_a_version_range(self) -> None:
        assert PIP_AUDIT_REQUIREMENT.startswith("pip-audit>=")
        assert "<3" in PIP_AUDIT_REQUIREMENT

    def test_installs_into_its_own_venv(self, tmp_path: Path) -> None:
        tool_dir = tmp_path / "tool"
        version_result = MagicMock(returncode=0, stdout="pip-audit 2.10.1\n")
        with (
            patch("depfresh.audit.create_venv", return_value="/tool/bin/python") as mock_venv,
            patch("depfresh.audit.run", return_value=version_result) as mock_run,
        ):
            python, version = install_pip_audit("/usr/bin/uv", tool_dir, "3.12")

        assert python == "/tool/bin/python"
        assert version == "2.10.1"
        mock_venv.assert_called_once_with("/usr/bin/uv", tool_dir, "3.12")
        install_cmd = mock_run.call_args_list[0].args[0]
        assert install_cmd[:3] == ["/usr/bin/uv", "pip", "install"]
        assert PIP_AUDIT_REQUIREMENT in install_cmd
        assert install_cmd[install_cmd.index("--python") + 1] == "/tool/bin/python"

    def test_unknown_version_when_version_call_fails(self, tmp_path: Path) -> None:
        results = [MagicMock(returncode=0, stdout=""), MagicMock(returncode=1, stdout="")]
        with (
            patch("depfresh.audit.create_venv", return_value="/tool/bin/python"),
            patch("depfresh.audit.run", side_effect=results),
        ):
            _, version = install_pip_audit("/usr/bin/uv", tmp_path / "tool", "3.11")
        assert version == "unknown"


class TestWritePinnedRequirements:
    def test_writes_sorted_exact_pins(self, tmp_path: Path) -> None:
        out = tmp_path / "pins.txt"
        write_pinned_requirements({"zlib": "1.0", "Flask": "2.3.0"}, out)
        assert out.read_text() == "Flask==2.3.0\nzlib==1.0\n"

    def test_skips_unversioned_entries(self, tmp_path: Path) -> None:
        out = tmp_path / "pins.txt"
        write_pinned_requirements({"flask": "*", "requests": ""}, out)
        assert out.read_text() == ""


class TestRunAudit:
    def test_empty_input_is_not_sent_to_pip_audit(self, tmp_path: Path) -> None:
        req = tmp_path / "reqs.txt"
        req.write_text("")
        with patch("depfresh.audit.run") as mock_run:
            assert run_audit("/tool/bin/python", req, "test") == []
        mock_run.assert_not_called()

    def test_calls_pip_audit_with_json_format(self, tmp_path: Path) -> None:
        req = tmp_path / "reqs.txt"
        req.write_text("flask==2.3.0\n")
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '{"dependencies": [], "fixes": []}'

        with patch("depfresh.audit.run", return_value=mock_result) as mock_run:
            run_audit("/venv/bin/python", req, "test")

        cmd = mock_run.call_args[0][0]
        assert "--format" in cmd
        assert "json" in cmd

    def test_no_desc_flag_in_command(self, tmp_path: Path) -> None:
        req = tmp_path / "reqs.txt"
        req.write_text("flask==2.3.0\n")
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '{"dependencies": [], "fixes": []}'

        with patch("depfresh.audit.run", return_value=mock_result) as mock_run:
            run_audit("/venv/bin/python", req, "test")

        cmd = mock_run.call_args[0][0]
        assert "--desc" not in cmd

    def test_returns_vulnerabilities_from_json(self, tmp_path: Path) -> None:
        """Uses the real pip-audit --format json envelope structure."""
        req = tmp_path / "reqs.txt"
        req.write_text("urllib3==2.0.4\n")
        # Real pip-audit output wraps results in {"dependencies": [...], "fixes": [...]}
        payload = json.dumps({
            "dependencies": [
                {
                    "name": "urllib3",
                    "version": "2.0.4",
                    "vulns": [
                        {
                            "id": "PYSEC-2023-192",
                            "fix_versions": ["2.0.6"],
                            "aliases": ["CVE-2023-43804"],
                            "description": "bad",
                        },
                    ],
                }
            ],
            "fixes": [],
        })
        mock_result = MagicMock()
        mock_result.returncode = 1  # pip-audit exits non-zero when vulns found
        mock_result.stdout = payload

        with patch("depfresh.audit.run", return_value=mock_result):
            vulns = run_audit("/venv/bin/python", req, "test")

        assert len(vulns) == 1
        assert vulns[0].cve == "CVE-2023-43804"

    def test_raises_when_pip_audit_fails(self, tmp_path: Path) -> None:
        req = tmp_path / "reqs.txt"
        req.write_text("flask==2.3.0\n")
        mock_result = MagicMock(returncode=2, stdout="", stderr="resolver blew up")

        with patch("depfresh.audit.run", return_value=mock_result):
            with pytest.raises(AuditError, match="exit code 2"):
                run_audit("/venv/bin/python", req, "test")

    def test_raises_when_output_is_not_json(self, tmp_path: Path) -> None:
        req = tmp_path / "reqs.txt"
        req.write_text("flask==2.3.0\n")
        mock_result = MagicMock(returncode=0, stdout="not json", stderr="")

        with patch("depfresh.audit.run", return_value=mock_result):
            with pytest.raises(AuditError, match="invalid JSON"):
                run_audit("/venv/bin/python", req, "test")


class TestChunkedAudit:
    def test_large_sets_are_split_and_merged(self, tmp_path: Path) -> None:
        """Every pin is audited, across parallel pip-audit processes."""
        req = tmp_path / "pins.txt"
        names = [f"pkg{i:02d}" for i in range(40)]
        req.write_text("".join(f"{n}==1.0\n" for n in names))
        seen: list[str] = []

        def fake_run(cmd: list[str], check: bool = True, cwd: str | None = None) -> MagicMock:
            path = Path(cmd[cmd.index("-r") + 1])
            pins = path.read_text().split()
            seen.extend(pins)
            deps = [{"name": p.split("==")[0], "version": "1.0", "vulns": []} for p in pins]
            if "pkg07==1.0" in pins:
                deps[pins.index("pkg07==1.0")]["vulns"] = [
                    {"id": "GHSA-x", "aliases": [], "fix_versions": ["1.1"]},
                ]
            return MagicMock(returncode=1, stdout=json.dumps({"dependencies": deps}), stderr="")

        with patch("depfresh.audit.run", side_effect=fake_run) as mock_run:
            vulns = run_audit("/tool/bin/python", req, "test")

        assert mock_run.call_count == 3  # 40 pins in chunks of 15
        assert sorted(seen) == [f"{n}==1.0" for n in names]
        assert [(v.package, v.cve) for v in vulns] == [("pkg07", "GHSA-x")]
        assert sorted(p.name for p in tmp_path.iterdir()) == ["pins.txt"]

    def test_one_failing_chunk_fails_the_audit(self, tmp_path: Path) -> None:
        req = tmp_path / "pins.txt"
        req.write_text("".join(f"pkg{i}==1.0\n" for i in range(20)))
        results = [
            MagicMock(returncode=0, stdout='{"dependencies": []}', stderr=""),
            MagicMock(returncode=2, stdout="", stderr="osv unreachable"),
        ]
        with patch("depfresh.audit.run", side_effect=results):
            with pytest.raises(AuditError, match="osv unreachable"):
                run_audit("/tool/bin/python", req, "test")
