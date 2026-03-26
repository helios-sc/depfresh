"""Tests for audit module — pip-audit JSON parsing."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from depfresh.audit import _parse_pip_audit_json, run_audit
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


class TestRunAudit:
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
