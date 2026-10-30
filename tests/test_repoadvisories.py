"""Tests for repoadvisories — the opt-in GitHub repository advisory pass."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from packaging.version import Version

from depfresh.advisories import AdvisoryLookupError, Release, TargetEnv, plan_fixes
from depfresh.models import Vulnerability
from depfresh.remediation import Auditor
from depfresh.repoadvisories import (
    RepoAdvisoryChecker,
    RepoAdvisoryError,
    _concatenated_arrays,
    gh_advisories,
    github_repo,
    range_contains,
)

PYASN1_REPO_ADVISORY: dict[str, Any] = {
    "ghsa_id": "GHSA-mm57-4v3p-rchx",
    "cve_id": None,
    "severity": "high",
    "summary": "Quadratic-complexity DoS in binary REAL decoding",
    "vulnerabilities": [{
        "package": {"ecosystem": "pip", "name": "pyasn1"},
        "vulnerable_version_range": "<= 0.6.4",
        "patched_versions": "0.6.5",
    }],
}
GRPC_REPO_ADVISORY: dict[str, Any] = {
    "ghsa_id": "GHSA-2xm2-c8xx-p9vh",
    "cve_id": None,
    "severity": "critical",
    "summary": "bundled roots.pem trusts compromised intermediates",
    "vulnerabilities": [{
        "package": {"ecosystem": "pip", "name": "grpcio"},
        "vulnerable_version_range": "< 1.84.1",
        "patched_versions": "1.84.1",
    }],
}


class FakeUrls:
    def __init__(self, urls: dict[str, list[str]]) -> None:
        self.urls = urls

    def project_urls(self, package: str) -> list[str]:
        if package not in self.urls:
            raise AdvisoryLookupError("not on PyPI")
        return self.urls[package]


class TestHelpers:
    @pytest.mark.parametrize(
        ("urls", "repo"),
        [
            (["https://github.com/pyasn1/pyasn1"], ("pyasn1", "pyasn1")),
            (["https://grpc.io", "https://github.com/grpc/grpc/tree/master/src/python"],
             ("grpc", "grpc")),
            (["git@github.com:org/proj.git"], ("org", "proj")),
            (["https://github.com/sponsors/someone", "https://github.com/a/b"], ("a", "b")),
            (["https://gitlab.com/x/y"], None),
        ],
    )
    def test_github_repo(self, urls: list[str], repo: tuple[str, str] | None) -> None:
        assert github_repo(urls) == repo

    @pytest.mark.parametrize(
        ("rng", "version", "expected"),
        [
            ("<= 0.6.4", "0.6.4", True),
            ("<= 0.6.4", "0.6.5", False),
            (">= 0.3.3, < 0.6.5", "0.6.3", True),
            ("= 3.3.1", "3.3.1", True),
            ("= 3.3.1", "4.0.0", False),
        ],
    )
    def test_range_contains(self, rng: str, version: str, expected: bool) -> None:
        assert range_contains(rng, version) is expected

    def test_paginated_output(self) -> None:
        text = '[{"ghsa_id": "A"}]\n[{"ghsa_id": "B", "summary": "x][y"}]\n'
        assert [a["ghsa_id"] for a in _concatenated_arrays(text, "o/r")] == ["A", "B"]

    def test_invalid_output(self) -> None:
        with pytest.raises(RepoAdvisoryError):
            _concatenated_arrays("[{", "o/r")


class TestGhAdvisories:
    def test_missing_gh(self) -> None:
        with patch("depfresh.repoadvisories.shutil.which", return_value=None):
            with pytest.raises(RepoAdvisoryError, match="GitHub CLI"):
                gh_advisories("pyasn1", "pyasn1")

    def test_api_call(self) -> None:
        result = MagicMock(returncode=0, stdout=json.dumps([PYASN1_REPO_ADVISORY]), stderr="")
        with (
            patch("depfresh.repoadvisories.shutil.which", return_value="/usr/bin/gh"),
            patch("depfresh.repoadvisories.subprocess.run", return_value=result) as mock,
        ):
            advisories = gh_advisories("pyasn1", "pyasn1")
        assert advisories[0]["ghsa_id"] == "GHSA-mm57-4v3p-rchx"
        cmd = mock.call_args.args[0]
        assert cmd[:3] == ["/usr/bin/gh", "api", "--paginate"]
        assert cmd[-1].startswith("repos/pyasn1/pyasn1/security-advisories")

    def test_missing_repo_is_empty(self) -> None:
        result = MagicMock(returncode=1, stdout="", stderr="gh: Not Found (HTTP 404)")
        with (
            patch("depfresh.repoadvisories.shutil.which", return_value="/usr/bin/gh"),
            patch("depfresh.repoadvisories.subprocess.run", return_value=result),
        ):
            assert gh_advisories("gone", "repo") == []

    def test_other_errors_fail_the_run(self) -> None:
        result = MagicMock(returncode=1, stdout="", stderr="HTTP 401: Bad credentials")
        with (
            patch("depfresh.repoadvisories.shutil.which", return_value="/usr/bin/gh"),
            patch("depfresh.repoadvisories.subprocess.run", return_value=result),
        ):
            with pytest.raises(RepoAdvisoryError, match="Bad credentials"):
                gh_advisories("pyasn1", "pyasn1")


class TestChecker:
    URLS = {
        "pyasn1": ["https://github.com/pyasn1/pyasn1"],
        "grpcio": ["https://github.com/grpc/grpc"],
        "grpcio-status": ["https://github.com/grpc/grpc"],
        "six": ["https://github.com/benjaminp/six"],
        "internal-tool": [],
    }

    def _checker(self, calls: list[tuple[str, str]]) -> RepoAdvisoryChecker:
        def fetch(owner: str, repo: str) -> list[dict[str, Any]]:
            calls.append((owner, repo))
            return {
                ("pyasn1", "pyasn1"): [PYASN1_REPO_ADVISORY],
                ("grpc", "grpc"): [GRPC_REPO_ADVISORY],
            }.get((owner, repo), [])

        return RepoAdvisoryChecker(urls=FakeUrls(self.URLS), fetch=fetch)

    def test_finds_advisories_missing_from_the_db(self) -> None:
        calls: list[tuple[str, str]] = []
        checker = self._checker(calls)
        pins = {"pyasn1": "0.6.4", "grpcio": "1.83.0", "grpcio-status": "1.83.0",
                "six": "1.17.0", "internal-tool": "1.0"}
        found = checker.findings(pins, known=[])
        assert sorted((v.package, v.cve, v.fix_versions) for v in found) == [
            ("grpcio", "GHSA-2xm2-c8xx-p9vh", "1.84.1"),
            ("pyasn1", "GHSA-mm57-4v3p-rchx", "0.6.5"),
        ]
        assert "repository advisory, CRITICAL" in next(v for v in found
                                                        if v.package == "grpcio").description
        assert sorted(calls) == [("benjaminp", "six"), ("grpc", "grpc"), ("pyasn1", "pyasn1")]
        assert checker.unmapped == {"internal-tool"}

    def test_fixed_versions_and_known_findings_are_skipped(self) -> None:
        checker = self._checker([])
        known = [Vulnerability("pyasn1", "0.6.3", "CVE-1", "0.6.4", "", ("GHSA-mm57-4v3p-rchx",))]
        found = checker.findings({"pyasn1": "0.6.3", "grpcio": "1.84.1"}, known=known)
        assert found == []

    def test_repositories_are_fetched_once_per_run(self) -> None:
        calls: list[tuple[str, str]] = []
        checker = self._checker(calls)
        checker.findings({"pyasn1": "0.6.4"}, known=[])
        checker.findings({"pyasn1": "0.6.5"}, known=[])
        assert calls == [("pyasn1", "pyasn1")]

    def test_planner_targets_the_patched_version(self) -> None:
        """No OSV record exists yet: the plan falls back to the patched version."""
        found = self._checker([]).findings({"pyasn1": "0.6.4"}, known=[])

        class Sources:
            def osv_records(self, package: str, version: str) -> list[dict[str, Any]]:
                return []

            def releases(self, package: str) -> list[Release]:
                return [Release(Version(v)) for v in ("0.6.4", "0.6.5", "0.6.6")]

        plan = plan_fixes(found, {"pyasn1": "0.6.4"}, env=TargetEnv("3.12"),
                          sources=Sources())["pyasn1"]
        assert plan.target == "0.6.5"


class TestAuditorIntegration:
    def test_audit_adds_repository_findings(self, tmp_path: Path) -> None:
        calls: list[tuple[str, str]] = []
        checker = TestChecker()._checker(calls)
        auditor = Auditor("/tool/bin/python", tmp_path, repo_check=checker)
        db = [Vulnerability("urllib3", "2.6.3", "CVE-2026-1", "2.8.0", "")]
        with patch("depfresh.remediation.run_audit", return_value=db):
            vulns = auditor.audit({"urllib3": "2.6.3", "pyasn1": "0.6.4"}, "pre-upgrade")
        assert [v.package for v in vulns] == ["urllib3", "pyasn1"]
        assert "checked" in auditor.notes()[0]

    def test_disabled_by_default(self, tmp_path: Path) -> None:
        auditor = Auditor("/tool/bin/python", tmp_path)
        with patch("depfresh.remediation.run_audit", return_value=[]):
            assert auditor.audit({"pyasn1": "0.6.4"}, "pre-upgrade") == []
        assert auditor.notes() == []
