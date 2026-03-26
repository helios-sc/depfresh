"""Tests for constraints module — parsing, normalisation, constraint building."""

from __future__ import annotations

import logging

import pytest

from depfresh.constraints import (
    build_constraints,
    compute_changes,
    diagnose_remaining,
    format_allow_major,
    format_keep_version,
    normalise,
)
from depfresh.models import Vulnerability

# ---------------------------------------------------------------------------
# normalise
# ---------------------------------------------------------------------------

class TestNormalise:
    def test_lowercase(self) -> None:
        assert normalise("Flask") == "flask"

    def test_underscores(self) -> None:
        assert normalise("my_package") == "my-package"

    def test_dots(self) -> None:
        assert normalise("zope.interface") == "zope-interface"

    def test_mixed(self) -> None:
        assert normalise("My_Cool.Package") == "my-cool-package"

    def test_multiple_separators(self) -> None:
        assert normalise("a--b__c..d") == "a-b-c-d"


# ---------------------------------------------------------------------------
# build_constraints
# ---------------------------------------------------------------------------

class TestBuildConstraints:
    def test_default_minor_patch_only(self) -> None:
        pkgs = {"flask": "2.3.0", "requests": "2.31.0"}
        result = build_constraints(pkgs)
        assert "flask>=2.3.0,<3.0" in result
        assert "requests>=2.31.0,<3.0" in result

    def test_allow_major_all(self) -> None:
        pkgs = {"flask": "2.3.0"}
        result = build_constraints(pkgs, allow_major=[])
        assert result == ["flask>=2.3.0"]

    def test_allow_major_selective(self) -> None:
        pkgs = {"flask": "2.3.0", "requests": "2.31.0"}
        result = build_constraints(pkgs, allow_major=["flask"])
        assert "flask>=2.3.0" in result
        assert "requests>=2.31.0,<3.0" in result

    def test_keep_version(self) -> None:
        pkgs = {"flask": "2.3.0", "requests": "2.31.0"}
        result = build_constraints(pkgs, keep_version=["flask"])
        assert "flask==2.3.0" in result
        assert "requests>=2.31.0,<3.0" in result

    def test_keep_version_overrides_allow_major(self) -> None:
        pkgs = {"flask": "2.3.0"}
        result = build_constraints(pkgs, allow_major=[], keep_version=["flask"])
        assert result == ["flask==2.3.0"]

    def test_non_numeric_version_pinned(self) -> None:
        pkgs = {"weird-pkg": "abc.123"}
        result = build_constraints(pkgs)
        assert result == ["weird-pkg==abc.123"]

    def test_sorted_output(self) -> None:
        pkgs = {"zlib": "1.0.0", "aiohttp": "3.0.0"}
        result = build_constraints(pkgs)
        assert result[0].startswith("aiohttp")
        assert result[1].startswith("zlib")


# ---------------------------------------------------------------------------
# compute_changes
# ---------------------------------------------------------------------------

class TestComputeChanges:
    def test_upgraded_package(self) -> None:
        old = {"flask": "2.3.0"}
        new = {"flask": "2.4.0"}
        upgraded, new_deps, unchanged = compute_changes(old, new, set())
        assert len(upgraded) == 1
        assert upgraded[0].name == "flask"
        assert upgraded[0].old_version == "2.3.0"
        assert upgraded[0].new_version == "2.4.0"
        assert not upgraded[0].is_security_fix
        assert new_deps == []
        assert unchanged == []

    def test_security_fix_flagged(self) -> None:
        old = {"urllib3": "2.0.0"}
        new = {"urllib3": "2.0.7"}
        upgraded, _, _ = compute_changes(old, new, {"urllib3"})
        assert upgraded[0].is_security_fix is True

    def test_new_transitive_dependency(self) -> None:
        old = {"flask": "2.3.0"}
        new = {"flask": "2.3.0", "markupsafe": "2.1.0"}
        _, new_deps, _ = compute_changes(old, new, set())
        assert len(new_deps) == 1
        assert new_deps[0].name == "markupsafe"
        assert new_deps[0].old_version == "(new)"

    def test_unchanged_package(self) -> None:
        old = {"flask": "2.3.0"}
        new = {"flask": "2.3.0"}
        _, _, unchanged = compute_changes(old, new, set())
        assert unchanged == ["flask==2.3.0"]


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

class TestFormatHelpers:
    def test_format_allow_major_none(self) -> None:
        assert format_allow_major(None) == "no (minor/patch only)"

    def test_format_allow_major_all(self) -> None:
        assert format_allow_major([]) == "yes (all packages)"

    def test_format_allow_major_selective(self) -> None:
        result = format_allow_major(["urllib3", "flask"])
        assert "urllib3" in result
        assert "selective" in result

    def test_format_keep_version_none(self) -> None:
        assert format_keep_version(None) == "none"

    def test_format_keep_version_list(self) -> None:
        assert format_keep_version(["crewai", "litellm"]) == "crewai, litellm"


# ---------------------------------------------------------------------------
# diagnose_remaining
# ---------------------------------------------------------------------------

def _vuln(pkg: str, version: str, fix: str) -> Vulnerability:
    return Vulnerability(pkg, version, "CVE-2026-0001", fix, "desc")


class TestDiagnoseRemaining:
    def test_major_upgrade_required(self) -> None:
        vulns = [_vuln("black", "23.12.1", "26.3.1")]
        old_pkgs = {"black": "23.12.1"}
        reasons = diagnose_remaining(vulns, old_pkgs)
        assert len(reasons) == 1
        assert "major upgrade" in reasons[0].lower()
        assert "23" in reasons[0] and "26" in reasons[0]
        assert "--allow-major black" in reasons[0]

    def test_pinned_by_keep_version(self) -> None:
        vulns = [_vuln("flask", "2.3.0", "2.4.0")]
        old_pkgs = {"flask": "2.3.0"}
        reasons = diagnose_remaining(vulns, old_pkgs, keep_version=["flask"])
        assert "keep-version" in reasons[0].lower()

    def test_within_bounds_conflict(self) -> None:
        vulns = [_vuln("requests", "2.28.0", "2.31.0")]
        old_pkgs = {"requests": "2.28.0"}
        reasons = diagnose_remaining(vulns, old_pkgs)
        assert "within" in reasons[0].lower()
        assert "conflict" in reasons[0].lower()

    def test_major_allowed_but_unresolved(self) -> None:
        vulns = [_vuln("pyopenssl", "25.3.0", "26.0.0")]
        old_pkgs = {"pyopenssl": "25.3.0"}
        reasons = diagnose_remaining(vulns, old_pkgs, allow_major=["pyopenssl"])
        assert "allowed" in reasons[0].lower()
        assert "conflict" in reasons[0].lower()

    def test_allow_major_all_but_unresolved(self) -> None:
        vulns = [_vuln("pyopenssl", "25.3.0", "26.0.0")]
        old_pkgs = {"pyopenssl": "25.3.0"}
        reasons = diagnose_remaining(vulns, old_pkgs, allow_major=[])
        assert "allowed" in reasons[0].lower()

    def test_no_fix_version(self) -> None:
        vulns = [Vulnerability("badpkg", "1.0.0", "CVE-2026-9999", "", "desc")]
        old_pkgs = {"badpkg": "1.0.0"}
        reasons = diagnose_remaining(vulns, old_pkgs)
        assert "no fix" in reasons[0].lower()

    def test_multiple_vulns(self) -> None:
        vulns = [
            _vuln("black", "23.12.1", "26.3.1"),
            _vuln("flask", "2.3.0", "2.4.0"),
        ]
        old_pkgs = {"black": "23.12.1", "flask": "2.3.0"}
        reasons = diagnose_remaining(vulns, old_pkgs)
        assert len(reasons) == 2
        assert "major upgrade" in reasons[0].lower()
        assert "within" in reasons[1].lower()

    def test_keep_version_overrides_major(self) -> None:
        vulns = [_vuln("black", "23.12.1", "26.3.1")]
        old_pkgs = {"black": "23.12.1"}
        reasons = diagnose_remaining(
            vulns, old_pkgs, allow_major=["black"], keep_version=["black"],
        )
        assert "keep-version" in reasons[0].lower()


# ---------------------------------------------------------------------------
# Unknown package warnings (--allow-major / --keep-version typo detection)
# ---------------------------------------------------------------------------


class TestUnknownPackageWarnings:
    def test_allow_major_unknown_warns(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="depfresh"):
            build_constraints({"flask": "2.0"}, allow_major=["urllib"])
        assert any("urllib" in rec.message and "not found" in rec.message for rec in caplog.records)

    def test_keep_version_unknown_warns(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="depfresh"):
            build_constraints({"flask": "2.0"}, keep_version=["typo-pkg"])
        assert any(
            "typo-pkg" in rec.message and "not found" in rec.message for rec in caplog.records
        )

    def test_known_packages_no_warning(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="depfresh"):
            build_constraints({"flask": "2.0"}, allow_major=["flask"])
        warning_messages = [rec.message for rec in caplog.records if rec.levelno >= logging.WARNING]
        assert not warning_messages

    def test_allow_major_all_no_warning(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="depfresh"):
            build_constraints({"flask": "2.0"}, allow_major=[])
        warning_messages = [rec.message for rec in caplog.records if rec.levelno >= logging.WARNING]
        assert not warning_messages
