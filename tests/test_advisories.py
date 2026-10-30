"""Tests for advisories — OSV range evaluation and minimal fix planning."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from packaging.version import Version

from depfresh.advisories import (
    AdvisoryLookupError,
    OnlineSources,
    Release,
    TargetEnv,
    evaluate_marker,
    major_allowed,
    plan_fixes,
    range_affects,
    record_affects,
)
from depfresh.models import Vulnerability


def _record(
    vid: str, package: str, *ranges: list[dict[str, str]], aliases: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": vid,
        "aliases": aliases or [],
        "affected": [
            {"package": {"name": package, "ecosystem": "PyPI"},
             "ranges": [{"type": "ECOSYSTEM", "events": events}]}
            for events in ranges
        ],
    }


class FakeSources:
    """In-memory OSV/PyPI; records every lookup so tests can assert on them."""

    def __init__(
        self,
        records: dict[str, list[dict[str, Any]]] | None = None,
        releases: dict[str, list[str | Release]] | None = None,
        fail_osv: bool = False,
        fail_pypi: bool = False,
    ) -> None:
        self._records = records or {}
        self._releases = releases or {}
        self.fail_osv = fail_osv
        self.fail_pypi = fail_pypi
        self.lookups: list[tuple[str, str]] = []

    def osv_records(self, package: str, version: str) -> list[dict[str, Any]]:
        self.lookups.append(("osv", package))
        if self.fail_osv:
            raise AdvisoryLookupError("osv down")
        return self._records.get(package, [])

    def releases(self, package: str) -> list[Release]:
        self.lookups.append(("pypi", package))
        if self.fail_pypi:
            raise AdvisoryLookupError("pypi down")
        out = []
        for r in self._releases.get(package, []):
            out.append(r if isinstance(r, Release) else Release(Version(r)))
        return sorted(out, key=lambda r: r.version)


def _vuln(package: str, version: str, vid: str, fixes: str = "", aliases: tuple[str, ...] = ()
          ) -> Vulnerability:
    return Vulnerability(package, version, vid, fixes, "desc", aliases)


ENV = TargetEnv("3.12")


class TestRangeAffects:
    def test_introduced_and_fixed(self) -> None:
        events = [{"introduced": "3.0.0"}, {"fixed": "3.4.10"}]
        assert range_affects(events, Version("3.4.2"))
        assert not range_affects(events, Version("3.4.10"))
        assert not range_affects(events, Version("2.9.0"))

    def test_last_affected(self) -> None:
        events = [{"introduced": "2.11.0"}, {"last_affected": "2.13.0"}]
        assert range_affects(events, Version("2.13.0"))
        assert not range_affects(events, Version("2.14.0"))

    def test_introduced_zero(self) -> None:
        assert range_affects([{"introduced": "0"}, {"fixed": "1.2"}], Version("0.1"))

    def test_reintroduced(self) -> None:
        events = [{"introduced": "0"}, {"fixed": "1.26.17"}, {"introduced": "2.0.0"},
                  {"fixed": "2.0.6"}]
        assert not range_affects(events, Version("1.26.18"))
        assert range_affects(events, Version("2.0.4"))
        assert not range_affects(events, Version("2.0.6"))


class TestRecordAffects:
    def test_every_affected_entry_counts(self) -> None:
        """pip-audit keeps only the last OSV range; the planner must read all of them."""
        record = _record(
            "GHSA-7xgj-8392-5q4r", "fastmcp",
            [{"introduced": "3.0.0"}, {"fixed": "3.4.10"}],
            [{"introduced": "4.0.0"}, {"fixed": "4.1.2"}],
        )
        assert record_affects(record, "fastmcp", Version("3.4.2"))
        assert not record_affects(record, "fastmcp", Version("3.4.10"))
        assert record_affects(record, "fastmcp", Version("4.1.0"))
        assert not record_affects(record, "fastmcp-slim", Version("3.4.2"))

    def test_explicit_versions_list(self) -> None:
        record = {"id": "X", "affected": [
            {"package": {"name": "pkg", "ecosystem": "PyPI"}, "versions": ["1.0", "1.1"]},
        ]}
        assert record_affects(record, "pkg", Version("1.1"))
        assert not record_affects(record, "pkg", Version("1.2"))


class TestPlanFixes:
    def test_in_major_fix_beats_pip_audit_fix_versions(self) -> None:
        """pip-audit says fastmcp -> 4.1.2; OSV also fixes 3.4.10."""
        sources = FakeSources(
            records={"fastmcp": [_record(
                "GHSA-7xgj-8392-5q4r", "fastmcp",
                [{"introduced": "3.0.0"}, {"fixed": "3.4.10"}],
                [{"introduced": "4.0.0"}, {"fixed": "4.1.2"}],
            )]},
            releases={"fastmcp": ["3.4.2", "3.4.9", "3.4.10", "3.4.11", "4.0.0", "4.1.2"]},
        )
        vuln = _vuln("fastmcp", "3.4.2", "GHSA-7xgj-8392-5q4r", "4.1.2")
        plan = plan_fixes([vuln], {"fastmcp": "3.4.2"}, env=ENV, sources=sources)["fastmcp"]
        assert plan.status == "fix"
        assert plan.target == "3.4.10"
        assert plan.kind == "patch"

    def test_last_affected_without_fixed_event(self) -> None:
        """pyjwt GHSA-gvp8: last_affected 2.13.0, so pip-audit reports no fix at all."""
        sources = FakeSources(
            records={"pyjwt": [_record(
                "GHSA-gvp8-978c-rx2q", "pyjwt",
                [{"introduced": "2.11.0"}, {"last_affected": "2.13.0"}],
                aliases=["CVE-2026-103001"],
            )]},
            releases={"pyjwt": ["2.13.0", "2.14.0", "2.15.1"]},
        )
        vuln = _vuln("pyjwt", "2.13.0", "CVE-2026-103001", "", ("GHSA-gvp8-978c-rx2q",))
        plan = plan_fixes([vuln], {"pyjwt": "2.13.0"}, env=ENV, sources=sources)["pyjwt"]
        assert plan.target == "2.14.0"

    def test_lowest_release_clearing_every_advisory(self) -> None:
        sources = FakeSources(
            records={"anyio": [
                _record("GHSA-a", "anyio", [{"introduced": "0"}, {"fixed": "4.14.0"}]),
                _record("GHSA-b", "anyio", [{"introduced": "0"}, {"fixed": "4.14.1"}]),
            ]},
            releases={"anyio": ["4.13.0", "4.14.0", "4.14.1", "4.14.2", "4.15.1"]},
        )
        vulns = [_vuln("anyio", "4.13.0", "GHSA-a"), _vuln("anyio", "4.13.0", "GHSA-b")]
        plan = plan_fixes(vulns, {"anyio": "4.13.0"}, env=ENV, sources=sources)["anyio"]
        assert plan.target == "4.14.1"
        assert plan.kind == "minor"

    @pytest.fixture()
    def crypto_sources(self) -> FakeSources:
        return FakeSources(
            records={"cryptography": [_record(
                "GHSA-g6cj", "cryptography", [{"introduced": "0"}, {"fixed": "50.0.0"}],
            )]},
            releases={"cryptography": ["46.0.6", "46.0.7", "48.0.1", "50.0.0", "50.0.2"]},
        )

    def test_major_needs_permission(self, crypto_sources: FakeSources) -> None:
        vuln = _vuln("cryptography", "46.0.6", "GHSA-g6cj", "50.0.0")
        plan = plan_fixes([vuln], {"cryptography": "46.0.6"}, env=ENV,
                          sources=crypto_sources)["cryptography"]
        assert plan.status == "needs-major"
        assert plan.target is None
        assert plan.lowest_fix == "50.0.0"
        assert "--allow-major cryptography" in plan.reason

    @pytest.mark.parametrize("allow", [[], ["cryptography"], ["Cryptography"]])
    def test_major_with_permission(self, crypto_sources: FakeSources, allow: list[str]) -> None:
        vuln = _vuln("cryptography", "46.0.6", "GHSA-g6cj", "50.0.0")
        plan = plan_fixes([vuln], {"cryptography": "46.0.6"}, env=ENV, sources=crypto_sources,
                          allow_major=allow)["cryptography"]
        assert plan.status == "fix"
        assert plan.target == "50.0.0"
        assert plan.kind == "major"
        assert "MAJOR" in plan.reason

    def test_major_allowed_for_another_package_only(self, crypto_sources: FakeSources) -> None:
        vuln = _vuln("cryptography", "46.0.6", "GHSA-g6cj", "50.0.0")
        plan = plan_fixes([vuln], {"cryptography": "46.0.6"}, env=ENV, sources=crypto_sources,
                          allow_major=["pillow"])["cryptography"]
        assert plan.status == "needs-major"

    def test_calendar_versions_are_not_majors(self) -> None:
        sources = FakeSources(
            records={"certifi": [_record(
                "GHSA-6q48", "certifi", [{"introduced": "0"}, {"fixed": "2026.10.19"}],
            )]},
            releases={"certifi": ["2024.12.14", "2026.10.19", "2026.10.23"]},
        )
        vuln = _vuln("certifi", "2024.12.14", "GHSA-6q48")
        plan = plan_fixes([vuln], {"certifi": "2024.12.14"}, env=ENV, sources=sources)["certifi"]
        assert plan.status == "fix"
        assert plan.target == "2026.10.19"
        assert plan.kind == "calver"

    def test_skips_yanked_prerelease_and_incompatible_releases(self) -> None:
        sources = FakeSources(
            records={"pkg": [_record("GHSA-p", "pkg", [{"introduced": "0"}, {"fixed": "1.1"}])]},
            releases={"pkg": [
                "1.0", Release(Version("1.1"), yanked=True), "1.2rc1",
                Release(Version("1.2"), requires_python=(">=3.13",)), "1.3",
            ]},
        )
        plan = plan_fixes([_vuln("pkg", "1.0", "GHSA-p")], {"pkg": "1.0"}, env=ENV,
                          sources=sources)["pkg"]
        assert plan.target == "1.3"

    def test_no_fix(self) -> None:
        sources = FakeSources(
            records={"pkg": [_record("GHSA-p", "pkg", [{"introduced": "0"}])]},
            releases={"pkg": ["1.0", "1.1"]},
        )
        plan = plan_fixes([_vuln("pkg", "1.0", "GHSA-p")], {"pkg": "1.0"}, env=ENV,
                          sources=sources)["pkg"]
        assert plan.status == "no-fix"
        assert plan.target is None

    def test_keep_version(self) -> None:
        sources = FakeSources()
        plan = plan_fixes([_vuln("pkg", "1.0", "GHSA-p")], {"pkg": "1.0"}, env=ENV,
                          sources=sources, keep_version=["pkg"])["pkg"]
        assert plan.status == "kept"
        assert sources.lookups == []

    def test_private_packages_are_never_looked_up(self) -> None:
        """A private package name must not reach public PyPI (dependency confusion)."""
        sources = FakeSources()
        plan = plan_fixes([_vuln("private-widget", "0.1.0", "X")], {"private-widget": "0.1.0"},
                          env=ENV, sources=sources, private={"private-widget"})["private-widget"]
        assert plan.status == "private"
        assert sources.lookups == []

    def test_osv_failure_falls_back_to_pip_audit_fix_versions(self) -> None:
        sources = FakeSources(releases={"idna": ["3.11", "3.13", "3.15"]}, fail_osv=True)
        plan = plan_fixes([_vuln("idna", "3.11", "GHSA-i", "3.15")], {"idna": "3.11"}, env=ENV,
                          sources=sources)["idna"]
        assert plan.target == "3.15"
        assert plan.approximate is True

    def test_pypi_failure_falls_back_to_advisory_fix_versions(self) -> None:
        sources = FakeSources(
            records={"idna": [_record("GHSA-i", "idna", [{"introduced": "0"}, {"fixed": "3.15"}])]},
            fail_pypi=True,
        )
        plan = plan_fixes([_vuln("idna", "3.11", "GHSA-i", "3.15")], {"idna": "3.11"}, env=ENV,
                          sources=sources)["idna"]
        assert plan.target == "3.15"
        assert plan.approximate is True


def _open_range(vid: str, package: str, *events: dict[str, str],
                aliases: list[str] | None = None) -> dict[str, Any]:
    return _record(vid, package, [{"introduced": "0"}, *events], aliases=aliases)


class TestMixedFixes:
    """Each advisory is judged on its own: one without a fix never blocks the others."""

    RELEASES = {"demo": ["2.0.0", "2.0.1", "2.1.0", "3.0.0"]}
    VULNS = [_vuln("demo", "2.0.0", "GHSA-aaaa", "2.0.1"), _vuln("demo", "2.0.0", "GHSA-bbbb")]

    def _plan(self, *records: dict[str, Any], vulns: list[Vulnerability] | None = None,
              **kwargs: Any) -> Any:
        sources = FakeSources(records={"demo": list(records)}, releases=self.RELEASES)
        return plan_fixes(vulns or self.VULNS, {"demo": "2.0.0"}, env=ENV, sources=sources,
                          **kwargs)["demo"]

    def test_fixes_what_it_can_when_another_advisory_has_no_fix(self) -> None:
        plan = self._plan(_open_range("GHSA-aaaa", "demo", {"fixed": "2.0.1"}),
                          _open_range("GHSA-bbbb", "demo"))
        assert (plan.status, plan.target, plan.lowest_fix) == ("fix", "2.0.1", "2.0.1")
        assert plan.open_advisories == {"GHSA-bbbb": "No fixed release available yet"}
        assert "fixes 1 of 2 advisories; still open: GHSA-bbbb" in plan.reason

    def test_a_fix_in_a_later_major_does_not_block_the_in_major_fix(self) -> None:
        records = (_open_range("GHSA-aaaa", "demo", {"fixed": "2.0.1"}),
                   _open_range("GHSA-bbbb", "demo", {"fixed": "3.0.0"}))
        plan = self._plan(*records)
        assert (plan.status, plan.target, plan.lowest_fix) == ("fix", "2.0.1", "3.0.0")
        assert plan.open_advisories["GHSA-bbbb"] == (
            "Requires major upgrade (2→3, lowest fix 3.0.0). Use --allow-major demo"
        )
        allowed = self._plan(*records, allow_major=["demo"])
        assert (allowed.status, allowed.target, allowed.open_advisories) == ("fix", "3.0.0", {})
        assert "MAJOR 2→3" in allowed.reason

    def test_needs_major_while_another_advisory_has_no_fix(self) -> None:
        plan = self._plan(_open_range("GHSA-aaaa", "demo", {"fixed": "3.0.0"}),
                          _open_range("GHSA-bbbb", "demo"))
        assert (plan.status, plan.target, plan.lowest_fix) == ("needs-major", None, "3.0.0")
        assert plan.reason.endswith("Use --allow-major demo; still open after it: GHSA-bbbb")
        assert plan.open_advisories == {
            "GHSA-aaaa": "Requires major upgrade (2→3, lowest fix 3.0.0). Use --allow-major demo",
            "GHSA-bbbb": "No fixed release available yet",
        }

    def test_no_advisory_has_a_fix(self) -> None:
        plan = self._plan(_open_range("GHSA-aaaa", "demo"), _open_range("GHSA-bbbb", "demo"))
        assert (plan.status, plan.target, plan.lowest_fix) == ("no-fix", None, None)
        assert set(plan.open_advisories) == {"GHSA-aaaa", "GHSA-bbbb"}

    def test_advisories_no_single_release_fixes_together(self) -> None:
        """GHSA-aaaa comes back in 2.1.0, the first release without GHSA-bbbb."""
        plan = self._plan(
            _open_range("GHSA-aaaa", "demo", {"fixed": "2.0.1"}, {"introduced": "2.1.0"}),
            _open_range("GHSA-bbbb", "demo", {"fixed": "2.1.0"}),
        )
        assert (plan.status, plan.target) == ("fix", "2.0.1")
        assert "affected by another advisory of demo" in plan.open_advisories["GHSA-bbbb"]

    def test_the_most_advisories_win_over_the_lowest_release(self) -> None:
        plan = self._plan(
            _open_range("GHSA-aaaa", "demo", {"fixed": "2.0.1"}),
            _open_range("GHSA-bbbb", "demo", {"fixed": "2.1.0"}),
            vulns=[*self.VULNS, _vuln("demo", "2.0.0", "GHSA-cccc")],
        )
        assert (plan.target, list(plan.open_advisories)) == ("2.1.0", ["GHSA-cccc"])

    def test_open_advisories_are_keyed_by_every_alias(self) -> None:
        vulns = [self.VULNS[0], _vuln("demo", "2.0.0", "CVE-2026-1", "", ("GHSA-bbbb",))]
        plan = self._plan(_open_range("GHSA-aaaa", "demo", {"fixed": "2.0.1"}),
                          _open_range("GHSA-bbbb", "demo", aliases=["CVE-2026-1"]), vulns=vulns)
        assert set(plan.open_advisories) == {"CVE-2026-1", "GHSA-bbbb"}


class TestOpenAdvisoryRows:
    """How a plan's open advisories reach the report rows and remaining reasons."""

    @staticmethod
    def _mixed() -> dict[str, Any]:
        sources = FakeSources(
            records={"demo": [_open_range("GHSA-aaaa", "demo", {"fixed": "2.0.1"}),
                              _open_range("GHSA-bbbb", "demo")]},
            releases=TestMixedFixes.RELEASES,
        )
        return plan_fixes(TestMixedFixes.VULNS, {"demo": "2.0.0"}, env=ENV, sources=sources)

    def test_only_the_open_advisory_remains_so_the_fix_is_applied(self) -> None:
        from depfresh.remediation import planned_fixes, remaining_reasons

        left = [_vuln("demo", "2.0.1", "GHSA-bbbb")]
        rows = planned_fixes(self._mixed(), {"demo": "2.0.1"}, {}, left, applied=True)
        assert [(r.status, r.target, r.final) for r in rows] == [("applied", "2.0.1", "2.0.1")]
        assert remaining_reasons(left, rows) == ["No fixed release available yet"]

    def test_an_advisory_the_target_should_fix_still_blocks(self) -> None:
        from depfresh.remediation import planned_fixes, remaining_reasons

        left = [_vuln("demo", "2.0.1", "GHSA-aaaa"), _vuln("demo", "2.0.1", "GHSA-bbbb")]
        rows = planned_fixes(self._mixed(), {"demo": "2.0.1"}, {}, left, applied=True)
        assert rows[0].status == "blocked"
        assert remaining_reasons(left, rows) == [
            "Moved to 2.0.1, still vulnerable; see remaining findings",
            "No fixed release available yet",
        ]

    def test_a_failed_fix_keeps_each_advisory_reason(self) -> None:
        from depfresh.remediation import planned_fixes, remaining_reasons

        left = list(TestMixedFixes.VULNS)
        rows = planned_fixes(self._mixed(), {"demo": "2.0.0"}, {"demo": "uv could not lock it"},
                             left, applied=True)
        assert rows[0].status == "blocked"
        assert remaining_reasons(left, rows) == ["uv could not lock it",
                                                 "No fixed release available yet"]

    def test_audit_only_rows_are_planned_with_a_reason_per_advisory(self) -> None:
        from depfresh.remediation import planned_fixes, remaining_reasons

        left = list(TestMixedFixes.VULNS)
        rows = planned_fixes(self._mixed(), {"demo": "2.0.0"}, {}, left, applied=False)
        assert rows[0].status == "planned"
        reasons = remaining_reasons(left, rows)
        assert reasons[0].startswith("Upgrade to 2.0.1")
        assert reasons[1] == "No fixed release available yet"


class TestRecordPlans:
    """One report row per package, across rounds and the repository step."""

    def test_a_second_move_keeps_the_original_version(self) -> None:
        from depfresh.advisories import FixPlan
        from depfresh.remediation import record_plans

        first = FixPlan("demo", "2.0.0", [_vuln("demo", "2.0.0", "GHSA-aaaa")], status="fix",
                        target="2.0.1", kind="patch")
        second = FixPlan("demo", "2.0.1", [_vuln("demo", "2.0.1", "GHSA-bbbb")], status="fix",
                         target="2.1.0", kind="minor")
        plans: dict[str, Any] = {}
        record_plans(plans, {"demo": first})
        record_plans(plans, {"demo": second})
        row = plans["demo"]
        assert (row.current, row.target, row.kind) == ("2.0.0", "2.1.0", "minor")
        assert [v.cve for v in row.vulns] == ["GHSA-aaaa", "GHSA-bbbb"]

    def test_a_later_plan_without_a_fix_explains_its_advisories(self) -> None:
        from depfresh.advisories import FixPlan
        from depfresh.remediation import planned_fixes, record_plans, remaining_reasons

        first = FixPlan("demo", "2.0.0", [_vuln("demo", "2.0.0", "GHSA-aaaa")], status="fix",
                        target="2.0.1")
        later = FixPlan("demo", "2.0.1", [_vuln("demo", "2.0.1", "GHSA-new")], status="no-fix",
                        reason="No fixed release available yet",
                        open_advisories={"GHSA-new": "No fixed release available yet"})
        plans: dict[str, Any] = {}
        record_plans(plans, {"demo": first})
        record_plans(plans, {"demo": later})
        left = [_vuln("demo", "2.0.1", "GHSA-new")]
        rows = planned_fixes(plans, {"demo": "2.0.1"}, {}, left, applied=True)
        assert rows[0].status == "applied"
        assert remaining_reasons(left, rows) == ["No fixed release available yet"]


class TestTargetEnv:
    def test_linux_markers(self) -> None:
        env = TargetEnv("3.11")
        assert evaluate_marker("sys_platform == 'linux'", env)
        assert not evaluate_marker("sys_platform == 'win32'", env)
        assert evaluate_marker("platform_machine == 'x86_64' and python_version >= '3.11'", env)
        assert not evaluate_marker("python_version < '3.11'", env)
        assert evaluate_marker(None, env)

    def test_macos_markers(self) -> None:
        env = TargetEnv("3.12", "aarch64-apple-darwin")
        assert evaluate_marker("sys_platform == 'darwin'", env)

    def test_unknown_platform(self) -> None:
        with pytest.raises(ValueError, match="Unsupported platform"):
            TargetEnv("3.11", "sparc-sun-solaris")

    @pytest.mark.parametrize(
        ("spec", "ok"),
        [(">=3.11.4", True), ("<3.11", False), (">=3.8", True), ("!=3.11.*", False), (None, True)],
    )
    def test_requires_python_for_a_minor(self, spec: str | None, ok: bool) -> None:
        assert TargetEnv("3.11").accepts_requires_python(spec) is ok

    def test_requires_python_for_a_full_version(self) -> None:
        assert not TargetEnv("3.11.2").accepts_requires_python(">=3.11.4")


class TestMajorAllowed:
    def test_policy(self) -> None:
        assert not major_allowed("pkg", None)
        assert major_allowed("pkg", [])
        assert major_allowed("My_Pkg", ["my-pkg"])
        assert not major_allowed("pkg", ["other"])


class TestOnlineSources:
    def test_osv_query_follows_pages(self) -> None:
        pages = [
            {"vulns": [{"id": "A"}], "next_page_token": "t"},
            {"vulns": [{"id": "B"}]},
        ]
        responses = [MagicMock(read=MagicMock(return_value=json.dumps(p).encode())) for p in pages]
        for r in responses:
            r.__enter__ = MagicMock(return_value=r)
            r.__exit__ = MagicMock(return_value=False)
        with patch("depfresh.advisories.urllib.request.urlopen", side_effect=responses) as mock:
            records = OnlineSources().osv_records("urllib3", "2.6.3")
        assert [r["id"] for r in records] == ["A", "B"]
        second = json.loads(mock.call_args_list[1].args[0].data)
        assert second["page_token"] == "t"
        assert second["package"] == {"name": "urllib3", "ecosystem": "PyPI"}

    def test_pypi_releases_flag_fully_yanked_versions(self) -> None:
        payload = {"releases": {
            "1.0": [{"yanked": False, "requires_python": ">=3.8"}],
            "1.1": [{"yanked": True}],
            "1.2": [],
            "bogus": [{"yanked": False}],
        }}
        response = MagicMock(read=MagicMock(return_value=json.dumps(payload).encode()))
        response.__enter__ = MagicMock(return_value=response)
        response.__exit__ = MagicMock(return_value=False)
        with patch("depfresh.advisories.urllib.request.urlopen", return_value=response) as mock:
            releases = OnlineSources().releases("My_Pkg")
        assert mock.call_args.args[0].full_url == "https://pypi.org/pypi/my-pkg/json"
        assert [(str(r.version), r.yanked) for r in releases] == [("1.0", False), ("1.1", True)]
        assert releases[0].requires_python == (">=3.8",)

    def test_network_errors_become_lookup_errors(self) -> None:
        import urllib.error

        with patch(
            "depfresh.advisories.urllib.request.urlopen",
            side_effect=urllib.error.URLError("denied"),
        ):
            with pytest.raises(AdvisoryLookupError, match="denied"):
                OnlineSources().releases("idna")
