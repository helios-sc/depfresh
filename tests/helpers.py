"""Shared test utilities."""

from __future__ import annotations

from typing import Any

from packaging.version import Version

from depfresh.advisories import Release
from depfresh.models import UpgradeResult, Vulnerability


def make_result(**kwargs: Any) -> UpgradeResult:
    """Build a minimal ``UpgradeResult`` for testing.

    Provides sensible defaults for all required fields so individual tests
    only need to override the fields they care about.
    """
    defaults: dict[str, object] = dict(
        date="2026-03-23",
        python_version="3.11",
        uv_version="0.5.0",
        pip_audit_version="2.7.0",
        requirements_path="requirements.txt",
        venv_name=".venv-upgrade",
        service_label="test_service",
        original_count=10,
        final_count=10,
    )
    defaults.update(kwargs)
    return UpgradeResult(**defaults)  # type: ignore[arg-type]


class MixedAuditor:
    """demo has GHSA-aaaa (fixed in 2.0.1) and GHSA-bbbb (no fix released)."""

    def audit(self, pins: dict[str, str], label: str) -> list[Vulnerability]:
        if "demo" not in pins:
            return []
        version = pins["demo"]
        found = [Vulnerability("demo", version, "GHSA-bbbb", "", "")]
        if Version(version) < Version("2.0.1"):
            found.insert(0, Vulnerability("demo", version, "GHSA-aaaa", "2.0.1", ""))
        return found


class MixedSources:
    def osv_records(self, package: str, version: str) -> list[dict[str, Any]]:
        def record(vid: str, *events: dict[str, str]) -> dict[str, Any]:
            return {"id": vid, "affected": [{
                "package": {"name": "demo", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, *events]}],
            }]}

        return [record("GHSA-aaaa", {"fixed": "2.0.1"}), record("GHSA-bbbb")]

    def releases(self, package: str) -> list[Release]:
        return [Release(Version(v)) for v in ("2.0.0", "2.0.1", "2.1.0", "3.0.0")]
