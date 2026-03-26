"""Shared test utilities."""

from __future__ import annotations

from typing import Any

from depfresh.models import UpgradeResult


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
