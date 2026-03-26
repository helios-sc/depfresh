"""depfresh — Upgrade Python dependencies to their latest safe versions.

Usage as a library::

    from depfresh import upgrade, audit_only

    # Full upgrade workflow
    result = upgrade(
        "/path/to/project",
        python="3.12",
        allow_major=["urllib3"],
        keep_version=["crewai"],
    )
    print(result.upgraded)
    print(result.pre_audit_vulns)

    # Audit-only (no modifications)
    result = audit_only("/path/to/project")
    print(result.pre_audit_vulns)

Usage as a CLI::

    depfresh /path/to/project
    depfresh /path/to/project --dry-run --allow-major urllib3
"""

from importlib.metadata import PackageNotFoundError, version

from depfresh.models import ImportCheck, PackageChange, UpgradeResult, Vulnerability
from depfresh.upgrade import audit_only, upgrade

try:
    __version__ = version("depfresh")
except PackageNotFoundError:
    __version__ = "0.0.0"

__all__ = [
    "audit_only",
    "upgrade",
    "ImportCheck",
    "PackageChange",
    "UpgradeResult",
    "Vulnerability",
    "__version__",
]
