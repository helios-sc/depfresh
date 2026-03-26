"""Data models for depfresh."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

DependencyScope = Literal["runtime", "all"]
DependencySourceKind = Literal["registry", "direct-reference"]


@dataclass(frozen=True)
class DependencySpec:
    """A parsed dependency entry with enough metadata for safe installs.

    ``requirement`` is a PEP 508-ish requirement line suitable for temporary
    install files. ``version`` is the extracted current/minimum version used
    by depfresh for upgrade planning and diagnostics.
    """

    name: str
    version: str
    requirement: str
    raw: str
    source_kind: DependencySourceKind = "registry"
    group: str = "runtime"
    is_runtime: bool = True


@dataclass
class DependencyInspection:
    """Structured view of a dependency file before upgrade orchestration."""

    registry: list[DependencySpec] = field(default_factory=list)
    direct_references: list[DependencySpec] = field(default_factory=list)

    def selected_registry(self, dependency_scope: DependencyScope) -> list[DependencySpec]:
        """Return registry dependencies selected for the chosen scope."""
        if dependency_scope == "all":
            return list(self.registry)
        return [dep for dep in self.registry if dep.is_runtime]

    def selected_direct_references(self, dependency_scope: DependencyScope) -> list[DependencySpec]:
        """Return direct references selected for the chosen scope."""
        if dependency_scope == "all":
            return list(self.direct_references)
        return [dep for dep in self.direct_references if dep.is_runtime]


@dataclass
class Vulnerability:
    """A single known vulnerability found by pip-audit."""

    package: str
    version: str
    cve: str
    fix_versions: str
    description: str


@dataclass
class PackageChange:
    """A package that changed version during upgrade."""

    name: str
    old_version: str
    new_version: str
    is_security_fix: bool = False


@dataclass
class ImportCheck:
    """Results from verifying third-party imports against the upgraded environment."""

    files_scanned: int = 0
    total_imports: int = 0
    verified: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)
    skipped_local: list[str] = field(default_factory=list)
    warnings: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class UpgradeResult:
    """Complete result of an upgrade run — the primary return type of the public API."""

    date: str
    python_version: str
    uv_version: str
    pip_audit_version: str
    requirements_path: str
    venv_name: str
    service_label: str
    dependency_scope: DependencyScope = "runtime"
    ignore_direct_references: bool = False
    allow_major: list[str] | None = None
    keep_version: list[str] | None = None
    dry_run: bool = False
    dep_file_updated: bool = False
    import_check: ImportCheck | None = None

    pre_audit_vulns: list[Vulnerability] = field(default_factory=list)
    post_audit_vulns: list[Vulnerability] = field(default_factory=list)
    remaining_reasons: list[str] = field(default_factory=list)
    direct_references_ignored: list[str] = field(default_factory=list)

    upgraded: list[PackageChange] = field(default_factory=list)
    new_deps: list[PackageChange] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)

    original_count: int = 0
    final_count: int = 0

    log_path: str | None = None
    markdown_path: str | None = None
