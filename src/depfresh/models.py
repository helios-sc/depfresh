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
    """One advisory affecting one installed package, as found by pip-audit.

    OSV often returns the same advisory more than once (a GHSA record and a
    PYSEC record that alias each other); depfresh merges those into a single
    :class:`Vulnerability`.  ``cve`` is the display id (the CVE alias when
    there is one) and ``aliases`` holds every other id of the advisory.
    """

    package: str
    version: str
    cve: str
    fix_versions: str
    description: str
    aliases: tuple[str, ...] = ()

    @property
    def ids(self) -> tuple[str, ...]:
        """All ids of this advisory: the display id first, then the aliases."""
        return (self.cve, *(a for a in self.aliases if a != self.cve))

    @property
    def ghsa(self) -> str:
        """The GitHub Advisory Database id, or ``""`` when the advisory has none."""
        return next((i for i in self.ids if i.startswith("GHSA-")), "")


@dataclass
class PackageChange:
    """A package that changed version during upgrade."""

    name: str
    old_version: str
    new_version: str
    is_security_fix: bool = False


@dataclass
class PlannedFix:
    """One vulnerable package and what depfresh did (or could not do) about it.

    Attributes:
        package: Normalised name.
        current: Version before remediation.
        target: Lowest release that fixes every advisory (``None`` when none
            was chosen, see *status*).
        status: ``"applied"``, ``"needs-major"``, ``"kept"``, ``"no-fix"``,
            ``"private"``, ``"blocked"`` (a fix exists but could not be
            resolved) or ``"planned"`` (dry runs and audit-only runs).
        kind: Version change class (``"patch"``, ``"minor"``, ``"major"``…).
        reason: Human-readable explanation.
        advisories: Display ids of the advisories involved.
        final: Version shipped after remediation.
        open_advisories: ``{advisory id: reason}`` for the advisories the plan
            leaves open (see :attr:`depfresh.advisories.FixPlan.open_advisories`).
    """

    package: str
    current: str
    target: str | None
    status: str
    kind: str = ""
    reason: str = ""
    advisories: list[str] = field(default_factory=list)
    final: str | None = None
    open_advisories: dict[str, str] = field(default_factory=dict)


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
    import_check_baseline: ImportCheck | None = None
    #: Modules that resolved before the upgrade and fail after it.  When
    #: non-empty the dependency file is not written and the CLI exits 3.
    import_regressions: dict[str, str] = field(default_factory=dict)
    #: Why the write-back was withheld (empty when it ran or on a dry run).
    write_back_skipped: str = ""
    #: Unified diff of the dependency file: what was written, or on a dry run
    #: (or a withheld write-back) what would have been written.
    manifest_diff: str = ""

    pre_audit_vulns: list[Vulnerability] = field(default_factory=list)
    post_audit_vulns: list[Vulnerability] = field(default_factory=list)
    remaining_reasons: list[str] = field(default_factory=list)
    direct_references_ignored: list[str] = field(default_factory=list)

    upgraded: list[PackageChange] = field(default_factory=list)
    new_deps: list[PackageChange] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)

    original_count: int = 0
    final_count: int = 0

    #: ``"lock"`` (uv.lock), ``"requirements"``/``"pyproject"`` (resolved for
    #: the deploy platform) or ``"legacy"`` (``--strategy latest``).
    mode: str = "legacy"
    #: ``"minimal"`` (only vulnerable packages move) or ``"latest"``.
    strategy: str = "latest"
    #: Target platform the shipped set was resolved/evaluated for.
    platform: str = ""
    extras: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    fixes: list[PlannedFix] = field(default_factory=list)
    #: Every package version change in uv.lock (all groups, all platforms).
    lock_changes: list[PackageChange] = field(default_factory=list)
    #: ``"passed"``, ``"failed: …"`` or ``""`` when not applicable.
    lock_check: str = ""
    #: Fresh resolution of the written manifest for the target platform.
    resolution_check: str = ""
    #: Packages in the shipped set that were not audited, with the reason.
    not_audited: list[str] = field(default_factory=list)
    #: How many packages of the shipped set were audited before the upgrade
    #: (``None`` for ``--strategy latest``, which does not count them).
    audited_count: int | None = None
    #: Audited packages that a non-PyPI index (a mirror or proxy) serves,
    #: ``{name: index url}``.
    other_index: dict[str, str] = field(default_factory=dict)
    #: The commands depfresh ran to change the dependency files.
    commands: list[str] = field(default_factory=list)
    #: Files written (or that would be written on a dry run).
    files_changed: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    log_path: str | None = None
    markdown_path: str | None = None
