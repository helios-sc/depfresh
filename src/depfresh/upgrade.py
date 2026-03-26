"""Core upgrade orchestration — the main public API entry point."""

from __future__ import annotations

import datetime
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from depfresh.audit import install_pip_audit, run_audit
from depfresh.constraints import (
    build_constraints,
    compute_changes,
    diagnose_remaining,
    normalise,
)
from depfresh.exceptions import DirectReferenceError, RequirementsNotFoundError, TargetNotFoundError
from depfresh.models import DependencyScope, DependencySpec, UpgradeResult, Vulnerability
from depfresh.parsers import (
    DependencyFormat,
    FormatHandler,
    RequirementsSimpleHandler,
    detect_dep_file,
    detect_format,
    get_handler,
)
from depfresh.reports import write_log, write_markdown
from depfresh.uv import (
    cleanup_venv,
    create_venv,
    find_uv,
    freeze,
    get_uv_version,
    install_packages,
    install_requirements,
    run,
)
from depfresh.verify import verify_imports

log = logging.getLogger("depfresh")

_RUN_ID = f"{os.getpid()}"


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _write_installable_requirements(path: Path, deps: list[DependencySpec]) -> None:
    """Write a temp requirements file suitable for installing selected dependencies."""
    lines = [dep.requirement for dep in deps if dep.requirement]
    path.write_text("\n".join(lines) + "\n")


def _select_dependencies(
    handler: FormatHandler,
    req_path: Path,
    *,
    dependency_scope: DependencyScope,
    ignore_direct_references: bool,
) -> tuple[list[DependencySpec], dict[str, str], list[str]]:
    """Return selected registry dependencies, versions, and ignored direct refs."""
    inspection = handler.inspect(req_path)
    selected_registry = inspection.selected_registry(dependency_scope)
    selected_direct = inspection.selected_direct_references(dependency_scope)

    if selected_direct and not ignore_direct_references:
        raise DirectReferenceError(str(req_path), [dep.raw for dep in selected_direct])

    ignored_direct_refs = [dep.raw for dep in selected_direct] if ignore_direct_references else []
    old_pkgs = {dep.name: dep.version for dep in selected_registry}
    return selected_registry, old_pkgs, ignored_direct_refs


def _resolve_dep_file(
    target_dir: Path,
    dep_file: str | None,
    fmt: str | None,
) -> tuple[Path, DependencyFormat, FormatHandler]:
    """Locate and identify the dependency file.

    Returns
    -------
    tuple[Path, DependencyFormat, FormatHandler]
        ``(req_path, dep_format, handler)``

    Raises
    ------
    RequirementsNotFoundError
        If no dependency file can be located or the explicit path does not exist.
    """
    if dep_file:
        req_path = target_dir / dep_file
    else:
        try:
            req_path = detect_dep_file(target_dir)
        except FileNotFoundError as exc:
            raise RequirementsNotFoundError(str(target_dir)) from exc

    if not req_path.exists():
        raise RequirementsNotFoundError(str(req_path))

    dep_format = DependencyFormat(fmt) if fmt else detect_format(req_path)
    handler = get_handler(dep_format)
    return req_path, dep_format, handler


def _setup_venv(
    uv: str,
    target_dir: Path,
    venv_path: Path,
    python: str,
    handler: FormatHandler,
    install_deps: list[DependencySpec],
    old_pkgs: dict[str, str],
    req_path: Path,
    use_original_requirements: bool,
) -> tuple[str, str, str, frozenset[str], dict[str, str]]:
    """Create venv, install user deps, install pip-audit, freeze if needed.

    pip-audit is installed *before* the optional freeze so that its
    transitive dependencies can be excluded from the frozen baseline via
    ``extra_exclude``.

    Returns
    -------
    tuple
        ``(venv_python, actual_py_version, pip_audit_version,
           pip_audit_deps, resolved_pkgs)``
        where *resolved_pkgs* equals *old_pkgs* for pinned formats, or the
        output of :func:`depfresh.uv.freeze` (pip-audit deps excluded) for
        unpinned formats.
    """
    venv_python = create_venv(uv, venv_path, python)

    if use_original_requirements:
        install_requirements(uv, venv_python, req_path)
    else:
        # Generate a temp requirements file that preserves the selected scope,
        # markers, and extras for formats that cannot be installed directly.
        temp_install = target_dir / f".depfresh_install_{_RUN_ID}.tmp"
        _write_installable_requirements(temp_install, install_deps)
        try:
            install_requirements(uv, venv_python, temp_install)
        finally:
            temp_install.unlink(missing_ok=True)

    # Install pip-audit first so its deps are known before we freeze
    pip_audit_version, pip_audit_deps = install_pip_audit(uv, venv_python)

    resolved_pkgs = old_pkgs
    if not handler.is_pinned:
        resolved_pkgs = freeze(uv, venv_python, extra_exclude=pip_audit_deps)
        log.info("Resolved %d actual installed versions via freeze", len(resolved_pkgs))

    py_ver_result = run([venv_python, "--version"])
    actual_py_version = py_ver_result.stdout.strip().replace("Python ", "")

    return venv_python, actual_py_version, pip_audit_version, pip_audit_deps, resolved_pkgs


def _run_audit_with_temp(
    venv_python: str,
    target_dir: Path,
    pkgs: dict[str, str],
    label: str,
) -> list[Vulnerability]:
    """Write *pkgs* to a temp requirements file, run pip-audit, delete the file.

    The temp file is always removed, even when :func:`run_audit` raises.
    """
    tmp = target_dir / f".depfresh_audit_{label}_{_RUN_ID}.tmp"
    RequirementsSimpleHandler().write(pkgs, tmp)
    try:
        return run_audit(venv_python, tmp, label)
    finally:
        tmp.unlink(missing_ok=True)


@dataclass
class _CommonSetup:
    """Shared state produced by :func:`_prepare_run`."""

    target_dir: Path
    req_path: Path
    dep_format: DependencyFormat
    handler: FormatHandler
    uv: str
    uv_version: str
    venv_path: Path
    venv_python: str
    actual_py_version: str
    pip_audit_version: str
    pip_audit_deps: frozenset[str]
    old_pkgs: dict[str, str]
    ignored_direct_refs: list[str]


def _prepare_run(
    target: str | Path,
    *,
    dep_file: str | None,
    fmt: str | None,
    python: str,
    venv_name: str,
    dependency_scope: DependencyScope,
    ignore_direct_references: bool,
    log_header: str,
) -> _CommonSetup:
    """Validate inputs, resolve the dep file, create venv, and install deps.

    Shared between :func:`upgrade` and :func:`audit_only`.
    """
    target_dir = Path(target).expanduser().resolve()
    if not target_dir.is_dir():
        raise TargetNotFoundError(str(target_dir))

    req_path, dep_format, handler = _resolve_dep_file(target_dir, dep_file, fmt)
    venv_path = target_dir / f"{venv_name}-{_RUN_ID}"
    uv = find_uv()
    uv_version = get_uv_version(uv)

    log.info("%s — %s (format: %s)", log_header, req_path, dep_format.value)
    log.info("  dependency scope: %s", dependency_scope)
    log.info(
        "  direct references: %s",
        "ignored" if ignore_direct_references else "fail",
    )

    install_deps, old_pkgs, ignored_direct_refs = _select_dependencies(
        handler,
        req_path,
        dependency_scope=dependency_scope,
        ignore_direct_references=ignore_direct_references,
    )
    if ignored_direct_refs:
        for dep in ignored_direct_refs:
            log.warning("Ignoring direct reference due to --ignore-direct-references: %s", dep)

    use_original_requirements = (
        dep_format in (
            DependencyFormat.REQUIREMENTS_SIMPLE,
            DependencyFormat.REQUIREMENTS_HASHED,
            DependencyFormat.REQUIREMENTS_IN,
        )
        and not ignored_direct_refs
    )

    (venv_python, actual_py_version, pip_audit_version,
     pip_audit_deps, old_pkgs) = _setup_venv(
        uv,
        target_dir,
        venv_path,
        python,
        handler,
        install_deps,
        old_pkgs,
        req_path,
        use_original_requirements,
    )

    return _CommonSetup(
        target_dir=target_dir,
        req_path=req_path,
        dep_format=dep_format,
        handler=handler,
        uv=uv,
        uv_version=uv_version,
        venv_path=venv_path,
        venv_python=venv_python,
        actual_py_version=actual_py_version,
        pip_audit_version=pip_audit_version,
        pip_audit_deps=pip_audit_deps,
        old_pkgs=old_pkgs,
        ignored_direct_refs=ignored_direct_refs,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def derive_label(target_dir: Path) -> str:
    """Derive a human-readable label from a target directory path.

    Walks up from *target_dir*, collecting path parts until it finds a
    known boundary (a git root or a well-known parent like ``src``,
    ``services``).  Joins the collected parts with underscores.

    Examples::

        /code/myapp/src/jobs  -> myapp_jobs
        /code/myapp/src/api   -> myapp_api
        /code/other-repo      -> other-repo
    """
    parts: list[str] = []
    boundaries = {"src", "services", "packages", "libs", "apps"}
    current = target_dir.resolve()

    for _ in range(10):  # safety limit
        parts.append(current.name)
        parent = current.parent

        if (parent / ".git").exists():
            parts.append(parent.name)
            break

        if parent.name in boundaries:
            parts.append(parent.parent.name)
            break

        if parent == current:  # filesystem root
            break
        current = parent

    parts.reverse()
    return "_".join(parts)


def upgrade(
    target: str | Path,
    *,
    label: str | None = None,
    dep_file: str | None = None,
    fmt: str | None = None,
    python: str = "3.11",
    venv_name: str = ".venv-upgrade",
    dependency_scope: DependencyScope = "runtime",
    ignore_direct_references: bool = False,
    dry_run: bool = False,
    allow_major: list[str] | None = None,
    keep_version: list[str] | None = None,
    reports_dir: str | Path | None = None,
) -> UpgradeResult:
    """Upgrade Python dependencies and audit for vulnerabilities.

    This is the primary public API.  It performs the full workflow:

    1. Create a clean ``uv`` virtual environment
    2. Install current requirements
    3. Run a pre-upgrade vulnerability audit (``pip-audit``)
    4. Build constraints and upgrade packages
    5. Freeze the upgraded environment
    6. Verify that all third-party imports still resolve
    7. Run a post-upgrade vulnerability audit
    8. Write reports (log + markdown)
    9. Update the dependency file (unless *dry_run*)
    10. Clean up the temporary venv

    Parameters
    ----------
    target:
        Directory containing the dependency file.
    label:
        Report label / subfolder name.  Auto-derived from *target* if not
        given.
    dep_file:
        Name of the dependency file inside *target*.  Auto-detected when
        ``None``.
    fmt:
        Force a specific format (e.g. ``"pyproject-pep621"``).  Auto-detected
        when ``None``.
    python:
        Python version for the venv (e.g. ``"3.11"``, ``"3.12"``).
    venv_name:
        Name for the temporary virtual environment directory.
    dependency_scope:
        ``"runtime"`` → only the main dependency set for grouped formats.
        ``"all"`` → include optional/dev groups as well.
    ignore_direct_references:
        If ``False`` (default), selected git/path/url dependencies abort the
        run. If ``True``, they are skipped with a warning.
    dry_run:
        If ``True``, report what would change without modifying the
        dependency file.
    allow_major:
        ``None`` → minor/patch only (default).
        ``[]`` → allow major upgrades for all packages.
        ``["urllib3", ...]`` → allow major only for named packages.
    keep_version:
        Pin named packages to their current version exactly.
    reports_dir:
        Directory for report output.  Defaults to ``./reports/`` relative
        to the current working directory.

    Returns
    -------
    UpgradeResult
        Structured result with all upgrade details.

    Raises
    ------
    TargetNotFoundError
        If *target* is not an existing directory.
    RequirementsNotFoundError
        If no dependency file can be found.
    UvNotFoundError
        If ``uv`` is not installed.
    """
    ctx = _prepare_run(
        target,
        dep_file=dep_file,
        fmt=fmt,
        python=python,
        venv_name=venv_name,
        dependency_scope=dependency_scope,
        ignore_direct_references=ignore_direct_references,
        log_header="depfresh — upgrading",
    )

    service_label = label or derive_label(ctx.target_dir)
    today = datetime.date.today().isoformat()

    if reports_dir is not None:
        out_dir = Path(reports_dir).expanduser().resolve() / service_label
    else:
        out_dir = Path.cwd() / "reports" / service_label
    out_dir.mkdir(parents=True, exist_ok=True)

    constraints_path = ctx.target_dir / f".depfresh_constraints_{_RUN_ID}.txt"

    try:
        pre_vulns = _run_audit_with_temp(
            ctx.venv_python, ctx.target_dir, ctx.old_pkgs, "pre-upgrade",
        )

        log.info("Building upgrade constraints")
        constraints = build_constraints(
            ctx.old_pkgs, allow_major=allow_major, keep_version=keep_version,
        )
        constraints_path.write_text("\n".join(constraints) + "\n")
        log.debug("Wrote %d constraints to %s", len(constraints), constraints_path.name)

        install_packages(ctx.uv, ctx.venv_python, constraints_path)

        new_pkgs = freeze(ctx.uv, ctx.venv_python, extra_exclude=ctx.pip_audit_deps)

        import_check = verify_imports(ctx.target_dir, ctx.venv_python)

        post_vulns = _run_audit_with_temp(
            ctx.venv_python, ctx.target_dir, new_pkgs, "post-upgrade",
        )
    finally:
        constraints_path.unlink(missing_ok=True)
        cleanup_venv(ctx.venv_path)

    vuln_packages = {normalise(v.package) for v in pre_vulns}
    upgraded, new_deps, unchanged = compute_changes(ctx.old_pkgs, new_pkgs, vuln_packages)

    remaining_reasons = diagnose_remaining(
        post_vulns, ctx.old_pkgs,
        allow_major=allow_major, keep_version=keep_version,
    )

    result = UpgradeResult(
        date=today,
        python_version=ctx.actual_py_version,
        uv_version=ctx.uv_version,
        pip_audit_version=ctx.pip_audit_version,
        requirements_path=ctx.req_path.name,
        venv_name=venv_name,
        service_label=service_label,
        dependency_scope=dependency_scope,
        ignore_direct_references=ignore_direct_references,
        allow_major=allow_major,
        keep_version=keep_version,
        dry_run=dry_run,
        import_check=import_check,
        pre_audit_vulns=pre_vulns,
        post_audit_vulns=post_vulns,
        remaining_reasons=remaining_reasons,
        direct_references_ignored=ctx.ignored_direct_refs,
        upgraded=upgraded,
        new_deps=new_deps,
        unchanged=unchanged,
        original_count=len(ctx.old_pkgs),
        final_count=len(new_pkgs),
    )

    if not dry_run:
        ctx.handler.write(
            new_pkgs,
            ctx.req_path,
            uv=ctx.uv,
            python_version=python,
            dependency_scope=dependency_scope,
        )
        result.dep_file_updated = True
        log.info("%s UPDATED", ctx.req_path)
    else:
        log.info("DRY RUN — %s NOT modified", ctx.req_path.name)
        log.info("Would upgrade %d packages, add %d new deps", len(upgraded), len(new_deps))

    log.info("Writing reports to %s", out_dir)
    log_path = write_log(result, out_dir, today)
    md_path = write_markdown(result, out_dir, today)
    result.log_path = str(log_path)
    result.markdown_path = str(md_path)

    return result


def audit_only(
    target: str | Path,
    *,
    dep_file: str | None = None,
    fmt: str | None = None,
    python: str = "3.11",
    venv_name: str = ".venv-audit",
    dependency_scope: DependencyScope = "runtime",
    ignore_direct_references: bool = False,
) -> UpgradeResult:
    """Run a vulnerability audit without upgrading anything.

    Creates a temporary venv, installs requirements, runs pip-audit,
    and returns the results.  The dependency file is never modified.
    """
    ctx = _prepare_run(
        target,
        dep_file=dep_file,
        fmt=fmt,
        python=python,
        venv_name=venv_name,
        dependency_scope=dependency_scope,
        ignore_direct_references=ignore_direct_references,
        log_header="depfresh audit-only",
    )

    try:
        vulns = _run_audit_with_temp(ctx.venv_python, ctx.target_dir, ctx.old_pkgs, "audit")
    finally:
        cleanup_venv(ctx.venv_path)

    return UpgradeResult(
        date=datetime.date.today().isoformat(),
        python_version=ctx.actual_py_version,
        uv_version=ctx.uv_version,
        pip_audit_version=ctx.pip_audit_version,
        requirements_path=ctx.req_path.name,
        venv_name=venv_name,
        service_label=derive_label(ctx.target_dir),
        dependency_scope=dependency_scope,
        ignore_direct_references=ignore_direct_references,
        pre_audit_vulns=vulns,
        direct_references_ignored=ctx.ignored_direct_refs,
        original_count=len(ctx.old_pkgs),
        final_count=len(ctx.old_pkgs),
    )
