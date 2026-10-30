"""Core upgrade orchestration — the main public API entry point."""

from __future__ import annotations

import datetime
import difflib
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from depfresh.advisories import DEFAULT_PLATFORM, AdvisorySources, TargetEnv
from depfresh.audit import install_pip_audit, run_audit, write_pinned_requirements
from depfresh.constraints import (
    build_constraints,
    compute_changes,
    diagnose_remaining,
    normalise,
)
from depfresh.exceptions import DirectReferenceError, RequirementsNotFoundError, TargetNotFoundError
from depfresh.lockmode import LockOutcome, remediate_lock
from depfresh.models import DependencyScope, DependencySpec, UpgradeResult, Vulnerability
from depfresh.parsers import (
    DependencyFormat,
    FormatHandler,
    choose_dep_file,
    detect_format,
    get_handler,
)
from depfresh.remediation import (
    Auditor,
    RemediationOptions,
    default_sources,
    diff_sets,
    planned_fixes,
    remaining_reasons,
)
from depfresh.reports import write_log, write_markdown
from depfresh.textio import decode_bytes, read_text_file
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
from depfresh.verify import import_regressions, verify_imports

log = logging.getLogger("depfresh")

_RUN_ID = f"{os.getpid()}"

Strategy = Literal["minimal", "latest"]


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
            choice = choose_dep_file(target_dir)
        except FileNotFoundError as exc:
            raise RequirementsNotFoundError(str(target_dir)) from exc
        req_path = choice.path
        log.info("Auto-detected %s: %s", req_path.name, choice.reason)

    if not req_path.exists():
        raise RequirementsNotFoundError(str(req_path))

    dep_format = DependencyFormat(fmt) if fmt else detect_format(req_path)
    handler = get_handler(dep_format)
    return req_path, dep_format, handler


def _setup_venv(
    uv: str,
    work_dir: Path,
    venv_path: Path,
    python: str,
    handler: FormatHandler,
    install_deps: list[DependencySpec],
    old_pkgs: dict[str, str],
    req_path: Path,
    use_original_requirements: bool,
) -> tuple[str, str, dict[str, str]]:
    """Create the project venv, install the user's dependencies, freeze if needed.

    pip-audit is *not* installed here: it runs from its own tool environment
    (see :func:`depfresh.audit.install_pip_audit`), so this venv holds only
    the project's packages.

    Returns
    -------
    tuple
        ``(venv_python, actual_py_version, resolved_pkgs)`` where
        *resolved_pkgs* equals *old_pkgs* for pinned formats, or the output of
        :func:`depfresh.uv.freeze` for unpinned formats.
    """
    venv_python = create_venv(uv, venv_path, python)

    if use_original_requirements:
        install_requirements(uv, venv_python, req_path)
    else:
        # Generate a temp requirements file that preserves the selected scope,
        # markers, and extras for formats that cannot be installed directly.
        temp_install = work_dir / f".depfresh_install_{_RUN_ID}.tmp"
        _write_installable_requirements(temp_install, install_deps)
        try:
            install_requirements(uv, venv_python, temp_install)
        finally:
            temp_install.unlink(missing_ok=True)

    resolved_pkgs = old_pkgs
    if not handler.is_pinned:
        resolved_pkgs = freeze(uv, venv_python)
        log.info("Resolved %d actual installed versions via freeze", len(resolved_pkgs))

    py_ver_result = run([venv_python, "--version"])
    actual_py_version = py_ver_result.stdout.strip().replace("Python ", "")

    return venv_python, actual_py_version, resolved_pkgs


def _run_audit_with_temp(
    audit_python: str,
    work_dir: Path,
    pkgs: dict[str, str],
    label: str,
) -> list[Vulnerability]:
    """Write *pkgs* to a temp pinned requirements file, run pip-audit, delete the file.

    The temp file is always removed, even when :func:`run_audit` raises.
    """
    tmp = work_dir / f".depfresh_audit_{label}_{_RUN_ID}.tmp"
    write_pinned_requirements(pkgs, tmp)
    try:
        return run_audit(audit_python, tmp, label)
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
    work_dir: Path
    venv_path: Path
    venv_python: str
    audit_python: str
    actual_py_version: str
    pip_audit_version: str
    old_pkgs: dict[str, str]
    ignored_direct_refs: list[str]


def _cleanup_work_dir(work_dir: Path, venv_path: Path) -> None:
    """Remove the temporary venv and depfresh's work directory."""
    cleanup_venv(venv_path)
    shutil.rmtree(work_dir, ignore_errors=True)


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
    uv_binary: str | None = None,
) -> _CommonSetup:
    """Validate inputs, resolve the dep file, create venvs, and install deps.

    Shared between :func:`upgrade` and :func:`audit_only`.  Everything depfresh
    creates lives in a temporary work directory outside the target, which is
    removed again if any step here fails.
    """
    target_dir = Path(target).expanduser().resolve()
    if not target_dir.is_dir():
        raise TargetNotFoundError(str(target_dir))

    req_path, dep_format, handler = _resolve_dep_file(target_dir, dep_file, fmt)

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

    uv = find_uv(uv_binary)
    uv_version = get_uv_version(uv)
    log.info("Using uv %s at %s", uv_version, uv)

    use_original_requirements = (
        dep_format in (
            DependencyFormat.REQUIREMENTS_SIMPLE,
            DependencyFormat.REQUIREMENTS_HASHED,
            DependencyFormat.REQUIREMENTS_IN,
        )
        and not ignored_direct_refs
        # uv reads requirements files as UTF-8; a UTF-16 file goes through
        # the synthesized install file instead.
        and read_text_file(req_path).is_utf8
    )

    work_dir = Path(tempfile.mkdtemp(prefix=f"depfresh-{_RUN_ID}-"))
    venv_path = work_dir / venv_name
    try:
        venv_python, actual_py_version, old_pkgs = _setup_venv(
            uv,
            work_dir,
            venv_path,
            python,
            handler,
            install_deps,
            old_pkgs,
            req_path,
            use_original_requirements,
        )
        audit_python, pip_audit_version = install_pip_audit(
            uv, work_dir / ".pip-audit-tool", python,
        )
    except BaseException:
        _cleanup_work_dir(work_dir, venv_path)
        raise

    return _CommonSetup(
        target_dir=target_dir,
        req_path=req_path,
        dep_format=dep_format,
        handler=handler,
        uv=uv,
        uv_version=uv_version,
        work_dir=work_dir,
        venv_path=venv_path,
        venv_python=venv_python,
        audit_python=audit_python,
        actual_py_version=actual_py_version,
        pip_audit_version=pip_audit_version,
        old_pkgs=old_pkgs,
        ignored_direct_refs=ignored_direct_refs,
    )


def _render_write(
    handler: FormatHandler, pkgs: dict[str, str], req_path: Path, **kwargs: object,
) -> bytes:
    """Return the bytes *handler* would write to *req_path*, without touching it."""
    with tempfile.TemporaryDirectory(prefix="depfresh-render-") as tmp:
        copy = Path(tmp) / req_path.name
        shutil.copy2(req_path, copy)
        handler.write(pkgs, copy, **kwargs)
        return copy.read_bytes()


def manifest_diff(path: Path, new_content: bytes) -> str:
    """Unified diff between *path* on disk and *new_content* (``""`` if equal)."""
    before = read_text_file(path).text
    after = decode_bytes(new_content, source=str(path)).text
    if before == after:
        return ""
    return "".join(difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"a/{path.name}",
        tofile=f"b/{path.name}",
    ))


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


def _upgrade_latest(
    target: str | Path,
    *,
    label: str | None,
    dep_file: str | None,
    fmt: str | None,
    python: str,
    venv_name: str,
    dependency_scope: DependencyScope,
    ignore_direct_references: bool,
    dry_run: bool,
    allow_major: list[str] | None,
    keep_version: list[str] | None,
    reports_dir: str | Path | None,
    uv_binary: str | None,
) -> UpgradeResult:
    """The ``--strategy latest`` workflow: upgrade every package within its bounds.

    It performs:

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

    The environment is resolved on this machine, not for the deploy
    platform; the minimal strategy (the default) resolves for the target.
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
        uv_binary=uv_binary,
    )

    service_label = label or derive_label(ctx.target_dir)
    today = datetime.date.today().isoformat()

    if reports_dir is not None:
        out_dir = Path(reports_dir).expanduser().resolve() / service_label
    else:
        out_dir = Path.cwd() / "reports" / service_label
    out_dir.mkdir(parents=True, exist_ok=True)
    log.warning(
        "--strategy latest: upgrading every package within its bounds, resolved on this "
        "machine rather than for the deploy platform"
    )

    constraints_path = ctx.work_dir / f".depfresh_constraints_{_RUN_ID}.txt"

    try:
        pre_vulns = _run_audit_with_temp(
            ctx.audit_python, ctx.work_dir, ctx.old_pkgs, "pre-upgrade",
        )
        baseline_check = verify_imports(ctx.target_dir, ctx.venv_python, label="baseline")

        log.info("Building upgrade constraints")
        constraints = build_constraints(
            ctx.old_pkgs, allow_major=allow_major, keep_version=keep_version,
        )
        constraints_path.write_text("\n".join(constraints) + "\n")
        log.debug("Wrote %d constraints to %s", len(constraints), constraints_path.name)

        install_packages(ctx.uv, ctx.venv_python, constraints_path)

        new_pkgs = freeze(ctx.uv, ctx.venv_python)

        import_check = verify_imports(ctx.target_dir, ctx.venv_python, label="upgraded")

        post_vulns = _run_audit_with_temp(
            ctx.audit_python, ctx.work_dir, new_pkgs, "post-upgrade",
        )
    finally:
        constraints_path.unlink(missing_ok=True)
        _cleanup_work_dir(ctx.work_dir, ctx.venv_path)

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
        import_check_baseline=baseline_check,
        import_regressions=import_regressions(baseline_check, import_check),
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

    # Render the write-back on a copy first: the report shows exactly what
    # changes (or would change) in the dependency file, dry run or not.
    new_content = _render_write(
        ctx.handler,
        new_pkgs,
        ctx.req_path,
        uv=ctx.uv,
        python_version=python,
        dependency_scope=dependency_scope,
    )
    result.manifest_diff = manifest_diff(ctx.req_path, new_content)

    if result.import_regressions:
        result.write_back_skipped = (
            f"{len(result.import_regressions)} import(s) resolved before the upgrade "
            "and fail after it"
        )
        log.error(
            "NOT writing %s: %s: %s",
            ctx.req_path.name, result.write_back_skipped,
            ", ".join(result.import_regressions),
        )
    elif not dry_run:
        if result.manifest_diff:
            ctx.req_path.write_bytes(new_content)
            result.dep_file_updated = True
            log.info("%s UPDATED", ctx.req_path)
        else:
            log.info("%s already up to date", ctx.req_path.name)
    else:
        log.info("DRY RUN — %s NOT modified", ctx.req_path.name)
        log.info("Would upgrade %d packages, add %d new deps", len(upgraded), len(new_deps))

    if result.manifest_diff:
        result.files_changed = [ctx.req_path.name]
    _write_reports(result, out_dir, today)
    return result


def _audit_only_legacy(
    target: str | Path,
    *,
    dep_file: str | None,
    fmt: str | None,
    python: str,
    venv_name: str,
    dependency_scope: DependencyScope,
    ignore_direct_references: bool,
    uv_binary: str | None,
) -> UpgradeResult:
    """Audit by installing the dependency file into a venv on this machine."""
    ctx = _prepare_run(
        target,
        dep_file=dep_file,
        fmt=fmt,
        python=python,
        venv_name=venv_name,
        dependency_scope=dependency_scope,
        ignore_direct_references=ignore_direct_references,
        log_header="depfresh audit-only",
        uv_binary=uv_binary,
    )

    try:
        vulns = _run_audit_with_temp(ctx.audit_python, ctx.work_dir, ctx.old_pkgs, "audit")
    finally:
        _cleanup_work_dir(ctx.work_dir, ctx.venv_path)

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


def _write_reports(result: UpgradeResult, out_dir: Path, today: str) -> None:
    log.info("Writing reports to %s", out_dir)
    result.log_path = str(write_log(result, out_dir, today))
    result.markdown_path = str(write_markdown(result, out_dir, today))


# ---------------------------------------------------------------------------
# Minimal remediation (lock-aware and resolved modes)
# ---------------------------------------------------------------------------


@dataclass
class _Manifest:
    """The dependency file of a run and how it ships."""

    target_dir: Path
    path: Path
    fmt: DependencyFormat
    handler: FormatHandler
    dockerfile_extras: tuple[str, ...] = ()
    detection_reason: str = ""

    @property
    def is_uv_lock_project(self) -> bool:
        return (
            self.path.name == "pyproject.toml"
            and self.fmt == DependencyFormat.PYPROJECT_PEP621
            and (self.path.parent / "uv.lock").is_file()
        )


def _resolve_manifest(target_dir: Path, dep_file: str | None, fmt: str | None) -> _Manifest:
    if dep_file:
        path = target_dir / dep_file
        extras: tuple[str, ...] = ()
        reason = "--dep-file"
    else:
        try:
            choice = choose_dep_file(target_dir)
        except FileNotFoundError as exc:
            raise RequirementsNotFoundError(str(target_dir)) from exc
        path, extras, reason = choice.path, choice.extras, choice.reason
        log.info("Auto-detected %s: %s", path.name, reason)
    if not path.exists():
        raise RequirementsNotFoundError(str(path))
    dep_format = DependencyFormat(fmt) if fmt else detect_format(path)
    return _Manifest(target_dir, path, dep_format, get_handler(dep_format), extras, reason)


def _options(
    *,
    python: str,
    platform: str,
    allow_major: list[str] | None,
    keep_version: list[str] | None,
    dry_run: bool,
    import_check: bool,
    extras: list[str] | None,
    all_extras: bool,
    groups: list[str] | None,
    all_groups: bool,
    dependency_scope: DependencyScope,
    manifest: _Manifest,
) -> RemediationOptions:
    chosen_extras = tuple(_split_names(extras))
    if not chosen_extras and not all_extras and manifest.dockerfile_extras:
        chosen_extras = manifest.dockerfile_extras
        log.info(
            "Using the extras the Dockerfile installs: %s (override with --extra)",
            ", ".join(chosen_extras),
        )
    return RemediationOptions(
        env=TargetEnv(python, platform),
        allow_major=allow_major,
        keep_version=keep_version,
        dry_run=dry_run,
        import_check=import_check,
        extras=chosen_extras,
        all_extras=all_extras or dependency_scope == "all",
        groups=tuple(_split_names(groups)),
        all_groups=all_groups or dependency_scope == "all",
    )


def _split_names(values: list[str] | None) -> list[str]:
    """Accept ``["a,b", "c"]`` as well as ``["a", "b", "c"]``."""
    out: list[str] = []
    for value in values or []:
        out += [v.strip() for v in value.split(",") if v.strip()]
    return out


def _out_dir(reports_dir: str | Path | None, service_label: str) -> Path:
    if reports_dir is not None:
        out = Path(reports_dir).expanduser().resolve() / service_label
    else:
        out = Path.cwd() / "reports" / service_label
    out.mkdir(parents=True, exist_ok=True)
    return out


def _lock_result(
    outcome: LockOutcome,
    *,
    manifest: _Manifest,
    options: RemediationOptions,
    uv_version: str,
    pip_audit_version: str,
    service_label: str,
    venv_name: str,
    dependency_scope: DependencyScope,
    audit_only_run: bool,
) -> UpgradeResult:
    """Build the :class:`UpgradeResult` of a lock-aware run (nothing written yet)."""
    vulnerable = {normalise(v.package) for v in outcome.pre_vulns}
    still = {normalise(v.package) for v in outcome.post_vulns}
    changed, added, unchanged, removed = diff_sets(
        outcome.baseline.pins, outcome.final.pins, vulnerable,
    )
    fixes = planned_fixes(
        outcome.plans, outcome.final.pins, outcome.failures, still,
        applied=not (options.dry_run or audit_only_run),
    )
    files = (["uv.lock"] if outcome.new_lock else []) + (
        ["pyproject.toml"] if outcome.new_pyproject else []
    )
    gate = outcome.gate
    result = UpgradeResult(
        date=datetime.date.today().isoformat(),
        python_version=options.env.python_version,
        uv_version=uv_version,
        pip_audit_version=pip_audit_version,
        requirements_path="uv.lock",
        venv_name=venv_name,
        service_label=service_label,
        dependency_scope=dependency_scope,
        allow_major=options.allow_major,
        keep_version=options.keep_version,
        dry_run=options.dry_run,
        import_check=gate.after,
        import_check_baseline=gate.baseline,
        import_regressions=gate.regressions(),
        pre_audit_vulns=outcome.pre_vulns,
        post_audit_vulns=[] if audit_only_run else outcome.post_vulns,
        upgraded=changed,
        new_deps=added,
        unchanged=unchanged,
        original_count=len(outcome.baseline.pins),
        final_count=len(outcome.final.pins),
        mode="lock",
        strategy="minimal",
        platform=options.env.platform,
        extras=list(options.extras) or (["(all)"] if options.all_extras else []),
        groups=list(options.groups) or (["(all)"] if options.all_groups else ["(no dev)"]),
        fixes=fixes,
        lock_changes=outcome.lock_changes,
        lock_check=outcome.lock_check,
        not_audited=outcome.baseline.not_audited,
        commands=outcome.commands,
        files_changed=files,
        notes=[*outcome.notes, *gate.notes, *(f"Removed from the shipped set: {c.name} "
                                              f"{c.old_version}" for c in removed)],
        manifest_diff=outcome.pyproject_diff,
    )
    result.remaining_reasons = remaining_reasons(result.post_audit_vulns, fixes)
    if gate.blocked:
        result.write_back_skipped = gate.blocked
    elif result.import_regressions:
        result.write_back_skipped = (
            f"{len(result.import_regressions)} import(s) resolved before the upgrade "
            "and fail after it"
        )
    elif outcome.lock_check.startswith("failed"):
        result.write_back_skipped = f"uv lock --check {outcome.lock_check}"
    return result


def _run_lock_mode(
    manifest: _Manifest,
    options: RemediationOptions,
    *,
    uv_binary: str | None,
    service_label: str,
    venv_name: str,
    dependency_scope: DependencyScope,
    sources: AdvisorySources | None,
    audit_only_run: bool,
) -> UpgradeResult:
    uv = find_uv(uv_binary)
    uv_version = get_uv_version(uv)
    log.info("depfresh — lock-aware %s of %s (uv %s at %s)",
             "audit" if audit_only_run else "remediation", manifest.target_dir, uv_version, uv)
    log.info("  target: %s, Python %s; groups: %s; extras: %s",
             options.env.platform, options.env.python_version,
             "all" if options.all_groups else (", ".join(options.groups) or "no dev"),
             "all" if options.all_extras else (", ".join(options.extras) or "none"))
    work_dir = Path(tempfile.mkdtemp(prefix=f"depfresh-{_RUN_ID}-"))
    try:
        audit_python, pip_audit_version = install_pip_audit(
            uv, work_dir / ".pip-audit-tool", options.env.python_minor,
        )
        outcome = remediate_lock(
            uv=uv,
            target_dir=manifest.target_dir,
            work_dir=work_dir,
            auditor=Auditor(audit_python, work_dir),
            options=options,
            sources=sources or default_sources(),
            venv_name=venv_name,
            audit_only=audit_only_run,
        )
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    result = _lock_result(
        outcome, manifest=manifest, options=options, uv_version=uv_version,
        pip_audit_version=pip_audit_version, service_label=service_label,
        venv_name=venv_name, dependency_scope=dependency_scope, audit_only_run=audit_only_run,
    )
    if audit_only_run:
        return result
    if result.write_back_skipped:
        log.error("NOT writing %s: %s", ", ".join(result.files_changed) or "uv.lock",
                  result.write_back_skipped)
    elif options.dry_run:
        log.info("DRY RUN — %s NOT modified", ", ".join(result.files_changed) or "nothing")
    elif result.files_changed:
        if outcome.new_lock is not None:
            (manifest.target_dir / "uv.lock").write_bytes(outcome.new_lock)
        if outcome.new_pyproject is not None:
            manifest.path.write_bytes(outcome.new_pyproject)
        result.dep_file_updated = True
        log.info("UPDATED %s", ", ".join(result.files_changed))
    else:
        log.info("Nothing to change")
    return result


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
    uv_binary: str | None = None,
    strategy: Strategy = "minimal",
    extras: list[str] | None = None,
    all_extras: bool = False,
    groups: list[str] | None = None,
    all_groups: bool = False,
    platform: str = DEFAULT_PLATFORM,
    import_check: bool = True,
    sources: AdvisorySources | None = None,
) -> UpgradeResult:
    """Audit Python dependencies and fix the vulnerable ones.

    This is the primary public API.  With the default ``strategy="minimal"``
    only vulnerable packages move, each to the lowest release that fixes all
    of its advisories:

    * **uv projects** (``pyproject.toml`` next to ``uv.lock``): the locked set
      is exported and audited, fixed with ``uv lock --upgrade-package
      <pkg>==<fix>``, re-exported and re-audited, and checked with ``uv lock
      --check``.  The write-back is the updated ``uv.lock``.
    * other formats keep the ``latest`` workflow for now.

    ``strategy="latest"`` upgrades every package to its newest release within
    the current major (or across it with *allow_major*).

    Imports are checked before and after; a module that resolved before and
    fails after blocks the write-back (``import_regressions``).

    Parameters
    ----------
    target:
        Directory containing the dependency file.
    label:
        Report label / subfolder name.  Auto-derived from *target* if not
        given.
    dep_file:
        Name of the dependency file inside *target*.  Auto-detected when
        ``None`` (``pyproject.toml`` when a ``uv.lock`` exists, otherwise what
        a local Dockerfile installs, otherwise the first known file).
    fmt:
        Force a specific format (e.g. ``"pyproject-pep621"``).
    python:
        Deploy Python version (e.g. ``"3.11"``, ``"3.12"``).
    venv_name:
        Name for the temporary virtual environment directory.
    dependency_scope:
        ``"runtime"`` → only the main dependency set; ``"all"`` → every
        optional group and dependency group as well.
    ignore_direct_references:
        If ``False`` (default), selected git/path/url dependencies abort the
        run. If ``True``, they are skipped with a warning.
    dry_run:
        If ``True``, report what would change without modifying any file.
    allow_major:
        ``None`` → stay within the current major (default); ``[]`` → any
        package may cross a major; ``["urllib3", ...]`` → only those.
    keep_version:
        Packages that must keep their current version.
    reports_dir:
        Directory for report output (default ``./reports/``).
    uv_binary:
        Path to the ``uv`` binary.  By default depfresh searches
        ``DEPFRESH_UV``, its own environment and ``PATH`` for a uv of at least
        :data:`depfresh.uv.MIN_UV_VERSION`.
    strategy:
        ``"minimal"`` (default) or ``"latest"``.
    extras, all_extras:
        Optional-dependency groups that ship.  When neither is given and a
        Dockerfile installs ``.[a,b]``, those extras are used.
    groups, all_groups:
        Dependency groups that ship (lock mode; default: everything but dev).
    platform:
        Deploy platform (``uv pip compile --python-platform`` names).
    import_check:
        Compare imports before and after (installs both sets on this host).
    sources:
        Advisory/release sources (tests inject fakes; default OSV + PyPI).

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
    UvNotFoundError, UvVersionError
        If no supported ``uv`` is available.
    PrivateIndexError
        If a private package index cannot be reached.
    """
    if strategy not in ("minimal", "latest"):
        raise ValueError(f"Unknown strategy {strategy!r}; use 'minimal' or 'latest'")
    target_dir = Path(target).expanduser().resolve()
    if not target_dir.is_dir():
        raise TargetNotFoundError(str(target_dir))
    manifest = _resolve_manifest(target_dir, dep_file, fmt)

    if strategy == "minimal" and manifest.is_uv_lock_project:
        service_label = label or derive_label(target_dir)
        options = _options(
            python=python, platform=platform, allow_major=allow_major,
            keep_version=keep_version, dry_run=dry_run, import_check=import_check,
            extras=extras, all_extras=all_extras, groups=groups, all_groups=all_groups,
            dependency_scope=dependency_scope, manifest=manifest,
        )
        result = _run_lock_mode(
            manifest, options, uv_binary=uv_binary, service_label=service_label,
            venv_name=venv_name, dependency_scope=dependency_scope, sources=sources,
            audit_only_run=False,
        )
        _write_reports(result, _out_dir(reports_dir, service_label), result.date)
        return result

    if strategy == "minimal":
        log.info("Minimal remediation for %s arrives with resolved mode; using 'latest'",
                 manifest.fmt.value)
    return _upgrade_latest(
        target_dir,
        label=label,
        dep_file=dep_file or str(manifest.path.relative_to(target_dir)),
        fmt=fmt,
        python=python,
        venv_name=venv_name,
        dependency_scope=dependency_scope,
        ignore_direct_references=ignore_direct_references,
        dry_run=dry_run,
        allow_major=allow_major,
        keep_version=keep_version,
        reports_dir=reports_dir,
        uv_binary=uv_binary,
    )


def audit_only(
    target: str | Path,
    *,
    dep_file: str | None = None,
    fmt: str | None = None,
    python: str = "3.11",
    venv_name: str = ".venv-audit",
    dependency_scope: DependencyScope = "runtime",
    ignore_direct_references: bool = False,
    uv_binary: str | None = None,
    extras: list[str] | None = None,
    all_extras: bool = False,
    groups: list[str] | None = None,
    all_groups: bool = False,
    platform: str = DEFAULT_PLATFORM,
    sources: AdvisorySources | None = None,
) -> UpgradeResult:
    """Run a vulnerability audit of what ships, without changing anything.

    For uv projects the locked set is exported for the deploy platform and
    audited; ``fixes`` holds the plan a remediation run would apply.  Other
    formats are installed into a venv on this machine and audited.
    """
    target_dir = Path(target).expanduser().resolve()
    if not target_dir.is_dir():
        raise TargetNotFoundError(str(target_dir))
    manifest = _resolve_manifest(target_dir, dep_file, fmt)
    if manifest.is_uv_lock_project:
        options = _options(
            python=python, platform=platform, allow_major=None, keep_version=None,
            dry_run=True, import_check=False, extras=extras, all_extras=all_extras,
            groups=groups, all_groups=all_groups, dependency_scope=dependency_scope,
            manifest=manifest,
        )
        return _run_lock_mode(
            manifest, options, uv_binary=uv_binary, service_label=derive_label(target_dir),
            venv_name=venv_name, dependency_scope=dependency_scope, sources=sources,
            audit_only_run=True,
        )
    return _audit_only_legacy(
        target_dir,
        dep_file=dep_file or str(manifest.path.relative_to(target_dir)),
        fmt=fmt,
        python=python,
        venv_name=venv_name,
        dependency_scope=dependency_scope,
        ignore_direct_references=ignore_direct_references,
        uv_binary=uv_binary,
    )
