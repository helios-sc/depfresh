"""Core upgrade orchestration — the main public API entry point."""

from __future__ import annotations

import datetime
import difflib
import logging
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[import-not-found]

from depfresh.advisories import DEFAULT_PLATFORM, AdvisorySources, TargetEnv
from depfresh.audit import install_pip_audit, run_audit, write_pinned_requirements
from depfresh.constraints import (
    build_constraints,
    compute_changes,
    diagnose_remaining,
    normalise,
)
from depfresh.exceptions import (
    DepfreshError,
    DirectReferenceError,
    RequirementsNotFoundError,
    TargetNotFoundError,
)
from depfresh.indexes import (
    PrivateSourceError,
    check_requirements_against_sources,
    foreign_sources,
    uv_source_indexes,
)
from depfresh.lockmode import (
    LockOutcome,
    check_not_workspace_member,
    check_static_project,
    remediate_lock,
)
from depfresh.models import DependencyScope, DependencySpec, UpgradeResult, Vulnerability
from depfresh.parsers import (
    DependencyFormat,
    FormatHandler,
    SetupPyHandler,
    choose_dep_file,
    detect_format,
    dockerfile_uv_sync_flags,
    extras_of_uv_flags,
    get_handler,
)
from depfresh.pipmode import (
    PIP_FORMATS,
    PipOutcome,
    changes_of,
    local_sources,
    remediate_pip,
    source_direct_refs,
)
from depfresh.remediation import (
    Auditor,
    RemediationOptions,
    default_sources,
    diff_sets,
    planned_fixes,
    remaining_reasons,
)
from depfresh.repoadvisories import ProjectUrls, RepoAdvisoryChecker
from depfresh.reports import write_log, write_markdown
from depfresh.reqlines import inspect_tree
from depfresh.textio import decode_bytes, read_text_file, write_text_like
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
    exactly_pinned = all(
        str(dep.requirement).split(";")[0].strip().endswith(f"=={dep.version}")
        for dep in install_deps
    )
    if not handler.is_pinned or not exactly_pinned:
        # A floor (>=2.10.0) is not the version that ships: read what was installed.
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

    use_original_requirements = dep_format in _REQUIREMENTS_FORMATS

    work_dir = Path(tempfile.mkdtemp(prefix=f"depfresh-{_RUN_ID}-"))
    venv_path = work_dir / venv_name
    try:
        install_path = req_path
        if use_original_requirements:
            # uv installs a mirrored copy of the file and its includes (UTF-8, every
            # direct line refused or, with --ignore-direct-references, dropped), never
            # the target's own files.
            tree = inspect_tree(req_path, target_dir)
            if tree.direct and not ignore_direct_references:
                raise DirectReferenceError(str(req_path), tree.direct)
            install_path = tree.copy_to(work_dir / "manifest", strip=True)
        venv_python, actual_py_version, old_pkgs = _setup_venv(
            uv,
            work_dir,
            venv_path,
            python,
            handler,
            install_deps,
            old_pkgs,
            install_path,
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
    if ctx.dep_format == DependencyFormat.SETUP_PY:
        new_content = ctx.req_path.read_bytes()
        result.write_back_skipped = "setup.py is never edited"
        result.notes.append(
            "setup.py was read statically (ast): depfresh never executes or edits it."
        )
    else:
        new_content = _render_write(
            ctx.handler,
            new_pkgs,
            ctx.req_path,
            uv=ctx.uv,
            python_version=python,
            dependency_scope=dependency_scope,
        )
    result.manifest_diff = manifest_diff(ctx.req_path, new_content)

    if result.write_back_skipped:
        log.error("NOT writing %s: %s", ctx.req_path.name, result.write_back_skipped)
    elif result.import_regressions:
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
    dockerfile_uv_flags: tuple[str, ...] | None = None

    @property
    def is_uv_lock_project(self) -> bool:
        return (
            self.path.name == "pyproject.toml"
            and self.fmt == DependencyFormat.PYPROJECT_PEP621
            and (self.path.parent / "uv.lock").is_file()
        )

    @property
    def project_dir(self) -> Path:
        """The project the run works on: where uv runs and what the import check scans.

        The directory of a ``pyproject.toml`` or ``setup.py`` (a subproject
        with ``--dep-file sub/pyproject.toml``); the target for requirements
        files, whose includes resolve inside it.
        """
        if self.fmt in _REQUIREMENTS_FORMATS:
            return self.target_dir
        return self.path.parent

    def relative(self, name: str) -> str:
        """*name* in the project directory, as a path relative to the target."""
        prefix = self.project_dir.resolve().relative_to(self.target_dir.resolve())
        return (prefix / name).as_posix()


def _resolve_manifest(target_dir: Path, dep_file: str | None, fmt: str | None) -> _Manifest:
    uv_flags: tuple[str, ...] | None = None
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
        uv_flags = choice.uv_sync_flags
        log.info("Auto-detected %s: %s", path.name, reason)
    if not path.exists():
        raise RequirementsNotFoundError(str(path))
    if not path.resolve().is_relative_to(target_dir.resolve()):
        raise DepfreshError(
            f"--dep-file {dep_file} is outside {target_dir}; point depfresh at a directory "
            "that contains it"
        )
    if dep_file and path.name == "pyproject.toml" and (path.parent / "uv.lock").is_file():
        uv_flags = dockerfile_uv_sync_flags(path.parent)
        extras = extras_of_uv_flags(uv_flags or ())
    dep_format = DependencyFormat(fmt) if fmt else detect_format(path)
    return _Manifest(target_dir, path, dep_format, get_handler(dep_format), extras, reason,
                     uv_flags)


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
    chosen_groups = tuple(_split_names(groups))
    user_chose = bool(chosen_extras or chosen_groups or all_extras or all_groups
                      or dependency_scope == "all")
    uv_flags = None
    if not user_chose and manifest.is_uv_lock_project and manifest.dockerfile_uv_flags is not None:
        uv_flags = manifest.dockerfile_uv_flags
        chosen_extras = extras_of_uv_flags(uv_flags)
        log.info(
            "Exporting what the Dockerfile's uv sync installs: %s (override with --group/--extra)",
            " ".join(uv_flags) or "the default groups, dev included",
        )
    elif not chosen_extras and not all_extras and manifest.dockerfile_extras:
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
        groups=chosen_groups,
        all_groups=all_groups or dependency_scope == "all",
        uv_group_flags=uv_flags,
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
    changed, added, unchanged, removed = diff_sets(
        outcome.baseline.pins, outcome.final.pins, vulnerable,
    )
    fixes = planned_fixes(
        outcome.plans, outcome.final.pins, outcome.failures, outcome.post_vulns,
        applied=not (options.dry_run or audit_only_run),
    )
    files = ([manifest.relative("uv.lock")] if outcome.new_lock else []) + (
        [manifest.relative("pyproject.toml")] if outcome.new_pyproject else []
    )
    gate = outcome.gate
    result = UpgradeResult(
        date=datetime.date.today().isoformat(),
        python_version=options.env.python_version,
        uv_version=uv_version,
        pip_audit_version=pip_audit_version,
        requirements_path=manifest.relative("uv.lock"),
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
        groups=(
            [f"(Dockerfile: uv sync {' '.join(options.uv_group_flags) or 'default groups'})"]
            if options.uv_group_flags is not None
            else list(options.groups) or (["(all)"] if options.all_groups else ["(no dev)"])
        ),
        fixes=fixes,
        lock_changes=outcome.lock_changes,
        lock_check=outcome.lock_check,
        not_audited=outcome.baseline.not_audited,
        audited_count=len(outcome.baseline.pins),
        other_index=dict(outcome.baseline.other_index),
        commands=outcome.commands,
        files_changed=files,
        notes=[*outcome.notes, *gate.notes, *(f"Removed from the shipped set: {c.name} "
                                              f"{c.old_version}" for c in removed)],
        manifest_diff=outcome.pyproject_diff,
    )
    result.remaining_reasons = remaining_reasons(result.post_audit_vulns, fixes)
    if not files:
        if outcome.lock_check.startswith("failed"):
            result.notes.append(f"uv lock --check {outcome.lock_check} (nothing was changed)")
        return result
    if gate.blocked:
        _withhold(result, gate.blocked)
    elif result.import_regressions:
        _withhold(result, (
            f"{len(result.import_regressions)} import(s) resolved before the upgrade "
            "and fail after it"
        ))
    elif outcome.lock_check.startswith("failed"):
        _withhold(result, f"uv lock --check {outcome.lock_check}")
    return result


def _withhold(result: UpgradeResult, reason: str) -> None:
    """Record that nothing is written: the planned changes stay planned."""
    result.write_back_skipped = reason
    for fix in result.fixes:
        if fix.status == "applied":
            fix.status = "planned, not written"


def _auditor(
    audit_python: str, work_dir: Path, sources: AdvisorySources, repo_advisories: bool,
) -> Auditor:
    checker = None
    if repo_advisories:
        if not hasattr(sources, "project_urls"):
            raise DepfreshError("--repo-advisories needs advisory sources that know PyPI URLs")
        checker = RepoAdvisoryChecker(urls=cast(ProjectUrls, sources))
    return Auditor(audit_python, work_dir, repo_check=checker)


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
    repo_advisories: bool = False,
) -> UpgradeResult:
    uv = find_uv(uv_binary)
    uv_version = get_uv_version(uv)
    sources = sources or default_sources()
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
        auditor = _auditor(audit_python, work_dir, sources, repo_advisories)
        outcome = remediate_lock(
            uv=uv,
            target_dir=manifest.project_dir,
            work_dir=work_dir,
            auditor=auditor,
            options=options,
            sources=sources,
            venv_name=venv_name,
            audit_only=audit_only_run,
            context_dir=manifest.target_dir,
        )
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
    outcome.notes.extend(auditor.notes())

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
            (manifest.project_dir / "uv.lock").write_bytes(outcome.new_lock)
        if outcome.new_pyproject is not None:
            manifest.path.write_bytes(outcome.new_pyproject)
        result.dep_file_updated = True
        log.info("UPDATED %s", ", ".join(result.files_changed))
    else:
        log.info("Nothing to change")
    return result



def _pip_result(
    outcome: PipOutcome,
    *,
    manifest: _Manifest,
    options: RemediationOptions,
    uv_version: str,
    pip_audit_version: str,
    service_label: str,
    venv_name: str,
    dependency_scope: DependencyScope,
    ignore_direct_references: bool,
    audit_only_run: bool,
) -> UpgradeResult:
    """Build the :class:`UpgradeResult` of a resolved-mode run (nothing written yet)."""
    changed, added, unchanged, removed = changes_of(outcome)
    fixes = planned_fixes(
        outcome.plans, outcome.final.pins, outcome.failures, outcome.post_vulns,
        applied=not (options.dry_run or audit_only_run),
    )
    diff = ""
    if outcome.changed:
        diff = "".join(difflib.unified_diff(
            outcome.baseline_text_lines(), outcome.new_text.splitlines(keepends=True),
            fromfile=f"a/{manifest.path.name}", tofile=f"b/{manifest.path.name}",
        ))
    gate = outcome.gate
    is_pyproject = manifest.fmt == DependencyFormat.PYPROJECT_PEP621
    result = UpgradeResult(
        date=datetime.date.today().isoformat(),
        python_version=options.env.python_version,
        uv_version=uv_version,
        pip_audit_version=pip_audit_version,
        requirements_path=str(manifest.path.relative_to(manifest.target_dir)),
        venv_name=venv_name,
        service_label=service_label,
        dependency_scope=dependency_scope,
        ignore_direct_references=ignore_direct_references,
        allow_major=options.allow_major,
        keep_version=options.keep_version,
        dry_run=options.dry_run,
        import_check=gate.after,
        import_check_baseline=gate.baseline,
        import_regressions=gate.regressions(),
        pre_audit_vulns=outcome.pre_vulns,
        post_audit_vulns=[] if audit_only_run else outcome.post_vulns,
        direct_references_ignored=outcome.direct_refs if ignore_direct_references else [],
        upgraded=changed,
        new_deps=added,
        unchanged=unchanged,
        original_count=len(outcome.baseline.pins),
        final_count=len(outcome.final.pins),
        mode="pyproject" if is_pyproject else "requirements",
        strategy="minimal",
        platform=options.env.platform,
        extras=(list(options.extras) or (["(all)"] if options.all_extras else []))
        if is_pyproject else [],
        fixes=fixes,
        resolution_check=outcome.resolution_check,
        not_audited=outcome.not_audited,
        audited_count=outcome.audited_count,
        other_index=dict(outcome.other_index),
        commands=outcome.commands,
        files_changed=[str(manifest.path.relative_to(manifest.target_dir))]
        if outcome.changed else [],
        notes=[*outcome.notes, *gate.notes, *(f"Removed from the shipped set: {c.name} "
                                              f"{c.old_version}" for c in removed)],
        manifest_diff=diff,
    )
    result.remaining_reasons = remaining_reasons(result.post_audit_vulns, fixes)
    if not outcome.changed:
        return result
    if gate.blocked:
        _withhold(result, gate.blocked)
    elif result.import_regressions:
        _withhold(result, (
            f"{len(result.import_regressions)} import(s) resolved before the upgrade "
            "and fail after it"
        ))
    elif outcome.resolution_check.startswith("failed"):
        _withhold(result, f"the edited manifest does not resolve for {options.env.platform}")
    return result


_REQUIREMENTS_FORMATS = (
    DependencyFormat.REQUIREMENTS_SIMPLE,
    DependencyFormat.REQUIREMENTS_HASHED,
    DependencyFormat.REQUIREMENTS_IN,
)


def _validate_inputs(
    manifest: _Manifest, *, ignore_direct_references: bool, dependency_scope: DependencyScope,
) -> None:
    """Fail closed before uv is even located.

    * requirements files: every line of the file and of every file it
      includes; any path, archive, VCS, URL or editable line is refused
      (unless --ignore-direct-references drops it), and so is a name that
      ``[tool.uv.sources]`` pins to a private index;
    * ``setup.py``: its static requirements, the same way;
    * ``pyproject.toml`` without a lock: ``name @ url`` requirements and
      names ``[tool.uv.sources]`` maps to a path, workspace, VCS or URL;
    * uv projects: every project uv would have to build to lock (see
      :func:`depfresh.lockmode.check_static_project`);
    * a ``pyproject.toml`` that is a uv workspace member: what ships is the
      workspace's lock, so the run is refused and pointed at the root.
    """
    if manifest.fmt in _REQUIREMENTS_FORMATS:
        tree = inspect_tree(manifest.path, manifest.target_dir)
        if tree.direct and not ignore_direct_references:
            raise DirectReferenceError(str(manifest.path), tree.direct)
        for directory in dict.fromkeys((manifest.path.parent, manifest.target_dir)):
            check_requirements_against_sources(tree.registry, directory, manifest.path.name)
    elif manifest.fmt == DependencyFormat.SETUP_PY:
        _select_dependencies(
            manifest.handler, manifest.path, dependency_scope=dependency_scope,
            ignore_direct_references=ignore_direct_references,
        )
        listed = set(manifest.handler.parse(manifest.path))
        check_requirements_against_sources(listed, manifest.project_dir, manifest.path.name)
    elif manifest.is_uv_lock_project:
        check_not_workspace_member(manifest.project_dir, manifest.path)
        check_static_project(manifest.project_dir)
    elif manifest.fmt == DependencyFormat.PYPROJECT_PEP621:
        check_not_workspace_member(manifest.project_dir, manifest.path)
        selected, _, _ = _select_dependencies(
            manifest.handler, manifest.path, dependency_scope=dependency_scope,
            ignore_direct_references=ignore_direct_references,
        )
        refs = source_direct_refs(manifest.path, {dep.name: "" for dep in selected})
        if refs and not ignore_direct_references:
            raise DirectReferenceError(str(manifest.path), refs)


def _check_latest_sources(manifest: _Manifest) -> None:
    """The latest strategy installs a synthesized file: it cannot honour package sources."""
    if manifest.fmt == DependencyFormat.PYPROJECT_PEP621:
        pinned = sorted(set(uv_source_indexes(manifest.path)) | set(
            local_sources(tomllib.loads(manifest.path.read_text(encoding="utf-8")))
        ))
        if pinned:
            raise PrivateSourceError(
                f"{manifest.path.name} maps {', '.join(pinned)} to their own sources "
                "([tool.uv.sources]); --strategy latest installs a synthesized requirements "
                "file that cannot honour them and would look the names up on public PyPI. "
                "Use the default minimal strategy, which runs uv on the project itself."
            )
    elif manifest.fmt in (DependencyFormat.PYPROJECT_POETRY, DependencyFormat.PIPFILE):
        foreign = foreign_sources(manifest.path)
        if foreign:
            raise PrivateSourceError(
                f"{manifest.path.name} declares package sources other than PyPI "
                f"({', '.join(foreign)}); depfresh cannot honour them for this format and "
                "will not resolve those packages against public PyPI."
            )


def _setup_py_manifest(manifest: _Manifest, work_dir: Path, options: RemediationOptions) -> Path:
    """Write setup.py's static requirements to a scratch requirements file for uv."""
    handler = manifest.handler
    assert isinstance(handler, SetupPyHandler)
    path = work_dir / "setup.py.requirements.in"
    path.write_text(handler.requirements_text(manifest.path, options.all_extras))
    return path


def _run_pip_mode(
    manifest: _Manifest,
    options: RemediationOptions,
    *,
    uv_binary: str | None,
    service_label: str,
    venv_name: str,
    dependency_scope: DependencyScope,
    ignore_direct_references: bool,
    sources: AdvisorySources | None,
    audit_only_run: bool,
    repo_advisories: bool = False,
) -> UpgradeResult:
    uv = find_uv(uv_binary)
    uv_version = get_uv_version(uv)
    sources = sources or default_sources()
    log.info("depfresh — %s of %s, resolved for %s / Python %s (uv %s at %s)",
             "audit" if audit_only_run else "minimal remediation", manifest.path,
             options.env.platform, options.env.python_version, uv_version, uv)
    work_dir = Path(tempfile.mkdtemp(prefix=f"depfresh-{_RUN_ID}-"))
    try:
        audit_python, pip_audit_version = install_pip_audit(
            uv, work_dir / ".pip-audit-tool", options.env.python_minor,
        )
        is_setup_py = manifest.fmt == DependencyFormat.SETUP_PY
        outcome = remediate_pip(
            uv=uv,
            target_dir=manifest.project_dir,
            manifest=_setup_py_manifest(manifest, work_dir, options) if is_setup_py
            else manifest.path,
            fmt=DependencyFormat.REQUIREMENTS_IN if is_setup_py else manifest.fmt,
            work_dir=work_dir,
            auditor=(auditor := _auditor(audit_python, work_dir, sources, repo_advisories)),
            options=options,
            sources=sources,
            venv_name=venv_name,
            ignore_direct_references=ignore_direct_references,
            audit_only=audit_only_run,
        )
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
    outcome.notes.extend(auditor.notes())

    result = _pip_result(
        outcome, manifest=manifest, options=options, uv_version=uv_version,
        pip_audit_version=pip_audit_version, service_label=service_label,
        venv_name=venv_name, dependency_scope=dependency_scope,
        ignore_direct_references=ignore_direct_references, audit_only_run=audit_only_run,
    )
    if manifest.fmt == DependencyFormat.SETUP_PY:
        result.requirements_path = "setup.py"
        result.files_changed = []
        result.manifest_diff = ""
        result.notes.insert(0, (
            "setup.py was read statically (ast): depfresh never executes or edits it. "
            "Apply the versions under Security Fixes to install_requires by hand."
        ))
        if not audit_only_run and outcome.changed:
            _withhold(result, "setup.py is never edited; apply the planned versions by hand")
    if audit_only_run:
        return result
    if result.write_back_skipped:
        log.error("NOT writing %s: %s", manifest.path.name, result.write_back_skipped)
    elif options.dry_run:
        log.info("DRY RUN — %s NOT modified", manifest.path.name)
    elif outcome.changed:
        write_text_like(manifest.path, outcome.new_text, read_text_file(manifest.path))
        result.dep_file_updated = True
        log.info("UPDATED %s", manifest.path)
    else:
        log.info("Nothing to change in %s", manifest.path.name)
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
    repo_advisories: bool = False,
) -> UpgradeResult:
    """Audit Python dependencies and fix the vulnerable ones.

    This is the primary public API.  With the default ``strategy="minimal"``
    only vulnerable packages move, each to the lowest release that fixes all
    of its advisories that have a fix (the others stay open, each with its
    own reason):

    * **uv projects** (``pyproject.toml`` next to ``uv.lock``): the locked set
      is exported and audited, fixed with ``uv lock --upgrade-package
      <pkg>==<fix>``, re-exported and re-audited, and checked with ``uv lock
      --check``.  The write-back is the updated ``uv.lock``.
    * **requirements files and pyproject.toml without a lock**: the manifest
      is resolved with ``uv pip compile`` for the deploy *platform* and
      *python*, audited, and only the affected lines are edited (pins moved,
      floors raised, a commented floor added for a vulnerable transitive
      package); the edited manifest is resolved again and re-audited.

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
    repo_advisories:
        Also check the GitHub repository advisories of every shipped package
        (needs an authenticated ``gh``); they reach the Advisory DB late.

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
    _validate_inputs(
        manifest, ignore_direct_references=ignore_direct_references,
        dependency_scope=dependency_scope,
    )

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
            audit_only_run=False, repo_advisories=repo_advisories,
        )
        _write_reports(result, _out_dir(reports_dir, service_label), result.date)
        return result

    if strategy == "minimal":
        if manifest.fmt not in (*PIP_FORMATS, DependencyFormat.SETUP_PY):
            raise DepfreshError(
                f"The minimal strategy supports requirements files, PEP 621 pyproject.toml "
                f"(with or without uv.lock) and setup.py, not {manifest.fmt.value}. Re-run with "
                "--strategy latest to upgrade every package within its bounds."
            )
        service_label = label or derive_label(target_dir)
        options = _options(
            python=python, platform=platform, allow_major=allow_major,
            keep_version=keep_version, dry_run=dry_run, import_check=import_check,
            extras=extras, all_extras=all_extras, groups=groups, all_groups=all_groups,
            dependency_scope=dependency_scope, manifest=manifest,
        )
        result = _run_pip_mode(
            manifest, options, uv_binary=uv_binary, service_label=service_label,
            venv_name=venv_name, dependency_scope=dependency_scope,
            ignore_direct_references=ignore_direct_references, sources=sources,
            audit_only_run=False, repo_advisories=repo_advisories,
        )
        _write_reports(result, _out_dir(reports_dir, service_label), result.date)
        return result

    _check_latest_sources(manifest)
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
    repo_advisories: bool = False,
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
    _validate_inputs(
        manifest, ignore_direct_references=ignore_direct_references,
        dependency_scope=dependency_scope,
    )
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
            audit_only_run=True, repo_advisories=repo_advisories,
        )
    if manifest.fmt in (*PIP_FORMATS, DependencyFormat.SETUP_PY):
        options = _options(
            python=python, platform=platform, allow_major=None, keep_version=None,
            dry_run=True, import_check=False, extras=extras, all_extras=all_extras,
            groups=groups, all_groups=all_groups, dependency_scope=dependency_scope,
            manifest=manifest,
        )
        return _run_pip_mode(
            manifest, options, uv_binary=uv_binary, service_label=derive_label(target_dir),
            venv_name=venv_name, dependency_scope=dependency_scope,
            ignore_direct_references=ignore_direct_references, sources=sources,
            audit_only_run=True, repo_advisories=repo_advisories,
        )
    _check_latest_sources(manifest)
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
