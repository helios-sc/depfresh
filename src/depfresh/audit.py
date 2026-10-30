"""pip-audit integration — install, run, and parse vulnerability reports.

pip-audit runs from its own isolated virtual environment, never from the
environment that holds the audited packages, and it audits an exact,
fully pinned set of requirements:

* ``--no-deps --disable-pip`` — the input is already a complete resolution,
  so pip-audit must not resolve it again.  Resolving mode makes pip-audit
  build a copy-mode virtual environment with ``ensurepip``, which aborts
  (SIGABRT) with uv-managed CPython 3.12 on macOS.
* ``-s osv`` — the OSV service, which carries the GitHub Advisory Database
  and PyPA advisories with their aliases.
* a pinned pip-audit version range (:data:`PIP_AUDIT_REQUIREMENT`).
"""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from packaging.version import InvalidVersion, Version

from depfresh.exceptions import AuditError
from depfresh.models import Vulnerability
from depfresh.uv import create_venv, run

log = logging.getLogger("depfresh")

#: The pip-audit releases depfresh is tested against.  2.9 is the first
#: release whose JSON output and ``--no-deps --disable-pip`` behaviour match
#: what :func:`run_audit` expects; 3.x may change the CLI.
PIP_AUDIT_REQUIREMENT = "pip-audit>=2.9.0,<3"


def install_pip_audit(uv: str, tool_dir: Path, python: str) -> tuple[str, str]:
    """Create an isolated virtual environment holding a pinned pip-audit.

    The audited packages are never installed next to pip-audit, so
    pip-audit's own dependencies (``rich``, ``msgpack``, ``platformdirs``…)
    can neither shadow nor hide the project's copies of those packages.

    Args:
        uv: Path to the ``uv`` binary.
        tool_dir: Directory for the tool environment.  It is created (or
            replaced) and should live in depfresh's temporary work directory.
        python: Python version request for the tool environment.

    Returns:
        ``(tool_python, version)``: the interpreter of the tool environment and
        the installed pip-audit version (``"unknown"`` if it cannot be read).
    """
    tool_python = create_venv(uv, tool_dir, python)
    log.info("Installing %s into an isolated tool environment", PIP_AUDIT_REQUIREMENT)
    run([uv, "pip", "install", PIP_AUDIT_REQUIREMENT, "--python", tool_python])
    result = run([tool_python, "-m", "pip_audit", "--version"], check=False)
    version = result.stdout.strip().split()[-1] if result.returncode == 0 and result.stdout else ""
    version = version or "unknown"
    log.debug("pip-audit version: %s", version)
    return tool_python, version


def audit_command(tool_python: str, req_path: Path) -> list[str]:
    """Return the pip-audit command line used for every audit.

    Args:
        tool_python: Interpreter of the pip-audit tool environment.
        req_path: Fully pinned requirements file (``name==version`` lines).
    """
    return [
        tool_python, "-m", "pip_audit",
        "-r", str(req_path),
        "--no-deps", "--disable-pip",
        "-s", "osv",
        "--format", "json",
        "--progress-spinner", "off",
    ]


def write_pinned_requirements(pkgs: dict[str, str], path: Path) -> None:
    """Write ``name==version`` lines for :func:`run_audit`.

    Packages without a concrete version (``"*"``) cannot be audited with
    ``--no-deps`` and are left out; callers report them separately.
    """
    lines = [f"{name}=={ver}" for name, ver in sorted(pkgs.items()) if ver and ver != "*"]
    path.write_text("\n".join(lines) + "\n" if lines else "")


#: Requirements per pip-audit process.  pip-audit queries OSV once per package,
#: one after another, so a 100-package set takes ~40 s in one process; the
#: set is split into chunks audited in parallel (still the complete set).
AUDIT_CHUNK_SIZE = 15
AUDIT_MAX_JOBS = 8


def run_audit(tool_python: str, req_path: Path, label: str) -> list[Vulnerability]:
    """Run pip-audit against a fully pinned requirements file.

    Large files are split into chunks of :data:`AUDIT_CHUNK_SIZE` lines that
    are audited by parallel pip-audit processes; every line is audited.

    Args:
        tool_python: Interpreter of the pip-audit tool environment (see
            :func:`install_pip_audit`).
        req_path: Path to the pinned requirements file to audit.
        label: Human label for logging (e.g. ``"pre-upgrade"``).

    Returns:
        The vulnerabilities found.

    Raises:
        AuditError: If pip-audit fails or produces no valid JSON.  depfresh
            fails closed: a broken audit never reads as a clean one.
    """
    log.info("Running vulnerability audit (%s)", label)
    lines = [line for line in req_path.read_text().splitlines() if line.strip()]
    if not lines:
        log.info("Audit (%s): nothing to audit", label)
        return []

    chunks = [lines[i:i + AUDIT_CHUNK_SIZE] for i in range(0, len(lines), AUDIT_CHUNK_SIZE)]
    if len(chunks) == 1:
        datasets = [_audit_file(tool_python, req_path, label)]
    else:
        paths = []
        for index, chunk in enumerate(chunks):
            chunk_path = req_path.with_name(f"{req_path.stem}.part{index}{req_path.suffix}")
            chunk_path.write_text("\n".join(chunk) + "\n")
            paths.append(chunk_path)
        try:
            with ThreadPoolExecutor(max_workers=min(AUDIT_MAX_JOBS, len(paths))) as pool:
                datasets = list(pool.map(lambda p: _audit_file(tool_python, p, label), paths))
        finally:
            for chunk_path in paths:
                chunk_path.unlink(missing_ok=True)

    dependencies: list[object] = []
    for data in datasets:
        if isinstance(data, dict):
            dependencies.extend(data.get("dependencies", []))
        elif isinstance(data, list):
            dependencies.extend(data)
    vulns = _parse_pip_audit_data({"dependencies": dependencies})
    log.info("Audit (%s): found %d vulnerabilities", label, len(vulns))

    if vulns:
        pkg_vulns: dict[str, list[str]] = {}
        for v in vulns:
            key = f"{v.package}=={v.version}"
            pkg_vulns.setdefault(key, []).append(v.cve)
        for pkg, cves in pkg_vulns.items():
            log.debug("  %s: %s", pkg, ", ".join(cves))

    return vulns


def _audit_file(tool_python: str, req_path: Path, label: str) -> object:
    """Run one pip-audit process over *req_path* and return its decoded JSON."""
    result = run(audit_command(tool_python, req_path), check=False)

    if result.returncode not in (0, 1):
        detail = result.stderr.strip() or result.stdout.strip() or "no output"
        raise AuditError(
            f"pip-audit failed during {label} with exit code {result.returncode}: {detail[-800:]}"
        )

    if not result.stdout.strip():
        detail = result.stderr.strip() or "no output"
        raise AuditError(
            f"pip-audit produced no JSON output during {label}: {detail[-800:]}"
        )

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        detail = result.stderr.strip() or result.stdout.strip()
        raise AuditError(
            f"pip-audit produced invalid JSON during {label}: {detail[-800:]}"
        ) from exc


def _parse_pip_audit_json(output: str) -> list[Vulnerability]:
    """Parse pip-audit ``--format json`` output into :class:`Vulnerability` objects.

    pip-audit wraps results in ``{"dependencies": [...], "fixes": [...]}``.
    Each dependency entry may have a ``vulns`` array with ``id``, ``fix_versions``,
    and ``description`` fields.  An empty string or unparseable JSON returns ``[]``.
    """
    if not output.strip():
        return []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        log.debug("pip-audit produced non-JSON output (possibly no vulns): %r", output[:200])
        return []

    return _parse_pip_audit_data(data)


def _parse_pip_audit_data(data: object) -> list[Vulnerability]:
    """Parse decoded pip-audit JSON data, merging aliased duplicates.

    pip-audit reports one entry per OSV record, and OSV frequently holds the
    same advisory twice (``GHSA-…`` and ``PYSEC-…`` records that list each
    other, or the CVE, as aliases).  Records of one package whose id/alias
    sets overlap are merged into a single :class:`Vulnerability`, so each
    advisory is counted once.
    """

    # pip-audit --format json wraps the list in {"dependencies": [...], "fixes": [...]}
    if isinstance(data, dict):
        packages: list[object] = data.get("dependencies", [])
    elif isinstance(data, list):
        packages = data
    else:
        return []

    vulns: list[Vulnerability] = []
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name: str = pkg.get("name", "")
        version: str = pkg.get("version", "")
        records = [v for v in pkg.get("vulns", []) if isinstance(v, dict)]
        vulns.extend(_merge_aliased_records(name, version, records))
    return vulns


def _merge_aliased_records(
    name: str, version: str, records: list[dict[str, object]],
) -> list[Vulnerability]:
    """Group *records* whose ids or aliases overlap and build one entry per group."""
    groups: list[tuple[list[str], set[str], list[dict[str, object]]]] = []
    for record in records:
        primary = str(record.get("id", ""))
        raw_aliases = record.get("aliases") or []
        aliases = [str(a) for a in raw_aliases] if isinstance(raw_aliases, list) else []
        ids = {i for i in [primary, *aliases] if i}
        overlapping = [g for g in groups if g[1] & ids]
        if overlapping:
            target = overlapping[0]
            for other in overlapping[1:]:  # this record links two groups
                target[0].extend(i for i in other[0] if i not in target[0])
                target[1].update(other[1])
                target[2].extend(other[2])
                groups.remove(other)
        else:
            target = ([], set(), [])
            groups.append(target)
        if primary and primary not in target[0]:
            target[0].append(primary)
        target[1].update(ids)
        target[2].append(record)

    merged: list[Vulnerability] = []
    for primaries, ids, group_records in groups:
        cves = sorted(i for i in ids if i.startswith("CVE-"))
        display = cves[0] if cves else (primaries[0] if primaries else sorted(ids)[0])
        fixes: set[str] = set()
        description = ""
        for record in group_records:
            raw_fixes = record.get("fix_versions") or []
            if isinstance(raw_fixes, list):
                fixes.update(str(f) for f in raw_fixes)
            if not description:
                description = str(record.get("description") or "")
        if len(description) > 120:
            description = description[:120] + "..."
        merged.append(Vulnerability(
            package=name,
            version=version,
            cve=display,
            fix_versions=", ".join(sorted(fixes, key=_version_sort_key)),
            description=description,
            aliases=tuple(sorted(ids - {display})),
        ))
    return merged


def _version_sort_key(value: str) -> tuple[int, Version | str]:
    """Sort PEP 440 versions numerically, anything else after them as text."""
    try:
        return (0, Version(value))
    except InvalidVersion:
        return (1, value)
