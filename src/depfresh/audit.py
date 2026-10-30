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
from pathlib import Path

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


def run_audit(tool_python: str, req_path: Path, label: str) -> list[Vulnerability]:
    """Run pip-audit against a fully pinned requirements file.

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
    if not req_path.read_text().strip():
        log.info("Audit (%s): nothing to audit", label)
        return []
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
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        detail = result.stderr.strip() or result.stdout.strip()
        raise AuditError(
            f"pip-audit produced invalid JSON during {label}: {detail[-800:]}"
        ) from exc

    vulns = _parse_pip_audit_data(data)
    log.info("Audit (%s): found %d vulnerabilities", label, len(vulns))

    if vulns:
        pkg_vulns: dict[str, list[str]] = {}
        for v in vulns:
            key = f"{v.package}=={v.version}"
            pkg_vulns.setdefault(key, []).append(v.cve)
        for pkg, cves in pkg_vulns.items():
            log.debug("  %s: %s", pkg, ", ".join(cves))

    return vulns


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
    """Parse decoded pip-audit JSON data."""

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
        for v in pkg.get("vulns", []):
            if not isinstance(v, dict):
                continue
            # Prefer a CVE alias over the primary PYSEC/GHSA id when available
            aliases: list[str] = v.get("aliases", [])
            vid: str = next((a for a in aliases if a.startswith("CVE-")), v.get("id", ""))
            fix_versions: str = ", ".join(v.get("fix_versions", []))
            desc: str = v.get("description", "")
            if len(desc) > 120:
                desc = desc[:120] + "..."
            vulns.append(Vulnerability(
                package=name,
                version=version,
                cve=vid,
                fix_versions=fix_versions,
                description=desc,
            ))
    return vulns
