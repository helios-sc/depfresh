"""pip-audit integration — install, run, and parse vulnerability reports."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from depfresh.exceptions import AuditError
from depfresh.models import Vulnerability
from depfresh.uv import installed_names, run

log = logging.getLogger("depfresh")


def install_pip_audit(uv: str, venv_python: str) -> tuple[str, frozenset[str]]:
    """Install pip-audit into the venv.

    Returns ``(version, added_package_names)`` where *added_package_names*
    is the set of package names introduced by pip-audit and its dependencies.
    Pass this set to :func:`depfresh.uv.freeze` as ``extra_exclude`` so that
    pip-audit's transitive dependencies are not mistaken for user packages.
    """
    before = installed_names(uv, venv_python)
    log.info("Installing pip-audit")
    run([uv, "pip", "install", "pip-audit", "--python", venv_python])
    after = installed_names(uv, venv_python)
    added = after - before
    log.debug("pip-audit introduced %d package(s): %s", len(added), sorted(added))

    venv_bin = str(Path(venv_python).parent)
    pip_audit_bin = os.path.join(venv_bin, "pip-audit")
    result = run([pip_audit_bin, "--version"], check=False)
    version = result.stdout.strip().split()[-1] if result.returncode == 0 else "unknown"
    log.debug("pip-audit version: %s", version)
    return version, added


def run_audit(venv_python: str, req_path: Path, label: str) -> list[Vulnerability]:
    """Run pip-audit against a requirements file.

    Parameters
    ----------
    venv_python:
        Path to the Python binary inside the venv.
    req_path:
        Path to the requirements file to audit.
    label:
        Human label for logging (e.g. ``"pre-upgrade"`` or ``"post-upgrade"``).

    Returns
    -------
    list[Vulnerability]
        Vulnerabilities found.
    """
    log.info("Running vulnerability audit (%s)", label)
    venv_bin = str(Path(venv_python).parent)
    pip_audit_bin = os.path.join(venv_bin, "pip-audit")
    result = run([pip_audit_bin, "-r", str(req_path), "--format", "json"], check=False)

    if result.returncode not in (0, 1):
        detail = result.stderr.strip() or result.stdout.strip() or "no output"
        raise AuditError(
            f"pip-audit failed during {label} with exit code {result.returncode}: {detail[:500]}"
        )

    if not result.stdout.strip():
        detail = result.stderr.strip() or "no output"
        raise AuditError(
            f"pip-audit produced no JSON output during {label}: {detail[:500]}"
        )

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        detail = result.stderr.strip() or result.stdout.strip()
        raise AuditError(
            f"pip-audit produced invalid JSON during {label}: {detail[:500]}"
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
