"""uv binary discovery and virtual environment management."""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from depfresh.constraints import normalise
from depfresh.exceptions import CommandError, UvNotFoundError

log = logging.getLogger("depfresh")


# ---------------------------------------------------------------------------
# Shell helper
# ---------------------------------------------------------------------------

def run(
    cmd: list[str],
    *,
    cwd: str | None = None,
    check: bool = True,
    timeout: int = 600,
) -> subprocess.CompletedProcess[str]:
    """Run a command and return the result.

    Raises :class:`CommandError` when *check* is True and the command exits
    with a non-zero return code.
    """
    log.debug("$ %s", " ".join(cmd))
    result = subprocess.run(
        cmd, capture_output=True, text=True, cwd=cwd, timeout=timeout,
    )
    if check and result.returncode != 0:
        log.debug("STDERR: %s", result.stderr.strip())
        raise CommandError(cmd, result.returncode, result.stderr)
    return result


# ---------------------------------------------------------------------------
# uv discovery
# ---------------------------------------------------------------------------

def find_uv() -> str:
    """Locate the ``uv`` binary on PATH.

    Raises :class:`UvNotFoundError` if not found.
    """
    uv = shutil.which("uv")
    if not uv:
        raise UvNotFoundError()
    return uv


def get_uv_version(uv: str) -> str:
    """Return the version string for the given *uv* binary."""
    result = run([uv, "--version"], check=False)
    if result.returncode == 0:
        return result.stdout.strip().split()[1]
    return "unknown"


# ---------------------------------------------------------------------------
# Virtual-environment helpers
# ---------------------------------------------------------------------------

def create_venv(uv: str, venv_path: Path, python_version: str) -> str:
    """Create a uv virtual environment. Returns the python path inside it."""
    log.info("Creating uv virtual environment at %s (Python %s)", venv_path, python_version)

    if venv_path.exists():
        log.debug("Removing existing venv %s", venv_path)
        shutil.rmtree(venv_path)

    run([uv, "venv", str(venv_path), "--python", python_version])
    if sys.platform == "win32":
        venv_python = str(venv_path / "Scripts" / "python.exe")
    else:
        venv_python = str(venv_path / "bin" / "python")
    result = run([venv_python, "--version"])
    actual = result.stdout.strip().replace("Python ", "")
    log.info("Created venv with Python %s", actual)
    return venv_python


def install_requirements(uv: str, venv_python: str, req_path: Path) -> None:
    """Install packages from a requirements file into the venv."""
    log.info("Installing requirements from %s", req_path)
    run(
        [uv, "pip", "install", "-r", str(req_path), "--python", venv_python],
        check=True,
    )


def installed_names(uv: str, venv_python: str) -> frozenset[str]:
    """Return the normalised names of all packages currently in the venv.

    Unlike :func:`freeze`, this applies no exclusions — it is used to
    snapshot the venv state before and after installing pip-audit so that
    pip-audit's transitive dependencies can be identified dynamically.
    """
    result = run([uv, "pip", "freeze", "--python", venv_python], check=False)
    names: set[str] = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)==", line)
        if m:
            names.add(normalise(m.group(1)))
    return frozenset(names)


def freeze(
    uv: str,
    venv_python: str,
    extra_exclude: frozenset[str] | None = None,
) -> dict[str, str]:
    """Freeze current environment, excluding pip-audit tooling.

    Parameters
    ----------
    uv:
        Path to the ``uv`` binary.
    venv_python:
        Path to the Python binary inside the venv.
    extra_exclude:
        Additional package names to exclude beyond the static baseline.
        Pass the set returned by :func:`install_pip_audit` to ensure all
        of pip-audit's transitive dependencies are filtered out.

    Returns
    -------
    dict[str, str]
        ``{normalised_name: version}``
    """
    log.info("Freezing upgraded environment")
    result = run([uv, "pip", "freeze", "--python", venv_python])

    # Static baseline: packages that pip-audit is known to install.
    # Extended dynamically via extra_exclude to catch transitive deps
    # that vary across pip-audit versions.
    audit_deps: frozenset[str] = frozenset({
        "pip", "pip-audit", "pip-api", "pip-requirements-parser",
        "boolean-py", "cachecontrol", "cyclonedx-python-lib",
        "defusedxml", "filelock", "license-expression", "markdown-it-py",
        "mdurl", "msgpack", "packageurl-python", "platformdirs",
        "py-serializable", "pygments", "rich", "tomli", "tomli-w",
    })
    exclude = audit_deps | (extra_exclude or frozenset())

    pkgs: dict[str, str] = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)==(.+)$", line)
        if m:
            name = normalise(m.group(1))
            if name not in exclude:
                pkgs[name] = m.group(2)

    log.info("Frozen %d packages (excluded pip-audit tooling)", len(pkgs))
    return pkgs


def install_packages(uv: str, venv_python: str, constraints_path: Path) -> str:
    """Upgrade packages from a constraints file. Returns combined output."""
    log.info("Upgrading packages from %s", constraints_path)
    result = run(
        [uv, "pip", "install", "--upgrade", "-r", str(constraints_path),
         "--python", venv_python],
        check=True,
    )
    output = result.stdout + result.stderr
    changes = [line for line in output.splitlines() if line.strip().startswith(("+", "-"))]
    if changes:
        log.debug("Upgrade changes (%d lines): %s", len(changes), "\n".join(changes[-30:]))
    return output


def compile_hashed(
    uv: str,
    pkgs: dict[str, str],
    output_path: Path,
    python_version: str,
) -> None:
    """Compile pinned packages into a hashed requirements file via ``uv pip compile``.

    Creates a temporary ``.in`` file with ``name==version`` lines, runs
    ``uv pip compile --generate-hashes``, and cleans up the temp file.
    """
    temp_in = output_path.parent / f".tmp_compile_{output_path.stem}_{os.getpid()}.in"
    lines = [f"{name}=={ver}" for name, ver in sorted(pkgs.items())]
    temp_in.write_text("\n".join(lines) + "\n")

    cmd = [
        uv, "pip", "compile", str(temp_in),
        "--generate-hashes",
        "--python-version", python_version,
        "-o", str(output_path),
    ]
    try:
        result = run(cmd, check=False)
        if result.returncode == 0:
            log.debug("Wrote hashed requirements: %s (%d packages)", output_path, len(pkgs))
        else:
            raise CommandError(cmd, result.returncode, result.stderr or result.stdout)
    finally:
        temp_in.unlink(missing_ok=True)


def cleanup_venv(venv_path: Path) -> None:
    """Remove a virtual environment directory if it exists."""
    if venv_path.exists():
        log.debug("Cleaning up venv %s", venv_path)
        shutil.rmtree(venv_path)
