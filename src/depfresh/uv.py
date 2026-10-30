"""uv binary discovery and virtual environment management."""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

from packaging.version import InvalidVersion, Version

from depfresh.constraints import normalise
from depfresh.exceptions import CommandError, UvNotFoundError, UvVersionError

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

#: Oldest uv depfresh supports.  Older releases cannot read the lockfile
#: revisions current uv writes (uv 0.6.17 fails on ``revision = 3``) and lack
#: options depfresh relies on (``uv export --no-emit-project``, ``uv lock
#: --check``, ``--no-default-groups``, named ``[[tool.uv.index]]`` entries).
MIN_UV_VERSION = "0.9.0"

#: Environment variable naming the uv binary to use.
UV_ENV_VAR = "DEPFRESH_UV"


def find_uv(explicit: str | None = None) -> str:
    """Locate a ``uv`` binary that is at least :data:`MIN_UV_VERSION`.

    Candidates, in order: *explicit* (``--uv``), the ``DEPFRESH_UV``
    environment variable, a ``uv`` installed in the same environment as
    depfresh, then every ``uv`` on ``PATH``.  An explicit choice is never
    replaced by another binary: if it is missing or too old, that is an
    error.  Otherwise the first candidate that is new enough wins, so an
    old ``uv`` early on ``PATH`` is skipped (and logged), never used silently.

    Raises:
        UvNotFoundError: If no ``uv`` binary exists.
        UvVersionError: If every ``uv`` found is older than the minimum.
    """
    chosen = explicit or os.environ.get(UV_ENV_VAR)
    if chosen:
        resolved = shutil.which(chosen) or (chosen if Path(chosen).is_file() else None)
        if not resolved:
            raise UvNotFoundError(f"uv binary {chosen!r} not found")
        version = get_uv_version(resolved)
        if not uv_version_ok(version):
            raise UvVersionError([(resolved, version)], MIN_UV_VERSION)
        return resolved

    too_old: list[tuple[str, str]] = []
    seen: set[str] = set()
    for candidate in _uv_candidates():
        real = os.path.realpath(candidate)
        if real in seen:
            continue
        seen.add(real)
        version = get_uv_version(candidate)
        if uv_version_ok(version):
            if too_old:
                log.info(
                    "Skipping uv %s (older than %s); using uv %s at %s",
                    ", ".join(f"{v} at {p}" for p, v in too_old), MIN_UV_VERSION,
                    version, candidate,
                )
            return candidate
        too_old.append((candidate, version))
    if too_old:
        raise UvVersionError(too_old, MIN_UV_VERSION)
    raise UvNotFoundError()


def _uv_candidates() -> list[str]:
    """uv binaries next to the running interpreter, then every uv on PATH."""
    candidates: list[str] = []
    exe = "uv.exe" if sys.platform == "win32" else "uv"
    for directory in (sysconfig.get_path("scripts"), str(Path(sys.executable).parent)):
        path = Path(directory) / exe
        if path.is_file() and os.access(path, os.X_OK):
            candidates.append(str(path))
    for directory in os.environ.get("PATH", os.defpath).split(os.pathsep):
        if not directory:
            continue
        path = Path(directory) / exe
        if path.is_file() and os.access(path, os.X_OK):
            candidates.append(str(path))
    return candidates


def uv_version_ok(version: str) -> bool:
    """True when *version* parses and is at least :data:`MIN_UV_VERSION`."""
    try:
        return Version(version) >= Version(MIN_UV_VERSION)
    except InvalidVersion:
        return False


def get_uv_version(uv: str) -> str:
    """Return the version string for the given *uv* binary (``"unknown"`` on failure)."""
    try:
        result = run([uv, "--version"], check=False)
    except OSError:
        return "unknown"
    parts = result.stdout.strip().split()
    if result.returncode == 0 and len(parts) >= 2:
        return parts[1]
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
    """Freeze the current environment.

    pip-audit runs from its own tool environment (see
    :func:`depfresh.audit.install_pip_audit`), so every package in this
    environment belongs to the project and is reported.  Earlier releases
    dropped a static list of pip-audit's dependencies here, which also hid
    the project's own ``msgpack``, ``rich``, ``platformdirs``… from the audit.

    Parameters
    ----------
    uv:
        Path to the ``uv`` binary.
    venv_python:
        Path to the Python binary inside the venv.
    extra_exclude:
        Package names to leave out of the result.

    Returns
    -------
    dict[str, str]
        ``{normalised_name: version}``
    """
    log.info("Freezing environment")
    result = run([uv, "pip", "freeze", "--python", venv_python])
    exclude = extra_exclude or frozenset()

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

    log.info("Frozen %d packages", len(pkgs))
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
