"""Format-aware dependency file parsing and writing.

Supports:
- requirements.txt (simple and hashed/pip-compile)
- requirements.in (pip-tools / uv pip compile input)
- pyproject.toml (PEP 621)
- pyproject.toml (Poetry)
- Pipfile (pipenv)
"""

from __future__ import annotations

import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[import-not-found]

from depfresh.parsers._base import DependencyFormat, FormatHandler
from depfresh.parsers._pipfile import PipfileHandler
from depfresh.parsers._pyproject import PyprojectPEP621Handler, PyprojectPoetryHandler
from depfresh.parsers._requirements import (
    RequirementsHashedHandler,
    RequirementsInHandler,
    RequirementsSimpleHandler,
    _merge_continuation_lines,
)
from depfresh.parsers._setup_py import SetupPyError, SetupPyHandler, read_setup_py
from depfresh.textio import UnreadableTextError, read_text

log = logging.getLogger("depfresh")

_FORMAT_CHOICES = [fmt.value for fmt in DependencyFormat]


# ---------------------------------------------------------------------------
# Auto-detection
# ---------------------------------------------------------------------------

def detect_format(path: Path) -> DependencyFormat:
    """Auto-detect the dependency format from a file path and its contents."""
    name = path.name.lower()

    if name == "pipfile":
        return DependencyFormat.PIPFILE

    if name == "setup.py":
        # read statically, never executed (see parsers._setup_py)
        return DependencyFormat.SETUP_PY

    if name == "setup.cfg":
        raise ValueError(
            f"{path}: setup.cfg is not supported; uv would run the build backend to read it. "
            "Point depfresh at pyproject.toml or a requirements file."
        )

    if name == "requirements.in":
        return DependencyFormat.REQUIREMENTS_IN

    if name == "pyproject.toml":
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        has_pep621 = bool(data.get("project", {}).get("dependencies"))
        has_poetry = bool(data.get("tool", {}).get("poetry", {}).get("dependencies"))
        if has_pep621:
            return DependencyFormat.PYPROJECT_PEP621
        if has_poetry:
            return DependencyFormat.PYPROJECT_POETRY
        raise ValueError(
            f"{path}: pyproject.toml has neither [project.dependencies] "
            "nor [tool.poetry.dependencies]"
        )

    # Default: requirements.txt (simple vs hashed), UTF-8 or UTF-16
    content = read_text(path)
    if "--hash=" in content:
        return DependencyFormat.REQUIREMENTS_HASHED
    return DependencyFormat.REQUIREMENTS_SIMPLE


_CANDIDATES = ("requirements.txt", "requirements.in", "pyproject.toml", "Pipfile")


@dataclass(frozen=True)
class DepFileChoice:
    """The dependency file auto-detection picked, and why.

    Attributes:
        path: The chosen file.
        reason: Human-readable explanation, logged and shown in reports.
        extras: Extras the project's Dockerfile installs (``pip install
            -e ".[full,gcs]"``), when the choice came from a Dockerfile.
    """

    path: Path
    reason: str
    extras: tuple[str, ...] = ()


def detect_dep_file(target_dir: Path) -> Path:
    """Return the dependency file to use for *target_dir* (see :func:`choose_dep_file`)."""
    return choose_dep_file(target_dir).path


def choose_dep_file(target_dir: Path) -> DepFileChoice:
    """Pick the manifest that describes what *target_dir* ships.

    In order:

    1. ``pyproject.toml`` when a ``uv.lock`` sits next to it: the lock is
       what ``uv sync --frozen`` installs.
    2. What a ``Dockerfile`` in *target_dir* installs: the file passed to
       ``pip install -r``, or ``pyproject.toml`` for ``pip install .``/``-e .``
       and ``uv sync`` (with the extras named there).  A ``requirements.txt``
       that nothing installs is not the shipped manifest.
    3. The first of ``requirements.txt``, ``requirements.in``,
       ``pyproject.toml``, ``Pipfile`` that exists and can be read.

    Raises:
        FileNotFoundError: If no dependency file exists.
    """
    pyproject = target_dir / "pyproject.toml"
    has_pyproject = _declares_dependencies(pyproject)

    if has_pyproject and (target_dir / "uv.lock").exists():
        return DepFileChoice(pyproject, "pyproject.toml with uv.lock (the lock is what ships)")

    hint = _dockerfile_hint(target_dir, has_pyproject)
    if hint is not None:
        return hint

    readable = []
    for name in _CANDIDATES:
        p = target_dir / name
        if not p.exists():
            continue
        if name == "pyproject.toml" and not has_pyproject:
            continue
        if name.startswith("requirements"):
            try:
                read_text(p)
            except UnreadableTextError:
                log.warning("Skipping %s (not valid UTF-8 or UTF-16)", p)
                continue
        readable.append(p)
    if not readable:
        raise FileNotFoundError(
            f"No dependency file found in {target_dir}. "
            f"Looked for: {', '.join(_CANDIDATES)}"
        )
    chosen = readable[0]
    if len(readable) > 1:
        log.warning(
            "Several dependency files in %s (%s); using %s. Pass --dep-file to choose another.",
            target_dir, ", ".join(p.name for p in readable), chosen.name,
        )
    return DepFileChoice(chosen, f"first of {', '.join(_CANDIDATES)} present")


def _declares_dependencies(pyproject: Path) -> bool:
    """True when *pyproject* exists and declares PEP 621 or Poetry dependencies."""
    if not pyproject.is_file():
        return False
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        return False
    project = data.get("project", {})
    return bool(
        "dependencies" in project
        or project.get("optional-dependencies")
        or data.get("tool", {}).get("poetry", {}).get("dependencies")
    )


_REQ_FLAG = re.compile(r"(?:^|\s)(?:-r|--requirement)(?:\s+|=)[\"']?([^\s\"';&|]+)")
_PROJECT_INSTALL = re.compile(
    r"(?:pip3?|uv\s+pip)\s+install\b[^;&|]*?(?:\s|^)(?:-e\s+|--editable\s+)?"
    r"[\"']?\.(?:\[([^\]]*)\])?[\"']?(?=\s|$|[;&|])"
)
_UV_SYNC = re.compile(r"\buv\s+sync\b(?P<args>[^;&|]*)")


def _dockerfile_hint(target_dir: Path, has_pyproject: bool) -> DepFileChoice | None:
    """Infer the shipped manifest from the RUN instructions of local Dockerfiles."""
    dockerfiles = sorted(
        p for p in target_dir.iterdir()
        if p.is_file() and (p.name == "Dockerfile" or p.name.startswith("Dockerfile.")
                            or p.name.endswith(".Dockerfile"))
    )
    for dockerfile in dockerfiles:
        try:
            text = dockerfile.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for command in _run_commands(text):
            for match in _REQ_FLAG.finditer(command):
                candidate = target_dir / Path(match.group(1)).name
                if candidate.is_file():
                    return DepFileChoice(
                        candidate, f"{dockerfile.name} installs it (pip install -r)",
                    )
            if not has_pyproject:
                continue
            project = _PROJECT_INSTALL.search(command)
            if project:
                extras = tuple(
                    e.strip() for e in (project.group(1) or "").split(",") if e.strip()
                )
                return DepFileChoice(
                    target_dir / "pyproject.toml",
                    f"{dockerfile.name} installs the project (pip install .)",
                    extras,
                )
            sync = _UV_SYNC.search(command)
            if sync:
                extras = tuple(re.findall(r"--extra[\s=]+([A-Za-z0-9_.-]+)", sync.group("args")))
                return DepFileChoice(
                    target_dir / "pyproject.toml", f"{dockerfile.name} runs uv sync", extras,
                )
    return None


def _run_commands(dockerfile_text: str) -> list[str]:
    """Return the shell commands of the RUN instructions, continuation lines joined."""
    joined = re.sub(r"\\\r?\n", " ", dockerfile_text)
    commands = []
    for line in joined.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("RUN "):
            commands.append(stripped[4:].strip())
    return commands


def get_handler(fmt: DependencyFormat) -> FormatHandler:
    """Return the handler instance for a given format."""
    handlers: dict[DependencyFormat, FormatHandler] = {
        DependencyFormat.REQUIREMENTS_SIMPLE: RequirementsSimpleHandler(),
        DependencyFormat.REQUIREMENTS_HASHED: RequirementsHashedHandler(),
        DependencyFormat.REQUIREMENTS_IN: RequirementsInHandler(),
        DependencyFormat.PYPROJECT_PEP621: PyprojectPEP621Handler(),
        DependencyFormat.PYPROJECT_POETRY: PyprojectPoetryHandler(),
        DependencyFormat.PIPFILE: PipfileHandler(),
        DependencyFormat.SETUP_PY: SetupPyHandler(),
    }
    return handlers[fmt]


__all__ = [
    "DependencyFormat",
    "FormatHandler",
    "RequirementsSimpleHandler",
    "RequirementsHashedHandler",
    "RequirementsInHandler",
    "PyprojectPEP621Handler",
    "PyprojectPoetryHandler",
    "PipfileHandler",
    "SetupPyHandler",
    "SetupPyError",
    "read_setup_py",
    "detect_format",
    "detect_dep_file",
    "choose_dep_file",
    "DepFileChoice",
    "get_handler",
    "_FORMAT_CHOICES",
    "_merge_continuation_lines",
]
