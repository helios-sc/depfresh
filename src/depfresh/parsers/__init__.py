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
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from depfresh.parsers._base import DependencyFormat, FormatHandler
from depfresh.parsers._pipfile import PipfileHandler
from depfresh.parsers._pyproject import PyprojectPEP621Handler, PyprojectPoetryHandler
from depfresh.parsers._requirements import (
    RequirementsHashedHandler,
    RequirementsInHandler,
    RequirementsSimpleHandler,
    _merge_continuation_lines,
)

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

    if name == "requirements.in":
        return DependencyFormat.REQUIREMENTS_IN

    if name == "pyproject.toml":
        data = tomllib.loads(path.read_text())
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

    # Default: requirements.txt (simple vs hashed)
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise ValueError(
            f"{path}: file is not valid UTF-8. "
            "Re-save it as UTF-8 or specify --dep-file / --format explicitly."
        )
    if "--hash=" in content:
        return DependencyFormat.REQUIREMENTS_HASHED
    return DependencyFormat.REQUIREMENTS_SIMPLE


def detect_dep_file(target_dir: Path) -> Path:
    """Scan *target_dir* for a known dependency file, in priority order.

    Returns the first match found.  Raises ``FileNotFoundError`` if none.
    """
    candidates = [
        "requirements.txt",
        "requirements.in",
        "pyproject.toml",
        "Pipfile",
    ]
    for name in candidates:
        p = target_dir / name
        if p.exists():
            try:
                p.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                log.warning("Skipping %s (not valid UTF-8)", p)
                continue
            return p
    raise FileNotFoundError(
        f"No dependency file found in {target_dir}. "
        f"Looked for: {', '.join(candidates)}"
    )


def get_handler(fmt: DependencyFormat) -> FormatHandler:
    """Return the handler instance for a given format."""
    handlers: dict[DependencyFormat, FormatHandler] = {
        DependencyFormat.REQUIREMENTS_SIMPLE: RequirementsSimpleHandler(),
        DependencyFormat.REQUIREMENTS_HASHED: RequirementsHashedHandler(),
        DependencyFormat.REQUIREMENTS_IN: RequirementsInHandler(),
        DependencyFormat.PYPROJECT_PEP621: PyprojectPEP621Handler(),
        DependencyFormat.PYPROJECT_POETRY: PyprojectPoetryHandler(),
        DependencyFormat.PIPFILE: PipfileHandler(),
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
    "detect_format",
    "detect_dep_file",
    "get_handler",
    "_FORMAT_CHOICES",
    "_merge_continuation_lines",
]
