"""Format enum and handler protocol."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from depfresh.models import DependencyInspection


# ---------------------------------------------------------------------------
# Format enum
# ---------------------------------------------------------------------------

class DependencyFormat(str, Enum):
    """Supported dependency file formats."""

    REQUIREMENTS_SIMPLE = "requirements-simple"
    REQUIREMENTS_HASHED = "requirements-hashed"
    REQUIREMENTS_IN = "requirements-in"
    PYPROJECT_PEP621 = "pyproject-pep621"
    PYPROJECT_POETRY = "pyproject-poetry"
    PIPFILE = "pipfile"


# ---------------------------------------------------------------------------
# Handler protocol
# ---------------------------------------------------------------------------

class FormatHandler(Protocol):
    """Interface that every format handler must satisfy."""

    def parse(self, path: Path) -> dict[str, str]:
        """Read the file and return ``{normalised_name: version}``."""
        ...

    def inspect(self, path: Path) -> DependencyInspection:
        """Return structured dependency metadata for safe orchestration."""
        ...

    def write(self, pkgs: dict[str, str], path: Path, **kwargs: Any) -> None:
        """Write *pkgs* back to *path*, preserving format-specific style."""
        ...

    @property
    def is_pinned(self) -> bool:
        """Whether the format contains exact pinned versions.

        ``False`` for formats like ``requirements.in`` where deps may be
        unpinned — the caller must freeze after install to get true versions.
        """
        ...
