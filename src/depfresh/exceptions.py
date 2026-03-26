"""Custom exceptions for depfresh."""

from __future__ import annotations


class DepfreshError(Exception):
    """Base exception for all depfresh errors."""


class UvNotFoundError(DepfreshError):
    """Raised when the ``uv`` binary cannot be found on PATH."""

    def __init__(self) -> None:
        super().__init__(
            "'uv' is not installed. Install it from https://docs.astral.sh/uv/"
        )


class RequirementsNotFoundError(DepfreshError):
    """Raised when the requirements file does not exist."""

    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__(f"Requirements file not found: {path}")


class TargetNotFoundError(DepfreshError):
    """Raised when the target directory does not exist."""

    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__(f"Target directory not found: {path}")


class CommandError(DepfreshError):
    """Raised when a subprocess command fails."""

    def __init__(self, cmd: list[str], returncode: int, stderr: str) -> None:
        self.cmd = cmd
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(
            f"Command failed (exit {returncode}): {' '.join(cmd)}\n{stderr[:500]}"
        )


class AuditError(DepfreshError):
    """Raised when pip-audit encounters an unexpected error."""

    def __init__(self, message: str) -> None:
        super().__init__(f"Audit error: {message}")


class DirectReferenceError(DepfreshError):
    """Raised when selected dependency groups contain direct references."""

    def __init__(self, path: str, refs: list[str]) -> None:
        joined = "; ".join(refs[:5])
        if len(refs) > 5:
            joined += "; ..."
        super().__init__(
            "Direct references are not supported by default in "
            f"{path}: {joined}. Re-run with --ignore-direct-references "
            "to skip them."
        )
