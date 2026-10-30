"""Custom exceptions for depfresh."""

from __future__ import annotations


class DepfreshError(Exception):
    """Base exception for all depfresh errors."""


class UvNotFoundError(DepfreshError):
    """Raised when the ``uv`` binary cannot be found."""

    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message or "'uv' is not installed. Install it from https://docs.astral.sh/uv/"
        )


class UvVersionError(DepfreshError):
    """Raised when every ``uv`` binary found is older than depfresh's minimum."""

    def __init__(self, found: list[tuple[str, str]], minimum: str) -> None:
        self.found = found
        self.minimum = minimum
        listing = ", ".join(f"uv {version} at {path}" for path, version in found)
        super().__init__(
            f"depfresh needs uv >= {minimum}, found {listing}. Upgrade uv "
            "(https://docs.astral.sh/uv/) or point depfresh at a newer binary "
            "with --uv or DEPFRESH_UV."
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
