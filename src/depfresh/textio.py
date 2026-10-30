"""Encoding-aware reading and writing of requirements-style text files.

Requirements files are usually UTF-8, but Windows editors and PowerShell
redirection (``pip freeze > requirements.txt``) produce UTF-16 files with a
byte-order mark.  pip reads those; depfresh must too, and must write them back
in the encoding (and line endings) they came in.

Write-backs go through :func:`replace_together`: every file of a change is
written to a temporary sibling first and then renamed into place, so a run
leaves either all of its files or none of them.
"""

from __future__ import annotations

import codecs
import os
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

_BOMS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF32_LE, "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)


class UnreadableTextError(ValueError):
    """Raised when a text file is neither UTF-8 nor BOM-marked/recognisable UTF-16/32."""


@dataclass(frozen=True)
class TextFile:
    """Decoded text plus what is needed to write it back the same way.

    Attributes:
        text: The decoded content, with the original line endings.
        encoding: Codec used to decode (without BOM handling, e.g. ``"utf-16-le"``).
        bom: The byte-order mark the file started with (``b""`` if none).
    """

    text: str
    encoding: str = "utf-8"
    bom: bytes = b""

    @property
    def is_utf8(self) -> bool:
        """True when the file is plain UTF-8 (no BOM), i.e. safe to hand to uv as is."""
        return self.encoding == "utf-8" and not self.bom


def decode_bytes(data: bytes, *, source: str = "file") -> TextFile:
    """Decode *data*, detecting a BOM or BOM-less UTF-16.

    Args:
        data: Raw file content.
        source: Name used in error messages.

    Raises:
        UnreadableTextError: If the content cannot be decoded.
    """
    for bom, encoding in _BOMS:
        if data.startswith(bom):
            try:
                return TextFile(data[len(bom):].decode(encoding), encoding, bom)
            except UnicodeDecodeError as exc:
                raise UnreadableTextError(
                    f"{source}: starts with a {encoding} byte-order mark but is not valid "
                    f"{encoding}: {exc}"
                ) from exc
    guessed = _guess_bomless_utf16(data)
    if guessed:
        try:
            return TextFile(data.decode(guessed), guessed)
        except UnicodeDecodeError:
            pass
    try:
        return TextFile(data.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise UnreadableTextError(
            f"{source}: file is not valid UTF-8 or UTF-16. Re-save it as UTF-8 "
            "or specify --dep-file / --format explicitly."
        ) from exc


def _guess_bomless_utf16(data: bytes) -> str | None:
    """Recognise BOM-less UTF-16 by the NUL bytes ASCII text leaves in every other byte."""
    sample = data[:4096]
    if len(sample) < 4 or len(sample) % 2:
        return None
    even_nuls = sample[0::2].count(0)
    odd_nuls = sample[1::2].count(0)
    half = len(sample) // 2
    if odd_nuls >= half * 0.6 and even_nuls == 0:
        return "utf-16-le"
    if even_nuls >= half * 0.6 and odd_nuls == 0:
        return "utf-16-be"
    return None


def read_text_file(path: Path) -> TextFile:
    """Read *path* with encoding detection (see :func:`decode_bytes`)."""
    return decode_bytes(path.read_bytes(), source=str(path))


def read_text(path: Path) -> str:
    """Return the decoded text of *path* (see :func:`decode_bytes`)."""
    return read_text_file(path).text


def write_text_like(path: Path, text: str, original: TextFile) -> None:
    """Write *text* to *path* in the encoding (and BOM) of *original*, atomically."""
    replace_together({path: original.bom + text.encode(original.encoding)})


def with_newlines_of(text: str, original: str) -> str:
    """*text* with the line endings of *original* (CRLF files stay CRLF)."""
    if "\r\n" not in original:
        return text
    return text.replace("\r\n", "\n").replace("\n", "\r\n")


def replace_together(files: Mapping[Path, bytes]) -> None:
    """Write every file of *files*, or none of them.

    Each one goes to a temporary sibling first (keeping the original's
    permissions), then all are renamed into place.  If a rename fails, the
    files already replaced get their previous content back.

    Raises:
        OSError: When a file cannot be written; the targets are as before.
    """
    targets = {path.resolve(): data for path, data in files.items()}
    temps: dict[Path, Path] = {}
    try:
        for path, data in targets.items():
            temp = path.with_name(f".{path.name}.depfresh-{os.getpid()}.tmp")
            temp.write_bytes(data)
            if path.exists():
                shutil.copymode(path, temp)
            temps[path] = temp
        before = {path: path.read_bytes() for path in targets if path.exists()}
        replaced: list[Path] = []
        try:
            for path, temp in temps.items():
                os.replace(temp, path)
                replaced.append(path)
        except OSError:
            for path in replaced:
                if path in before:
                    path.write_bytes(before[path])
                else:
                    path.unlink(missing_ok=True)
            raise
    finally:
        for temp in temps.values():
            temp.unlink(missing_ok=True)
