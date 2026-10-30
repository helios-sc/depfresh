"""Tests for textio — encoding detection for requirements-style files."""

from __future__ import annotations

import codecs
from pathlib import Path

import pytest

from depfresh.parsers import (
    DependencyFormat,
    RequirementsInHandler,
    RequirementsSimpleHandler,
    detect_dep_file,
    detect_format,
)
from depfresh.textio import (
    UnreadableTextError,
    decode_bytes,
    read_text,
    read_text_file,
    write_text_like,
)

_CONTENT = "flask==2.3.0\r\nrequests==2.31.0\r\n"


class TestDecodeBytes:
    @pytest.mark.parametrize(
        ("bom", "encoding"),
        [
            (codecs.BOM_UTF16_LE, "utf-16-le"),
            (codecs.BOM_UTF16_BE, "utf-16-be"),
            (codecs.BOM_UTF8, "utf-8"),
            (codecs.BOM_UTF32_LE, "utf-32-le"),
        ],
    )
    def test_bom_marked_files(self, bom: bytes, encoding: str) -> None:
        decoded = decode_bytes(bom + _CONTENT.encode(encoding))
        assert decoded.text == _CONTENT
        assert decoded.encoding == encoding
        assert decoded.bom == bom
        assert decoded.is_utf8 is False

    def test_plain_utf8(self) -> None:
        decoded = decode_bytes(_CONTENT.encode("utf-8"))
        assert decoded.text == _CONTENT
        assert decoded.is_utf8 is True

    @pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be"])
    def test_bomless_utf16(self, encoding: str) -> None:
        decoded = decode_bytes(_CONTENT.encode(encoding))
        assert decoded.text == _CONTENT
        assert decoded.encoding == encoding

    def test_undecodable_bytes_raise_a_value_error(self) -> None:
        with pytest.raises(UnreadableTextError, match="not valid UTF-8 or UTF-16"):
            decode_bytes(b"flask==2.3.0\n\xff\xfe\xfa\n")
        assert issubclass(UnreadableTextError, ValueError)


class TestRoundTrip:
    def test_write_text_like_keeps_encoding_and_bom(self, tmp_path: Path) -> None:
        path = tmp_path / "requirements.txt"
        path.write_bytes(codecs.BOM_UTF16_LE + _CONTENT.encode("utf-16-le"))
        original = read_text_file(path)
        write_text_like(path, original.text.replace("2.3.0", "2.3.3"), original)
        raw = path.read_bytes()
        assert raw.startswith(codecs.BOM_UTF16_LE)
        assert read_text(path) == "flask==2.3.3\r\nrequests==2.31.0\r\n"


class TestUtf16Requirements:
    """pip freeze redirected in Windows PowerShell writes UTF-16LE."""

    @staticmethod
    def _utf16_file(tmp_path: Path, name: str = "requirements.txt") -> Path:
        path = tmp_path / name
        path.write_bytes(codecs.BOM_UTF16_LE + _CONTENT.encode("utf-16-le"))
        return path

    def test_detect_format(self, tmp_path: Path) -> None:
        assert detect_format(self._utf16_file(tmp_path)) == DependencyFormat.REQUIREMENTS_SIMPLE

    def test_detect_dep_file_accepts_utf16(self, tmp_path: Path) -> None:
        path = self._utf16_file(tmp_path)
        assert detect_dep_file(tmp_path) == path

    def test_parse(self, tmp_path: Path) -> None:
        pkgs = RequirementsSimpleHandler().parse(self._utf16_file(tmp_path))
        assert pkgs == {"flask": "2.3.0", "requests": "2.31.0"}

    def test_requirements_in_write_keeps_utf16(self, tmp_path: Path) -> None:
        path = self._utf16_file(tmp_path, "requirements.in")
        RequirementsInHandler().write({"flask": "2.3.3"}, path)
        assert path.read_bytes().startswith(codecs.BOM_UTF16_LE)
        assert "flask==2.3.3" in read_text(path)
