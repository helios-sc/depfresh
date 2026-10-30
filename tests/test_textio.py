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
    replace_together,
    with_newlines_of,
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


class TestReplaceTogether:
    def test_writes_every_file_and_keeps_permissions(self, tmp_path: Path) -> None:
        lock, pyproject = tmp_path / "uv.lock", tmp_path / "pyproject.toml"
        lock.write_text("old lock\n")
        pyproject.write_text("old\n")
        pyproject.chmod(0o640)
        replace_together({lock: b"new lock\n", pyproject: b"new\n"})
        assert (lock.read_text(), pyproject.read_text()) == ("new lock\n", "new\n")
        assert pyproject.stat().st_mode & 0o777 == 0o640
        assert sorted(p.name for p in tmp_path.iterdir()) == ["pyproject.toml", "uv.lock"]

    def test_both_or_neither(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import os

        lock, pyproject = tmp_path / "uv.lock", tmp_path / "pyproject.toml"
        lock.write_text("old lock\n")
        pyproject.write_text("old\n")
        real_replace = os.replace
        calls: list[str] = []

        def second_fails(src: str, dst: str) -> None:
            calls.append(str(dst))
            if len(calls) == 2:
                raise OSError("disk full")
            real_replace(src, dst)

        monkeypatch.setattr("depfresh.textio.os.replace", second_fails)
        with pytest.raises(OSError, match="disk full"):
            replace_together({lock: b"new lock\n", pyproject: b"new\n"})
        assert (lock.read_text(), pyproject.read_text()) == ("old lock\n", "old\n")
        assert sorted(p.name for p in tmp_path.iterdir()) == ["pyproject.toml", "uv.lock"]


class TestWithNewlinesOf:
    def test_crlf_original(self) -> None:
        assert with_newlines_of("a\nb\r\nc\n", "x\r\n") == "a\r\nb\r\nc\r\n"

    def test_lf_original(self) -> None:
        assert with_newlines_of("a\nb\n", "x\n") == "a\nb\n"
