"""Private package indexes: find them, and refuse runs that would bypass them.

A package that a project pins to a private index (``[tool.uv.sources] pkg = {
index = "internal" }``) must only ever be resolved against that index.  If its
name reaches public PyPI instead, anyone who registers the name there can
ship code into the build (dependency confusion).

uv honours the project's index configuration when it is handed the project
itself (``uv lock``, ``uv export``, ``uv pip compile pyproject.toml``), which
is how the lock-aware and resolved modes run.  It cannot when the package
name arrives in a plain requirements file, so those runs are refused.

What is private (:class:`PrivateScope`): the packages a project pins to a
non-PyPI index with ``[tool.uv.sources]``, and anything an ``explicit = true``
index serves (uv uses an explicit index for pinned packages only).  They are
never audited and their names are never sent to PyPI or OSV.  Every other
package is audited by name, whichever index serves it: a mirror or proxy set
as the default index (``UV_INDEX_URL``, ``[[tool.uv.index]] default = true``)
serves public packages, and treating them as private would leave the whole
shipped set unaudited.  Reports name those indexes.
"""

from __future__ import annotations

import sys
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from depfresh.constraints import normalise
from depfresh.exceptions import DepfreshError

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[import-not-found]

_PYPI_HOSTS = {"pypi.org", "pypi.python.org", "files.pythonhosted.org"}


class PrivateSourceError(DepfreshError):
    """Raised when a run would resolve a private-index package against public PyPI."""


def _load(path: Path) -> dict[str, Any]:
    try:
        data: dict[str, Any] = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        return {}
    return data


def _is_pypi(url: str) -> bool:
    return (urllib.parse.urlparse(url).hostname or "").lower() in _PYPI_HOSTS


def uv_source_indexes(pyproject: Path) -> dict[str, str]:
    """``{package: index url or name}`` for every package ``[tool.uv.sources]`` pins to an index."""
    data = _load(pyproject)
    tool_uv = data.get("tool", {}).get("uv", {})
    urls = {
        str(entry.get("name")): str(entry.get("url"))
        for entry in tool_uv.get("index", []) or []
        if isinstance(entry, dict) and entry.get("name")
    }
    pinned: dict[str, str] = {}
    for name, source in (tool_uv.get("sources") or {}).items():
        entries = source if isinstance(source, list) else [source]
        for entry in entries:
            if isinstance(entry, dict) and "index" in entry:
                index = str(entry["index"])
                url = urls.get(index, index)
                if not _is_pypi(url):
                    pinned[normalise(str(name))] = url
    return pinned


def _url_key(url: str) -> str:
    return url.strip().rstrip("/").lower()


def explicit_index_urls(path: Path) -> set[str]:
    """URLs of the ``explicit = true`` indexes of a pyproject.toml or uv.toml."""
    data = _load(path)
    entries = data.get("index") if path.name == "uv.toml" else (
        data.get("tool", {}).get("uv", {}).get("index")
    )
    return {
        _url_key(str(entry["url"])) for entry in entries or []
        if isinstance(entry, dict) and entry.get("explicit") and entry.get("url")
    }


@dataclass
class PrivateScope:
    """The packages depfresh never audits and never looks up (see the module docstring).

    Attributes:
        pinned: ``{package: index}`` for every package ``[tool.uv.sources]``
            pins to a non-PyPI index.
        explicit: Normalised URLs of the explicit indexes.
    """

    pinned: dict[str, str] = field(default_factory=dict)
    explicit: set[str] = field(default_factory=set)

    def is_private(self, name: str, index_url: str | None) -> bool:
        """True for a pinned package, or one an explicit index served."""
        if normalise(name) in self.pinned:
            return True
        return bool(index_url) and _url_key(str(index_url)) in self.explicit


def private_scope(pyprojects: Iterable[Path], config_files: Iterable[Path] = ()) -> PrivateScope:
    """Collect the pins and explicit indexes of *pyprojects* and uv.toml *config_files*."""
    scope = PrivateScope()
    for path in [*pyprojects, *config_files]:
        if not path.is_file():
            continue
        if path.name != "uv.toml":
            scope.pinned.update(uv_source_indexes(path))
        scope.explicit |= explicit_index_urls(path)
    return scope


def other_index_note(audited: dict[str, str]) -> str:
    """The report note for packages audited although a non-PyPI index served them."""
    urls = sorted(set(audited.values()))
    return (
        f"{len(audited)} audited packages come from {', '.join(urls)}, not from PyPI. "
        "depfresh audited them by name against the public advisory database (OSV): only "
        "packages pinned to an index with [tool.uv.sources], or served by an explicit "
        "index, count as private. Pin private packages that way so their names never "
        "leave their index."
    )


def foreign_sources(manifest: Path) -> list[str]:
    """Non-PyPI package sources declared by a Poetry pyproject or a Pipfile."""
    data = _load(manifest)
    if manifest.name == "Pipfile":
        sources = data.get("source", []) or []
    else:
        sources = data.get("tool", {}).get("poetry", {}).get("source", []) or []
    return [
        str(s.get("url")) for s in sources
        if isinstance(s, dict) and s.get("url") and not _is_pypi(str(s.get("url")))
    ]


def check_requirements_against_sources(
    listed: set[str], target_dir: Path, manifest_name: str,
) -> None:
    """Refuse a requirements file that lists a package pinned to a private index.

    ``uv pip compile requirements.txt`` does not apply ``[tool.uv.sources]``,
    so it would look the private name up on public PyPI.

    Raises:
        PrivateSourceError: If any listed package is pinned to an index.
    """
    pinned = uv_source_indexes(target_dir / "pyproject.toml")
    clash = sorted(set(pinned) & listed)
    if clash:
        detail = ", ".join(f"{name} (index {pinned[name]})" for name in clash)
        raise PrivateSourceError(
            f"{manifest_name} lists {detail}, which pyproject.toml pins to a private index "
            "with [tool.uv.sources]. uv cannot apply that to a requirements file and would "
            "look the name up on public PyPI (dependency confusion). Run depfresh on "
            "pyproject.toml instead, or add the index to the requirements file with "
            "--index-url."
        )
