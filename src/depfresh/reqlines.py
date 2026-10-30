"""Classify the lines of requirements files, following pip's own rules.

depfresh never lets uv build or install repository code, so every line of a
requirements file, and of every file it includes with ``-r``/``-c``, is
classified before uv sees any of them:

* *registry* — ``name[extras] <specifier> ; <marker>``, resolved from an index;
* *direct* — anything uv would fetch from a path, an archive, a VCS or a URL:
  ``-e``/``--editable`` in any spelling, ``git+…``/``hg+…``/``svn+…``/``bzr+…``,
  ``name @ <url>``, ``http(s)://``/``file:`` URLs, local find-links, relative or
  absolute paths (``./pkg``, ``libs/core``, ``pkg/``, ``~/x``, ``C:\\x``) and
  archives (``x.tar.gz``, ``x.whl``…).  A line that cannot be parsed counts as
  direct too: depfresh does not guess what uv would do with it;
* *include* — ``-r``/``--requirement``/``-c``/``--constraint``;
* *option* — every other ``-x``/``--xxx`` line; and blanks and comments.

Lines are joined like pip joins them (``pip._internal.req.req_file``): a line
ending in ``\\`` continues, unless it holds a comment, so a comment ending in a
backslash never swallows the next requirement.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from packaging.requirements import InvalidRequirement, Requirement

from depfresh.constraints import normalise
from depfresh.exceptions import DepfreshError, DirectReferenceError
from depfresh.textio import read_text

LineKind = Literal["blank", "comment", "option", "include", "registry", "direct"]

#: pip's comment rule: ``#`` at the start or after whitespace.
COMMENT_RE = re.compile(r"(^|\s+)#.*$")
_INCLUDE_SHORT = re.compile(r"^-([rc])\s*=?\s*(\S+)")
_INCLUDE_LONG = re.compile(r"^--(requirement|constraint)(?:\s*=\s*|\s+)(\S+)")
_EDITABLE = re.compile(r"^(?:-e|--editable)(?=$|[\s=./~\"'A-Za-z0-9])")
_FIND_LINKS = re.compile(r"^(?:-f|--find-links)(?:\s*=\s*|\s+|(?<=-f))(\S+)")
_PEP508_URL = re.compile(r"^\s*[A-Za-z0-9][A-Za-z0-9._-]*\s*(\[[^\]]*\])?\s*@")
_VCS = re.compile(r"^(git|hg|svn|bzr)\+", re.IGNORECASE)
_ARCHIVE = re.compile(
    r"\.(whl|tar\.gz|tgz|tar\.bz2|tbz|tar\.xz|txz|tar|zip)(\[[^\]]*\])?\s*$", re.IGNORECASE,
)
_REQ_OPTION = re.compile(r"\s--?[A-Za-z]")


@dataclass(frozen=True)
class ReqLine:
    """One logical line of a requirements file.

    Attributes:
        kind: See the module docstring.
        start: Index of the first physical line.
        end: Index of the last physical line (continuations included).
        code: The logical line without its comment, stripped.
        requirement: For registry and direct lines, the requirement text
            without per-requirement options (``--hash``…).
        detail: Why a line is direct (``"editable"``, ``"VCS"``…), or the
            include path for include lines.
        include_kind: ``"requirement"`` or ``"constraint"`` for include lines.
    """

    kind: LineKind
    start: int
    end: int
    code: str
    requirement: str = ""
    detail: str = ""
    include_kind: str = ""

    @property
    def name(self) -> str:
        """Normalised project name of a registry line (``""`` otherwise)."""
        if self.kind != "registry":
            return ""
        return normalise(Requirement(self.requirement).name)


def logical_lines(text: str) -> Iterator[tuple[int, int, str]]:
    """Yield ``(start, end, logical_text)`` with pip's continuation rules."""
    physical = text.splitlines()
    start: int | None = None
    parts: list[str] = []
    for index, raw in enumerate(physical):
        line = raw.rstrip("\r\n")
        if not line.endswith("\\") or COMMENT_RE.search(line):
            if start is None:
                yield index, index, line
            else:
                parts.append(line)
                yield start, index, "".join(parts)
                start, parts = None, []
        else:
            if start is None:
                start = index
            parts.append(line[:-1])
    if start is not None:
        yield start, len(physical) - 1, "".join(parts)


def strip_comment(line: str) -> str:
    """The line without its comment, stripped."""
    return COMMENT_RE.sub("", line).strip()


def classify(code: str) -> tuple[LineKind, str, str, str]:
    """Classify one comment-free logical line.

    Returns:
        ``(kind, requirement, detail, include_kind)``.
    """
    if not code:
        return "blank", "", "", ""
    if code.startswith("-"):
        for pattern in (_INCLUDE_SHORT, _INCLUDE_LONG):
            match = pattern.match(code)
            if match:
                kind = "constraint" if match.group(1) in ("c", "constraint") else "requirement"
                return "include", "", match.group(2), kind
        if _EDITABLE.match(code):
            return "direct", code, "editable", ""
        match = _FIND_LINKS.match(code)
        if match:
            value = match.group(1)
            if re.match(r"^https?://", value, re.IGNORECASE):
                return "option", "", "", ""
            return "direct", code, "local find-links", ""
        return "option", "", "", ""
    option = _REQ_OPTION.search(code)
    requirement = code[:option.start()].strip() if option else code
    base = requirement.split(";", 1)[0].strip()
    if _PEP508_URL.match(requirement):
        return "direct", requirement, "URL", ""
    if _VCS.match(base):
        return "direct", requirement, "VCS", ""
    if "://" in base or base.lower().startswith("file:"):
        return "direct", requirement, "URL", ""
    if "/" in base or "\\" in base or base.startswith((".", "~")):
        return "direct", requirement, "local path", ""
    if _ARCHIVE.search(base):
        return "direct", requirement, "archive", ""
    try:
        req = Requirement(requirement)
    except InvalidRequirement:
        return "direct", requirement, "unparseable", ""
    if req.url:
        return "direct", requirement, "URL", ""
    return "registry", requirement, "", ""


def parse_lines(text: str) -> list[ReqLine]:
    """Every logical line of *text*, classified."""
    out: list[ReqLine] = []
    for start, end, logical in logical_lines(text):
        stripped = logical.strip()
        if stripped.startswith("#"):
            out.append(ReqLine("comment", start, end, ""))
            continue
        code = strip_comment(logical)
        kind, requirement, detail, include_kind = classify(code)
        out.append(ReqLine(kind, start, end, code, requirement, detail, include_kind))
    return out


@dataclass
class RequirementsTree:
    """A requirements file and every file it includes, inspected.

    Attributes:
        files: Inspected files in visiting order, as resolved paths.
        texts: ``{path: decoded text}``.
        direct: ``"<file>: <line>"`` for every direct line, in every file.
        registry: Normalised names of every registry line, in every file.
    """

    root: Path
    files: list[Path] = field(default_factory=list)
    texts: dict[Path, str] = field(default_factory=dict)
    lines: dict[Path, list[ReqLine]] = field(default_factory=dict)
    direct: list[str] = field(default_factory=list)
    registry: set[str] = field(default_factory=set)

    def relative(self, path: Path) -> Path:
        return path.relative_to(self.root)

    def copy_to(self, dest_root: Path, *, strip: bool) -> Path:
        """Write every file of the tree under *dest_root*, laid out like the target.

        Args:
            dest_root: Scratch directory to mirror the files into (as UTF-8).
            strip: Drop direct lines (``--ignore-direct-references``).

        Returns:
            The copy of the manifest (the first file of the tree).
        """
        copies: list[Path] = []
        for path in self.files:
            dest = dest_root / self.relative(path)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(self.sanitized(path) if strip else self.texts[path], encoding="utf-8")
            copies.append(dest)
        return copies[0]

    def sanitized(self, path: Path) -> str:
        """*path*'s text without its direct lines (for --ignore-direct-references)."""
        physical = self.texts[path].splitlines(keepends=True)
        drop: set[int] = set()
        for line in self.lines[path]:
            if line.kind == "direct":
                drop.update(range(line.start, line.end + 1))
        return "".join(p for i, p in enumerate(physical) if i not in drop)


class IncludeOutsideTargetError(DepfreshError):
    """Raised when a requirements file includes a file outside the target directory."""


def inspect_tree(manifest: Path, root: Path) -> RequirementsTree:
    """Inspect *manifest* and, recursively, every file it includes.

    Args:
        manifest: The requirements file.
        root: Directory includes must stay inside (the target).

    Raises:
        IncludeOutsideTargetError: For an include outside *root* or missing.
    """
    root = root.resolve()
    tree = RequirementsTree(root=root)
    pending = [manifest.resolve()]
    while pending:
        path = pending.pop(0)
        if path in tree.texts:
            continue
        text = read_text(path)
        tree.files.append(path)
        tree.texts[path] = text
        tree.lines[path] = parse_lines(text)
        label = path.relative_to(root) if path.is_relative_to(root) else path.name
        for line in tree.lines[path]:
            if line.kind == "direct":
                tree.direct.append(f"{label}: {line.requirement or line.code} ({line.detail})")
            elif line.kind == "registry":
                tree.registry.add(line.name)
            elif line.kind == "include":
                target = (path.parent / line.detail).resolve()
                if not target.is_relative_to(root):
                    raise IncludeOutsideTargetError(
                        f"{label} includes {line.detail}, outside {root}; depfresh only "
                        "follows includes inside the target directory"
                    )
                if not target.is_file():
                    raise IncludeOutsideTargetError(f"{label} includes {line.detail}, which "
                                                    "does not exist")
                pending.append(target)
    return tree


def check_no_direct_references(tree: RequirementsTree, manifest: Path) -> None:
    """Fail closed: refuse any direct line anywhere in the tree.

    Raises:
        DirectReferenceError: When the tree has a direct line.
    """
    if tree.direct:
        raise DirectReferenceError(str(manifest), tree.direct)
