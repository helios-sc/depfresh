"""Static, read-only reading of ``setup.py`` — it is never executed.

Running ``setup.py`` (or handing it to ``uv pip install -r``/``uv pip
compile``, which runs it to learn the metadata) executes repository code,
which can do anything, such as pip-installing more unpinned packages.
depfresh only reads the literal ``install_requires``/``extras_require`` of a
``setup()`` call with :mod:`ast`, and refuses anything it cannot read that way.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from depfresh.exceptions import DepfreshError
from depfresh.models import DependencyInspection
from depfresh.parsers._helpers import _dependency_from_requirement

log = logging.getLogger("depfresh")


class SetupPyError(DepfreshError):
    """Raised when ``setup.py`` cannot be read without executing it."""


def _setup_call(tree: ast.Module) -> ast.Call | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else (
                func.attr if isinstance(func, ast.Attribute) else ""
            )
            if name == "setup":
                return node
    return None


def _module_literals(tree: ast.Module) -> dict[str, Any]:
    """Module-level ``NAME = <literal>`` assignments (``REQUIRES = [...]``)."""
    values: dict[str, Any] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(
            node.targets[0], ast.Name,
        ):
            try:
                values[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, SyntaxError):
                continue
    return values


def _literal(node: ast.expr, literals: dict[str, Any], what: str, path: Path) -> Any:
    if isinstance(node, ast.Name) and node.id in literals:
        return literals[node.id]
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError):
        raise SetupPyError(
            f"{path}: {what} is computed, not a literal; depfresh never executes setup.py. "
            "Declare the dependencies statically (pyproject.toml or requirements.txt)."
        ) from None


def read_setup_py(path: Path) -> tuple[list[str], dict[str, list[str]]]:
    """Return ``(install_requires, extras_require)`` read statically from *path*.

    Raises:
        SetupPyError: If there is no ``setup()`` call or its arguments are not
            literals (or module-level literal names).
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
    except SyntaxError as exc:
        raise SetupPyError(f"{path}: not valid Python ({exc.msg})") from exc
    call = _setup_call(tree)
    if call is None:
        raise SetupPyError(
            f"{path}: no setup(install_requires=...) call to read. depfresh never "
            "executes setup.py, and this one is a script, not package metadata."
        )
    literals = _module_literals(tree)
    install: list[str] = []
    extras: dict[str, list[str]] = {}
    for keyword in call.keywords:
        if keyword.arg == "install_requires":
            value = _literal(keyword.value, literals, "install_requires", path)
            install = [str(v) for v in (value or [])]
        elif keyword.arg == "extras_require":
            value = _literal(keyword.value, literals, "extras_require", path)
            extras = {str(k): [str(v) for v in vs] for k, vs in (value or {}).items()}
        elif keyword.arg is None:
            raise SetupPyError(
                f"{path}: setup(**kwargs) hides its arguments; depfresh never executes setup.py"
            )
    return install, extras


class SetupPyHandler:
    """Read-only handler for ``setup.py``: static parsing, no write-back."""

    is_pinned = False

    def parse(self, path: Path) -> dict[str, str]:
        return {dep.name: dep.version for dep in self.inspect(path).registry}

    def inspect(self, path: Path) -> DependencyInspection:
        install, extras = read_setup_py(path)
        inspection = DependencyInspection()
        groups: list[tuple[str, bool, list[str]]] = [("runtime", True, install)]
        groups += [(name, False, deps) for name, deps in extras.items()]
        for group, runtime, deps in groups:
            for raw in deps:
                try:
                    req = Requirement(raw)
                except InvalidRequirement:
                    log.warning("%s: skipping unparseable requirement %r", path.name, raw)
                    continue
                dep = _dependency_from_requirement(req, raw=raw, group=group, is_runtime=runtime)
                target = (
                    inspection.direct_references if dep.source_kind == "direct-reference"
                    else inspection.registry
                )
                target.append(dep)
        return inspection

    def requirements_text(self, path: Path, include_extras: bool) -> str:
        """The static requirements as a requirements file, for uv (never setup.py itself)."""
        install, extras = read_setup_py(path)
        lines = list(install)
        if include_extras:
            for deps in extras.values():
                lines += deps
        return "".join(f"{line}\n" for line in lines)

    def write(self, pkgs: dict[str, str], path: Path, **kwargs: Any) -> None:
        raise SetupPyError(
            f"{path}: depfresh does not edit setup.py; apply the planned versions to "
            "install_requires by hand (or move the dependencies to pyproject.toml)"
        )
