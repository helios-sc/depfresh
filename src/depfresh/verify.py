"""AST-based import verification against the upgraded environment.

Imports are read from the project's ``.py`` files with :mod:`ast` (no project
code runs) and then *located* — not imported — in the target venv: the
top-level name with :func:`importlib.util.find_spec`, each submodule with a
:class:`importlib.machinery.FileFinder` inside its parent's search path.  No
third-party module code runs either, and one missing module cannot abort the
check for the others.

Because a project usually has some imports that never resolve (test-only
tools, optional extras, modules put on ``sys.path`` at runtime), the result is
only meaningful relative to a baseline: :func:`import_regressions` reports the
modules that resolved before the upgrade and fail after it.
"""

from __future__ import annotations

import ast
import json
import logging
import subprocess
import textwrap
import warnings
from pathlib import Path

from depfresh.models import ImportCheck

log = logging.getLogger("depfresh")

_SKIP_DIRS = {
    "__pycache__", ".git", ".tox", ".mypy_cache", ".pytest_cache", "node_modules",
    "site-packages", "dist-packages",
}


def verify_imports(target_dir: Path, venv_python: str, *, label: str = "upgraded") -> ImportCheck:
    """Verify that third-party imports from the codebase resolve in a venv.

    Scans all ``.py`` files under *target_dir*, classifies imports into
    stdlib / local / third-party, then checks that every third-party import
    is resolvable in the venv without importing it (safe for packages with
    side effects or missing configuration).

    Args:
        target_dir: Project directory to scan.
        venv_python: Interpreter of the environment to check against.
        label: Which environment this is, for logging (``"baseline"``…).
    """
    log.info("Verifying imports against the %s environment", label)

    # 1. Extract imports from Python files
    all_imports, files_scanned = _extract_imports(target_dir)
    log.info("Scanned %d Python files, found %d unique imports", files_scanned, len(all_imports))

    # 2. Identify local and stdlib modules
    local_modules = _find_local_modules(target_dir)
    stdlib_modules = _get_stdlib_modules(venv_python)

    # 3. Classify imports
    local_skipped: set[str] = set()
    third_party: set[str] = set()
    for imp in all_imports:
        top = imp.split(".")[0]
        if top in local_modules:
            local_skipped.add(top)
        elif top in stdlib_modules:
            pass
        else:
            third_party.add(imp)

    log.info(
        "Third-party: %d, local: %d, stdlib: %d",
        len(third_party), len(local_skipped),
        len(all_imports) - len(third_party) - len(local_skipped),
    )

    if not third_party:
        log.info("No third-party imports to verify")
        return ImportCheck(
            files_scanned=files_scanned,
            total_imports=len(all_imports),
            skipped_local=sorted(local_skipped),
        )

    # 4. Batch import check in the venv
    results, warns = _batch_import_check(venv_python, third_party)

    verified = sorted(mod for mod, err in results.items() if err is None)
    failed = {mod: err for mod, err in sorted(results.items()) if err is not None}
    dep_warnings = {mod: msgs for mod, msgs in warns.items() if msgs}

    log.info("Results: %d verified, %d failed", len(verified), len(failed))
    if failed:
        for mod, err in failed.items():
            log.warning("FAIL: %s — %s", mod, err)
    if dep_warnings:
        log.info("Deprecation warnings in %d package(s)", len(dep_warnings))
    if not failed:
        log.info("All third-party imports verified successfully")

    return ImportCheck(
        files_scanned=files_scanned,
        total_imports=len(all_imports),
        verified=verified,
        failed=failed,
        skipped_local=sorted(local_skipped),
        warnings=dep_warnings,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_imports(target_dir: Path) -> tuple[set[str], int]:
    """Extract all import module paths from ``.py`` files in *target_dir*."""
    imports: set[str] = set()
    files_scanned = 0
    for py_file in target_dir.rglob("*.py"):
        rel_parts = py_file.relative_to(target_dir).parts
        if any(_is_skipped_dir(p) for p in rel_parts[:-1]):
            continue
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(
                    py_file.read_text(encoding="utf-8", errors="replace"),
                    filename=str(py_file),
                )
        except (SyntaxError, ValueError):
            continue
        files_scanned += 1
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.level == 0:
                    imports.add(node.module)
    return imports, files_scanned


def _find_local_modules(target_dir: Path) -> set[str]:
    """Identify local package/module names in *target_dir* (not third-party).

    Projects often put directories such as ``src/`` on ``sys.path`` at
    runtime, so a module anywhere in the tree can be imported by its bare
    name.  Every ``.py`` file stem and every directory holding Python files
    counts as local, at any depth (virtual environments and caches excluded).
    """
    local: set[str] = {target_dir.name}
    for py_file in target_dir.rglob("*.py"):
        rel_parts = py_file.relative_to(target_dir).parts
        if any(_is_skipped_dir(part) for part in rel_parts[:-1]):
            continue
        local.add(py_file.stem)
        local.update(rel_parts[:-1])
    for item in target_dir.iterdir():
        # Top-level directories (even without .py files yet) are local namespaces.
        if item.is_dir() and not _is_skipped_dir(item.name):
            local.add(item.name)
    local.discard("__init__")
    return local


def _is_skipped_dir(name: str) -> bool:
    """Return True for directories that never hold project modules."""
    return (
        name in _SKIP_DIRS
        or name.startswith((".", "venv"))
    )


def import_regressions(baseline: ImportCheck, after: ImportCheck) -> dict[str, str]:
    """Return the modules that resolved in *baseline* but fail in *after*.

    Args:
        baseline: Import check against the environment before the upgrade.
        after: Import check against the upgraded environment.

    Returns:
        ``{module: error}`` for every regression, sorted by module name.
    """
    resolved_before = set(baseline.verified)
    return {
        mod: err for mod, err in sorted(after.failed.items()) if mod in resolved_before
    }


def _get_stdlib_modules(venv_python: str) -> set[str]:
    """Get stdlib module names from the venv Python."""
    result = subprocess.run(
        [venv_python, "-c",
         "import sys, json; print(json.dumps(sorted(sys.stdlib_module_names)))"],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode == 0 and result.stdout.strip():
        return set(json.loads(result.stdout.strip()))
    return set()


def _batch_import_check(
    venv_python: str, modules: set[str],
) -> tuple[dict[str, str | None], dict[str, list[str]]]:
    """Check that third-party modules can be located in the venv.

    Each module is resolved on its own, inside its own ``try``: the top-level
    name with :func:`importlib.util.find_spec`, which searches ``sys.path``
    without importing anything, then each dotted part with a
    :class:`importlib.machinery.FileFinder` over the parent's
    ``submodule_search_locations`` (namespace packages such as ``google.cloud``
    included).  Unlike ``find_spec("pkg.sub")``, that never imports ``pkg`` (no
    module code runs) and a missing ``pkg`` fails only ``pkg.sub`` instead of
    the whole batch.

    Returns ``(results, warnings)`` where:
      - results: ``{module: error_string_or_None}``
      - warnings: ``{module: [warning_messages]}`` (always empty: nothing is
        imported, so no import-time warnings are raised)
    """
    if not modules:
        return {}, {}

    check_script = textwrap.dedent("""\
        import importlib.machinery as machinery
        import importlib.util
        import json
        import os
        import sys

        LOADERS = [
            (machinery.ExtensionFileLoader, machinery.EXTENSION_SUFFIXES),
            (machinery.SourceFileLoader, machinery.SOURCE_SUFFIXES),
            (machinery.SourcelessFileLoader, machinery.BYTECODE_SUFFIXES),
        ]

        def child(fullname, locations):
            # FileFinder per directory: unlike PathFinder it never builds a
            # _NamespacePath, which needs the parent package in sys.modules.
            portions = []
            for entry in locations:
                if not os.path.isdir(entry):
                    continue
                spec = machinery.FileFinder(entry, *LOADERS).find_spec(fullname)
                if spec is None:
                    continue
                if spec.loader is None and spec.submodule_search_locations:
                    portions.extend(spec.submodule_search_locations)  # namespace portion
                    continue
                return True, spec.submodule_search_locations
            return bool(portions), (portions or None)

        def locate(mod):
            parts = mod.split(".")
            spec = importlib.util.find_spec(parts[0])
            if spec is None:
                return f"No module named '{parts[0]}'"
            locations = spec.submodule_search_locations
            locations = list(locations) if locations is not None else None
            name = parts[0]
            for part in parts[1:]:
                if locations is None:
                    return f"'{name}' is not a package, so '{mod}' cannot be imported"
                name = f"{name}.{part}"
                found, locations = child(name, locations)
                if not found:
                    return f"No module named '{name}'"
                locations = list(locations) if locations is not None else None
            return None

        results = {}
        for mod in json.loads(sys.argv[1]):
            try:
                results[mod] = locate(mod)
            except Exception as exc:  # one broken module must not stop the batch
                results[mod] = f"{type(exc).__name__}: {exc}"

        print(json.dumps({"results": results, "warnings": {}}))
    """)

    result = subprocess.run(
        [venv_python, "-I", "-c", check_script, json.dumps(sorted(modules))],
        capture_output=True, text=True, timeout=120,
    )

    if result.returncode == 0 and result.stdout.strip():
        data = json.loads(result.stdout.strip())
        return data["results"], data.get("warnings", {})

    return {mod: f"check error: {result.stderr[:200]}" for mod in modules}, {}
