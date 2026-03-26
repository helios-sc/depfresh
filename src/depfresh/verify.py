"""AST-based import verification against the upgraded environment."""

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
}


def verify_imports(target_dir: Path, venv_python: str) -> ImportCheck:
    """Verify that third-party imports from the codebase resolve in the upgraded venv.

    Scans all ``.py`` files under *target_dir*, classifies imports into
    stdlib / local / third-party, then checks that every third-party import
    is resolvable in the venv without actually importing it (safe for
    packages with side-effects or missing configs).
    """
    log.info("Verifying imports against upgraded environment")

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
        if any(p in _SKIP_DIRS or p.startswith((".venv", "venv")) for p in rel_parts):
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
    """Identify local package/module names in *target_dir* (not third-party)."""
    local: set[str] = set()
    local.add(target_dir.name)
    for item in target_dir.iterdir():
        if item.name.startswith("."):
            continue
        if item.is_dir() and not item.name.startswith(("venv", ".venv")):
            local.add(item.name)
            for sub in item.iterdir():
                if sub.is_dir() and not sub.name.startswith((".", "_")):
                    local.add(sub.name)
        elif item.is_file() and item.suffix == ".py":
            local.add(item.stem)
    return local


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
    """Verify that third-party modules are available in the venv.

    Uses ``importlib.metadata.packages_distributions()`` (Python 3.11+) to
    check package availability without actually importing — avoids crashes
    from missing configs, C-extension segfaults, or side-effects during
    import.  Falls back to ``importlib.import_module()`` only for modules
    not found in the metadata map.

    Returns ``(results, warnings)`` where:
      - results: ``{module: error_string_or_None}``
      - warnings: ``{module: [warning_messages]}``
    """
    if not modules:
        return {}, {}

    check_script = textwrap.dedent("""\
        import sys, json, importlib, importlib.metadata, importlib.util, warnings

        modules = json.loads(sys.argv[1])

        # Map of importable top-level names -> distribution packages (safe, no side-effects)
        try:
            pkg_map = importlib.metadata.packages_distributions()
        except AttributeError:
            pkg_map = {}  # Python < 3.11 fallback

        results = {}
        warns = {}
        for mod in modules:
            top = mod.split(".")[0]
            if "." in mod:
                spec = importlib.util.find_spec(mod)
                if spec is not None:
                    results[mod] = None
                    continue

            if top in pkg_map and mod == top:
                results[mod] = None
                continue

            # Fallback: actual import for packages not in metadata map
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                try:
                    importlib.import_module(mod)
                    results[mod] = None
                except ImportError as e:
                    results[mod] = str(e)
                except Exception as e:
                    results[mod] = f"{type(e).__name__}: {e}"
            if caught:
                warns[mod] = [
                    f"{w.category.__name__}: {w.message}"
                    for w in caught
                    if issubclass(w.category, DeprecationWarning)
                ]

        print(json.dumps({"results": results, "warnings": warns}))
    """)

    result = subprocess.run(
        [venv_python, "-c", check_script, json.dumps(sorted(modules))],
        capture_output=True, text=True, timeout=120,
    )

    if result.returncode == 0 and result.stdout.strip():
        data = json.loads(result.stdout.strip())
        return data["results"], data.get("warnings", {})

    return {mod: f"check error: {result.stderr[:200]}" for mod in modules}, {}
