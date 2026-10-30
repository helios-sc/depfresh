"""AST-based import verification against the upgraded environment.

Imports are read from the project's ``.py`` files with :mod:`ast` (no project
code runs) and then *located* — not imported — in the target venv: the
top-level name with :func:`importlib.util.find_spec`, each submodule with a
:class:`importlib.machinery.FileFinder` inside its parent's search path.  No
third-party module code runs either, and one missing module cannot abort the
check for the others.

The venv's interpreter runs as ``python -I -S`` from an empty temporary
directory: ``-I`` keeps the working directory, ``PYTHON*`` variables and the
user site out of ``sys.path``, and ``-S`` skips :mod:`site`, so no ``.pth``
hook of an installed package runs.  The check adds the venv's site-packages
itself and reads each ``.pth`` file as text, taking its path entries and
ignoring its ``import`` lines.  Only the standard library executes.

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
import tempfile
import textwrap
import warnings
from dataclasses import dataclass, field
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
    local_modules = LocalModules.of(target_dir)
    stdlib_modules = _get_stdlib_modules(venv_python)

    # 3. Classify imports
    local_skipped: set[str] = set()
    third_party: set[str] = set()
    either: set[str] = set()   # a bare name of a local namespace directory
    for imp in all_imports:
        top = imp.split(".")[0]
        where = local_modules.classify(imp)
        if where == "local":
            local_skipped.add(top)
        elif top in stdlib_modules:
            pass
        else:
            third_party.add(imp)
            if where == "either":
                either.add(imp)

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
    for mod in sorted(either):
        # Not in the venv either: the local namespace directory is what it imports.
        if results.get(mod) is not None:
            del results[mod]
            local_skipped.add(mod.split(".")[0])

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


@dataclass
class LocalModules:
    """The project's own top-level modules, as its import roots expose them.

    The import roots are the project directory and ``src/``: only what sits
    directly in one of them is importable by a bare name.  A module deeper in
    the tree (``app/integrations/google/``) is ``app.integrations.google`` and
    never hides a third-party ``google``.

    Attributes:
        regular: ``.py`` modules and packages with an ``__init__.py`` at a root,
            and the project directory's own name.
        namespaces: Directories without ``__init__.py`` at a root.  Python merges
            such a namespace with same-named ones in site-packages, and a
            regular package there wins over it, so ``google.cloud`` stays
            third-party when the local ``google/`` has no ``cloud``, and a bare
            ``alembic`` next to an ``alembic/`` migrations directory may well be
            the third-party package.
    """

    regular: set[str] = field(default_factory=set)
    namespaces: dict[str, list[Path]] = field(default_factory=dict)

    @classmethod
    def of(cls, target_dir: Path) -> LocalModules:
        found = cls(regular={target_dir.name})
        roots = [target_dir, *([target_dir / "src"] if (target_dir / "src").is_dir() else [])]
        for root in roots:
            for item in sorted(root.iterdir()):
                if item.is_file() and item.suffix == ".py" and item.stem != "__init__":
                    found.regular.add(item.stem)
                elif item.is_dir() and not _is_skipped_dir(item.name):
                    if (item / "__init__.py").is_file():
                        found.regular.add(item.name)
                    else:
                        found.namespaces.setdefault(item.name, []).append(item)
        return found

    def classify(self, module: str) -> str:
        """``"local"``, ``"other"`` (stdlib or third-party), or ``"either"``.

        ``"either"`` is the bare name of a local namespace directory: the venv
        decides (a third-party package of that name wins; otherwise it is local).
        """
        parts = module.split(".")
        if parts[0] in self.regular:
            return "local"
        if parts[0] not in self.namespaces:
            return "other"
        if len(parts) == 1:
            return "either"
        if any((d / parts[1]).is_dir() or (d / f"{parts[1]}.py").is_file()
               for d in self.namespaces[parts[0]]):
            return "local"
        return "other"

    def provides(self, module: str) -> bool:
        """True when *module* certainly resolves to the project's own code."""
        return self.classify(module) == "local"

    def names(self) -> set[str]:
        return self.regular | set(self.namespaces)


def _find_local_modules(target_dir: Path) -> set[str]:
    """Top-level names the project's import roots provide (see :class:`LocalModules`)."""
    return LocalModules.of(target_dir).names()


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


def _run_isolated(
    venv_python: str, script: str, *args: str, timeout: int,
) -> subprocess.CompletedProcess[str]:
    """``python -I -S -c script`` from an empty directory: only the stdlib runs."""
    with tempfile.TemporaryDirectory(prefix="depfresh-check-") as empty:
        return subprocess.run(
            [venv_python, "-I", "-S", "-c", script, *args],
            capture_output=True, text=True, timeout=timeout, cwd=empty,
        )


def site_dirs(venv_python: str) -> list[str]:
    """The site-packages directories of the venv *venv_python* belongs to.

    Found from the venv layout, not by asking the interpreter: with ``-S``
    it does not know about its venv, and without it every ``.pth`` hook runs.
    """
    venv = Path(venv_python).parent.parent
    found: list[str] = []
    for pattern in ("lib/python*/site-packages", "lib64/python*/site-packages",
                    "Lib/site-packages"):
        for path in sorted(venv.glob(pattern)):
            resolved = str(path.resolve())
            if path.is_dir() and resolved not in found:
                found.append(resolved)
    return found


def _get_stdlib_modules(venv_python: str) -> set[str]:
    """Get stdlib module names from the venv Python."""
    result = _run_isolated(
        venv_python, "import sys, json; print(json.dumps(sorted(sys.stdlib_module_names)))",
        timeout=30,
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

        def add_site_dir(sitedir):
            # site.addsitedir() without running anything: .pth path entries
            # are added, "import" lines are skipped.
            if sitedir not in sys.path:
                sys.path.append(sitedir)
            try:
                names = sorted(os.listdir(sitedir))
            except OSError:
                return
            for name in names:
                if not name.endswith(".pth") or name.startswith("."):
                    continue
                try:
                    with open(os.path.join(sitedir, name), encoding="utf-8") as handle:
                        lines = handle.read().splitlines()
                except (OSError, UnicodeDecodeError):
                    continue
                for line in lines:
                    line = line.rstrip()
                    if not line or line.startswith(("#", "import ", "import\t")):
                        continue
                    path = os.path.abspath(os.path.join(sitedir, line))
                    if os.path.exists(path) and path not in sys.path:
                        sys.path.append(path)

        for sitedir in json.loads(sys.argv[2]):
            add_site_dir(sitedir)

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

    result = _run_isolated(
        venv_python, check_script, json.dumps(sorted(modules)),
        json.dumps(site_dirs(venv_python)), timeout=120,
    )

    if result.returncode == 0 and result.stdout.strip():
        data = json.loads(result.stdout.strip())
        return data["results"], data.get("warnings", {})

    return {mod: f"check error: {result.stderr[:200]}" for mod in modules}, {}
