# Changelog

All notable changes to depfresh will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

The default remediation now audits and fixes what actually ships, and moves only vulnerable packages. 0.1.0 audited a fresh resolution instead of the lock, so it could report a uv-locked project clean while its lock shipped known advisories; it also rewrote requirements files as a freeze of the machine it ran on and could downgrade packages. This release addresses those issues.

### Added

- **Lock-aware mode** for `pyproject.toml` + `uv.lock`: audits `uv export --frozen --no-emit-project --no-hashes` (groups and extras configurable, default `--no-dev`), fixes with `uv lock --upgrade-package <pkg>==<fix>`, re-exports, re-audits and checks `uv lock --check`. The write-back is `uv.lock`; `pyproject.toml` changes only when a direct dependency's constraint blocks a fix.
- **Minimal strategy** (`--strategy minimal`, the default): only vulnerable packages move, each to the lowest release that fixes all of its advisories that have a fix (an advisory without a fixed release, or fixed only in a later major, stays open with its own reason and does not block the others), planned from the full OSV records and PyPI releases (in-major fixes such as fastmcp 3.4.10 and mcp 1.30.0 are found even where pip-audit only reports the next major). Majors need `--allow-major <pkg>` and are flagged; calendar versions never count as majors.
- **Deploy-platform resolution** for requirements files and lock-less `pyproject.toml`: `uv pip compile --python-platform <target> --python-version X.Y` (`--platform`, default `x86_64-unknown-linux-gnu`). Only affected lines are edited; comments, markers, floors and order are preserved, hashes regenerated, and vulnerable transitive packages get a commented floor line (`pkg>=X  # depfresh: GHSA-…`). Blocking pins get the lowest co-upgrade that resolves.
- `--extra`/`--all-extras` and `--group`/`--all-groups`; extras installed by a local Dockerfile are used by default.
- `--audit-only`, `--skip-import-check`, `--uv` (or `DEPFRESH_UV`) and opt-in `--repo-advisories`, which adds GitHub repository advisories not yet in the Advisory DB (via `gh api`).
- Exit code `3`: imports that resolved before the upgrade fail after it; nothing is written.
- Read-only, static (`ast`) support for `setup.py`.
- Reports list the lock changes, the fix plan with bumps and reasons, the commands run, what was not audited, and the dependency-file diff (also on dry runs).

### Changed

- pip-audit runs from its own environment with a pinned range (`pip-audit>=2.9.0,<3`), on the exact pins with `--no-deps --disable-pip -s osv`, in parallel chunks. This fixes the SIGABRT with uv-managed CPython 3.12 on macOS, and the project's own copies of pip-audit's dependencies (msgpack, rich, platformdirs…) are audited again.
- Advisories are deduplicated by alias (GHSA/PYSEC/CVE), so each is counted once.
- Auto-detection prefers `pyproject.toml` when a `uv.lock` exists, then the manifest a local Dockerfile installs, before the old file order.
- uv must be at least 0.9.0; older binaries on `PATH` are skipped (and named) instead of being used silently.
- The import check locates modules (including namespace packages) without importing them, guards each module separately, compares against the pre-upgrade baseline, and blocks the write-back on regressions. Local modules are recognised at any depth.
- `--strategy latest` (the 0.1 behaviour) edits requirement lines in place instead of writing a freeze, and reads floors as the installed versions, so a `>=2.10.0` floor is no longer "upgraded" down to 2.19.0.
- All temporary venvs and files live in a work directory outside the target, removed even when installation fails.

### Fixed

- `[tool.uv.sources]` and `[[tool.uv.index]]` are honoured; a private-index package is never looked up on public PyPI, an unreachable private index fails the run, and requirements files that cannot pin a private package to its index are refused.
- The import check runs the venv's interpreter as `python -I -S` from an empty directory (no `.pth` hook runs, the working directory is not on `sys.path`; site-packages and `.pth` path entries are added without executing anything), and pip-audit runs as `python -I -m pip_audit` from an empty directory. The README lists what runs on the machine.
- `--keep-version` packages are never moved as another fix's co-upgrade, in either mode, and resolved mode checks its first trial resolution for unapproved major co-upgrades too.
- Raising a constraint for a fix keeps its upper bound and granularity: `~=2.31.0` and `==2.31.*` no longer become an unbounded `>=2.32.0`, a `<` cap moves only as far as the fix needs instead of to the next major, and epochs (`~=1!2.0`) are handled.
- A non-PyPI default index (a mirror or proxy, `UV_INDEX_URL`) no longer makes every package private and the run clean with nothing audited: only packages pinned to an index with `[tool.uv.sources]`, or served by an explicit index, are private; the others are audited by name and the report names their index. The summary gives the audited and not-audited counts, never reports clean while packages went unaudited, and a run that audited nothing exits 2.
- `setup.py` is never executed; local paths and archives in requirements files are treated as direct references instead of being built.
- UTF-16 requirements files are read, and written back in their encoding.
- `--dep-file sub/pyproject.toml` works on that subproject (its lock, its pyproject.toml, its imports, uv run from there) instead of the target's root project; uv workspace members are refused and pointed at the workspace root.
- The PR markdown no longer claims "no major version changes" while the manifest changed.

---

## [0.1.0] — 2026-03-23

Initial public release.

### Added

- **Six dependency formats** — `requirements.txt` (simple and hashed/pip-compile), `requirements.in`, `pyproject.toml` (PEP 621 and Poetry), `Pipfile`
- **Format-preserving writes** — extras, markers, comments and format-specific operators (Poetry `^`/`~`, PEP 508 extras) are kept intact
- **Pre- and post-upgrade vulnerability audit** via `pip-audit`
- **Remaining vulnerability diagnostics** — each unfixed CVE is classified with an actionable reason:
  - Major upgrade required (use `--allow-major`)
  - Pinned via `--keep-version`
  - Major allowed but blocked by transitive conflict
  - Within bounds but unresolvable
  - No fix available upstream
- **Minor/patch-only upgrades by default** — major version crossing requires explicit opt-in via `--allow-major`
- **Selective major upgrades** — `--allow-major urllib3 cryptography` targets individual packages
- **Version pinning** — `--keep-version crewai litellm` preserves exact current versions
- **Dry-run mode** — `--dry-run` reports what would change without touching files
- **AST-based import verification** — checks that third-party imports still resolve after upgrade without executing any user code
- **PR-ready markdown report** and detailed log written per run
- **Public library API** — `upgrade()` and `audit_only()` functions for programmatic use
- **`--python`** flag to target a specific Python version for the upgrade venv
- **`--label`**, **`--dep-file`**, **`--format`**, **`--reports-dir`**, **`--venv`** options
- PEP 503 package name normalization throughout
- Custom exception hierarchy (`DepfreshError` and subclasses) for clean error handling
- Exit codes: `0` = clean, `1` = error, `2` = vulnerabilities remain

[Unreleased]: https://github.com/helios-sc/depfresh/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/helios-sc/depfresh/releases/tag/v0.1.0
