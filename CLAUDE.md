# CLAUDE.md — depfresh

## What is depfresh?

A Python dependency upgrade and security audit tool. It combines **uv** (fast package manager) and **pip-audit** (CVE scanner) to upgrade dependencies to their latest safe versions, audit for vulnerabilities before and after, verify imports still resolve, and generate PR-ready markdown reports.

**Version:** 0.1.0 (Beta) · **License:** MIT · **Python:** 3.10+

## Project layout

```
src/depfresh/          # Source code
  cli.py               # CLI entry point (argparse)
  upgrade.py           # Orchestration + public API (dispatches lock / resolved / legacy modes)
  lockmode.py          # Lock-aware mode: uv export, uv lock --upgrade-package, uv lock --check
  pipmode.py           # Resolved mode: uv pip compile for the deploy platform, line-preserving edits
  remediation.py       # Shared minimal-mode pieces: options, auditor, import gate, result rows
  advisories.py        # Fix planning from OSV ranges + PyPI releases; deploy-target markers
  repoadvisories.py    # Opt-in GitHub repository advisories (gh api)
  indexes.py           # Private-index detection and refusals
  parsers/             # Format-aware dependency parsing (7 formats, setup.py read statically)
  models.py            # Dataclasses (Vulnerability, PlannedFix, UpgradeResult, etc.)
  constraints.py       # Version constraints, bump classification, PEP 503 normalization
  uv.py                # uv discovery (minimum version), venv management, subprocess helper
  audit.py             # Isolated, pinned pip-audit; alias dedupe
  verify.py            # AST-based import verification (no imports executed)
  textio.py            # UTF-8/UTF-16 aware reading and writing
  reports.py           # Log/markdown report generation
  exceptions.py        # Custom exceptions
tests/                 # pytest test suite (mirrors src modules)
pyproject.toml         # All project metadata and tool config
uv.lock               # Locked dependencies
```

## Development setup

```bash
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
```

Runtime requires a `uv` binary of at least 0.9.0 installed separately (`--uv` or `DEPFRESH_UV` to pick one). Dev extras include pytest, ruff, and mypy.

## Commands

```bash
# Run tests
pytest

# Lint
ruff check src/ tests/

# Format
ruff format src/ tests/

# Type check
mypy src/
```

## Code style

- **Ruff** for linting and formatting — line length 100, rules: E, F, I, W, UP
- **mypy** strict mode — all functions and variables must be typed
- `from __future__ import annotations` in every module
- Google-style docstrings
- Target version: Python 3.10

## Build & publish

Build system is **hatchling**. Entry point: `depfresh = depfresh.cli:main`.

```bash
python -m build
```

## Test conventions

- pytest with class-based organization
- Fixtures: `tmp_path`, `capsys`, standard pytest built-ins
- Parameterized tests where appropriate
- Mocking for subprocess/external tool calls
- Test files mirror source modules: `test_cli.py`, `test_parsers.py`, etc.

## Supported dependency formats

| Format | File | Minimal strategy |
|--------|------|------------------|
| uv project | `pyproject.toml` + `uv.lock` | lock-aware (`lockmode.py`) |
| Simple / hashed requirements | `requirements.txt` | resolved (`pipmode.py`) |
| Requirements input | `requirements.in` | resolved |
| PEP 621 | `pyproject.toml` | resolved |
| setup.py (static, read-only) | `setup.py` | resolved, never written |
| Poetry | `pyproject.toml` | `--strategy latest` only |
| Pipfile | `Pipfile` | `--strategy latest` only |

Auto-detection (`parsers.choose_dep_file`): `pyproject.toml` when `uv.lock` exists, then what a local Dockerfile installs, then `requirements.txt` → `requirements.in` → `pyproject.toml` → `Pipfile`.

## CLI usage

```bash
depfresh /path/to/project
depfresh /path/to/project --audit-only
depfresh /path/to/project --dry-run
depfresh /path/to/project --allow-major urllib3 cryptography
depfresh /path/to/project --keep-version crewai litellm
depfresh /path/to/project --python 3.12 --extra full --reports-dir ./artifacts
depfresh /path/to/project --strategy latest
```

Exit codes: `0` = no known vulnerabilities in what was audited, `1` = error, `2` = vulnerabilities remain, nothing was written, or nothing could be audited, `3` = imports regressed (nothing written). Only packages pinned to an index (`[tool.uv.sources]`) or served by an explicit index are private (`indexes.PrivateScope`); everything else is audited by name.

Never execute repository code (no `setup.py`, no building local paths) and never resolve a private-index package against public PyPI.

## Remaining vulnerability diagnostics

In the minimal modes each remaining advisory carries the reason from its fix plan (`advisories.plan_fixes` → `remediation.remaining_reasons`): needs `--allow-major`, kept, no fix released, private index, or the uv error that blocked it. Advisories are planned one by one: `FixPlan.open_advisories` holds the ones the target leaves open, each with its own reason, so they never block the package's other fixes. With `--strategy latest`, `diagnose_remaining()` in `constraints.py` classifies each one:
- **Major upgrade required** — fix crosses a major version boundary (default constraints cap at `<major+1.0`)
- **Pinned via --keep-version** — user explicitly pinned the package
- **Major allowed but unresolved** — major was permitted but uv hit a transitive conflict
- **Within bounds but unresolved** — fix is within minor/patch bounds but couldn't resolve
- **No fix available** — upstream hasn't released a patched version

Results are stored in `UpgradeResult.remaining_reasons` (parallel list to `post_audit_vulns`) and shown in both log and markdown reports with a "Reason" column.
