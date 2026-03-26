# CLAUDE.md — depfresh

## What is depfresh?

A Python dependency upgrade and security audit tool. It combines **uv** (fast package manager) and **pip-audit** (CVE scanner) to upgrade dependencies to their latest safe versions, audit for vulnerabilities before and after, verify imports still resolve, and generate PR-ready markdown reports.

**Version:** 0.1.0 (Beta) · **License:** MIT · **Python:** 3.10+

## Project layout

```
src/depfresh/          # Source code
  cli.py               # CLI entry point (argparse)
  upgrade.py           # Core orchestration + public API
  parsers.py           # Format-aware dependency parsing (6 formats)
  models.py            # Dataclasses (Vulnerability, PackageChange, UpgradeResult, etc.)
  constraints.py       # Version constraint building, PEP 503 normalization, remaining vuln diagnostics
  uv.py                # uv binary discovery & venv management
  audit.py             # pip-audit integration
  verify.py            # AST-based import verification
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

Runtime requires the `uv` binary installed separately. Dev extras include pytest, ruff, and mypy.

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

| Format | File | Detection order |
|--------|------|-----------------|
| Simple requirements | `requirements.txt` | 1st |
| Pip-compile (hashed) | `requirements.txt` | 1st (auto) |
| Requirements input | `requirements.in` | 2nd |
| PEP 621 | `pyproject.toml` | 3rd |
| Poetry | `pyproject.toml` | 3rd |
| Pipfile | `Pipfile` | 4th |

## CLI usage

```bash
depfresh /path/to/project
depfresh /path/to/project --dry-run
depfresh /path/to/project --allow-major urllib3 cryptography
depfresh /path/to/project --keep-version crewai litellm
depfresh /path/to/project --python 3.12 --reports-dir ./artifacts
```

Exit codes: `0` = clean, `1` = error, `2` = vulnerabilities remain.

## Remaining vulnerability diagnostics

When vulnerabilities remain after upgrade, `diagnose_remaining()` in `constraints.py` classifies each one:
- **Major upgrade required** — fix crosses a major version boundary (default constraints cap at `<major+1.0`)
- **Pinned via --keep-version** — user explicitly pinned the package
- **Major allowed but unresolved** — major was permitted but uv hit a transitive conflict
- **Within bounds but unresolved** — fix is within minor/patch bounds but couldn't resolve
- **No fix available** — upstream hasn't released a patched version

Results are stored in `UpgradeResult.remaining_reasons` (parallel list to `post_audit_vulns`) and shown in both log and markdown reports with a "Reason" column.
