<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/helios-sc/depfresh/refs/heads/main/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/helios-sc/depfresh/refs/heads/main/assets/logo.svg">
  <img alt="depfresh" src="https://raw.githubusercontent.com/helios-sc/depfresh/refs/heads/main/assets/logo.svg" width="380">
</picture>

<br>

[![PyPI version](https://img.shields.io/pypi/v/depfresh)](https://pypi.org/project/depfresh/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**One command to upgrade your Python dependencies, audit for CVEs, and prove it's safe.**

depfresh combines [uv](https://docs.astral.sh/uv/) and [pip-audit](https://github.com/pypa/pip-audit) into a single workflow — upgrade to the latest safe versions, scan for vulnerabilities before and after, verify imports still resolve, and generate a PR-ready markdown report.

```bash
pip install depfresh
depfresh /path/to/project
```

> **Prerequisites:** Python 3.10+ and [uv](https://docs.astral.sh/uv/). pip-audit is installed automatically.

---

## Why depfresh?

- **Tired of Dependabot/Renovate noise?** Get one deliberate upgrade pass with full context instead of 30 individual PRs
- **Need CVE auditing baked in?** Vulnerability scanning happens automatically, not as an afterthought
- **Want CI-ready reports?** Get dated markdown with tables, diffs, and checklists you can paste straight into a PR
- **Running multiple Python services?** Point depfresh at each one — locally, in CI, or on a cron schedule

## How it works

```
  dependency file (auto-detected)
         │
         ▼
   parse dependencies ──▶ create temp venv ──▶ install & audit (before)
         │
   build constraints (major bounds, pins, keep-version)
         │
   upgrade ──▶ freeze ──▶ verify imports (AST scan) ──▶ audit (after)
         │
   write reports ──▶ update dependency file ──▶ cleanup
```

If resolution fails or the audit returns invalid output, depfresh aborts before updating anything. It fails closed — never generates a misleading clean result.

## Features

| | |
|---|---|
| **Safe by default** | Minor/patch upgrades only, with opt-in per-package major bumps |
| **CVE scanning** | Pre- and post-upgrade vulnerability auditing via pip-audit |
| **Remaining vuln diagnostics** | Explains *why* each unfixed CVE couldn't be resolved |
| **Import verification** | AST-based scanning confirms third-party imports still resolve |
| **Selective control** | `--allow-major urllib3` / `--keep-version crewai` for fine-grained power |
| **Multi-format** | `requirements.txt`, `.in`, `pyproject.toml` (PEP 621 & Poetry), `Pipfile` |
| **Format-preserving** | Keeps exact pins, upper bounds, extras, and wildcards intact |
| **Zero footprint** | Temporary venv, cleans up after itself |
| **Fail-closed** | Aborts on resolver, hash, or audit failures |

## Usage

```bash
# Upgrade everything (minor/patch only) — auto-detects format
depfresh /path/to/project

# Preview without touching anything
depfresh /path/to/project --dry-run

# Allow major bumps for specific packages
depfresh /path/to/project --allow-major urllib3 cryptography

# Pin packages you don't want touched
depfresh /path/to/project --keep-version crewai litellm

# Include optional/dev groups for grouped formats
depfresh /path/to/project --dependency-scope all

# Run in CI with a specific Python and report dir
depfresh /path/to/project --python 3.12 --reports-dir ./artifacts
```

<details>
<summary><strong>All CLI options</strong></summary>

| Option | Default | Description |
|--------|---------|-------------|
| `target_dir` | *(required)* | Directory containing the dependency file |
| `--label` | auto-derived | Report subfolder name |
| `--dep-file` | auto-detect | Dependency file name |
| `--format` | auto-detect | Force format: `requirements-simple`, `requirements-hashed`, `requirements-in`, `pyproject-pep621`, `pyproject-poetry`, `pipfile` |
| `--python` | `3.11` | Python version for the temp venv |
| `--dependency-scope` | `runtime` | `runtime` (main deps) or `all` (include optional/dev) |
| `--ignore-direct-references` | off | Skip git/path/url deps instead of failing |
| `--dry-run` | off | Preview without modifying files |
| `--allow-major [PKG ...]` | off | Allow major upgrades (all or named) |
| `--keep-version PKG [...]` | off | Pin packages to current version |
| `--reports-dir` | `./reports/` | Report output directory |
| `-v, --verbose` | off | Debug output |

**Exit codes:** `0` = clean, `1` = error, `2` = vulnerabilities remain.

</details>

## Supported formats

| Format | File | Ecosystem |
|--------|------|-----------|
| Simple requirements | `requirements.txt` | pip, uv |
| Hashed requirements | `requirements.txt` | pip-compile, uv pip compile |
| Requirements input | `requirements.in` | pip-tools, uv pip compile |
| PEP 621 | `pyproject.toml` | uv, pdm, hatch, flit |
| Poetry | `pyproject.toml` | poetry |
| Pipfile | `Pipfile` | pipenv |

Auto-detection order: `requirements.txt` → `requirements.in` → `pyproject.toml` → `Pipfile`

## Understanding remaining vulnerabilities

When CVEs remain after upgrade, depfresh diagnoses each one:

| Reason | What to do |
|--------|------------|
| **Requires major upgrade** | Re-run with `--allow-major <package>` |
| **Pinned via --keep-version** | Remove from `--keep-version` if the fix is needed |
| **Major allowed but unresolved** | Investigate transitive dependency conflicts |
| **Fix within constraints but unresolved** | Check for conflicting version requirements |
| **No fix available** | Monitor upstream for a patched release |

## Python API

```python
from depfresh import upgrade, audit_only

# Full upgrade workflow
result = upgrade(
    "/path/to/project",
    python="3.12",
    allow_major=["urllib3"],
    keep_version=["crewai"],
)

print(f"Upgraded {len(result.upgraded)} packages")
print(f"Vulns: {len(result.pre_audit_vulns)} → {len(result.post_audit_vulns)}")

for vuln, reason in zip(result.post_audit_vulns, result.remaining_reasons):
    print(f"  {vuln.package} {vuln.cve}: {reason}")

# Audit only — no modifications
result = audit_only("/path/to/project")
```

<details>
<summary><strong>API reference</strong></summary>

### `upgrade(target, **kwargs) -> UpgradeResult`

Full workflow: venv creation, install, audit, upgrade, import verification, reports.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `target` | *(required)* | Directory containing dependency file |
| `label` | `None` | Report subfolder name |
| `dep_file` | `None` | Dependency filename |
| `fmt` | `None` | Force format string |
| `python` | `"3.11"` | Python version for the venv |
| `dependency_scope` | `"runtime"` | `"runtime"` or `"all"` |
| `ignore_direct_references` | `False` | Skip git/path/url deps |
| `dry_run` | `False` | Preview without writing |
| `allow_major` | `None` | `None` (minor/patch), `[]` (all), or `["pkg"]` |
| `keep_version` | `None` | Packages to pin at current version |
| `reports_dir` | `./reports/` | Report output directory |

### `audit_only(target, **kwargs) -> UpgradeResult`

Vulnerability scan only. Same venv workflow, no file modifications.

### `UpgradeResult`

| Field | Type | Description |
|-------|------|-------------|
| `upgraded` | `list[PackageChange]` | Packages that changed version |
| `new_deps` | `list[PackageChange]` | New transitive dependencies |
| `pre_audit_vulns` | `list[Vulnerability]` | CVEs before upgrade |
| `post_audit_vulns` | `list[Vulnerability]` | CVEs remaining after upgrade |
| `remaining_reasons` | `list[str]` | Why each post-upgrade CVE wasn't fixed |
| `import_check` | `ImportCheck` | Import verification results |
| `log_path` / `markdown_path` | `str` | Paths to generated reports |

</details>

## CI / Automation

**GitHub Actions — weekly upgrade PR:**
```yaml
- name: Upgrade dependencies
  run: |
    pip install depfresh
    depfresh . --reports-dir ./artifacts --python 3.12
```

**Cron job — audit only, alert on CVEs:**
```python
from depfresh import audit_only

result = audit_only("/app")
if result.pre_audit_vulns:
    send_alert(f"{len(result.pre_audit_vulns)} CVEs found")
```

## Current limitations

- `pyproject.toml`, Poetry, and `Pipfile` projects are analyzed through a synthesized requirements file — the install/audit environment approximates the native tool's resolver
- Operates on a single dependency file per run
- Import verification checks resolution, not runtime behavior — always run your test suite after upgrading
- Pip directives (`-r`, `-c`, `--index-url`) in requirements files are not followed

<details>
<summary><strong>Known edge cases</strong></summary>

- **PEP 440 epochs** (`1!2.0`): Not recognized by major-version extraction; packages are pinned exactly (conservative but safe)
- **Environment markers**: Preserved on write-back but not evaluated during dependency selection
- **Hybrid pyproject.toml** (PEP 621 + Poetry): PEP 621 is detected first; use `--format pyproject-poetry` to force Poetry handling
- **Private indexes**: Configure via `uv`'s native settings (`UV_INDEX_URL`, `uv.toml`), not via `--index-url` in requirements files

</details>

## Contributing

```bash
git clone https://github.com/helios-sc/depfresh.git && cd depfresh
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
pytest && ruff check src/ && mypy src/
```

Open an issue first for larger changes so we can discuss the approach.

## License

MIT
