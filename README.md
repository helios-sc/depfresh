<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/helios-sc/depfresh/refs/heads/main/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/helios-sc/depfresh/refs/heads/main/assets/logo.svg">
  <img alt="depfresh" src="https://raw.githubusercontent.com/helios-sc/depfresh/refs/heads/main/assets/logo.svg" width="380">
</picture>

<br>

[![PyPI version](https://img.shields.io/pypi/v/depfresh)](https://pypi.org/project/depfresh/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**One command to audit what your Python service ships, fix only what is vulnerable, and prove it's safe.**

depfresh combines [uv](https://docs.astral.sh/uv/) and [pip-audit](https://github.com/pypa/pip-audit) into a single workflow: audit the exact set that ships (the `uv.lock`, or a resolution for the deploy platform), move each vulnerable package to the lowest release that fixes it, check that imports still resolve, audit again, and generate a PR-ready markdown report.

```bash
pip install depfresh
depfresh /path/to/project
```

> **Prerequisites:** Python 3.10+ and [uv](https://docs.astral.sh/uv/) **0.9.0 or newer**. pip-audit is installed automatically, into its own isolated environment.

---

## Why depfresh?

- **Tired of Dependabot/Renovate noise?** Get one deliberate upgrade pass with full context instead of 30 individual PRs
- **Need CVE auditing baked in?** Vulnerability scanning happens automatically, not as an afterthought
- **Want CI-ready reports?** Get dated markdown with tables, diffs, and checklists you can paste straight into a PR
- **Running multiple Python services?** Point depfresh at each one — locally, in CI, or on a cron schedule

## How it works

```
  dependency file (auto-detected: uv.lock project, Dockerfile hints, known files)
         │
         ▼
   the set that ships ──── uv.lock:      uv export --frozen --no-emit-project --no-hashes
         │            └─── otherwise:    uv pip compile --python-platform <deploy target>
         ▼
   audit (pip-audit --no-deps --disable-pip -s osv, advisories deduplicated)
         │
   plan: lowest release fixing every advisory (OSV ranges + PyPI releases)
         │
   apply ─── uv.lock:    uv lock --upgrade-package <pkg>==<fix>
         │└── otherwise:  edit only the affected lines, then resolve again
         ▼
   re-audit ──▶ uv lock --check / fresh resolution ──▶ import check (before vs after)
         │
   write back (only if every check passed) ──▶ reports ──▶ cleanup
```

If resolution fails, an audit returns invalid output, or imports regress, depfresh writes nothing. It fails closed — never generates a misleading clean result.

## Features

| | |
|---|---|
| **Audits what ships** | The locked set of uv projects, or a resolution for the deploy platform (default `x86_64-unknown-linux-gnu`) |
| **Minimal fixes** | Only vulnerable packages move, each to the lowest release that fixes all of its advisories |
| **Lock-aware** | Fixes `uv.lock` with `uv lock --upgrade-package`; `pyproject.toml` floors stay unless they block a fix |
| **Format-preserving** | Edits only the affected requirement lines; comments, markers, floors and order stay |
| **Safe majors** | A fix that crosses a major version needs `--allow-major <pkg>`, and is flagged in the report |
| **Import gate** | Imports that resolved before the upgrade and fail after it block the write-back (exit 3) |
| **Private indexes** | Honours `[tool.uv.sources]`/`[[tool.uv.index]]`; never looks a private package up on PyPI |
| **No repository code runs** | `setup.py` is read with `ast`, never executed |
| **Remaining vuln diagnostics** | Explains *why* each unfixed advisory could not be fixed |
| **Zero footprint** | Everything happens in a temporary work directory, removed even on failure |

## Usage

```bash
# Audit what ships and fix the vulnerable packages — auto-detects the format
depfresh /path/to/project

# Audit only: show the findings and the fix plan, change nothing (exit 2 if vulnerable)
depfresh /path/to/project --audit-only

# Preview the fix (runs every check, writes nothing)
depfresh /path/to/project --dry-run

# Let named packages cross a major version to reach their fix
depfresh /path/to/project --allow-major cryptography pillow

# The deploy target: Python version, platform, and the extras the image installs
depfresh /path/to/project --python 3.12 --platform x86_64-unknown-linux-gnu --extra full --extra gcs

# Never move some packages
depfresh /path/to/project --keep-version crewai litellm

# Upgrade every package within its current major instead (the 0.1 behaviour)
depfresh /path/to/project --strategy latest
```

<details>
<summary><strong>All CLI options</strong></summary>

| Option | Default | Description |
|--------|---------|-------------|
| `target_dir` | *(required)* | Directory containing the dependency file |
| `--label` | auto-derived | Report subfolder name |
| `--dep-file` | auto-detect | Dependency file name (see [Supported formats](#supported-formats)) |
| `--format` | auto-detect | Force format: `requirements-simple`, `requirements-hashed`, `requirements-in`, `pyproject-pep621`, `pyproject-poetry`, `pipfile`, `setup-py` |
| `--strategy` | `minimal` | `minimal`: move only vulnerable packages to their lowest fix. `latest`: upgrade every package within its bounds (resolved on this machine) |
| `--python` | `3.11` | Deploy Python version to resolve and audit for |
| `--platform` | `x86_64-unknown-linux-gnu` | Deploy platform (`uv pip compile --python-platform` names) |
| `--extra NAME` | Dockerfile's extras | Optional-dependency group that ships (repeatable, comma-separated) |
| `--all-extras` | off | Every optional-dependency group ships |
| `--group NAME` | all but `dev` | uv projects: dependency group that ships (repeatable) |
| `--all-groups` | off | uv projects: every dependency group ships |
| `--dependency-scope` | `runtime` | `all` = `--all-extras --all-groups` |
| `--allow-major [PKG ...]` | off | Let fixes cross a major version (all packages, or the named ones) |
| `--keep-version PKG [...]` | off | Packages that must not move |
| `--ignore-direct-references` | off | Skip git/path/url deps instead of failing |
| `--audit-only` | off | Audit and plan, change nothing |
| `--dry-run` | off | Run every step and check, write nothing |
| `--skip-import-check` | off | Do not install the before/after sets to compare imports |
| `--repo-advisories` | off | Also check GitHub repository advisories (needs an authenticated `gh`) |
| `--uv PATH` | auto | uv binary (also `DEPFRESH_UV`); must be at least 0.9.0 |
| `--reports-dir` | `./reports/` | Report output directory |
| `-v, --verbose` | off | Debug output |

**Exit codes:** `0` = clean, `1` = error (nothing written), `2` = vulnerabilities remain, `3` = imports regressed (nothing written).

</details>

## Lock-aware and minimal modes

depfresh 0.1 upgraded everything to the latest release it could find on the machine it ran on and wrote that back. That missed what ships (a `uv.lock` was never audited), churned dozens of unrelated packages, could downgrade (a `>=2.10.0` floor read as "2.10.0"), and dropped Linux-only packages, comments and markers. The default `minimal` strategy fixes that.

### uv projects: lock-aware mode

When `uv.lock` sits next to `pyproject.toml`, the lock is what `uv sync --frozen` installs, so it is what depfresh audits and fixes:

1. `uv export --frozen --no-emit-project --no-hashes` with the chosen groups and extras (default `--no-dev`), with markers evaluated for `--platform`/`--python`.
2. Audit, then plan the lowest fixing release per vulnerable package.
3. `uv lock --upgrade-package <pkg>==<fix>` (all at once; one at a time if that fails), re-export, re-audit. A co-upgrade that is itself vulnerable gets a follow-up round.
4. `uv lock --check`, and an import check between the installed baseline and remediated locks.

The write-back is the updated `uv.lock`. `pyproject.toml` is edited only when a direct dependency's own constraint excludes the fix (for example `cryptography>=41,<47` when the fix is 50.0.0, with `--allow-major cryptography`). uv may rewrite the lock header to its current revision; the report says so.

### Everything else: resolved for the deploy platform

Requirements files (simple, hashed, `.in`), `pyproject.toml` without a lock and a static `setup.py` ship whatever a fresh resolution picks when the image is built. depfresh resolves exactly that, for the deploy target, with `uv pip compile --python-platform x86_64-unknown-linux-gnu --python-version X.Y`, then:

- edits **only the affected lines**: a pin moves (`==`), a floor is raised (`>=`), a cap that blocks the fix is lifted to the next major only when `--allow-major` allows it. Comments, markers, extras, name spelling, ordering and line endings stay; `--hash` lines are regenerated;
- adds a commented floor for a vulnerable transitive package the file does not list: `urllib3>=2.8.0  # depfresh: GHSA-8988-9cw3-xx77`;
- when another pin blocks a fix (`fastapi==0.129.0` caps Starlette below 1.0), finds the **lowest** co-upgrade that resolves (every current version is kept as a preference) and pins it;
- resolves the edited file again, fresh, as the build would, and audits that.

A floor is never read as the version that ships: `google-cloud-storage>=2.10.0` stays at the 3.17.1 the build installs.

### Minimal upgrades

For each vulnerable package depfresh reads the full OSV records of its advisories (pip-audit keeps only the last affected range, so it reports fastmcp 3.4.2 → 4.1.2 although 3.4.10 fixes it) and walks its PyPI releases upwards, skipping yanked, pre-release and `Requires-Python`-incompatible ones. The target is the lowest release no advisory affects:

- in the current major when one exists; calendar versions (certifi, tzdata) never count as a major;
- otherwise the package needs `--allow-major <pkg>`; without it the advisory stays open and the report says "Requires major upgrade (46→50). Use --allow-major cryptography";
- co-upgrades that cross a major are refused unless `--allow-major` covers them.

Advisories are counted once: OSV's GHSA and PYSEC records of the same issue are merged by alias.

### Private indexes and repository code

- uv runs on the project itself, from the target directory, so `[[tool.uv.index]]`, `[tool.uv.sources]` and `uv.toml` apply. Packages from a non-PyPI index are reported as not audited and are never looked up on PyPI. An unreachable private index fails the run; there is no fallback to PyPI.
- A requirements file that lists a package `pyproject.toml` pins to a private index is refused: uv cannot pin it there from a requirements file and would ask PyPI (dependency confusion). `--strategy latest` refuses private sources for the same reason.
- `setup.py` is never executed (or handed to uv, which would run it): a literal `install_requires`/`extras_require` is read with `ast` and audited, anything else is refused, and the file is never edited. Projects with `dynamic` dependencies, local paths and archives in requirements files are refused too (`--ignore-direct-references` skips paths and URLs).

### Repository advisories (opt-in)

Maintainers can publish an advisory in their own GitHub repository days before it reaches the GitHub Advisory Database, OSV and pip-audit. `--repo-advisories` maps every shipped package to its repository (from its PyPI project URLs), reads the published advisories with `gh api`, and treats the ones that affect the shipped version like any other finding.

## Supported formats

| Format | File | Ecosystem | Minimal strategy |
|--------|------|-----------|------------------|
| uv project | `pyproject.toml` + `uv.lock` | uv | lock-aware: fixes `uv.lock` |
| PEP 621 | `pyproject.toml` | uv, pip, pdm, hatch, flit | resolved for the deploy platform |
| Simple requirements | `requirements.txt` | pip, uv | resolved for the deploy platform |
| Hashed requirements | `requirements.txt` | pip-compile, uv pip compile | resolved; hashes regenerated |
| Requirements input | `requirements.in` | pip-tools, uv pip compile | resolved for the deploy platform |
| `setup.py` (static) | `setup.py` | setuptools | audit and plan only, never executed or edited |
| Poetry | `pyproject.toml` | poetry | `--strategy latest` only |
| Pipfile | `Pipfile` | pipenv | `--strategy latest` only |

Auto-detection picks what ships: `pyproject.toml` when a `uv.lock` sits next to it; otherwise what a local `Dockerfile` installs (`pip install -r <file>`, `pip install -e ".[extras]"` — with those extras — or `uv sync`); otherwise the first of `requirements.txt`, `requirements.in`, `pyproject.toml`, `Pipfile`. UTF-16 requirements files are read and written back in their encoding.

## Understanding remaining vulnerabilities

When CVEs remain after upgrade, depfresh diagnoses each one:

| Reason | What to do |
|--------|------------|
| **Requires major upgrade** | Re-run with `--allow-major <package>` |
| **Pinned via --keep-version** | Remove from `--keep-version` if the fix is needed |
| **uv could not lock / no resolution fixes it** | Read uv's explanation in the report; usually another pin or cap blocks it |
| **Requires a major co-upgrade** | Re-run with `--allow-major` for both packages named in the report |
| **From a private index** | Not audited publicly; check it with the index owner |
| **No fix available** | Monitor upstream for a patched release |

## Python API

```python
from depfresh import upgrade, audit_only

# Fix what is vulnerable in what ships (minimal strategy)
result = upgrade(
    "/path/to/project",
    python="3.12",
    allow_major=["cryptography"],
    keep_version=["crewai"],
)

print(f"Mode: {result.mode}; files: {result.files_changed}; lock check: {result.lock_check}")
print(f"Vulns: {len(result.pre_audit_vulns)} → {len(result.post_audit_vulns)}")
for fix in result.fixes:
    print(f"  {fix.package} {fix.current} -> {fix.final or fix.target} [{fix.status}] {fix.reason}")

# Audit only — no modifications; result.fixes holds the plan
result = audit_only("/path/to/project", python="3.12")
```

<details>
<summary><strong>API reference</strong></summary>

### `upgrade(target, **kwargs) -> UpgradeResult`

Audit what ships and fix it: lock-aware for uv projects, resolved for the deploy platform otherwise.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `target` | *(required)* | Directory containing dependency file |
| `label` | `None` | Report subfolder name |
| `dep_file` | `None` | Dependency filename |
| `fmt` | `None` | Force format string |
| `strategy` | `"minimal"` | `"minimal"` or `"latest"` |
| `python` | `"3.11"` | Deploy Python version |
| `platform` | `"x86_64-unknown-linux-gnu"` | Deploy platform |
| `extras`, `all_extras` | `None`, `False` | Optional-dependency groups that ship |
| `groups`, `all_groups` | `None`, `False` | Dependency groups that ship (uv projects) |
| `dependency_scope` | `"runtime"` | `"runtime"` or `"all"` |
| `ignore_direct_references` | `False` | Skip git/path/url deps |
| `dry_run` | `False` | Preview without writing |
| `allow_major` | `None` | `None` (in-major fixes), `[]` (all), or `["pkg"]` |
| `keep_version` | `None` | Packages that must not move |
| `import_check` | `True` | Compare imports before and after |
| `repo_advisories` | `False` | Also check GitHub repository advisories |
| `uv_binary` | `None` | uv binary (default: `DEPFRESH_UV`, depfresh's environment, `PATH`) |
| `reports_dir` | `./reports/` | Report output directory |

### `audit_only(target, **kwargs) -> UpgradeResult`

Audit what ships and plan the fixes (`result.fixes`). Nothing is modified.

### `UpgradeResult`

| Field | Type | Description |
|-------|------|-------------|
| `mode` | `str` | `"lock"`, `"requirements"`, `"pyproject"` or `"legacy"` (`--strategy latest`) |
| `fixes` | `list[PlannedFix]` | Each vulnerable package: from, target, status, reason |
| `upgraded` | `list[PackageChange]` | Packages that changed version in the shipped set |
| `new_deps` | `list[PackageChange]` | New transitive dependencies |
| `lock_changes` | `list[PackageChange]` | Every version change in `uv.lock` |
| `files_changed`, `manifest_diff` | `list[str]`, `str` | What was (or would be) written |
| `pre_audit_vulns` | `list[Vulnerability]` | Advisories before the upgrade (deduplicated) |
| `post_audit_vulns` | `list[Vulnerability]` | Advisories remaining after it |
| `remaining_reasons` | `list[str]` | Why each remaining advisory wasn't fixed |
| `lock_check`, `resolution_check` | `str` | `uv lock --check` / fresh-resolution outcome |
| `import_check`, `import_check_baseline`, `import_regressions` | | Import verification after, before, and the difference |
| `not_audited` | `list[str]` | Private-index packages and direct references |
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
```bash
depfresh /app --audit-only --python 3.12 || send-alert "depfresh found vulnerabilities"
```

```python
from depfresh import audit_only

result = audit_only("/app", python="3.12")
if result.pre_audit_vulns:
    send_alert(f"{len(result.pre_audit_vulns)} advisories in what ships")
```

## Current limitations

- Advisories come from OSV (the GitHub Advisory Database and PyPA). Repository advisories that are not in the database yet are only seen with `--repo-advisories`.
- What the base image itself installs (for example the `setuptools` that `python:3.11` images ship outside your venv) is not part of the manifest and is not modelled.
- The import check installs the before and after sets on the machine running depfresh, so platform-specific packages may differ from the deploy target; it checks that imports resolve, not runtime behaviour. Always run your test suite.
- In lock-aware mode uv chooses the version of a required co-upgrade (the newest compatible one); in resolved mode depfresh pins the lowest that resolves.
- Poetry and Pipfile projects are supported only by `--strategy latest`, which resolves on the machine running depfresh.
- Operates on a single dependency file per run; `-r`/`-c` includes are followed only inside the target directory, and workspace path dependencies only inside the project.

<details>
<summary><strong>Known edge cases</strong></summary>

- **PEP 440 epochs** (`1!2.0`): treated by the major-version logic as any other version
- **Hybrid pyproject.toml** (PEP 621 + Poetry): PEP 621 is detected first; use `--format pyproject-poetry` to force Poetry handling
- **Hash-checking requirement files**: a vulnerable transitive package is added as a hashed `==` pin, because pip's hash-checking mode accepts nothing else

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
