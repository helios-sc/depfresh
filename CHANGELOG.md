# Changelog

All notable changes to depfresh will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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
