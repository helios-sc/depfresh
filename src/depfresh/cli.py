"""Command-line interface — thin wrapper over the public API."""

from __future__ import annotations

import argparse
import logging
import sys
import textwrap

from depfresh.advisories import DEFAULT_PLATFORM
from depfresh.exceptions import DepfreshError
from depfresh.models import UpgradeResult
from depfresh.parsers import _FORMAT_CHOICES
from depfresh.upgrade import audit_only, upgrade


def _setup_logging(verbose: bool = False) -> None:
    """Configure the ``depfresh`` logger for CLI output."""
    level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger("depfresh")
    logger.setLevel(level)
    logger.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)


def main(argv: list[str] | None = None) -> None:
    """Entry point for the ``depfresh`` CLI."""
    parser = argparse.ArgumentParser(
        prog="depfresh",
        description=(
            "Upgrade Python dependencies to their latest safe versions "
            "and audit for vulnerabilities."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            exit codes:
              0  no known vulnerabilities remain
              1  error (nothing written)
              2  vulnerabilities remain
              3  imports that resolved before the upgrade fail after it (nothing written)

            examples:
              depfresh /path/to/project
              depfresh /path/to/project --audit-only
              depfresh /path/to/project --extra full --extra gcs
              depfresh /path/to/project --allow-major cryptography --python 3.12
              depfresh /path/to/project --label my_service
              depfresh /path/to/project --python 3.12
              depfresh /path/to/project --dry-run
              depfresh /path/to/project --dependency-scope all
              depfresh /path/to/project --allow-major
              depfresh /path/to/project --allow-major urllib3 cryptography
              depfresh /path/to/project --keep-version crewai litellm
              depfresh /path/to/project --ignore-direct-references
              depfresh /path/to/project --dep-file pyproject.toml
              depfresh /path/to/project --format pyproject-poetry
              depfresh /path/to/project --dep-file Pipfile
        """),
    )
    parser.add_argument(
        "target_dir",
        help="Directory containing the dependency file to upgrade",
    )
    parser.add_argument(
        "--label", default=None,
        help="Report label / subfolder name (default: auto-derived from path)",
    )
    parser.add_argument(
        "--dep-file", default=None, dest="dep_file",
        help=(
            "Dependency file inside target_dir (default: auto-detect). "
            "Searches for requirements.txt, requirements.in, pyproject.toml, Pipfile"
        ),
    )
    parser.add_argument(
        "--format", default=None, dest="fmt",
        choices=_FORMAT_CHOICES,
        help=(
            "Force a specific format instead of auto-detecting. "
            "Choices: %(choices)s"
        ),
    )
    parser.add_argument(
        "--python", default="3.11", dest="python_version",
        help="Deploy Python version to resolve and audit for (default: 3.11)",
    )
    parser.add_argument(
        "--platform", default=DEFAULT_PLATFORM,
        help=(
            "Deploy platform to resolve and audit for, as a uv --python-platform name "
            f"(default: {DEFAULT_PLATFORM})"
        ),
    )
    parser.add_argument(
        "--strategy", choices=("minimal", "latest"), default="minimal",
        help=(
            "'minimal' (default): move only vulnerable packages, each to the lowest "
            "release that fixes all of its advisories. 'latest': upgrade every package "
            "to its newest release within the current major (resolved on this machine)."
        ),
    )
    parser.add_argument(
        "--extra", action="append", default=None, dest="extras", metavar="NAME",
        help=(
            "Optional-dependency group that ships (repeatable or comma-separated). "
            "Default: the extras a local Dockerfile installs, else none."
        ),
    )
    parser.add_argument(
        "--all-extras", action="store_true",
        help="Every optional-dependency group ships",
    )
    parser.add_argument(
        "--group", action="append", default=None, dest="groups", metavar="NAME",
        help=(
            "uv projects: dependency group that ships (repeatable). "
            "Default: every group except dev (uv export --no-dev)."
        ),
    )
    parser.add_argument(
        "--all-groups", action="store_true",
        help="uv projects: every dependency group ships",
    )
    parser.add_argument(
        "--venv", default=".venv-upgrade", dest="venv_name",
        help="Name for the virtual environment directory (default: .venv-upgrade)",
    )
    parser.add_argument(
        "--dependency-scope",
        choices=("runtime", "all"),
        default="runtime",
        help=(
            "Dependency groups to include for grouped formats. "
            "'runtime' upgrades only the main dependency set; "
            "'all' includes optional/dev groups too."
        ),
    )
    parser.add_argument(
        "--ignore-direct-references",
        action="store_true",
        help=(
            "Skip selected git/path/url dependencies instead of failing the run. "
            "By default depfresh aborts when selected dependency groups include them."
        ),
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would change without writing the dependency file",
    )
    parser.add_argument(
        "--audit-only", action="store_true",
        help="Audit what ships and show the fix plan; change nothing",
    )
    parser.add_argument(
        "--skip-import-check", action="store_true",
        help=(
            "Do not install the before/after sets on this machine to compare imports "
            "(faster; the write-back is then not gated on imports)"
        ),
    )
    parser.add_argument(
        "--allow-major", nargs="*", default=None, metavar="PKG",
        help=(
            "Allow major version upgrades. No args = all packages. "
            "With args = only named packages (e.g. --allow-major urllib3 cryptography)"
        ),
    )
    parser.add_argument(
        "--keep-version", nargs="+", default=None, metavar="PKG",
        help="Pin named packages to their current version (e.g. --keep-version crewai litellm)",
    )
    parser.add_argument(
        "--reports-dir", default=None,
        help="Directory for report output (default: ./reports/)",
    )
    parser.add_argument(
        "--uv", default=None, dest="uv_binary", metavar="PATH",
        help=(
            "uv binary to use (default: $DEPFRESH_UV, then a uv in depfresh's own "
            "environment, then PATH; it must be at least the supported minimum)"
        ),
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug output",
    )
    args = parser.parse_args(argv)

    _setup_logging(verbose=args.verbose)

    try:
        if args.audit_only:
            result = audit_only(
                target=args.target_dir,
                dep_file=args.dep_file,
                fmt=args.fmt,
                python=args.python_version,
                dependency_scope=args.dependency_scope,
                ignore_direct_references=args.ignore_direct_references,
                uv_binary=args.uv_binary,
                extras=args.extras,
                all_extras=args.all_extras,
                groups=args.groups,
                all_groups=args.all_groups,
                platform=args.platform,
            )
        else:
            result = upgrade(
                target=args.target_dir,
                label=args.label,
                dep_file=args.dep_file,
                fmt=args.fmt,
                python=args.python_version,
                venv_name=args.venv_name,
                dependency_scope=args.dependency_scope,
                ignore_direct_references=args.ignore_direct_references,
                dry_run=args.dry_run,
                allow_major=args.allow_major,
                keep_version=args.keep_version,
                reports_dir=args.reports_dir,
                uv_binary=args.uv_binary,
                strategy=args.strategy,
                extras=args.extras,
                all_extras=args.all_extras,
                groups=args.groups,
                all_groups=args.all_groups,
                platform=args.platform,
                import_check=not args.skip_import_check,
            )
    except (DepfreshError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.audit_only:
        _print_audit(result)
        return

    # Print final summary to stdout
    print()
    print(f"depfresh — {result.service_label}")
    print("=" * 60)
    print(f"  Dep file:     {result.requirements_path}")
    print(f"  Mode:         {result.mode} ({result.strategy})")
    if result.platform:
        print(f"  Target:       {result.platform}, Python {result.python_version}")
    print(f"  Packages:     {result.original_count} -> {result.final_count}")
    print(f"  Upgraded:     {len(result.upgraded)}")
    print(f"  New deps:     {len(result.new_deps)}")
    print(f"  Scope:        {result.dependency_scope}")
    print(f"  Vulns before: {len(result.pre_audit_vulns)}")
    print(f"  Vulns after:  {len(result.post_audit_vulns)}")
    if result.files_changed:
        state = "written" if result.dep_file_updated else "not written"
        print(f"  Files:        {', '.join(result.files_changed)} ({state})")
    if result.lock_check:
        print(f"  Lock check:   {result.lock_check}")
    if result.resolution_check:
        print(f"  Resolution:   {result.resolution_check}")
    if result.write_back_skipped:
        print(f"  Write-back:   skipped ({result.write_back_skipped})")
    if result.direct_references_ignored:
        print(f"  Direct refs:  ignored ({len(result.direct_references_ignored)})")
    if result.log_path:
        print(f"  Log:          {result.log_path}")
    if result.markdown_path:
        print(f"  Report:       {result.markdown_path}")

    if result.import_regressions:
        print(
            f"\n  ERROR: {len(result.import_regressions)} import(s) resolved before the "
            "upgrade and fail after it:"
        )
        for mod, err in result.import_regressions.items():
            print(f"    {mod}: {err}")
        print("  The dependency file was not written.")
        sys.exit(3)
    if result.post_audit_vulns:
        print(f"\n  WARNING: {len(result.post_audit_vulns)} vulnerabilities remain.")
        sys.exit(2)
    else:
        print("\n  All vulnerabilities resolved!")


def _print_audit(result: UpgradeResult) -> None:
    """Summary of an --audit-only run; exits 2 when vulnerabilities are found."""
    print()
    print(f"depfresh audit — {result.service_label}")
    print("=" * 60)
    print(f"  Dep file:     {result.requirements_path} ({result.mode})")
    if result.platform:
        print(f"  Target:       {result.platform}, Python {result.python_version}")
    print(f"  Packages:     {result.original_count}")
    print(f"  Vulns:        {len(result.pre_audit_vulns)}")
    for fix in result.fixes:
        target = fix.target or "-"
        print(f"    {fix.package} {fix.current} -> {target} [{fix.status}] {fix.reason}")
    for line in result.not_audited:
        print(f"  Not audited:  {line}")
    if result.pre_audit_vulns:
        sys.exit(2)


if __name__ == "__main__":
    main()
