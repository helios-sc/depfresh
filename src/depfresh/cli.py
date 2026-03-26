"""Command-line interface — thin wrapper over the public API."""

from __future__ import annotations

import argparse
import logging
import sys
import textwrap

from depfresh.exceptions import DepfreshError
from depfresh.parsers import _FORMAT_CHOICES
from depfresh.upgrade import upgrade


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
            examples:
              depfresh /path/to/project
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
        help="Python version for the venv (default: 3.11)",
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
        "-v", "--verbose", action="store_true",
        help="Enable debug output",
    )
    args = parser.parse_args(argv)

    _setup_logging(verbose=args.verbose)

    try:
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
        )
    except DepfreshError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    # Print final summary to stdout
    print()
    print(f"depfresh — {result.service_label}")
    print("=" * 60)
    print(f"  Dep file:     {result.requirements_path}")
    print(f"  Packages:     {result.original_count} -> {result.final_count}")
    print(f"  Upgraded:     {len(result.upgraded)}")
    print(f"  New deps:     {len(result.new_deps)}")
    print(f"  Scope:        {result.dependency_scope}")
    print(f"  Vulns before: {len(result.pre_audit_vulns)}")
    print(f"  Vulns after:  {len(result.post_audit_vulns)}")
    if result.direct_references_ignored:
        print(f"  Direct refs:  ignored ({len(result.direct_references_ignored)})")
    if result.log_path:
        print(f"  Log:          {result.log_path}")
    if result.markdown_path:
        print(f"  Report:       {result.markdown_path}")

    if result.post_audit_vulns:
        print(f"\n  WARNING: {len(result.post_audit_vulns)} vulnerabilities remain.")
        sys.exit(2)
    else:
        print("\n  All vulnerabilities resolved!")


if __name__ == "__main__":
    main()
