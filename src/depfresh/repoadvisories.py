"""Opt-in check of GitHub *repository* security advisories (``--repo-advisories``).

A maintainer can publish an advisory in their own repository days before it
reaches the global GitHub Advisory Database (and OSV, and pip-audit).
With ``--repo-advisories`` depfresh maps every shipped PyPI
package to its GitHub repository (from the PyPI project URLs), reads that
repository's published advisories with ``gh api``, and adds the ones that
affect the shipped version and are not already in the audit.

It needs the GitHub CLI (``gh``) with access to api.github.com.  A failure
to read the advisories fails the run: an audit the user asked for is never
silently skipped.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Protocol

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from depfresh.advisories import AdvisoryLookupError
from depfresh.constraints import normalise
from depfresh.exceptions import DepfreshError
from depfresh.models import Vulnerability

log = logging.getLogger("depfresh")

_GITHUB = re.compile(r"github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", re.IGNORECASE)
_NOT_REPOS = {"sponsors", "orgs", "users", "apps", "marketplace", "features"}


class RepoAdvisoryError(DepfreshError):
    """Raised when repository advisories were requested but cannot be read."""


class ProjectUrls(Protocol):
    def project_urls(self, package: str) -> list[str]:
        """URLs a package declares on PyPI."""
        ...


def github_repo(urls: list[str]) -> tuple[str, str] | None:
    """The first ``github.com/<owner>/<repo>`` among *urls*."""
    for url in urls:
        match = _GITHUB.search(url)
        if match and match.group(1).lower() not in _NOT_REPOS:
            repo = match.group(2)
            repo = repo[:-4] if repo.endswith(".git") else repo
            return match.group(1), repo
    return None


def range_contains(vulnerable_range: str, version: str) -> bool:
    """Evaluate a GitHub ``vulnerable_version_range`` (``">= 0.3.3, < 0.6.5"``)."""
    clauses = []
    for clause in vulnerable_range.split(","):
        clause = clause.strip()
        if not clause:
            continue
        clause = re.sub(r"^=\s*(?=[0-9])", "==", clause)
        clauses.append(re.sub(r"\s+", "", clause))
    if not clauses:
        return False
    try:
        return SpecifierSet(",".join(clauses)).contains(Version(version), prereleases=True)
    except (InvalidSpecifier, InvalidVersion):
        log.debug("Unparseable range %r; treating %s as affected", vulnerable_range, version)
        return True


def gh_advisories(owner: str, repo: str) -> list[dict[str, Any]]:
    """Published advisories of one repository, via ``gh api`` (``[]`` if the repo is gone).

    Raises:
        RepoAdvisoryError: If ``gh`` is missing or the API call fails.
    """
    gh = shutil.which("gh")
    if gh is None:
        raise RepoAdvisoryError(
            "--repo-advisories needs the GitHub CLI (gh), authenticated for api.github.com"
        )
    cmd = [gh, "api", "--paginate", "-H", "Accept: application/vnd.github+json",
           f"repos/{owner}/{repo}/security-advisories?state=published&per_page=100"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        if "HTTP 404" in result.stderr or "Not Found" in result.stderr:
            return []
        raise RepoAdvisoryError(
            f"gh api repos/{owner}/{repo}/security-advisories failed: "
            f"{result.stderr.strip()[:300]}"
        )
    return _concatenated_arrays(result.stdout, f"{owner}/{repo}")


def _concatenated_arrays(text: str, source: str) -> list[dict[str, Any]]:
    """Parse ``gh api --paginate`` output: one JSON array per page, back to back."""
    decoder = json.JSONDecoder()
    items: list[dict[str, Any]] = []
    index = 0
    while True:
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            return items
        try:
            page, index = decoder.raw_decode(text, index)
        except json.JSONDecodeError as exc:
            raise RepoAdvisoryError(f"gh api returned invalid JSON for {source}") from exc
        if isinstance(page, list):
            items.extend(a for a in page if isinstance(a, dict))


@dataclass
class RepoAdvisoryChecker:
    """Adds repository advisories missing from the Advisory DB to an audit."""

    urls: ProjectUrls
    fetch: Callable[[str, str], list[dict[str, Any]]] = gh_advisories
    repos_checked: set[tuple[str, str]] = field(default_factory=set)
    unmapped: set[str] = field(default_factory=set)
    _cache: dict[tuple[str, str], list[dict[str, Any]]] = field(default_factory=dict)

    def findings(
        self, pins: Mapping[str, str], known: list[Vulnerability],
    ) -> list[Vulnerability]:
        """Repository advisories affecting *pins* that *known* does not already hold."""
        known_ids = {(normalise(v.package), i) for v in known for i in v.ids}

        def repo_of(name: str) -> tuple[str, tuple[str, str] | None]:
            try:
                return name, github_repo(self.urls.project_urls(name))
            except AdvisoryLookupError:
                return name, None

        with ThreadPoolExecutor(max_workers=8) as pool:
            mapping = dict(pool.map(repo_of, sorted(pins)))
        by_repo: dict[tuple[str, str], list[str]] = {}
        for name, repo in mapping.items():
            if repo is None:
                self.unmapped.add(name)
            else:
                by_repo.setdefault(repo, []).append(name)

        def advisories(repo: tuple[str, str]) -> tuple[tuple[str, str], list[dict[str, Any]]]:
            if repo not in self._cache:
                self._cache[repo] = self.fetch(*repo)
            return repo, self._cache[repo]

        found: list[Vulnerability] = []
        with ThreadPoolExecutor(max_workers=8) as pool:
            for repo, items in pool.map(advisories, sorted(by_repo)):
                self.repos_checked.add(repo)
                for advisory in items:
                    found += self._affecting(advisory, by_repo[repo], pins, known_ids)
        return found

    @staticmethod
    def _affecting(
        advisory: dict[str, Any],
        names: list[str],
        pins: Mapping[str, str],
        known_ids: set[tuple[str, str]],
    ) -> list[Vulnerability]:
        ghsa = str(advisory.get("ghsa_id") or "")
        cve = str(advisory.get("cve_id") or "")
        if not ghsa or advisory.get("withdrawn_at"):
            return []
        out: list[Vulnerability] = []
        for vuln in advisory.get("vulnerabilities") or []:
            package = vuln.get("package") or {}
            if str(package.get("ecosystem", "")).lower() not in ("pip", "pypi"):
                continue
            name = normalise(str(package.get("name", "")))
            if name not in names or (name, ghsa) in known_ids or (name, cve) in known_ids:
                continue
            if not range_contains(str(vuln.get("vulnerable_version_range") or ""), pins[name]):
                continue
            severity = str(advisory.get("severity") or "unknown").upper()
            summary = str(advisory.get("summary") or "")
            out.append(Vulnerability(
                package=name,
                version=pins[name],
                cve=cve or ghsa,
                fix_versions=str(vuln.get("patched_versions") or "").replace(">=", "").strip(),
                description=f"[repository advisory, {severity}] {summary}"[:123],
                aliases=(ghsa,) if cve else (),
            ))
        return out
