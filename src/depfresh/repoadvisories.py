"""Opt-in check of GitHub *repository* security advisories (``--repo-advisories``).

A maintainer can publish an advisory in their own repository days before it
reaches the global GitHub Advisory Database (and OSV, and pip-audit).
With ``--repo-advisories`` depfresh maps every shipped PyPI
package to its GitHub repository (from the PyPI project URLs), reads that
repository's published advisories with ``gh api``, and adds the ones that

* affect the shipped version, read as :func:`parse_range` describes, and
* are not in the global database yet: ``gh api advisories/<ghsa>`` answers
  404.  An advisory the database has is already judged by OSV, whose ranges
  are curated; the repository copy's looser ranges would only add false
  findings that block real fixes.

A range depfresh cannot read is reported for checking by hand, never treated
as affecting every version.  The remediation loops fix the database findings
first and the repository findings afterwards, keeping the second step only
when it leaves no more database findings than the first.

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

from packaging.specifiers import InvalidSpecifier, Specifier, SpecifierSet
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


_COMPARATOR = re.compile(r"^(===|==|!=|<=|>=|<|>|=)\s*(\S.*)$")


def lowest_patched(patched_versions: str) -> Version | None:
    """The lowest version in a GitHub ``patched_versions`` (``"0.6.5"``, ``">= 38.0.3"``)."""
    found: list[Version] = []
    for clause in patched_versions.split(","):
        text = re.sub(r"^(>=|==|=)\s*", "", clause.strip())
        try:
            found.append(Version(text))
        except InvalidVersion:
            continue
    return min(found) if found else None


def parse_range(vulnerable_range: str, patched_versions: str = "") -> tuple[str, ...] | None:
    """A GitHub ``vulnerable_version_range`` as PEP 440 specifier sets (any one matches).

    * bare versions, alone or in a comma list (``"1.6.5, 1.6.6"``): each one
      exactly;
    * comparators (``">= 2.0, < 2.14.2"``, ``"= 3.3.1"``): all of them, as
      written;
    * comparators with no upper bound (``">= 37.0.0"``) end at the lowest
      *patched_versions* when there is one.

    Returns:
        The specifier sets, or ``None`` when the range cannot be read (empty,
        a mix of the two forms, or anything PEP 440 rejects).
    """
    clauses = [c.strip() for c in vulnerable_range.split(",") if c.strip()]
    if not clauses:
        return None
    matches = [_COMPARATOR.match(c) for c in clauses]
    try:
        if not any(matches):
            return tuple(f"=={Version(c)}" for c in clauses)
        if not all(matches):
            return None
        specs = [
            Specifier(f"{'==' if m.group(1) == '=' else m.group(1)}{m.group(2).strip()}")
            for m in matches if m is not None
        ]
    except (InvalidSpecifier, InvalidVersion):
        return None
    parts = [str(spec) for spec in specs]
    if not any(spec.operator in ("<", "<=", "==", "===") for spec in specs):
        fix = lowest_patched(patched_versions)
        if fix is not None:
            parts.append(f"<{fix}")
    return (",".join(parts),)


def affects(specifier_sets: tuple[str, ...], version: str) -> bool:
    """True when *version* matches any of *specifier_sets*."""
    try:
        parsed = Version(version)
    except InvalidVersion:
        return False
    return any(SpecifierSet(s).contains(parsed, prereleases=True) for s in specifier_sets)


def gh_in_database(ghsa: str) -> bool:
    """True when the global GitHub Advisory Database has *ghsa* (``gh api advisories/…``).

    Raises:
        RepoAdvisoryError: If ``gh`` is missing or the API answers anything but 200 or 404.
    """
    gh = shutil.which("gh")
    if gh is None:
        raise RepoAdvisoryError(
            "--repo-advisories needs the GitHub CLI (gh), authenticated for api.github.com"
        )
    cmd = [gh, "api", "-H", "Accept: application/vnd.github+json", f"advisories/{ghsa}"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode == 0:
        return True
    if "HTTP 404" in result.stderr or "Not Found" in result.stderr:
        return False
    raise RepoAdvisoryError(f"gh api advisories/{ghsa} failed: {result.stderr.strip()[:300]}")


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
    """Adds repository advisories missing from the Advisory DB to an audit.

    Attributes:
        repos_checked: Repositories whose advisories were read.
        unmapped: Packages that declare no GitHub repository.
        in_database: GHSA ids skipped because the global database has them.
        unreadable: ``{ghsa: "package: range"}`` for repository-only
            advisories whose range could not be read (check them by hand).
    """

    urls: ProjectUrls
    fetch: Callable[[str, str], list[dict[str, Any]]] = gh_advisories
    known_to_database: Callable[[str], bool] = gh_in_database
    repos_checked: set[tuple[str, str]] = field(default_factory=set)
    unmapped: set[str] = field(default_factory=set)
    in_database: set[str] = field(default_factory=set)
    unreadable: dict[str, str] = field(default_factory=dict)
    _cache: dict[tuple[str, str], list[dict[str, Any]]] = field(default_factory=dict)
    _database: dict[str, bool] = field(default_factory=dict)

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

        candidates: list[Vulnerability] = []
        unreadable: dict[str, str] = {}
        with ThreadPoolExecutor(max_workers=8) as pool:
            for repo, items in pool.map(advisories, sorted(by_repo)):
                self.repos_checked.add(repo)
                for advisory in items:
                    candidates += _affecting(advisory, by_repo[repo], pins, known_ids, unreadable)

        seen = {v.ghsa for v in candidates} | set(unreadable)
        ghsas = sorted(seen - set(self._database))
        with ThreadPoolExecutor(max_workers=8) as pool:
            self._database.update(zip(ghsas, pool.map(self.known_to_database, ghsas)))
        self.in_database.update(g for g in seen if self._database[g])
        self.unreadable.update({g: what for g, what in unreadable.items()
                                if not self._database[g]})
        return [v for v in candidates if not self._database[v.ghsa]]


def _affecting(
    advisory: dict[str, Any],
    names: list[str],
    pins: Mapping[str, str],
    known_ids: set[tuple[str, str]],
    unreadable: dict[str, str],
) -> list[Vulnerability]:
    """The findings *advisory* adds for *pins*; unreadable ranges go to *unreadable*."""
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
        vulnerable = str(vuln.get("vulnerable_version_range") or "")
        patched = str(vuln.get("patched_versions") or "")
        specs = parse_range(vulnerable, patched)
        if specs is None:
            unreadable[ghsa] = f"{name}: {vulnerable!r}"
            continue
        if not affects(specs, pins[name]):
            continue
        severity = str(advisory.get("severity") or "unknown").upper()
        summary = str(advisory.get("summary") or "")
        fix = lowest_patched(patched)
        out.append(Vulnerability(
            package=name,
            version=pins[name],
            cve=cve or ghsa,
            fix_versions=str(fix) if fix else "",
            description=f"[repository advisory, {severity}] {summary}"[:123],
            aliases=(ghsa,) if cve else (),
            source="repository",
            affected=specs,
        ))
    return out
