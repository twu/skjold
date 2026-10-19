import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, List, MutableMapping, Optional, Sequence, Tuple

import click
from packaging import specifiers
from packaging.utils import NormalizedName, canonicalize_name
from packaging.version import Version

from skjold.core import (
    Dependency,
    SecurityAdvisory,
    SecurityAdvisoryList,
    SecurityAdvisorySource,
)
from skjold.tasks import register_source

_GITHUB_REPO_RE = re.compile(
    r"https?://(?:www\.)?github\.com/([A-Za-z0-9-]+)/([\w.-]+)"
)
_NEXT_LINK_RE = re.compile(r'<([^>]+)>;\s*rel="next"')


def _get_json_and_next(
    url: str, headers: Optional[dict] = None
) -> Tuple[Any, Optional[str]]:
    """Return parsed JSON and the 'next' url from the Link header, or (None, None) on 404."""
    request_ = urllib.request.Request(
        url=url, headers={"Accept": "application/json", **(headers or {})}
    )
    try:
        with urllib.request.urlopen(request_) as response:
            match = _NEXT_LINK_RE.search(response.headers.get("Link") or "")
            return json.loads(response.read()), match and match.group(1)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None, None
        raise


def _get_json(url: str, headers: Optional[dict] = None) -> Any:
    return _get_json_and_next(url, headers)[0]


def find_github_repo(package_name: str, version: str) -> Optional[str]:
    """Return 'owner/repo' from a package's PyPI project urls, if any."""
    data = _get_json(f"https://pypi.org/pypi/{package_name}/{version}/json")
    if not data:
        return None

    info = data["info"]
    urls = list((info.get("project_urls") or {}).values()) + [info.get("home_page")]
    for url in urls:
        match = _GITHUB_REPO_RE.match(url or "")
        # First github link wins; prioritize by url label if this picks the wrong repo.
        if match and match.group(1) != "sponsors":
            repo = re.sub(r"\.git$", "", match.group(2))
            # Metadata is untrusted; '.' or '..' would walk to other api.github.com paths.
            if repo.strip("."):
                return f"{match.group(1)}/{repo}"
    return None


def _fetch_repo_advisories(repo: str) -> List[dict]:
    try:
        _api_token = os.environ["SKJOLD_GITHUB_API_TOKEN"]
    except KeyError:
        raise click.UsageError(
            "It looks like you're trying to use the github-repo source without providing an access token. "
            "You can generate a token at https://github.com/settings/tokens without giving it any permissions "
            "and make it available to skjold by setting SKJOLD_GITHUB_API_TOKEN in your environment."
        )
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {_api_token}",
    }

    # Drafts and triage advisories are visible to tokens with access to the repo; never report them.
    advisories: List[dict] = []
    url: Optional[str] = (
        f"https://api.github.com/repos/{repo}/security-advisories?state=published&per_page=100"
    )
    while url:
        data, url = _get_json_and_next(url, headers)
        advisories.extend(data or [])
    return advisories


def _parse_range_part(part: str) -> List[str]:
    if " - " in part:
        low, high = part.split(" - ", 1)
        return [f">={low.strip()}", f"<={high.strip()}"]
    if part[:1].isdigit():
        return [f"=={part}"]
    if part.startswith("=") and not part.startswith("=="):
        return [f"=={part[1:].strip()}"]
    return [part.replace(" ", "")]


def parse_version_range(value: str, patched: str = "") -> List[specifiers.SpecifierSet]:
    """Convert free-form ranges like '1.0 - 2.0', '≤ 2.0' or '1.5' into SpecifierSets (any of them matches)."""
    value = value.replace("≤", "<=").replace("≥", ">=")
    parts = [part.strip() for part in value.split(",")]
    # '1.4.1, 1.4.2' or '1.0 - 1.2, 1.4 - 1.6' list alternatives, while '>= 1.0, < 2.0' is one range.
    if all(" - " in part or part[:1].isdigit() for part in parts):
        groups = [_parse_range_part(part) for part in parts]
    else:
        groups = [[spec for part in parts for spec in _parse_range_part(part)]]

    # Some maintainers give only a lower bound and put the fix in patched_versions.
    # Max of several patched versions (backports) so we over-report rather than miss.
    patched_versions = re.findall(r"\d+(?:\.\d+)*", patched)
    results = []
    for group in groups:
        result = specifiers.SpecifierSet(",".join(group), prereleases=True)
        has_upper = any(s.operator in ("<", "<=", "==", "===", "~=") for s in result)
        if patched_versions and not has_upper:
            result &= f"<{max(patched_versions, key=Version)}"
        results.append(result)
    return results


class GithubRepoSecurityAdvisory(SecurityAdvisory):
    _json: dict
    _package_name: str
    _range: str
    _patched: str

    @classmethod
    def using(
        cls, json_: dict, package_name: str, vulnerable_range: str, patched: str = ""
    ) -> "GithubRepoSecurityAdvisory":
        obj = cls()
        obj._json = json_
        obj._package_name = package_name
        obj._range = vulnerable_range
        obj._patched = patched
        return obj

    @property
    def identifier(self) -> str:
        return str(self._json["ghsa_id"])

    @property
    def source(self) -> str:
        return "github-repo"

    @property
    def package_name(self) -> str:
        return self._package_name

    @property
    def canonical_name(self) -> NormalizedName:
        return canonicalize_name(self.package_name)

    @property
    def url(self) -> str:
        return str(self._json["html_url"])

    @property
    def references(self) -> List[str]:
        return []

    @property
    def summary(self) -> str:
        return str(self._json["summary"])

    @property
    def severity(self) -> str:
        return str(self._json.get("severity") or "unknown").upper()

    @property
    def vulnerable_versions(self) -> str:
        try:
            return "||".join(
                str(x) for x in parse_version_range(self._range, self._patched)
            )
        except specifiers.InvalidSpecifier:
            return self._range

    def is_affected(self, version: str) -> bool:
        # Ranges are typed by maintainers; when unparseable, report rather than silently skip.
        try:
            ranges = parse_version_range(self._range, self._patched)
        except specifiers.InvalidSpecifier:
            return True
        return any(Version(version) in x for x in ranges)


class GithubRepo(SecurityAdvisorySource):
    _name = "github-repo"

    @property
    def name(self) -> str:
        return self._name

    @property
    def path(self) -> Optional[str]:
        return None

    def populate_from_cache(self) -> None:
        pass

    @property
    def total_count(self) -> int:
        return 0

    def update(self) -> None:
        pass

    def has_security_advisory_for(self, dependency: Dependency) -> bool:
        return True

    def is_vulnerable_package(
        self, dependency: Dependency
    ) -> Tuple[bool, Sequence[SecurityAdvisory]]:
        repo = find_github_repo(dependency.canonical_name, dependency.version)
        if not repo:
            if self._verbose:
                click.secho(
                    f"github-repo: no GitHub repo found for {dependency.name}=={dependency.version}, skipping",
                    err=True,
                    fg="yellow",
                )
            return False, []

        advisories = []
        for item in _fetch_repo_advisories(repo):
            if item.get("state") != "published" or item.get("withdrawn_at"):
                continue
            for vuln in item.get("vulnerabilities") or []:
                package = vuln.get("package") or {}
                if package.get("ecosystem") and package["ecosystem"] != "pip":
                    continue
                if (
                    package.get("name")
                    and canonicalize_name(package["name"]) != dependency.canonical_name
                ):
                    continue
                vulnerable_range = vuln.get("vulnerable_version_range") or ""
                patched = vuln.get("patched_versions") or ""
                if self._verbose:
                    try:
                        ranges = parse_version_range(vulnerable_range, patched)
                        if any(len(x) == 0 for x in ranges):
                            click.secho(
                                f"github-repo: {item['ghsa_id']} has no version range, "
                                f"reporting all versions of {dependency.name} as affected",
                                err=True,
                                fg="yellow",
                            )
                    except specifiers.InvalidSpecifier:
                        click.secho(
                            f"github-repo: {item['ghsa_id']} has unparseable range '{vulnerable_range}', "
                            f"reporting all versions of {dependency.name} as affected",
                            err=True,
                            fg="yellow",
                        )
                advisory = GithubRepoSecurityAdvisory.using(
                    item, dependency.name, vulnerable_range, patched
                )
                if advisory.is_affected(dependency.version):
                    advisories.append(advisory)

        return len(advisories) > 0, advisories

    def get_security_advisories(
        self,
    ) -> MutableMapping[NormalizedName, SecurityAdvisoryList]:
        raise NotImplementedError


register_source("github-repo", GithubRepo)
