import json
import os
import urllib.request
from collections import defaultdict
from typing import List, Tuple, Optional, Iterator, Dict, Any

from packaging import specifiers
import click

from skjold.models import SecurityAdvisory, SecurityAdvisorySource
from skjold.tasks import register_source


class GithubSecurityAdvisory(SecurityAdvisory):
    _json: Dict

    @classmethod
    def using(cls, json_: dict) -> "GithubSecurityAdvisory":
        obj = cls()
        obj._json = json_
        return obj

    @property
    def identifier(self) -> str:
        return str(self.__advisory["ghsaId"])

    @property
    def source(self) -> str:
        return "github"

    @property
    def references(self) -> List[str]:
        return [reference["url"] for reference in self.__advisory["references"]]

    @property
    def package_name(self) -> str:
        return str(self._json["node"]["package"]["name"])

    @property
    def ecosystem(self) -> str:
        return str(self._json["node"]["package"]["ecosystem"])

    @property
    def severity(self) -> str:
        return str(self._json["node"]["severity"])

    @property
    def __advisory(self) -> Any:
        return self._json["node"]["advisory"]

    @property
    def summary(self) -> str:
        return str(self.__advisory["summary"])

    @property
    def first_patched_version(self) -> str:
        return str(self._json["node"]["firstPatchedVersion"]["identifier"])

    @property
    def vulnerable_version_range(self) -> specifiers.SpecifierSet:
        return specifiers.SpecifierSet(
            self._json["node"]["vulnerableVersionRange"], prereleases=True
        )

    @property
    def vulnerable_versions(self) -> str:
        return str(self.vulnerable_version_range)

    def is_affected(self, version: str) -> bool:
        version = specifiers.parse(version)
        return version in self.vulnerable_version_range

    @property
    def url(self) -> str:
        return f"https://github.com/advisories/{self.identifier}"


def _query_github_graphql(
    first: int = 10, after: Optional[str] = None
) -> Tuple[int, str, bool, dict]:
    _after = after and f'"{after}"' or "null"
    _limit = first and int(first) or 1

    try:
        _api_token = os.environ["SKJOLD_GITHUB_API_TOKEN"]
    except KeyError:
        raise click.UsageError(
            "It looks like you're trying to use the github source without providing an access token."
            "Skjold needs a token to access the Github GraphQL API."
            "You can generate a token at https://github.com/settings/tokens without giving it any permissions "
            "and make it available to skjold by setting SKJOLD_GITHUB_TOKEN in your environment."
        )

    query = f"""
    {{
        securityVulnerabilities(first: {_limit}, after: {_after}, ecosystem: PIP, orderBy: {{ field: UPDATED_AT, direction: DESC }}) {{
            pageInfo {{
                startCursor
                hasNextPage
                endCursor
            }}
            totalCount
            edges {{
                node {{
                    advisory {{
                        ghsaId
                        publishedAt
                        references {{
                            url
                        }}
                        summary
                    }}
                    firstPatchedVersion {{
                        identifier
                    }}
                    package {{
                        ecosystem
                        name
                    }}
                    severity
                    updatedAt
                    vulnerableVersionRange
                }}
            }}
        }}
    }}
    """
    payload = json.dumps({"query": query}).encode("utf-8")
    request_ = urllib.request.Request(
        url="https://api.github.com/graphql",
        data=payload,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {_api_token}",
            "Content-Type": "application/json; charset=utf-8",
        },
    )
    with urllib.request.urlopen(request_) as response:
        _data = json.loads(response.read())

    has_next = _data["data"]["securityVulnerabilities"]["pageInfo"]["hasNextPage"]
    cursor = _data["data"]["securityVulnerabilities"]["pageInfo"]["endCursor"]
    data = _data["data"]["securityVulnerabilities"]["edges"]
    total_count = int(_data["data"]["securityVulnerabilities"]["totalCount"])

    return total_count, cursor, has_next, data


def _fetch_github_security_advisories(
    limit: int = 100,
) -> Iterator[Tuple[int, str, bool, dict]]:
    total_count, cursor, has_next, data = _query_github_graphql(limit, None)
    yield from data

    while has_next:
        total_count, cursor, has_next, data = _query_github_graphql(limit, cursor)
        yield from data


class Github(SecurityAdvisorySource):
    _name = "github"

    @property
    def name(self) -> str:
        return self._name

    @property
    def total_count(self) -> int:
        return len(self._advisories.keys())

    def populate_from_cache(self) -> None:
        self._advisories = defaultdict(list)

        with open(self.path, "rb") as fh:
            for item in json.load(fh):
                obj = GithubSecurityAdvisory.using(item)
                self._advisories[obj.package_name].append(obj)

    @property
    def path(self) -> str:
        return os.path.join(self._cache_dir, "github.cache")

    def update(self) -> None:
        data = list(_fetch_github_security_advisories())
        with open(self.path, "w") as fh:
            json.dump(data, fh)

    def has_security_advisory_for(self, package_name: str) -> bool:
        return package_name.strip() in self.advisories.keys()

    def is_vulnerable_package(
        self, package_name: str, package_version: str
    ) -> Tuple[bool, List[SecurityAdvisory]]:
        advisories = []
        for candidate in self.advisories[package_name]:
            if candidate.is_affected(package_version):
                advisories.append(candidate)

        return len(advisories) > 0, advisories


register_source("github", Github)
