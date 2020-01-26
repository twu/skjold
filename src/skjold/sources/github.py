# -*- coding: utf-8 -*-
import os
import json
import pprint
from collections import defaultdict
from typing import List, Tuple, Optional, Iterator, Dict, Any

import requests
import semver
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
    def vulnerable_version_range(self) -> semver.VersionConstraint:
        return semver.parse_constraint(self._json["node"]["vulnerableVersionRange"])

    @property
    def vulnerable_versions(self) -> str:
        return str(self.vulnerable_version_range)

    def is_affected(self, version: str) -> bool:
        version = semver.Version.parse(version)
        if self.vulnerable_version_range.allows(version):
            return True
        return False

    @property
    def url(self) -> str:
        return f"https://github.com/advisories/{self.identifier}"


def _query_github_graphql(
    first: int = 10, after: Optional[str] = None
) -> Tuple[int, str, bool, dict]:
    _after = after and f'"{after}"' or "null"
    _limit = first and int(first) or 1
    _api_token = os.environ["SKJOLD_GITHUB_API_TOKEN"]

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
    response = requests.post(
        "https://api.github.com/graphql",
        json={"query": query},
        headers={"Accept": "application/json", "Authorization": f"Bearer {_api_token}"},
    )
    response.raise_for_status()
    _data = response.json()

    has_next = _data["data"]["securityVulnerabilities"]["pageInfo"]["hasNextPage"]
    cursor = _data["data"]["securityVulnerabilities"]["pageInfo"]["endCursor"]
    data = _data["data"]["securityVulnerabilities"]["edges"]
    total_count = int(_data["data"]["securityVulnerabilities"]["totalCount"])

    return total_count, cursor, has_next, data


def _fetch_github_security_advisories(
    limit: int = 100,
) -> Iterator[Tuple[int, str, bool, dict]]:
    total_count, cursor, has_next, data = _query_github_graphql(limit, None)
    for entry in data:
        yield entry

    while has_next:
        total_count, cursor, has_next, data = _query_github_graphql(limit, cursor)
        for entry in data:
            yield entry


def _is_vulnerable_package(package: str, version: str) -> None:  # pragma: no cover
    _api_token = os.environ["SKJOLD_GITHUB_API_TOKEN"]
    query = f"""
    {{
        securityVulnerabilities(first: 10, package: "{package}" orderBy: {{ field: UPDATED_AT, direction: DESC }}) {{
            totalCount
            edges {{
                node {{
                    advisory {{
                        ghsaId
                        publishedAt
                        summary
                        references {{
                          uri
                        }}

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
    response = requests.post(
        "https://api.github.com/graphql",
        json={"query": query},
        headers={"Accept": "application/json", "Authorization": f"Bearer {_api_token}"},
    )
    response.raise_for_status()
    _data = response.json()
    pprint.pprint(_data)


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
        with open(self.path, "w") as fh:
            json.dump(list(_fetch_github_security_advisories()), fh)

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
