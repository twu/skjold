import json
import os
import urllib.request
from typing import Any, Callable, List, MutableMapping, Optional, Sequence, Tuple

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


def _osv_dev_api_request(
    package_name: NormalizedName, package_version: str, ecosystem: str = "PyPI"
) -> Any:
    """Return list of vulnerabilities for a given `package_name` and `package_version` via OSV.dev API."""

    _api_token = os.environ.get("SKJOLD_OSV_API_TOKEN", None)

    payload = json.dumps(
        {
            "version": package_version,
            "package": {"name": package_name, "ecosystem": ecosystem},
        }
    ).encode("utf-8")
    request_ = urllib.request.Request(
        url="https://api.osv.dev/v1/query",
        data=payload,
        headers={
            "Accept": "application/json",
            # "Authorization": f"Bearer {_api_token}",
            "Content-Type": "application/json; charset=utf-8",
        },
    )
    with urllib.request.urlopen(request_) as response:
        _data = json.loads(response.read())

    return _data.get("vulns", [])


class OSVSecurityAdvisory(SecurityAdvisory):
    _json: dict

    @classmethod
    def using(cls, osv1_doc: dict) -> List["OSVSecurityAdvisory"]:
        if osv1_doc.get("withdrawn"):
            return []

        advisories = []
        for affected_package in osv1_doc.get("affected", []):
            obj = cls()
            obj._json = {
                "id": osv1_doc["id"],
                "name": affected_package["package"]["name"].strip(),
                "details": osv1_doc["details"],
                "aliases": osv1_doc.get("aliases", []),
                "references": osv1_doc.get("references", []),
                "affected_versions": affected_package.get("versions", []),
            }
            advisories.append(obj)
        return advisories

    @property
    def identifier(self) -> str:
        return str(self._json["id"])

    @property
    def source(self) -> str:
        return "osv"

    @property
    def severity(self) -> str:
        return "UNKNOWN"

    @property
    def url(self) -> str:
        return str(self.references[0])

    @property
    def references(self) -> List[str]:
        return [str(reference["url"]) for reference in self._json["references"]]

    @property
    def package_name(self) -> str:
        return str(self._json["name"]).strip()

    @property
    def canonical_name(self) -> NormalizedName:
        return canonicalize_name(self.package_name)

    @property
    def summary(self) -> str:
        return f"{self._json['details']}"

    @property
    def vulnerable_version_range(self) -> List[specifiers.SpecifierSet]:
        affected_versions = self._json.get("affected_versions", [])
        return [
            specifiers.SpecifierSet(f"=={x}", prereleases=True)
            for x in affected_versions
        ]

    @property
    def vulnerable_versions(self) -> str:
        return "||".join([str(x) for x in self.vulnerable_version_range])

    def is_affected(self, version: str) -> bool:
        version_ = Version(version)
        allows_: Callable[[specifiers.SpecifierSet], bool] = (
            lambda x: True if version_ in x else False
        )
        affected_versions = map(allows_, self.vulnerable_version_range)
        return any(affected_versions)


class OSV(SecurityAdvisorySource):

    _name = "osv"

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
        """Always return `True` since to ensure we always call the OSV API for every package."""
        return True

    def is_vulnerable_package(
        self, dependency: Dependency
    ) -> Tuple[bool, Sequence[SecurityAdvisory]]:

        findings = _osv_dev_api_request(dependency.canonical_name, dependency.version)
        if not len(findings):
            return False, []

        advisories = []
        for finding in findings:
            results = OSVSecurityAdvisory.using(finding)
            for advisory in results:
                advisories.append(advisory)

        return True, advisories

    def get_security_advisories(
        self,
    ) -> MutableMapping[NormalizedName, SecurityAdvisoryList]:
        raise NotImplementedError


register_source("osv", OSV)
