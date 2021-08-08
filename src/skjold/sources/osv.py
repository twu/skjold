import json
import os
import urllib.request
from typing import List, Tuple, Callable, Dict, Any, Sequence
from typing import Optional, MutableMapping

from packaging import specifiers

from skjold.models import SecurityAdvisory, SecurityAdvisorySource, SecurityAdvisoryList
from skjold.tasks import register_source


def _is_supported_range_type(affected_range: Dict) -> bool:
    """Return True if the given `affected.ranges` item is supported."""
    return "type" in affected_range and affected_range["type"] in {
        "ECOSYSTEM",
        "SEMVER",
    }


def _osv_dev_api_request(
    package_name: str, package_version: str, ecosystem: str = "PyPI"
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
    def using(cls, json_: dict) -> "OSVSecurityAdvisory":
        obj = cls()
        obj._json = json_
        return obj

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
        return str(self._json["package"]["name"]).strip()

    @property
    def summary(self) -> str:
        return f"{self._json['details']}"

    @property
    def vulnerable_version_range(self) -> List[specifiers.SpecifierSet]:
        # Try using ranges first to avoid clutter.
        affected_ecosystem_ranges = list(
            filter(
                _is_supported_range_type,
                self._json.get("affects", {}).get("ranges", []),
            )
        )
        if len(affected_ecosystem_ranges):
            ranges = []
            for affected_range in affected_ecosystem_ranges:
                _constraints = []
                if "introduced" in affected_range:
                    v = affected_range.get("introduced")
                    _constraints.append(f">={v}")

                if "fixed" in affected_range:
                    v = affected_range.get("fixed")
                    _constraints.append(f"<{v}")

                ranges.append(
                    specifiers.SpecifierSet(",".join(_constraints), prereleases=True)
                )
            return ranges

        # Try using versions (default).
        affected_versions = self._json.get("affects", {}).get("versions", [])
        if len(affected_versions):
            return [
                specifiers.SpecifierSet(f"=={x}", prereleases=True)
                for x in affected_versions
            ]

        return [specifiers.SpecifierSet(">=0", prereleases=True)]

    @property
    def vulnerable_versions(self) -> str:
        return "||".join([str(x) for x in self.vulnerable_version_range])

    def is_affected(self, version: str) -> bool:
        version_ = specifiers.parse(version)
        allows_: Callable[[specifiers.SpecifierSet], bool] = (
            lambda x: True if version_ in x else False
        )
        # affected_versions = map(lambda x: x.allows(version), self.vulnerable_version_range)
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

    def has_security_advisory_for(self, package_name: str) -> bool:
        """Always return `True` since to ensure we always call the OSV API for every package."""
        return True

    def is_vulnerable_package(
        self, package_name: str, package_version: str
    ) -> Tuple[bool, Sequence[SecurityAdvisory]]:

        findings = _osv_dev_api_request(package_name.strip().lower(), package_version)
        if not len(findings):
            return False, []

        advisories = []
        for finding in findings:
            advisory = OSVSecurityAdvisory.using(finding)
            advisories.append(advisory)

        return True, advisories

    def get_security_advisories(self) -> MutableMapping[str, SecurityAdvisoryList]:
        raise NotImplementedError


register_source("osv", OSV)
