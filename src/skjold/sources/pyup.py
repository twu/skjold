import datetime
import json
import os
import urllib.request
from collections import defaultdict
from typing import Tuple, List, Dict, Callable, Union, Any

from packaging import specifiers

from skjold.models import SecurityAdvisorySource, SecurityAdvisory
from skjold.tasks import register_source


class PyUpSecurityAdvisory(SecurityAdvisory):
    _json: Dict[str, str]

    @classmethod
    def using(cls, name: str, json_: dict) -> "PyUpSecurityAdvisory":
        obj = cls()
        obj._json = json_
        obj._json["name"] = name
        return obj

    @property
    def identifier(self) -> str:
        return self._json["id"]

    @property
    def source(self) -> str:
        return "pyup"

    @property
    def severity(self) -> str:
        return "UNKNOWN"

    @property
    def url(self) -> str:
        return f"https://pyup.io/{self.identifier}"

    @property
    def references(self) -> List[str]:
        return []

    @property
    def package_name(self) -> str:
        return self._json["name"]

    @property
    def summary(self) -> str:
        return self._json["advisory"]

    @property
    def vulnerable_version_range(self) -> List[specifiers.SpecifierSet]:
        return [
            specifiers.SpecifierSet(v, prereleases=True) for v in self._json["specs"]
        ]

    @property
    def vulnerable_versions(self) -> str:
        return ",".join([str(x) for x in self.vulnerable_version_range])

    def is_affected(self, version: str) -> bool:
        version_ = specifiers.parse(version)
        allows_: Callable[[specifiers.SpecifierSet], bool] = (
            lambda x: True if version_ in x else False
        )
        # affected_versions = map(lambda x: x.allows(version), self.vulnerable_version_range)
        affected_versions = map(allows_, self.vulnerable_version_range)
        return any(affected_versions)


class PyUp(SecurityAdvisorySource):

    _url: str = "https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json"
    _name: str = "pyup"
    _metadata: Dict[str, Union[str, int]] = {}

    @property
    def name(self) -> str:
        return self._name

    @property
    def total_count(self) -> int:
        return len(self._advisories.keys())

    @property
    def path(self) -> str:
        return os.path.join(self._cache_dir, "pyup.cache")

    @property
    def last_updated_at(self) -> datetime.datetime:
        timestamp = int(self._metadata["timestamp"])
        return datetime.datetime.utcfromtimestamp(timestamp)

    def _load_cache(self) -> Any:
        with open(self.path, "rb") as fh:
            json_ = json.load(fh)
            return json_

    def populate_from_cache(self) -> None:
        self._advisories = defaultdict(list)

        cache_ = self._load_cache()
        for package_name, advisories in cache_.items():
            if package_name in {"$meta"}:
                self._metadata = advisories
                continue

            for advisory in advisories:
                obj = PyUpSecurityAdvisory.using(package_name, advisory)
                self._advisories[obj.package_name].append(obj)

    def update(self) -> None:
        request_ = urllib.request.Request(
            url=self._url,
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(request_) as response:
            json_ = json.loads(response.read())

        with open(self.path, "w") as fh:
            json.dump(json_, fh)

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


register_source("pyup", PyUp)
