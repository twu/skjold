import os
import tarfile
import urllib.request
from collections import defaultdict
from typing import Callable, List, Tuple

import yaml
from packaging import specifiers
from packaging.utils import NormalizedName, canonicalize_name
from packaging.version import Version

from skjold.core import (
    Dependency,
    SecurityAdvisory,
    SecurityAdvisorySource,
    SkjoldException,
)
from skjold.cvss import parse_cvss
from skjold.tasks import register_source


class GemnasiumSecurityAdvisory(SecurityAdvisory):
    _json: dict

    @classmethod
    def using(cls, json_: dict) -> "GemnasiumSecurityAdvisory":
        obj = cls()
        obj._json = json_
        return obj

    @property
    def identifier(self) -> str:
        return str(self._json["identifier"])

    @property
    def source(self) -> str:
        return "gemnasium"

    @property
    def severity(self) -> str:
        for field in ["cvss_v3", "cvss_v2"]:
            vector = self._json.get(field, None)
            if vector:
                cvss = parse_cvss(vector)
                return cvss.severity

        return "UNKNOWN"

    @property
    def url(self) -> str:
        return str(self.references[0])

    @property
    def references(self) -> List[str]:
        return [str(url) for url in self._json["urls"]]

    @property
    def package_name(self) -> str:
        return str(self._json["package_slug"]).replace("pypi/", "").strip()

    @property
    def canonical_name(self) -> NormalizedName:
        return canonicalize_name(self.package_name)

    @property
    def summary(self) -> str:
        return f"{self._json['title']}. {self._json['description']}"

    @property
    def vulnerable_version_range(self) -> List[specifiers.SpecifierSet]:
        affected_range = self._json["affected_range"]

        # Gemnasium sometimes uses spaces instead of commas for ranges
        affected_range = affected_range.strip().replace(" ", ",")

        # Gemnasium seems to invalidate/withdraw advisories by marking them this way.
        # See pypi/pyspark/CVE-2020-27218.yml#L11 in gemnasium-db.
        if affected_range in {"(,0)"}:
            return []

        if not affected_range:
            return [specifiers.SpecifierSet(">=0.0.0", prereleases=True)]

        vulnerable_versions = []

        for spec in affected_range.split("||"):
            # Workaround to ensure that we strip any trailing dots from ranges/specs e.g. >=1.2.,<=2.0.
            spec = spec.replace(".,", ",")
            if "," in spec and spec.endswith("."):
                spec = spec[:-1]

            vulnerable_versions.append(specifiers.SpecifierSet(spec, prereleases=True))
        return vulnerable_versions

    @property
    def vulnerable_versions(self) -> str:
        return ",".join([str(x) for x in self.vulnerable_version_range])

    def is_affected(self, version: str) -> bool:
        version_ = Version(version)
        allows_: Callable[[specifiers.SpecifierSet], bool] = (
            lambda x: True if version_ in x else False
        )
        affected_versions = map(allows_, self.vulnerable_version_range)
        return any(affected_versions)


class Gemnasium(SecurityAdvisorySource):
    _url = "https://gitlab.com/gitlab-org/security-products/gemnasium-db/-/archive/master/gemnasium-db-master.tar.gz"
    _name = "gemnasium"

    @property
    def name(self) -> str:
        return self._name

    @property
    def path(self) -> str:
        return os.path.join(self._cache_dir, "gemnasium.cache")

    def populate_from_cache(self) -> None:
        self._advisories = defaultdict(list)
        with tarfile.TarFile.open(self.path, mode="r:gz") as archive:
            pypi_advisories = filter(
                lambda obj: "/pypi/" in obj.name and obj.name.endswith(".yml"),
                archive.getmembers(),
            )

            for obj in list(pypi_advisories):
                obj_fh = archive.extractfile(obj.name)
                if obj_fh:
                    doc = yaml.load(obj_fh, Loader=yaml.SafeLoader)
                    advisory = GemnasiumSecurityAdvisory.using(doc)
                    self._advisories[advisory.canonical_name].append(advisory)
                else:  # pragma: no cover
                    raise SkjoldException(
                        f"Unable to extract '{obj.name}' from source archive."
                    )

    @property
    def total_count(self) -> int:
        return len(self._advisories.keys())

    def update(self) -> None:
        request = urllib.request.Request(
            url=self._url, headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(request) as response:
            with open(self.path, "wb") as fh:
                fh.write(response.read())

    def has_security_advisory_for(self, dependency: Dependency) -> bool:
        return dependency.canonical_name in self.advisories.keys()

    def is_vulnerable_package(
        self, dependency: Dependency
    ) -> Tuple[bool, List[SecurityAdvisory]]:
        if not self.has_security_advisory_for(dependency):
            return False, []

        advisories = []
        for candidate in self.advisories[dependency.canonical_name]:
            if candidate.is_affected(dependency.version):
                advisories.append(candidate)

        return len(advisories) > 0, advisories


register_source("gemnasium", Gemnasium)
