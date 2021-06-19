import os
import tarfile
import urllib.request
from collections import defaultdict
from typing import List, Tuple

import yaml

from skjold.models import SecurityAdvisory, SecurityAdvisorySource, SkjoldException
from skjold.sources.osv import OSVSecurityAdvisory
from skjold.tasks import register_source


class PyPAAdvisoryDB(SecurityAdvisorySource):

    _url = "https://api.github.com/repos/pypa/advisory-db/tarball"
    _name = "pypa"

    @property
    def name(self) -> str:
        return self._name

    @property
    def path(self) -> str:
        return os.path.join(self._cache_dir, "pypa.cache")

    def populate_from_cache(self) -> None:
        self._advisories = defaultdict(list)
        with tarfile.TarFile.open(self.path, mode="r:gz") as archive:
            pypi_advisories = filter(
                lambda obj: "/vulns/" in obj.name and obj.name.endswith(".yaml"),
                archive.getmembers(),
            )

            for obj in list(pypi_advisories):
                obj_fh = archive.extractfile(obj.name)
                if obj_fh:
                    doc = yaml.load(obj_fh, Loader=yaml.SafeLoader)
                    advisory = OSVSecurityAdvisory.using(doc)
                    self._advisories[advisory.package_name.lower()].append(advisory)
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

    def has_security_advisory_for(self, package_name: str) -> bool:
        return package_name.strip().lower() in self.advisories.keys()

    def is_vulnerable_package(
        self, package_name: str, package_version: str
    ) -> Tuple[bool, List[SecurityAdvisory]]:
        if not self.has_security_advisory_for(package_name):
            return False, []

        advisories = []
        for candidate in self.advisories[package_name.strip().lower()]:
            if candidate.is_affected(package_version):
                advisories.append(candidate)

        return len(advisories) > 0, advisories


register_source("pypa", PyPAAdvisoryDB)
