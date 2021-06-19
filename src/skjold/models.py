import abc
import os
import time
from abc import ABCMeta, abstractmethod
from typing import List, Tuple, MutableMapping, Sequence, Optional


class SkjoldException(Exception):
    pass


Package = Tuple[str, str]
PackageList = Sequence[Package]


class SecurityAdvisory(metaclass=abc.ABCMeta):
    @property
    @abstractmethod
    def identifier(self) -> str:
        """Return this advisories unique identifier."""
        raise NotImplementedError

    @property
    @abstractmethod
    def source(self) -> str:
        """Return the data source the advisory comes from."""
        raise NotImplementedError

    @property
    @abstractmethod
    def package_name(self) -> str:
        """Return package name of the affected package."""
        raise NotImplementedError

    @property
    @abstractmethod
    def url(self) -> str:
        """Return direct link to more information for a given advisory."""
        raise NotImplementedError

    @property
    @abstractmethod
    def references(self) -> List[str]:
        """Return list of references for this advisory."""
        raise NotImplementedError

    @property
    @abstractmethod
    def summary(self) -> str:
        """Return string containing a short summary of the advisory."""
        raise NotImplementedError

    @property
    @abstractmethod
    def severity(self) -> str:
        """Return the severity level of the advisory/underlying vulnerability."""
        raise NotImplementedError

    @property
    @abstractmethod
    def vulnerable_versions(self) -> str:
        """Get string representation of the affected version ranges."""
        raise NotImplementedError

    @abstractmethod
    def is_affected(self, version: str) -> bool:
        """Return True if the given version is within the affected version range. False otherwise."""
        raise NotImplementedError


SecurityAdvisoryList = List[SecurityAdvisory]


def is_outdated(path: str, max_age: int = 3600) -> bool:
    """Return True if the given file's mtime exceeds 'max_age'. False otherwise."""
    last_modified = int(os.path.getmtime(path))
    diff = int(time.time()) - last_modified
    return diff >= max_age


class SecurityAdvisorySource(metaclass=ABCMeta):
    _advisories: MutableMapping[str, SecurityAdvisoryList] = {}
    _cache_dir: str
    _cache_expires: int
    _name: str

    def __init__(self, cache_dir: str, cache_expires: int = 0) -> None:
        self._cache_dir = cache_dir
        self._cache_expires = cache_expires

    @property
    @abstractmethod
    def name(self) -> str:
        """Return name of this source."""
        raise NotImplementedError

    @property
    def advisories(self) -> MutableMapping[str, SecurityAdvisoryList]:
        """Return list of SecurityAdvisories from the given source."""
        if self.requires_update:
            self.update()

        if not len(self._advisories):
            self.populate_from_cache()

        return self._advisories

    @property
    def requires_update(self) -> bool:
        """ Return True if the source should be updated. False otherwise. """
        if self.path is None:
            return True

        if not os.path.exists(self.path):
            return True

        return is_outdated(self.path, self._cache_expires)

    @property
    @abstractmethod
    def path(self) -> Optional[str]:
        """Return path to local database download."""
        raise NotImplementedError

    @property
    @abstractmethod
    def total_count(self) -> int:
        """Return number of total security advisories."""
        raise NotImplementedError

    @abstractmethod
    def update(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def populate_from_cache(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def is_vulnerable_package(
        self, package_name: str, package_version: str
    ) -> Tuple[bool, Sequence[SecurityAdvisory]]:
        raise NotImplementedError

    @abstractmethod
    def has_security_advisory_for(self, package_name: str) -> bool:
        raise NotImplementedError

    def get_security_advisories(
        self,
    ) -> MutableMapping[str, SecurityAdvisoryList]:
        return self.advisories
