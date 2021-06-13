import os
from typing import List, Any, Tuple

import pytest

from skjold.models import SecurityAdvisorySource, SecurityAdvisory, SkjoldException
from skjold.tasks import register_source, is_registered_source, Configuration


class DummyAdvisory(SecurityAdvisory):
    @property
    def identifier(self) -> str:
        return "D-UMMY"

    @property
    def source(self) -> str:
        return "dummy"

    @property
    def package_name(self) -> str:
        return "dummy"

    @property
    def url(self) -> str:
        return "https://dummy.url"

    @property
    def references(self) -> List[str]:
        return []

    @property
    def summary(self) -> str:
        return "This is a dummy advisory summary."

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def vulnerable_versions(self) -> str:
        return "==1.2.3"

    def is_affected(self, version: str) -> bool:
        return version == "==1.2.3"


class DummyAdvisorySource(SecurityAdvisorySource):
    _name: str = "dummy"

    @property
    def name(self) -> str:
        return self._name

    @property
    def path(self) -> str:
        return os.path.join(self._cache_dir, "dummy.cache")

    def populate_from_cache(self) -> None:
        pass

    def update(self) -> None:
        self._advisories = {"single": [DummyAdvisory()]}

    def has_security_advisory_for(self, package_name: str) -> bool:
        if package_name in ["vulnerable"]:
            return True
        return False

    def is_vulnerable_package(
        self, package_name: str, package_version: str
    ) -> Tuple[bool, List[SecurityAdvisory]]:
        return False, []

    @property
    def total_count(self) -> int:
        return len(self.advisories)


def test_ensure_accessing_advisories_triggers_update(
    mocker: Any, cache_dir: str
) -> None:
    source = DummyAdvisorySource(cache_dir)
    assert len(source._advisories) == 0

    _ = source.advisories
    spy = mocker.spy(source, "update")
    assert len(source.get_security_advisories()) == 1
    assert spy.assert_called


def test_register_source() -> None:
    DummyAdvisorySource._name = "dummy2"
    register_source("dummy2", DummyAdvisorySource)

    assert is_registered_source("dummy2")
    _config = Configuration()
    assert "dummy2" in _config.available_sources


def test_register_source_twice() -> None:
    with pytest.raises(SkjoldException):
        register_source("dummy", DummyAdvisorySource)
        assert is_registered_source("dummy")
        register_source("dummy", DummyAdvisorySource)
