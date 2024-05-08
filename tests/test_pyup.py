import datetime
import json
from typing import Any, Dict, List
from unittest import mock

import pytest

from skjold.core import Dependency
from skjold.sources.pyup import PyUp, PyUpSecurityAdvisory


@pytest.mark.parametrize(
    "name, raw, expected_url",
    [
        (
            "package_name",
            {
                "advisory": "Advisory summary.",
                "cve": "CVE-200X-XXXX",
                "id": "pyup.io-XXXXXX",
                "specs": ["<1.0.0", ">=1.1,<1.1.1"],
                "v": "<1.0.4,>=1.1,<1.1.1",
            },
            "",
        ),
        (
            "package_name",
            {
                "advisory": "Advisory summary.",
                "cve": "CVE-200X-XXXX",
                "id": "pyup.io-XXXXXX",
                "specs": ["<1.0.0", ">=1.1,<1.1.1"],
                "v": "<1.0.4,>=1.1,<1.1.1",
                "more_info_path": "/vulnerabilities/CVE-1970-0001/12345/",
            },
            "https://pyup.io/vulnerabilities/CVE-1970-0001/12345/",
        ),
    ],
)
def test_ensure_using_build_obj(
    name: str, raw: Dict[Any, Any], expected_url: str
) -> None:
    obj = PyUpSecurityAdvisory.using(name, raw)
    assert obj.package_name == "package_name"
    assert obj.canonical_name == "package-name"
    assert obj.identifier == "CVE-200X-XXXX"
    assert obj.source == "pyup"
    assert obj.summary == "Advisory summary."
    assert obj.severity == "UNKNOWN"
    assert obj.url == expected_url
    assert obj.references == []
    assert obj.vulnerable_versions == "<1.0.0,<1.1.1,>=1.1"


@pytest.mark.parametrize(
    "package_name, package_version, is_vulnerable",
    [
        ("package", "0.9.1", True),
        ("package", "0.9.9", True),
        ("package", "1.1.0", True),
        ("package", "1.1.1", False),
        ("package", "1.1.2", False),
        ("package", "2.0.0", False),
        ("package", "2.2.0", False),
    ],
)
@pytest.mark.parametrize(
    "specs",
    [
        ({"specs": ["<1.0.0", ">=1.1,<1.1.1"], "v": "<1.0.0,>=1.1,<1.1.1"}),
        ({"specs": ["<1.1.1"], "v": "<1.1.1"}),
    ],
)
def test_ensure_is_affected(
    specs: Dict[str, List[str]],
    package_name: str,
    package_version: str,
    is_vulnerable: bool,
) -> None:
    obj = PyUpSecurityAdvisory.using("package", specs)
    assert obj.package_name == "package"
    assert len(obj.vulnerable_version_range) == len(specs["specs"])
    assert obj.is_affected(package_version) is is_vulnerable


@pytest.mark.parametrize(
    "package_name, package_version, is_vulnerable",
    [
        ("package", "0.9.4", False),
        ("package", "1.0.0", True),
        ("package", "2.0.0", False),
    ],
)
def test_ensure_is_affected_single(
    package_name: str, package_version: str, is_vulnerable: bool
) -> None:
    obj = PyUpSecurityAdvisory.using("package", {"specs": ["==1.0.0"]})
    assert obj.package_name == "package"
    assert len(obj.vulnerable_version_range) == 1
    assert obj.is_affected(package_version) is is_vulnerable


@pytest.mark.parametrize(
    "source_name, dependency, is_vulnerable",
    [
        ("pyup", Dependency("werkzeug", "0.11.10"), True),
        ("pyup", Dependency("werkzeug", "0.9"), True),
        ("pyup", Dependency("werkzeug", "0.11.11"), True),
        ("pyup", Dependency("werkzeug", "0.12"), True),
        ("pyup", Dependency("werkzeug", "0.12"), True),
        ("pyup", Dependency("werkzeug", "1.0.0"), True),
        ("pyup", Dependency("werkzeug", "1.0.1"), True),
        ("pyup", Dependency("werkzeug", "2.2.3"), True),
        ("pyup", Dependency("werkzeug", "3.0.1"), False),
        ("pyup", Dependency("does-not-exist", "0"), False),
    ],
)
def test_ensure_source_is_affected_single(
    source_name: str,
    dependency: Dependency,
    is_vulnerable: bool,
    cache_dir: str,
) -> None:
    from skjold.tasks import _sources

    assert source_name in _sources
    source = _sources[source_name](cache_dir, 3600)
    assert source.name == source_name
    _ = source.advisories
    assert source.total_count > 0

    if is_vulnerable:
        assert source.has_security_advisory_for(dependency)

    vulnerable, _ = source.is_vulnerable_package(dependency)
    assert vulnerable == is_vulnerable


def pyup_advisories_with_metadata() -> Any:
    payload = """\
    {
      "$meta": {
        "advisory": "PyUp.io metadata",
        "timestamp": 1601532001
      },
      "package": [{
        "advisory": "...",
        "cve": "CVE-200X-XXXX",
        "id": "pyup.io-XXXXX",
        "specs": [">0", "<0"],
        "v": ">0,<0"
      }]
    }"""
    return json.loads(payload)


def test_pyup_handle_metadata(cache_dir: str) -> None:
    pyup = PyUp(cache_dir=cache_dir, cache_expires=0)
    assert pyup.total_count == 0
    with pytest.raises(KeyError):
        assert pyup.last_updated_at

    with mock.patch.object(pyup, "_load_cache", pyup_advisories_with_metadata):
        pyup.populate_from_cache()
        assert pyup.total_count == 1
        assert pyup.last_updated_at == datetime.datetime(2020, 10, 1, 6, 0, 1)


def test_ensure_accessing_advisories_triggers_update(
    cache_dir: str, mocker: Any
) -> None:
    source = PyUp(cache_dir=cache_dir, cache_expires=3600)
    assert len(source.advisories) > 0

    spy = mocker.spy(source, "update")
    assert len(source.get_security_advisories()) > 50
    assert spy.assert_called
    assert source.total_count > 50
