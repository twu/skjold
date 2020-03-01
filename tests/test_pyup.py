# -*- coding: utf-8 -*-
import pytest
from typing import List, Dict, Any

from skjold.sources.pyup import PyUpSecurityAdvisory


@pytest.mark.parametrize(
    "name, raw",
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
        )
    ],
)
def test_ensure_using_build_obj(name: str, raw: Dict[Any, Any]) -> None:
    obj = PyUpSecurityAdvisory.using(name, raw)
    assert obj.package_name == "package_name"
    assert obj.identifier == "pyup.io-XXXXXX"
    assert obj.source == "pyup"
    assert obj.summary == "Advisory summary."
    assert obj.severity == "UNKNOWN"
    assert obj.url == "https://pyup.io/pyup.io-XXXXXX"
    assert obj.references == []
    assert obj.vulnerable_versions == "<1.0.0,>=1.1,<1.1.1"


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

    # print(obj.as_dict)


@pytest.mark.parametrize(
    "source_name, package_name, package_version, is_vulnerable",
    [
        ("pyup", "werkzeug", "0.11.10", True),
        ("pyup", "werkzeug", "0.9", True),
        ("pyup", "werkzeug", "0.11.11", False),
        ("pyup", "werkzeug", "0.12", False),
        ("pyup", "werkzeug", "0.12", False),
        ("pyup", "does-not-exist", "0", False),
    ],
)
def test_ensure_source_is_affected_single(
    source_name: str,
    package_name: str,
    package_version: str,
    is_vulnerable: bool,
    cache_dir: str,
) -> None:

    import skjold.sources
    from skjold.tasks import _sources

    assert source_name in _sources
    source = _sources[source_name](cache_dir, 3600)
    assert source.name == source_name
    _ = source.advisories
    assert source.total_count > 0

    if is_vulnerable:
        assert source.has_security_advisory_for(package_name)

    vulnerable, _ = source.is_vulnerable_package(package_name, package_version)
    assert vulnerable == is_vulnerable
