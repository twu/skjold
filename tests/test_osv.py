import os
from typing import Any

import pytest
import yaml

from skjold.sources.osv import OSV, OSVSecurityAdvisory, _osv_dev_api_request


def osv_advisory_yml(name: str) -> Any:
    _path = os.path.join(os.path.dirname(__file__), "fixtures", "osv", name)
    assert _path.endswith(".yml") or _path.endswith(".yaml")
    assert os.path.exists(_path)

    with open(_path, "rb") as fh:
        doc = yaml.safe_load(fh)

    return doc


def test_osv_advisory_with_introduced_and_fixed() -> None:
    obj = OSVSecurityAdvisory.using(osv_advisory_yml("introduced-and-fixed.yaml"))

    assert obj.package_name == "package"
    assert obj.identifier == "PYSEC-0000-0"
    assert obj.source == "osv"
    assert obj.severity == "UNKNOWN"
    assert obj.url == "https://www.pypi.org"
    assert obj.references == ["https://www.pypi.org", "https://www.python.org"]
    assert obj.vulnerable_versions == ">=1.0.0,<1.1.0"
    assert obj.summary == "Too much cheese in the cheeseshop!"

    assert obj.is_affected("1.0.0")
    assert obj.is_affected("1.0.20")
    assert not obj.is_affected("0.9.0")
    assert not obj.is_affected("1.1.0")
    assert not obj.is_affected("2.0.0")


def test_osv_advisory_with_introduced_and_versions() -> None:
    obj = OSVSecurityAdvisory.using(osv_advisory_yml("introduced-and-versions.yaml"))

    assert obj.package_name == "package"
    assert obj.identifier == "PYSEC-0000-0"
    assert obj.source == "osv"
    assert obj.severity == "UNKNOWN"
    assert obj.url == "https://www.pypi.org"
    assert obj.references == ["https://www.pypi.org", "https://www.python.org"]
    assert obj.vulnerable_versions == ">=2.8.0"
    assert obj.summary == "Too much cheese in the cheeseshop!"

    assert not obj.is_affected("1.7.9")
    assert not obj.is_affected("2.7.9")

    assert obj.is_affected("2.8.0")
    assert obj.is_affected("2.8.1")
    assert obj.is_affected("2.8.2")
    assert obj.is_affected("2.8.3")

    assert obj.is_affected("2.8.4")
    assert obj.is_affected("3.0.0")


def test_osv_advisory_with_introduced_only() -> None:
    obj = OSVSecurityAdvisory.using(osv_advisory_yml("introduced-only.yaml"))

    assert obj.package_name == "package"
    assert obj.identifier == "PYSEC-0000-0"
    assert obj.source == "osv"
    assert obj.severity == "UNKNOWN"
    assert obj.url == "https://www.pypi.org"
    assert obj.references == ["https://www.pypi.org", "https://www.python.org"]
    assert obj.vulnerable_versions == ">=1.0.0"
    assert obj.summary == "Too much cheese in the cheeseshop!"

    assert not obj.is_affected("0.9")
    assert not obj.is_affected("0.9.0")

    assert obj.is_affected("1.0.0")
    assert obj.is_affected("1.0")
    assert obj.is_affected("1.2")
    assert obj.is_affected("2.0")
    assert obj.is_affected("2.0.0")


def test_ensure_osv_advisory_from_yaml_with_no_cvss_vector() -> None:
    obj = OSVSecurityAdvisory.using(osv_advisory_yml("PYSEC-2021-54.yaml"))

    assert obj.package_name == "salt"
    assert obj.identifier == "PYSEC-2021-54"
    assert obj.source == "osv"
    assert obj.severity == "UNKNOWN"
    assert obj.url == "https://github.com/saltstack/salt/releases"
    assert obj.references == [
        "https://github.com/saltstack/salt/releases",
        "https://saltproject.io/security_announcements/active-saltstack-cve-release-2021-feb-25/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YOGNT2XWPOYV7YT75DN7PS4GIYWFKOK5/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7GRVZ5WAEI3XFN2BDTL6DDXFS5HYSDVB/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FUGLOJ6NXLCIFRD2JTXBYQEMAEF2B6XH/",
        "https://security.gentoo.org/glsa/202103-01",
    ]
    assert (
        obj.vulnerable_versions
        == "<2015.8.10||>=2015.8.11,<2015.8.13||>=2016.3.0,<2016.3.4||>=2016.3.5,<2016.3.6||>=2016.3.7,<2016.3.8||>=2016.11.0,<2016.11.3||>=2016.11.4,<2016.11.5||>=2016.11.7,<2016.11.10||>=2017.7.0,<2017.7.8||>=2018.3.0rc1,<2019.2.0rc1||>=2019.2.0,<2019.2.5||>=2019.2.6,<2019.2.8||>=3000,<3000.6||>=3001,<3001.4||>=3002,<3002.5"
    )
    assert obj.summary.startswith("In SaltStack Salt before 3002.5, eauth tokens")


@pytest.mark.parametrize(
    "package_name, package_version, is_vulnerable",
    [
        ("package", "1.11.26", True),
        ("package", "0.11.26", True),
        ("package", "0.1.6", True),
        ("package", "2.2.8", True),
        ("package", "2.2.9", False),
        ("package", "3.0.0", True),
        ("package", "3.0.1", False),
        ("package", "3.2", False),
        ("package", "4", False),
    ],
)
@pytest.mark.parametrize(
    "doc",
    [
        (
            {
                "affects": {
                    "versions": ["1.11.26", "0.11.26", "0.1.6", "2.2.8", "3.0"]
                },
                "package": {"name": "package"},
            }
        )
    ],
)
def test_ensure_is_affected(
    doc: Any, package_name: str, package_version: str, is_vulnerable: bool
) -> None:
    obj = OSVSecurityAdvisory.using(doc)
    assert obj.package_name == "package"
    assert len(obj.vulnerable_version_range) == len(doc["affects"]["versions"])
    assert obj.is_affected(package_version) is is_vulnerable


def test_osv_advisory_with_vulnerable_package_via_osv_api() -> None:
    vulnerabilities = _osv_dev_api_request("jinja2", "2.11.2")
    assert vulnerabilities[0]

    obj = OSVSecurityAdvisory.using(vulnerabilities[0])
    assert obj.identifier == "PYSEC-2021-66"
    assert obj.package_name == "jinja2"
    assert obj.summary.startswith(
        "This affects the package jinja2 from 0.0.0 and before 2.11.3."
    )

    assert obj.is_affected("0.0.0")
    assert obj.is_affected("2.11.2")
    assert not obj.is_affected("2.11.3")


def test_ensure_pypi_advisory_db_update(cache_dir: str) -> None:
    source = OSV(cache_dir, 3600)
    assert source.name == "osv"

    assert len(source._advisories) == 0
    _ = source.advisories
    assert source.total_count == 0
    assert len(source._advisories) == 0

    assert source.has_security_advisory_for("ansible")

    found, findings = source.is_vulnerable_package("doesnotexist", "1.0.0")
    assert found is False and len(findings) == 0

    found, findings = source.is_vulnerable_package("ansible", "2.8.1")
    assert found and len(findings) > 0

    found, findings = source.is_vulnerable_package("ansible", "2.8.3")
    assert found and len(findings) > 0

    found, findings = source.is_vulnerable_package("ansible", "4.1.0")
    assert found is False and len(findings) == 0
