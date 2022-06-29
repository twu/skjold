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


def test_osv_advisory_with_type_ecosystem_and_versions() -> None:
    advisories = OSVSecurityAdvisory.using(osv_advisory_yml("PYSEC-2021-59.yaml"))
    assert len(advisories) == 1

    obj = advisories[0]
    assert obj.package_name == "urllib3"
    assert obj.identifier == "PYSEC-2021-59"
    assert obj.source == "osv"
    assert obj.severity == "UNKNOWN"
    assert obj.url == "https://github.com/urllib3/urllib3/commits/main"
    assert obj.references == [
        "https://github.com/urllib3/urllib3/commits/main",
        "https://pypi.org/project/urllib3/1.26.4/",
        "https://github.com/urllib3/urllib3/commit/8d65ea1ecf6e2cdc27d42124e587c1b83a3118b0",
        "https://github.com/urllib3/urllib3/security/advisories/GHSA-5phf-pp7p-vc2r",
    ]
    assert obj.vulnerable_versions == "==1.26.0||==1.26.1||==1.26.2||==1.26.3"
    assert obj.summary.startswith("The urllib3 library 1.26.x before")

    assert not obj.is_affected("1.25.9")
    assert not obj.is_affected("1.20.0")

    assert obj.is_affected("1.26.0")
    assert obj.is_affected("1.26.1")
    assert obj.is_affected("1.26.2")
    assert obj.is_affected("1.26.3")

    assert not obj.is_affected("1.26.4")
    assert not obj.is_affected("1.27")


def test_ensure_osv_advisory_from_yaml_with_no_cvss_vector() -> None:
    advisories = OSVSecurityAdvisory.using(osv_advisory_yml("PYSEC-2021-54.yaml"))
    assert len(advisories) == 1

    obj = advisories[0]
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
                "id": "PYSEC-0000-00",
                "details": "...",
                "affected": [
                    {
                        "package": {"name": "package"},
                        "versions": ["1.11.26", "0.11.26", "0.1.6", "2.2.8", "3.0"],
                    }
                ],
            }
        )
    ],
)
def test_ensure_is_affected(
    doc: Any, package_name: str, package_version: str, is_vulnerable: bool
) -> None:
    obj = OSVSecurityAdvisory.using(doc)[0]
    assert obj.package_name == "package"
    # assert len(obj.vulnerable_version_range) == len(doc["affected"]["versions"])
    assert obj.is_affected(package_version) is is_vulnerable


def test_osv_advisory_with_vulnerable_package_via_osv_api() -> None:
    vulnerabilities = _osv_dev_api_request("jinja2", "2.11.2")
    assert vulnerabilities[0]

    obj = OSVSecurityAdvisory.using(vulnerabilities[0])[0]
    assert obj.identifier == "PYSEC-2021-66"
    assert obj.package_name == "jinja2"
    assert obj.summary.startswith(
        "This affects the package jinja2 from 0.0.0 and before 2.11.3."
    )

    assert obj.is_affected("2.5.5")
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

    found, findings = source.is_vulnerable_package("httpx", "0.19.0")
    assert found is True and len(findings) > 0
