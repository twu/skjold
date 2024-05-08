import os
from typing import Any

import pytest
import yaml

from skjold.core import Dependency
from skjold.sources.gemnasium import Gemnasium, GemnasiumSecurityAdvisory


def gemnasium_advisory_yml(name: str) -> Any:
    _path = os.path.join(os.path.dirname(__file__), "fixtures", "gemnasium", name)
    assert _path.endswith(".yml") or _path.endswith(".yaml")
    assert os.path.exists(_path)

    with open(_path, "rb") as fh:
        doc = yaml.safe_load(fh)

    return doc


def test_ensure_gemnasium_advisory_from_yaml_with_cvss3_and_cvss2() -> None:
    """Ensure that we are able to create GemnasiumSecurityAdvisories from a given YAML document."""
    obj = GemnasiumSecurityAdvisory.using(gemnasium_advisory_yml("CVE-2019-19844.yml"))
    assert obj.package_name == "Django"
    assert obj.canonical_name == "django"
    assert obj.identifier == "CVE-2019-19844"
    assert obj.source == "gemnasium"
    assert obj.severity == "CRITICAL"
    assert obj.url == "https://nvd.nist.gov/vuln/detail/CVE-2019-19844"
    assert obj.references == [
        "https://nvd.nist.gov/vuln/detail/CVE-2019-19844",
        "https://docs.djangoproject.com/en/dev/releases/security/",
        "https://www.djangoproject.com/weblog/2019/dec/18/security-releases/",
    ]
    assert obj.vulnerable_versions == "<1.11.27,<2.2.9,>=2.2,==3.0"
    assert obj.summary.startswith(
        "Weak Password Recovery Mechanism for Forgotten Password"
    )
    # assert obj.published_at == "2019-12-18"


def test_ensure_gemnasium_advisory_from_yaml_with_cvss2_only() -> None:
    obj = GemnasiumSecurityAdvisory.using(gemnasium_advisory_yml("CVE-2014-1932.yml"))
    assert "cvss_v2" in obj._json
    obj._json.pop("cvss_v3", None)

    assert obj.package_name == "Pillow"
    assert obj.canonical_name == "pillow"
    assert obj.identifier == "CVE-2014-1932"
    assert obj.source == "gemnasium"
    assert obj.severity == "MEDIUM"
    assert obj.url == "http://seclists.org/oss-sec/2014/q1/310"
    assert obj.references == [
        "http://seclists.org/oss-sec/2014/q1/310",
        "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=737059",
    ]
    assert obj.vulnerable_versions == "<2.3.1"
    assert obj.summary.startswith(
        "Insecure use of tempfile.mktemp. In JpegImagePlugin.py,"
    )


def test_ensure_gemnasium_advisory_from_yaml_with_empty_affected_range_string() -> None:
    obj = GemnasiumSecurityAdvisory.using(gemnasium_advisory_yml("CVE-2020-28476.yml"))
    assert "cvss_v2" in obj._json
    obj._json.pop("cvss_v3", None)

    assert obj.package_name == "tornado"
    assert obj.identifier == "CVE-2020-28476"
    assert obj.source == "gemnasium"
    assert obj.severity == "MEDIUM"
    assert obj.url == "https://nvd.nist.gov/vuln/detail/CVE-2020-28476"
    assert obj.references == [
        "https://nvd.nist.gov/vuln/detail/CVE-2020-28476",
    ]
    assert obj.vulnerable_versions == ">=0.0.0"
    assert obj.summary.startswith(
        "Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)"
    )


def test_ensure_gemnasium_advisory_from_yaml_with_no_cvss_vector() -> None:
    obj = GemnasiumSecurityAdvisory.using(gemnasium_advisory_yml("CVE-2014-1932.yml"))

    # Drop any vectors that might be present.
    obj._json.pop("cvss_v3", None)
    obj._json.pop("cvss_v2", None)

    assert obj.package_name == "Pillow"
    assert obj.identifier == "CVE-2014-1932"
    assert obj.source == "gemnasium"
    assert obj.severity == "UNKNOWN"
    assert obj.url == "http://seclists.org/oss-sec/2014/q1/310"
    assert obj.references == [
        "http://seclists.org/oss-sec/2014/q1/310",
        "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=737059",
    ]
    assert obj.vulnerable_versions == "<2.3.1"
    assert obj.summary.startswith(
        "Insecure use of tempfile.mktemp. In JpegImagePlugin.py,"
    )


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
                "affected_range": "<1.11.27||>=2.2,<2.2.9||==3.0",
                "package_slug": "pypi/package",
            }
        )
    ],
)
def test_ensure_is_affected(
    doc: Any, package_name: str, package_version: str, is_vulnerable: bool
) -> None:
    obj = GemnasiumSecurityAdvisory.using(doc)
    assert obj.package_name == "package"
    assert obj.canonical_name == "package"
    assert len(obj.vulnerable_version_range) == len(doc["affected_range"].split("||"))
    assert obj.is_affected(package_version) is is_vulnerable


def test_ensure_gemnasium_update(cache_dir: str) -> None:
    source = Gemnasium(cache_dir, 3600)
    assert len(source._advisories) == 0

    _ = source.advisories
    assert len(source._advisories) > 0
    assert source.total_count > 100

    assert source.has_security_advisory_for(Dependency("Django", "X.X.X"))

    found, findings = source.is_vulnerable_package(Dependency("doesnotexist", "1.0.0"))
    assert found is False and len(findings) == 0

    found, findings = source.is_vulnerable_package(Dependency("Django", "2.2.3"))
    assert found and len(findings) > 0

    found, findings = source.is_vulnerable_package(Dependency("Django", "2.2.8"))
    assert found and len(findings) > 0

    found, findings = source.is_vulnerable_package(Dependency("django", "2.2.8"))
    assert found and len(findings) > 0

    found, findings = source.is_vulnerable_package(Dependency("Django", "2.3.0"))
    assert found is True and len(findings) > 0

    found, findings = source.is_vulnerable_package(Dependency("Django", "3.2.25"))
    assert found is False and len(findings) == 0
