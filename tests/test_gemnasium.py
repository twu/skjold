# -*- coding: utf-8 -*-
import os
import pytest
from skjold.sources.gemnasium import GemnasiumSecurityAdvisory, Gemnasium
import yaml


def gemnasium_advisory_yml(name):
    _path = os.path.join(os.path.dirname(__file__), "fixtures", "gemnasium", name)
    assert _path.endswith(".yml") or _path.endswith(".yaml")
    assert os.path.exists(_path)

    with open(_path, "rb") as fh:
        doc = yaml.safe_load(fh)

    return doc


def test_ensure_gemnasium_advisory_from_yaml():
    """Ensure that we are able to create GemnasiumSecurityAdvisories from a given YAML document."""
    obj = GemnasiumSecurityAdvisory.using(gemnasium_advisory_yml("multiple.yml"))
    assert obj.package_name == "Django"
    assert obj.identifier == "CVE-2019-19844"
    assert obj.source == "gemnasium"
    assert obj.severity == "UNKNOWN"
    assert obj.url == "https://nvd.nist.gov/vuln/detail/CVE-2019-19844"
    assert obj.references == [
        "https://nvd.nist.gov/vuln/detail/CVE-2019-19844",
        "https://docs.djangoproject.com/en/dev/releases/security/",
        "https://www.djangoproject.com/weblog/2019/dec/18/security-releases/",
    ]
    assert obj.vulnerable_versions == "<1.11.27,>=2.2,<2.2.9,3.0"
    assert obj.summary.startswith(
        "Weak Password Recovery Mechanism for Forgotten Password"
    )
    # assert obj.published_at == "2019-12-18"


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
def test_ensure_is_affected(doc, package_name, package_version, is_vulnerable):
    obj = GemnasiumSecurityAdvisory.using(doc)
    assert obj.package_name == "package"
    assert len(obj.vulnerable_version_range) == len(doc["affected_range"].split("||"))
    assert obj.is_affected(package_version) is is_vulnerable


def test_ensure_gemnasium_update(cache_dir):
    source = Gemnasium(cache_dir, 3600)
    assert len(source._advisories) == 0

    _ = source.advisories
    assert len(source._advisories) > 0
    assert source.total_count > 100

    assert source.has_security_advisory_for("Django")

    found, findings = source.is_vulnerable_package("doesnotexist", "1.0.0")
    assert found is False and len(findings) == 0

    found, findings = source.is_vulnerable_package("Django", "2.2.8")
    assert found and len(findings) > 0

    found, findings = source.is_vulnerable_package("django", "2.2.8")
    assert found and len(findings) > 0

    found, findings = source.is_vulnerable_package("Django", "2.2.9")
    assert found is False and len(findings) == 0
