from typing import Dict, Union, Any

import click
import pytest
from _pytest.monkeypatch import MonkeyPatch

from skjold.sources.github import GithubSecurityAdvisory, Github


@pytest.fixture
def github_advisory() -> Dict[str, Union[str, Dict]]:
    return {
        "cursor": "...",
        "node": {
            "advisory": {
                "ghsaId": "GHSA-p5wr-vp8g-q5p4",
                "publishedAt": "2018-07-12T14:45:15Z",
                "summary": "Moderate severity vulnerability that affects Plone",
            },
            "firstPatchedVersion": {"identifier": "4.3.12"},
            "package": {"ecosystem": "PIP", "name": "Plone"},
            "severity": "MODERATE",
            "updatedAt": "2018-07-11T19:41:00Z",
            "vulnerableVersionRange": ">= 4.0, < 4.3.12",
        },
    }


@pytest.mark.parametrize(
    "vulnerable_version_range, package_version, is_vulnerable",
    [
        (" = 1.4.2", "1.4.2", True),
        ("= 1.4.2", "1.4.2", True),
        ("==1.4.2", "1.4.2", True),
        ("== 1.4.2", "1.4.2", True),
        (" == 1.4.2", "1.4.2", True),
        ("< 8.2.0", "8.1.99", True),
        (" >= 4.0, < 4.3", "4.0", True),
        (">= 5.0.0, < 5.2.1", "5.2.0", True),
        (">=5.0.0,<5.2.1", "5.2.0", True),
        (">= 5.0.0, < 5.2.1", "5.0", True),
        (">= 4.0, < 4.3", "4.3", False),
        ("= 1.4.2", "1.4.3", False),
        ("= 1.4.2", "1.4.3", False),
        ("< 8.2.0", "8.2.0", False),
    ],
)
def test_ensure_is_affected_with_github_specifiers(
    vulnerable_version_range: str, package_version: str, is_vulnerable: bool
) -> None:
    obj = GithubSecurityAdvisory.using(
        {
            "node": {
                "vulnerableVersionRange": vulnerable_version_range,
            },
        }
    )

    assert len(obj.vulnerable_version_range) > 0
    assert (
        obj.is_affected(package_version) is is_vulnerable
    ), f"'{package_version}' should be vulnerable given '{vulnerable_version_range}'!"


def test_ensure_raises_when_encountering_too_many_specifiers() -> None:
    obj = GithubSecurityAdvisory.using(
        {
            "node": {
                "vulnerableVersionRange": "<1.0, = 2.0, >= 3.0",
            },
        }
    )
    with pytest.raises(ValueError):
        obj.is_affected("2.0")


def test_ensure_using_build_obj(github_advisory: Dict) -> None:
    obj = GithubSecurityAdvisory.using(github_advisory)

    assert obj.package_name == "Plone"
    assert obj.identifier == "GHSA-p5wr-vp8g-q5p4"
    assert obj.source == "github"
    assert "Moderate" in obj.summary
    assert obj.severity == "MODERATE"
    assert obj.first_patched_version == "4.3.12"
    assert obj.vulnerable_versions == "<4.3.12,>=4.0"
    assert obj.ecosystem == "PIP"


def test_ensure_is_affected_example(github_advisory: Dict) -> None:
    obj = GithubSecurityAdvisory.using(github_advisory)
    assert obj.package_name == "Plone"

    assert obj.is_affected("4.3.12") is False
    assert obj.is_affected("4.1") is True
    assert obj.is_affected("4.0") is True
    assert obj.is_affected("3.0") is False


def test_ensure_accessing_advisories_triggers_update(
    cache_dir: str, mocker: Any
) -> None:
    source = Github(cache_dir, 3600)
    assert len(source._advisories) == 0

    spy = mocker.spy(source, "update")
    assert len(source.get_security_advisories()) > 100
    assert spy.assert_called
    assert source.total_count > 100


def test_ensure_missing_github_token_raises_usage_error(
    cache_dir: str, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.delenv("SKJOLD_GITHUB_API_TOKEN")
    with pytest.raises(click.UsageError):
        gh = Github(cache_dir, 0)
        gh.update()
