# -*- coding: utf-8 -*-
import pytest
from typing import Dict, Union, Any

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


def test_ensure_using_build_obj(github_advisory: Dict) -> None:
    obj = GithubSecurityAdvisory.using(github_advisory)

    assert obj.package_name == "Plone"
    assert obj.identifier == "GHSA-p5wr-vp8g-q5p4"
    assert obj.source == "github"
    assert "Moderate" in obj.summary
    assert obj.severity == "MODERATE"
    assert obj.first_patched_version == "4.3.12"
    assert obj.vulnerable_versions == ">=4.0,<4.3.12"
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
