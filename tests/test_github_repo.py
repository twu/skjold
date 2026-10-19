import os
from pathlib import Path
from typing import Type
from unittest import mock

import click
import pytest
from packaging.version import InvalidVersion

from skjold.core import Dependency, SkjoldException
from skjold.sources.github_repo import (
    GithubRepo,
    GithubRepoSecurityAdvisory,
    _fetch_repo_advisories,
    find_github_repo,
    parse_version_range,
)


@pytest.mark.parametrize(
    "value, version, is_affected",
    [
        ("11.1.0 - 12.3.0", "12.0.0", True),
        ("11.1.0 - 12.3.0", "12.3.0", True),
        ("11.1.0 - 12.3.0", "13.0.0", False),
        ("11.1.0 - 12.3.0", "11.0.0", False),
        ("≤ 12.2.0", "12.2.0", True),
        ("≤ 12.2.0", "12.3.0", False),
        ("<=12.2.0", "12.2.0", True),
        ("< 12.2.0", "12.2.0", False),
        (">= 10.3.0, < 12.1.1", "11.0", True),
        (">= 10.3.0, < 12.1.1", "12.1.1", False),
        ("11.2.0", "11.2.0", True),
        ("11.2.0", "11.2.1", False),
        ("= 1.4.2", "1.4.2", True),
        ("", "1.0", True),
        ("1.4.1, 1.4.2", "1.4.1", True),
        ("1.4.1, 1.4.2", "1.4.2", True),
        ("1.4.1, 1.4.2", "1.4.3", False),
        ("1.0 - 1.2, 1.4 - 1.6", "1.3", False),
        ("1.0 - 1.2, 1.4 - 1.6", "1.5", True),
    ],
)
def test_parse_version_range(value: str, version: str, is_affected: bool) -> None:
    assert any(version in x for x in parse_version_range(value)) is is_affected


@pytest.mark.parametrize(
    "value, patched, version, is_affected",
    [
        (">=37.0.0", ">=38.0.3", "38.0.2", True),
        (">=37.0.0", ">=38.0.3", "38.0.3", False),
        (">=37.0.0", ">=38.0.3", "50.0.0", False),
        (">= 44.0.0", "50.0.0", "49.9", True),
        (">3.1", "3.3.2+", "3.3.2", False),
        ("", "Pillow 12.1.1", "12.1.0", True),
        ("", "Pillow 12.1.1", "12.1.1", False),
        (">=1.0", "1.2.5, 2.0.1", "2.0.0", True),
        ("<= 48.0.0", ">=49.0.0", "48.0.0", True),
        ("11.2.1 - 13.0.0", "", "13.0.0", True),
    ],
)
def test_parse_version_range_with_patched(
    value: str, patched: str, version: str, is_affected: bool
) -> None:
    ranges = parse_version_range(value, patched)
    assert any(version in x for x in ranges) is is_affected


def test_unparseable_range_is_reported() -> None:
    obj = GithubRepoSecurityAdvisory.using({}, "pkg", "all versions")
    assert obj.is_affected("1.0")


@pytest.mark.parametrize(
    "info, repo",
    [
        (
            {
                "home_page": None,
                "project_urls": {
                    "Funding": "https://github.com/sponsors/someone",
                    "Homepage": "https://python-pillow.org",
                    "Source": "https://github.com/python-pillow/Pillow",
                },
            },
            "python-pillow/Pillow",
        ),
        ({"home_page": "https://github.com/a/b.git", "project_urls": None}, "a/b"),
        ({"home_page": "https://example.com", "project_urls": {}}, None),
        (
            {
                "home_page": "https://github.com/a/..",
                "project_urls": {"Source": "https://github.com/../b"},
            },
            None,
        ),
    ],
)
def test_find_github_repo(info: dict, repo: str) -> None:
    with mock.patch(
        "skjold.sources.github_repo._get_json", return_value={"info": info}
    ):
        assert find_github_repo("pkg", "1.0") == repo


def test_fetch_repo_advisories_follows_next_links() -> None:
    pages = [([{"ghsa_id": "GHSA-1"}], "https://next"), ([{"ghsa_id": "GHSA-2"}], None)]
    with mock.patch.dict(os.environ, {"SKJOLD_GITHUB_API_TOKEN": "tok"}), mock.patch(
        "skjold.sources.github_repo._get_json_and_next", side_effect=pages
    ) as get:
        assert _fetch_repo_advisories("a/b") == [
            {"ghsa_id": "GHSA-1"},
            {"ghsa_id": "GHSA-2"},
        ]

    (first_url, headers), _ = get.call_args_list[0]
    assert (
        first_url
        == "https://api.github.com/repos/a/b/security-advisories?state=published&per_page=100"
    )
    assert headers["Authorization"] == "Bearer tok"
    assert get.call_args_list[1][0][0] == "https://next"


def test_fetch_repo_advisories_requires_token() -> None:
    with mock.patch.dict(os.environ, clear=True), mock.patch(
        "skjold.sources.github_repo._get_json_and_next"
    ) as get:
        with pytest.raises(click.UsageError):
            _fetch_repo_advisories("a/b")
    assert not get.called


def test_fetch_repo_advisories_missing_repo() -> None:
    with mock.patch.dict(os.environ, {"SKJOLD_GITHUB_API_TOKEN": "tok"}), mock.patch(
        "skjold.sources.github_repo._get_json_and_next", return_value=(None, None)
    ):
        assert _fetch_repo_advisories("a/b") == []


def test_lookup_is_cached(tmp_path: Path) -> None:
    advisories = [{"ghsa_id": "GHSA-1"}]
    with mock.patch(
        "skjold.sources.github_repo.find_github_repo", return_value="a/b"
    ) as find, mock.patch(
        "skjold.sources.github_repo._fetch_repo_advisories", return_value=advisories
    ) as fetch:
        source = GithubRepo(str(tmp_path), cache_expires=3600)
        assert source._lookup(Dependency("Pkg", "1.0")) == ("a/b", advisories)
        assert source._lookup(Dependency("pkg", "1.0")) == ("a/b", advisories)
        assert find.call_count == 1
        assert fetch.call_count == 1

        GithubRepo(str(tmp_path), cache_expires=0)._lookup(Dependency("pkg", "1.0"))
        assert fetch.call_count == 2


@pytest.mark.parametrize(
    "dependency, error",
    [
        (Dependency("/tmp/evil", "1.0"), SkjoldException),
        (Dependency("pkg", "1.0/../../evil"), InvalidVersion),
    ],
)
def test_lookup_rejects_paths(
    dependency: Dependency, error: Type[Exception], tmp_path: Path
) -> None:
    cache_dir = tmp_path / "cache"
    with mock.patch(
        "skjold.sources.github_repo.find_github_repo", return_value=None
    ) as find:
        with pytest.raises(error):
            GithubRepo(str(cache_dir), cache_expires=3600)._lookup(dependency)
    assert not find.called
    assert list(tmp_path.rglob("*.json")) == []


def test_is_vulnerable_package(tmp_path: Path) -> None:
    advisories = [
        {
            "ghsa_id": "GHSA-aaaa",
            "html_url": "https://github.com/a/b/security/advisories/GHSA-aaaa",
            "summary": "bad",
            "severity": "high",
            "state": "published",
            "withdrawn_at": None,
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "pip", "name": "Pkg"},
                    "vulnerable_version_range": "1.0 - 2.0",
                },
                {
                    "package": {"ecosystem": "npm", "name": "pkg"},
                    "vulnerable_version_range": "",
                },
                {
                    "package": {"ecosystem": "pip", "name": "other"},
                    "vulnerable_version_range": "",
                },
            ],
        },
        {
            "ghsa_id": "GHSA-cccc",
            "html_url": "https://github.com/a/b/security/advisories/GHSA-cccc",
            "summary": "no ecosystem",
            "severity": "low",
            "state": "published",
            "withdrawn_at": None,
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "", "name": "pkg"},
                    "vulnerable_version_range": ">= 1.0",
                    "patched_versions": ">=1.8",
                },
            ],
        },
        {
            "ghsa_id": "GHSA-bbbb",
            "state": "published",
            "withdrawn_at": "2024-01-01T00:00:00Z",
            "vulnerabilities": [{"package": None, "vulnerable_version_range": ""}],
        },
        {
            "ghsa_id": "GHSA-eeee",
            "state": "draft",
            "withdrawn_at": None,
            "vulnerabilities": [{"package": None, "vulnerable_version_range": ""}],
        },
    ]
    with mock.patch(
        "skjold.sources.github_repo.find_github_repo", return_value="a/b"
    ), mock.patch(
        "skjold.sources.github_repo._fetch_repo_advisories", return_value=advisories
    ):
        source = GithubRepo(str(tmp_path))
        is_vulnerable, found = source.is_vulnerable_package(Dependency("pkg", "1.5"))
        assert is_vulnerable
        assert [a.identifier for a in found] == ["GHSA-aaaa", "GHSA-cccc"]
        assert found[0].severity == "HIGH"

        is_vulnerable, found = source.is_vulnerable_package(Dependency("pkg", "2.1"))
        assert not is_vulnerable


@pytest.mark.parametrize("verbose", [True, False])
def test_verbose_no_repo(
    verbose: bool, capsys: pytest.CaptureFixture, tmp_path: Path
) -> None:
    with mock.patch("skjold.sources.github_repo.find_github_repo", return_value=None):
        source = GithubRepo(str(tmp_path), verbose=verbose)
        assert source.is_vulnerable_package(Dependency("pkg", "1.0")) == (False, [])

    err = capsys.readouterr().err
    assert ("no GitHub repo found for pkg==1.0" in err) is verbose


@pytest.mark.parametrize("verbose", [True, False])
@pytest.mark.parametrize(
    "vulnerable_range, patched, message",
    [
        (
            ">=1.3.3 and <= 1.4.1",
            "1.3.5, 1.4.2",
            "GHSA-dddd has unparseable range '>=1.3.3 and <= 1.4.1'",
        ),
        ("", "", "GHSA-dddd has no version range"),
    ],
)
def test_verbose_range_warnings(
    verbose: bool,
    vulnerable_range: str,
    patched: str,
    message: str,
    capsys: pytest.CaptureFixture,
    tmp_path: Path,
) -> None:
    advisories = [
        {
            "ghsa_id": "GHSA-dddd",
            "html_url": "https://github.com/a/b/security/advisories/GHSA-dddd",
            "summary": "odd range",
            "severity": "low",
            "state": "published",
            "withdrawn_at": None,
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "pip", "name": "pkg"},
                    "vulnerable_version_range": vulnerable_range,
                    "patched_versions": patched,
                },
            ],
        },
    ]
    with mock.patch(
        "skjold.sources.github_repo.find_github_repo", return_value="a/b"
    ), mock.patch(
        "skjold.sources.github_repo._fetch_repo_advisories", return_value=advisories
    ):
        source = GithubRepo(str(tmp_path), verbose=verbose)
        is_vulnerable, _ = source.is_vulnerable_package(Dependency("pkg", "9.0"))
        assert is_vulnerable

    err = capsys.readouterr().err
    assert (message in err) is verbose
