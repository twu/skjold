# -*- coding: utf-8 -*-
import io
import os
from typing import Optional

import pytest

from skjold.formats import extract_package_list_from, read_requirements_txt_from
from skjold.models import PackageList
from skjold.tasks import Configuration


def format_fixture_path_for(folder: str, filename: str) -> str:
    path_ = os.path.join(
        os.path.dirname(__file__), "fixtures", "formats", folder, filename
    )
    assert os.path.exists(path_)
    return path_


@pytest.mark.parametrize("folder", ["minimal", "random"])
@pytest.mark.parametrize(
    "filename", ["poetry.lock", "requirements.txt", "Pipfile.lock"]
)
def test_extract_dependencies_using_minimal_examples(
    folder: str, filename: str
) -> None:
    with open(format_fixture_path_for(folder, filename)) as fh:
        packages = list(extract_package_list_from(Configuration(), fh, None))
        assert len(packages) > 0


@pytest.mark.parametrize("folder", ["minimal", "random"])
@pytest.mark.parametrize(
    "filename, format_",
    [
        ("requirements.txt", None),
        ("poetry.lock", None),
        ("Pipfile.lock", None),
        ("requirements.txt", "requirements.txt"),
        ("poetry.lock", "poetry.lock"),
        ("Pipfile.lock", "Pipfile.lock"),
    ],
)
def test_extract_package_versions_from_with_poetry_lock(
    folder: str, filename: str, format_: Optional[str]
) -> None:

    with open(format_fixture_path_for(folder, filename)) as fh:
        packages = list(extract_package_list_from(Configuration(), fh, format_))
        assert len(packages) > 0


@pytest.mark.parametrize(
    "stdin, expected_package_list",
    [
        ('package==0.6.0; python_version < "3.8"', [("package", "0.6.0")]),
        (
            'foo==0.6.0; python_version < "3.8"\nbar==1.0.0',
            [("foo", "0.6.0"), ("bar", "1.0.0")],
        ),
        ('foo==1.4.0; python_version < "3.8"', [("foo", "1.4.0")]),
        ('foo==1.3.0; sys_platform == "win32"', [("foo", "1.3.0")]),
        # Ensure that we are able to handle dependencies with (multi-line) hashes.
        (
            "foo==1.3.0 --hash=sha256:05668158c7b85b791c5abde53e50265e16f98ad601c402ba44d70f96c4159612",
            [("foo", "1.3.0")],
        ),
        (
            "foo==1.3.0 --hash=sha256:deaddood...\\ \n --hash=sha256:deadbeef...\nbar==1.2.0",
            [("foo", "1.3.0"), ("bar", "1.2.0")],
        ),
        # Ensure that we are able to handle comments.
        ("# comment==0.1.2", []),
        (
            'bar==1.2.0\n # comment==0.1.2\nfoo==1.3.0; sys_platform == "win32"',
            [("bar", "1.2.0"), ("foo", "1.3.0")],
        ),
        # Ensure we skip invalid lines.
        (
            "bar==1.2.0\n--trusted-host internal-host\nfoo==1.3.0\n--extra-index-url http://internal-host/pypi/index/",
            [("bar", "1.2.0"), ("foo", "1.3.0")],
        ),
    ],
)
def test_extract_package_versions_from(
    stdin: str, expected_package_list: PackageList
) -> None:
    packages = read_requirements_txt_from(io.StringIO(stdin))
    assert list(packages) == expected_package_list


def test_extract_package_versions_from_file_with_hashes() -> None:
    with open(format_fixture_path_for("pip", "requirements_with_hashes.txt")) as fh:
        packages = read_requirements_txt_from(fh)
        assert list(packages) == [
            ("appdirs", "1.4.3"),
            ("argh", "0.26.2"),
            ("aspy.yaml", "1.3.0"),
            ("atomicwrites", "1.3.0"),
            ("attrs", "19.3.0"),
        ]
