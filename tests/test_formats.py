import io
import os
from typing import Optional, List, Tuple, Iterator

import pytest

from skjold.formats import (
    _extract_package_list_from,
    read_requirements_txt_from,
    extract_dependencies_from_files,
)
from skjold.core import Dependency
from skjold.tasks import Configuration

from packaging.utils import NormalizedName


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
        packages = list(_extract_package_list_from(Configuration(), fh, None))
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
        packages = list(_extract_package_list_from(Configuration(), fh, format_))
        assert len(packages) > 0


@pytest.mark.parametrize(
    "name, version, expected_name, expected_version, expected_canonical_name",
    [
        ("PyYAML", "1.0", "PyYAML", "1.0", "pyyaml"),
        ("Requests", "1.23.0", "Requests", "1.23.0", "requests"),
        ("requests", "1.22.0", "requests", "1.22.0", "requests"),
        ("Django", "1.22.0", "Django", "1.22.0", "django"),
        (
            "google_cloud_storage",
            "1.0",
            "google_cloud_storage",
            "1.0",
            "google-cloud-storage",
        ),
    ],
)
def test_dependency_canonicalize_name(
    name: str,
    version: str,
    expected_name: str,
    expected_version: str,
    expected_canonical_name: NormalizedName,
) -> None:
    dependency = Dependency(name=name, version=version)

    assert dependency.name == expected_name
    assert dependency.version == expected_version
    assert dependency.canonical_name == expected_canonical_name


@pytest.mark.parametrize(
    "stdin, expected_package_list",
    [
        ('package==0.6.0; python_version < "3.8"', [("package", "0.6.0", 1)]),
        (
            'foo==0.6.0; python_version < "3.8"\nbar==1.0.0',
            [("foo", "0.6.0", 1), ("bar", "1.0.0", 2)],
        ),
        ('foo==1.4.0; python_version < "3.8"', [("foo", "1.4.0", 1)]),
        ('foo==1.3.0; sys_platform == "win32"', [("foo", "1.3.0", 1)]),
        # Ensure that we are able to handle dependencies with (multi-line) hashes.
        (
            "foo==1.3.0 --hash=sha256:05668158c7b85b791c5abde53e50265e16f98ad601c402ba44d70f96c4159612",
            [("foo", "1.3.0", 1)],
        ),
        (
            "foo==1.3.0 --hash=sha256:deaddood...\\ \n --hash=sha256:deadbeef...\nbar==1.2.0",
            [("foo", "1.3.0", 1), ("bar", "1.2.0", 3)],
        ),
        # Ensure that we are able to handle comments.
        ("# comment==0.1.2", []),
        (
            'bar==1.2.0\n # comment==0.1.2\nfoo==1.3.0; sys_platform == "win32"',
            [("bar", "1.2.0", 1), ("foo", "1.3.0", 3)],
        ),
        # Ensure we skip invalid lines.
        (
            "bar==1.2.0\n--trusted-host internal-host\nfoo==1.3.0\n--extra-index-url http://internal-host/pypi/index/",
            [("bar", "1.2.0", 1), ("foo", "1.3.0", 3)],
        ),
    ],
)
def test_extract_package_versions_from(
    stdin: str, expected_package_list: List[Tuple[str, str, int]]
) -> None:
    contents = io.StringIO(stdin)
    contents.name = "<stdin>"
    packages = read_requirements_txt_from(contents)

    def _get_dependencies(items: List[Tuple[str, str, int]]) -> Iterator[Dependency]:
        for name, version, line_no in items:
            yield Dependency(name=name, version=version, source=("<stdin>", line_no))

    assert list(packages) == list(_get_dependencies(expected_package_list))


def test_extract_dependencies_from_files() -> None:
    path_a = format_fixture_path_for("minimal", "requirements.txt")
    path_b = format_fixture_path_for("minimal", "poetry.lock")
    path_c = format_fixture_path_for("minimal", "Pipfile.lock")
    config = Configuration()

    with open(path_a) as fha:
        with open(path_b) as fhb:
            with open(path_c) as fhc:
                dependencies = list(
                    extract_dependencies_from_files(config, [fha, fhb, fhc])
                )

    sources = set()
    for dep in dependencies:
        assert dep.canonical_name
        assert dep.name
        assert dep.version
        assert dep.source[0]
        sources.add(dep.source[0])

    assert sources == set({path_a, path_b, path_c})


def test_extract_package_versions_from_file_with_hashes() -> None:
    path_ = format_fixture_path_for("pip", "requirements_with_hashes.txt")
    with open(path_) as fh:
        packages = read_requirements_txt_from(fh)
        assert list(packages) == [
            Dependency("appdirs", "1.4.3", (path_, 1)),
            Dependency("argh", "0.26.2", (path_, 4)),
            Dependency("aspy.yaml", "1.3.0", (path_, 7)),
            Dependency("atomicwrites", "1.3.0", (path_, 10)),
            Dependency("attrs", "19.3.0", (path_, 13)),
        ]
