import json
import os
from typing import TextIO, MutableMapping, Callable, Optional, Iterator

import click
import toml

from skjold.models import PackageList, Package, SkjoldException
from skjold.tasks import Configuration


def read_poetry_lock_from(file: TextIO) -> Iterator[Package]:
    """Reads a poetry.lock given by path and yields 'package==version' items."""
    doc = toml.loads(file.read())
    for package in doc.get("package", []):
        yield package["name"], package["version"]


def read_pipfile_lock_from(file: TextIO) -> Iterator[Package]:
    """Reads a Pipfile.lock given by path and yields 'package==version' items."""
    json_ = json.load(file)
    for namespace in ["develop", "default"]:
        for package_name in json_[namespace].keys():
            package_info = json_[namespace][package_name]

            if "version" not in package_info:
                continue

            pinned_package_version = package_info["version"]
            if not pinned_package_version.startswith("=="):
                raise SkjoldException(
                    f"Unexpected value for pinned version '{pinned_package_version}'!"
                )

            package_version = pinned_package_version.replace("==", "")
            yield package_name, package_version


def read_requirements_txt_from(file: TextIO) -> Iterator[Package]:
    """Reads a requirements.txt given by path and yields 'package==version' items."""
    for line in file.readlines():
        # Skip empty lines or lines only containing a hash.
        if line.strip().startswith("--hash") or not len(line.strip()):
            continue
        # Skip lines only containing editable packages.
        if line.strip().startswith("-e"):
            continue
        # Skip comment lines.
        if line.strip().startswith("#"):
            continue

        try:
            line = line.split(";")[0]
            package_name, package_version = line.strip().split(" ")[0].split("==")
            yield package_name, package_version
        except (ValueError, KeyError):
            click.secho("Warning! ", err=True, nl=False, fg="yellow")
            click.secho(
                f"Unable extract package and version from '{line.strip()}'. Skipping!",
                err=True,
            )
            continue


class Format:  # pragma: no cover
    POETRY: str = "poetry.lock"
    REQUIREMENTS: str = "requirements.txt"
    PIPENV: str = "Pipfile.lock"

    SUPPORTED_FORMATS: MutableMapping[str, Callable] = {
        POETRY: read_poetry_lock_from,
        REQUIREMENTS: read_requirements_txt_from,
        PIPENV: read_pipfile_lock_from,
    }


def extract_package_list_from(
    configuration: Configuration, file: TextIO, format_: Optional[str] = None
) -> PackageList:
    """Extracts the list of tuples containing package name and version."""
    filename = os.path.basename(file.name)

    if not format_ or filename in Format.SUPPORTED_FORMATS.keys():
        format_ = filename
        if configuration.verbose:
            click.secho(f"Assuming '{format_}' from filename.", err=True)

    reader_func = Format.SUPPORTED_FORMATS.get(format_, None)
    if not reader_func:
        raise SkjoldException(f"Unsupported file or format '{format_}'!")

    _packages = []
    for package in reader_func(file):
        _packages.append(package)

    return _packages
