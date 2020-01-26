#!/usr/bin/env python
# -*- coding: utf-8 -*-
__version__ = "0.1.0"

import os
import sys
from typing import List, TextIO

import click
import tomlkit
import skjold.sources

from skjold.formats import extract_package_list_from, Format
from skjold.tasks import (
    Configuration,
    audit,
    print_configuration,
    report,
    is_registered_source,
    get_registered_sources,
)

configuration = click.make_pass_decorator(Configuration, ensure=True)


@click.group()  # pragma: no cover
@click.option(
    "configuration_file",
    "-c",
    "--configuration-file",
    type=click.Path(exists=False, dir_okay=False, resolve_path=True),
    default="./pyproject.toml",
    show_default=True,
    required=False,
)
@click.option(
    "verbose", "-v", "--verbose", is_flag=True, default=False, show_default=True
)
@click.version_option(version=__version__, prog_name="skjold")
@configuration
def cli(config: Configuration, configuration_file: click.Path, verbose: bool) -> None:
    """ Check a given Python dependency file against a set of advisory databases."""

    doc = {}
    if os.path.exists(str(configuration_file)):
        with open(str(configuration_file)) as fh:
            doc = tomlkit.parse(fh.read())
    else:
        click.secho("Warning: No 'pyproject.toml' found!", err=True, fg="yellow")

    _config = doc.get("tool", {}).get("skjold", {})

    # Configuration file
    config.report_only = _config.get("report_only", config.report_only)
    config.report_format = _config.get("report_format", config.report_format)
    config.cache_dir = _config.get("cache_dir", config.cache_dir)
    config.cache_expires = _config.get("cache_expires", config.cache_expires)
    config.verbose = verbose

    # Configure cache_dir selection: ENV > pyproject.toml > default(posix).
    app_home = click.get_app_dir("skjold", roaming=False, force_posix=True)
    default_cache_dir = os.path.join(app_home, "cache")
    config.cache_dir = os.environ.get(
        "SKJOLD_CACHE_DIR", _config.get("cache_dir", default_cache_dir)
    )
    if config.verbose:
        click.secho(f"Using {config.cache_dir} as cache location", err=True)

    # Check for cache directory and create it if necessary.
    if not os.path.isdir(config.cache_dir):
        os.makedirs(config.cache_dir, exist_ok=True)
        if config.verbose:
            click.secho(
                f"Cache '{config.cache_dir}' does not exist! Creating it.", err=True
            )

    if not os.path.isdir(config.cache_dir):
        raise click.ClickException(
            f"Unable to create cache directory '{config.cache_dir}'!"
        )

    # Configure and validate sources.
    config.sources = _config.get("sources", [])
    if not len(config.sources):
        click.secho("Warning: No advisory sources configured!", err=True, fg="yellow")

    for source_name in config.sources:
        if not is_registered_source(source_name):
            raise click.ClickException(
                f"Source with name '{source_name}' does not exist!"
            )

    if config.verbose:
        print_configuration(config)


@cli.command("config")  # pragma: no cover
@configuration
def config_(config: Configuration) -> None:
    """Print the current configuration and exit."""
    print_configuration(config)


@cli.command("audit")  # pragma: no cover
@click.option(
    "report_only",
    "-r",
    "--report-only",
    is_flag=True,
    default=False,
    help="Only report findings, always exit with zero.",
    show_default=True,
)
@click.option(
    "report_format",
    "-o",
    "--report-format",
    type=click.Choice(["json", "cli"], case_sensitive=True),
    default="cli",
    help="Output format",
    show_default=True,
)
@click.option(
    "file_format",
    "-f",
    "--file-format",
    type=click.Choice(Format.SUPPORTED_FORMATS, case_sensitive=True),
    default=Format.REQUIREMENTS,
    help="Input format",
    show_default=True,
)
@click.option(
    "sources",
    "-s",
    "--sources",
    type=click.Choice(get_registered_sources(), case_sensitive=True),
    default=[],
    help="Identifier of a registered advisory source.",
    show_default=False,
    multiple=True,
)
@click.argument("file", type=click.File(), default="./requirements.txt", required=False)
@configuration
def audit_(
    config: Configuration,
    report_only: bool,
    report_format: str,
    file_format: str,
    sources: List[str],
    file: TextIO,
) -> None:
    """
    Checks a given dependency file against advisory databases.

    \b
    FILE is the path to the dependency file to audit.
    """
    config.report_only = report_only
    config.report_format = report_format
    # Only override sources if at least once --source is passed.
    if len(sources) > 0:
        config.sources = list(set(sources))

    if len(config.sources) == 0:
        raise click.ClickException(
            "Please specify or configure at least one advisory source."
        )

    packages = extract_package_list_from(config, file, file_format)

    if config.verbose:
        click.secho("Checking ", nl=False, err=True)
        click.secho(f"{len(packages)}", fg="green", nl=False, err=True)
        click.secho(" package(s).", err=True)

        click.secho("Using ", nl=False, err=True)
        click.secho(f"{config.sources}", fg="green", nl=False, err=True)
        click.secho(" as source(s).", err=True)

    results, vulnerable = audit(config, packages)

    report(config, results)

    if len(vulnerable) > 0 and config.verbose:
        click.secho("", err=True)
        click.secho(
            f"  Found {len(vulnerable)} vulnerable packages!",
            fg="red",
            blink=True,
            err=True,
        )
        click.secho("", err=True)
    elif config.verbose:
        click.secho("", err=True)
        click.secho(f"  No vulnerable packages found!", fg="green", err=True)

    # By default we want to exit with a non-zero exit-code when we encounter
    # any findings.
    if not config.report_only and len(vulnerable) > 0:
        sys.exit(1)


if __name__ == "__main__":
    cli()
