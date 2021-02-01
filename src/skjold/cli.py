#!/usr/bin/env python
# -*- coding: utf-8 -*-
__version__ = "0.2.1"

import os
import sys
from typing import List, TextIO

import click
import skjold.sources

from skjold.formats import extract_package_list_from, Format
from skjold.tasks import (
    Configuration,
    audit,
    print_configuration,
    report,
    get_registered_sources,
    default_from_context,
    get_configuration_from_toml,
)

configuration = click.make_pass_decorator(Configuration, ensure=True)


@click.group()  # pragma: no cover
@click.option(
    "configuration_file",
    "-c",
    "--configuration-file",
    envvar="SKJOLD_RC",
    type=click.Path(exists=False, dir_okay=False, resolve_path=True),
    default="./pyproject.toml",
    show_default=True,
    required=False,
)
@click.option(
    "verbose",
    "-v",
    "--verbose",
    envvar="SKJOLD_VERBOSE",
    is_flag=True,
    default=False,
    show_default=True,
)
@click.version_option(version=__version__, prog_name="skjold")
@configuration
def cli(
    config: Configuration,
    configuration_file: click.Path,
    verbose: bool,
) -> None:
    """ Check a given Python dependency file against a set of advisory databases."""
    config.verbose = verbose

    file_ = str(configuration_file)
    skip_configuration = not os.environ.get("SKJOLD_SKIP_RC", None) is None

    if os.path.exists(file_) and not skip_configuration:
        settings = get_configuration_from_toml(file_)
        config.use(config=settings)
    else:
        click.secho("Warning: No 'pyproject.toml' found!", err=True, fg="yellow")

    if config.verbose:
        print_configuration(config)
        click.secho(f"Using {config.cache_dir} as cache location", err=True)

    # Cache Directory
    # Check for cache directory and create it if necessary.
    if not os.path.isdir(config.cache_dir):
        os.makedirs(config.cache_dir, exist_ok=True)
        if config.verbose:
            click.secho(
                f"Cache '{config.cache_dir}' does not exist! Creating it.",
                err=True,
            )

    if not os.path.isdir(config.cache_dir):
        raise click.ClickException(
            f"Unable to create cache directory '{config.cache_dir}'!"
        )


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
    cls=default_from_context("report_only", Configuration),
    help="Only report findings, always exit with zero.",
    show_default=True,
)
@click.option(
    "report_format",
    "-o",
    "--report-format",
    type=click.Choice(["json", "cli"], case_sensitive=True),
    cls=default_from_context("report_format", Configuration),
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
    cls=default_from_context("sources", Configuration),
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
