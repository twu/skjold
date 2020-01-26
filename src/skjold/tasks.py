# -*- coding: utf-8 -*-
"""Contains actual task implementations that can be either called directly or via the click cli."""
import json
import textwrap
from typing import List, MutableMapping, Type, AbstractSet, Union, Dict, Any, Tuple, Set

import click

from skjold.models import SecurityAdvisorySource, PackageList, SkjoldException

_sources: MutableMapping[str, Type[SecurityAdvisorySource]] = {}


class Configuration(object):
    sources: List[str] = []  # Advisory sources enabled by default.
    report_only: bool = False  # Return non-zero exit code when vulnerabilities are found.
    report_format: str = "json"  # Output parsable JSON instead of stupid colors.
    cache_dir: str = ".skjold_cache"  # Cache location.
    cache_expires: int = 12 * 3600  # Cache maximum age.
    verbose: bool = False  # Be verbose when processing package list.

    @property
    def available_sources(self) -> AbstractSet[str]:
        """Return list of available sources by name."""
        return _sources.keys()

    @property
    def as_dict(self) -> MutableMapping[str, Union[bool, str, int, List]]:
        """Return dictionary representation of configuration object."""
        return {
            "sources": self.sources,
            "report_only": self.report_only,
            "report_format": self.report_format,
            "verbose": self.verbose,
            "cache_dir": self.cache_dir,
            "cache_expires": self.cache_expires,
        }


def register_source(new_source_name: str, source: Type[SecurityAdvisorySource]) -> None:
    """Registers a new source by name. Throws Exception otherwise."""
    if not new_source_name or new_source_name in _sources:
        raise SkjoldException(
            f"A source named '{new_source_name}' appears to be already registered!"
        )

    _sources[new_source_name] = source


def get_registered_sources() -> AbstractSet[str]:
    """Return list of keys for registered advisory sources."""
    return _sources.keys()


def is_registered_source(name: str) -> bool:
    """Return True if a resource by the given name exists. False otherwise."""
    return name in _sources.keys()


def print_configuration(configuration: Configuration, stderr: bool = True) -> None:
    """Prints the currently active configuration for skjold to stdout and exits."""
    for key, value in configuration.as_dict.items():
        click.secho(key, fg="white", nl=False, err=stderr)
        click.secho(": ", nl=False, err=stderr)
        click.secho(str(value), fg="white", nl=False, err=stderr)
        click.secho("", err=stderr)


def report(configuration: Configuration, results: List[Dict[str, Any]]) -> None:
    """..."""

    if configuration.report_format == "json":
        click.echo(json.dumps(results, indent=2))
        return

    for result in results:
        _color = {
            "MEDIUM": "white",
            "MODERATE": "yellow",
            "HIGH": "red",
            "UNKNOWN": "yellow",
        }[result["severity"]]

        click.secho("")
        click.secho(result["name"], fg="white", nl=False)
        click.secho("==", nl=False)
        click.secho(result["version"], fg=_color, nl=False)
        click.secho(" (", nl=False)
        click.secho(result["versions"], fg=_color, nl=False)
        click.secho(") via ", nl=False)
        click.secho(result["source"], fg="cyan")

        click.secho("")
        click.secho(textwrap.fill(result["summary"], 79), fg="white")
        click.secho(result["url"], fg="green")
        click.secho("-- ")


def audit(
    configuration: Configuration, packages: PackageList
) -> Tuple[List[Dict[str, Any]], Set[str]]:
    """..."""

    results, vulnerable_packages = [], set({})
    for name in configuration.sources:
        source = _sources[name](
            cache_dir=configuration.cache_dir, cache_expires=configuration.cache_expires
        )

        for package_name, package_version in packages:
            if source.has_security_advisory_for(package_name):
                is_vulnerable, advisories = source.is_vulnerable_package(
                    package_name, package_version
                )

                if is_vulnerable:
                    vulnerable_packages.add(package_name)
                    for advisory in advisories:
                        results.append(
                            {
                                "severity": advisory.severity,
                                "name": package_name,
                                "version": package_version,
                                "versions": advisory.vulnerable_versions,
                                "source": source.name,
                                "summary": advisory.summary,
                                "references": advisory.references,
                                "url": advisory.url,
                            }
                        )

    return results, vulnerable_packages
