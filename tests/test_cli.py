# -*- coding: utf-8 -*-
import json
import os
from typing import Generator

import click.testing
import pytest
from _pytest.monkeypatch import MonkeyPatch
from click.testing import make_input_stream

import skjold
from skjold.cli import cli
from skjold.tasks import Configuration


def format_fixture_path_for(filename: str) -> str:
    path_ = os.path.join(
        os.path.dirname(__file__), "fixtures", "formats", "minimal", filename
    )
    assert os.path.exists(path_)
    return path_


@pytest.fixture(scope="session")
def runner() -> Generator:
    runner_ = click.testing.CliRunner(mix_stderr=False)
    with runner_.isolated_filesystem():
        yield runner_


def test_cli_run_config(
    runner: click.testing.CliRunner, cache_dir: str, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setenv("SKJOLD_CACHE_DIR", cache_dir)
    config = Configuration()
    config.use({"report_only": False, "report_format": "cli", "sources": ["pyup"]})

    result = runner.invoke(cli, args=["config"])
    assert result.exit_code == 0


def test_vulnerable_package_via_cli(
    runner: click.testing.CliRunner, cache_dir: str, monkeypatch: MonkeyPatch
) -> None:
    """Ensure that passing a vulnerable package via stdin produces the expected
    output."""
    monkeypatch.setenv("SKJOLD_CACHE_DIR", cache_dir)
    config = Configuration()
    config.use({"report_only": False, "report_format": "cli", "sources": ["pyup"]})

    # TODO(twu): Figure out how to do this right.
    input_ = make_input_stream("urllib3==1.23\nrequests==22.2.2\n", "utf-8")
    setattr(input_, "name", "<stdin>")

    result = runner.invoke(cli, args=["audit", "-s", "github", "-"], input=input_)
    assert result.exception
    assert result.exit_code == 1
    assert "via github" in result.stdout


def test_cli_json_report_with_package_list_via_stdin(
    runner: click.testing.CliRunner,
    cache_dir: str,
    monkeypatch: MonkeyPatch,
) -> None:
    """Ensure request json output with packages via stdin results in parsable stdout."""
    monkeypatch.setenv("SKJOLD_CACHE_DIR", cache_dir)
    config = Configuration()
    config.use({"report_only": False, "report_format": "cli", "sources": ["pyup"]})

    # TODO(twu): Figure out how to do this right.
    input_ = make_input_stream("urllib3==1.23\nrequests==22.2.2\n", "utf-8")
    setattr(input_, "name", "<stdin>")

    result = runner.invoke(
        cli, args=["audit", "-r", "-o", "json", "-s", "github", "-"], input=input_
    )
    assert not result.exception
    assert result.exit_code == 0

    json_ = json.loads(result.stdout)

    assert len(json_) > 0
    assert json_[0]["name"] == "urllib3"


@pytest.mark.parametrize(
    "folder, filename",
    [
        ("minimal", "poetry.lock"),
        ("minimal", "requirements.txt"),
        ("minimal", "Pipfile.lock"),
    ],
)
def test_cli_ensure_formats_are_handled_properly(
    folder: str,
    filename: str,
    runner: click.testing.CliRunner,
    cache_dir: str,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv("SKJOLD_CACHE_DIR", cache_dir)
    config = Configuration()
    config.use({"report_only": False, "report_format": "cli", "sources": ["pyup"]})

    path = format_fixture_path_for(filename)

    result = runner.invoke(
        cli,
        args=["audit", "-r", "-o", "json", "-s", "github", path],
        env={"SKJOLD_CACHE_DIR": cache_dir},
    )

    assert not result.exception
    assert result.exit_code == 0

    json_ = json.loads(result.stdout)

    assert len(json_) > 0
    assert json_[0]["name"] == "urllib3"
    assert json_[0]["source"] == "github"


def test_cli_configuration_override_via_cli(
    runner: click.testing.CliRunner,
    cache_dir: str,
    monkeypatch: MonkeyPatch,
) -> None:
    """Ensure that overriding configured values via CLI is possible."""
    monkeypatch.setenv("SKJOLD_CACHE_DIR", cache_dir)
    config = Configuration()
    config.use(
        {
            "report_only": True,
            "report_format": "json",
            "sources": ["pyup"],
            "cache_dir": cache_dir,
        }
    )
    result = runner.invoke(cli, args=["config"], obj=config)
    assert "report_only: True" in result.stderr
    assert "report_format: json" in result.stderr

    # TODO(twu): Figure out how to do this right.
    input_ = make_input_stream("urllib3==1.23\nrequests==22.2.2\n", "utf-8")
    setattr(input_, "name", "<stdin>")

    result = runner.invoke(
        cli,
        args=["audit", "-r", "-s", "github", "-o", "cli", "-"],
        input=input_,
        env={"SKJOLD_CACHE_DIR": cache_dir},
        obj=config,
    )
    assert result.exit_code == 0
    assert "urllib3" in result.stdout
    assert "via github" in result.stdout


def test_cli_configuration_used_by_default(
    runner: click.testing.CliRunner,
    cache_dir: str,
    monkeypatch: MonkeyPatch,
) -> None:
    """Ensure that we use options set in the configuration file if not overridden by passing CLI options."""
    monkeypatch.setenv("SKJOLD_CACHE_DIR", cache_dir)
    config = Configuration()
    config.use({"report_only": True, "report_format": "json", "sources": ["gemnasium"]})

    result = runner.invoke(cli, args=["config"], obj=config)
    assert "report_only: True" in result.stderr
    assert "report_format: json" in result.stderr

    # TODO(twu): Figure out how to do this right.
    input_ = make_input_stream("urllib3==1.23\nrequests==22.2.2\n", "utf-8")
    setattr(input_, "name", "<stdin>")

    result = runner.invoke(
        cli,
        args=["audit", "-"],
        env={"SKJOLD_CACHE_DIR": cache_dir},
        input=input_,
        obj=config,
    )
    assert result.exit_code == 0

    json_ = json.loads(result.stdout)
    assert len(json_) > 0
    assert json_[0]["name"] == "urllib3"
    assert json_[0]["source"] == "gemnasium"
