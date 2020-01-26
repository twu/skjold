# -*- coding: utf-8 -*-
import os
import json
import pytest
import skjold
import click.testing
from click.testing import make_input_stream
import skjold.cli as cli


def format_fixture_path_for(filename: str) -> str:
    path_ = os.path.join(
        os.path.dirname(__file__), "fixtures", "formats", "minimal", filename
    )
    assert os.path.exists(path_)
    return path_


@pytest.fixture
def runner() -> click.testing.CliRunner:
    return click.testing.CliRunner()


def test_main_succeeds_in_production_env(runner: click.testing.CliRunner) -> None:
    result = runner.invoke(cli.config_)
    assert result.exit_code == 0


def test_vulnerable_package_via_cli(runner: click.testing.CliRunner) -> None:
    """Ensure that passing a vulnerable package via stdin produces the expected
    output."""

    # TODO(twu): Figure out how to do this right.
    input_ = make_input_stream("urllib3==1.23\nrequests==22.2.2\n", "utf-8")
    setattr(input_, "name", "<stdin>")

    result = runner.invoke(cli.cli, args=["audit", "-s", "github", "-"], input=input_)
    assert result.exception
    assert result.exit_code == 1
    assert "via github" in result.output


def test_cli_json_report_with_package_list_via_stdin(
    runner: click.testing.CliRunner,
) -> None:
    """Ensure request json output with packages via stdin results in parsable stdout."""

    # TODO(twu): Figure out how to do this right.
    input_ = make_input_stream("urllib3==1.23\nrequests==22.2.2\n", "utf-8")
    setattr(input_, "name", "<stdin>")

    result = runner.invoke(
        cli.cli, args=["audit", "-r", "-o", "json", "-s", "github", "-"], input=input_
    )
    assert not result.exception
    assert result.exit_code == 0

    json_ = json.loads(result.output)

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
    folder: str, filename: str, runner: click.testing.CliRunner
) -> None:

    path = format_fixture_path_for(filename)

    result = runner.invoke(
        cli.cli, args=["audit", "-r", "-o", "json", "-s", "github", path]
    )

    assert not result.exception
    assert result.exit_code == 0

    json_ = json.loads(result.output)

    assert len(json_) > 0
    assert json_[0]["name"] == "urllib3"
