from typer.testing import CliRunner

from security_analyst_agent.cli import app


def test_cli_shows_help() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "alert.fetch" in result.stdout


def test_cli_exposes_actor_case_commands() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "actor.case-list" in result.output
    assert "actor.case-upsert" in result.output
    assert "actor.case-find-candidates" in result.output
