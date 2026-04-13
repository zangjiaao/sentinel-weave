from typer.testing import CliRunner

from security_analyst_agent.cli import app


def test_cli_shows_help() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "alert.fetch" in result.stdout
