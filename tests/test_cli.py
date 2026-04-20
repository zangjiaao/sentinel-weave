from typer.testing import CliRunner

from security_analyst_agent.cli import app


def test_cli_shows_help() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "alert.fetch" in result.stdout
    assert "alert.detail-batch" in result.stdout
    assert "alert.raw-ingest" in result.stdout
    assert "alert.raw-sample" in result.stdout
    assert "alert.map-upsert" in result.stdout
    assert "alert.map-apply" in result.stdout
    assert "alert.unmapped-list" in result.stdout
    assert "alert.import-csv" in result.stdout
    assert "alert.import-jobs" in result.stdout
    assert "alert.import-sample" in result.stdout
    assert "alert.import-apply" in result.stdout
    assert "alert.import-problems" in result.stdout
    assert "audit.agent-outputs" in result.stdout


def test_cli_exposes_actor_case_commands() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "actor.case-list" in result.output
    assert "actor.case-upsert" in result.output
    assert "actor.case-find-candidates" in result.output
    assert "actor.case-add-observation-batch" in result.output
    assert "actor.case-link-batch" in result.output
    assert "case.upsert-batch" in result.output
    assert "case.link-alert-batch" in result.output
    assert "case.list" in result.output
    assert "case.search" in result.output
    assert "assessment.upsert-batch" in result.output
