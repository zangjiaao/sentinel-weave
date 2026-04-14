from pathlib import Path
import sys

from security_analyst_agent import hermes_slow_verify
from security_analyst_agent.hermes_slow_verify import (
    build_chat_command,
    load_integration_manifest,
    prepare_isolated_hermes_home,
    resolve_round_specs,
)


def test_load_integration_manifest_returns_expected_scenario() -> None:
    manifest = load_integration_manifest("hermes-slow-integration")

    assert manifest["scenario"] == "hermes-slow-integration"
    assert [item["round_id"] for item in manifest["rounds"]] == [
        "round_01_recon",
        "round_02_exploit",
        "round_03_new_ip",
        "round_04_lateral_prep",
        "round_05_silent_period",
        "round_06_reactivation",
    ]
    assert manifest["round_defaults"]["required_tool_names"][0] == "alert.fetch"


def test_resolve_round_specs_merges_defaults_and_round_overrides() -> None:
    manifest = {
        "round_defaults": {
            "query": "Run one patrol pass",
            "max_turns": 12,
            "required_tool_names": ["alert.fetch"],
            "required_any_tool_names": [["case.get", "case.timeline"]],
            "required_output_headers": ["## Patrol Action Summary"],
            "min_tool_calls": 2,
        },
        "rounds": [
            {"round_id": "round_01_recon"},
            {
                "round_id": "round_02_exploit",
                "max_turns": 18,
                "required_tool_names": ["alert.fetch", "alert.ack"],
            },
        ],
    }

    round_specs = resolve_round_specs(manifest)

    assert round_specs[0]["round_id"] == "round_01_recon"
    assert round_specs[0]["query"] == "Run one patrol pass"
    assert round_specs[0]["max_turns"] == 12
    assert round_specs[0]["required_tool_names"] == ["alert.fetch"]
    assert round_specs[1]["round_id"] == "round_02_exploit"
    assert round_specs[1]["max_turns"] == 18
    assert round_specs[1]["required_tool_names"] == ["alert.fetch", "alert.ack"]


def test_round_05_silent_period_keeps_default_output_contract() -> None:
    manifest = load_integration_manifest("hermes-slow-integration")

    round_specs = resolve_round_specs(manifest)
    round_05 = next(item for item in round_specs if item["round_id"] == "round_05_silent_period")

    assert round_05["required_output_headers"] == [
        "## Patrol Action Summary",
        "## Remaining Uncertainty",
        "## Memory Summary",
    ]
    assert "required_exact_output" not in round_05
    assert round_05["max_turns"] == 18


def test_build_chat_command_includes_query_and_skill() -> None:
    command = build_chat_command(
        query="Run one patrol pass",
        max_turns=12,
        model="openai/gpt-5",
        skills=["secagent-patrol"],
    )

    assert command[:3] == ["hermes", "chat", "-q"]
    assert "Run one patrol pass" in command
    assert "--max-turns" in command
    assert "12" in command
    assert "-m" in command
    assert "openai/gpt-5" in command
    assert "-s" in command
    assert "secagent-patrol" in command


def test_prepare_isolated_hermes_home_copies_required_files(tmp_path: Path) -> None:
    source_home = tmp_path / "source"
    source_home.mkdir()
    (source_home / "config.yaml").write_text("model:\n  default: demo\n", encoding="utf-8")
    (source_home / ".env").write_text("DUMMY=1\n", encoding="utf-8")
    (source_home / "auth.json").write_text("{}", encoding="utf-8")
    (source_home / "SOUL.md").write_text("# soul\n", encoding="utf-8")

    dest_home = tmp_path / "dest"
    repo_skill_dir = Path("skills/secagent-patrol")

    prepare_isolated_hermes_home(source_home=source_home, dest_home=dest_home, repo_skill_dir=repo_skill_dir)

    assert (dest_home / "config.yaml").exists()
    assert (dest_home / ".env").exists()
    assert (dest_home / "auth.json").exists()
    assert (dest_home / "SOUL.md").exists()
    assert (dest_home / "skills" / "secagent-patrol" / "SKILL.md").exists()


def test_main_prints_progress_to_stderr_and_summary_to_stdout(monkeypatch, capsys, tmp_path: Path) -> None:
    db_path = tmp_path / "slow.db"

    def fake_run_slow_integration(*, scenario, db_path, model, provider, keep_artifacts, progress):
        progress(1, 3, "准备隔离 Hermes Home")
        progress(2, 3, "启动 MCP server")
        progress(3, 3, "运行真实 Hermes patrol")
        return {"scenario": scenario, "db_path": str(db_path), "tool_calls_count": 5}

    monkeypatch.setattr(hermes_slow_verify, "run_slow_integration", fake_run_slow_integration)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "security_analyst_agent.hermes_slow_verify",
            "--scenario",
            "hermes-slow-integration",
            "--db-path",
            str(db_path),
        ],
    )

    hermes_slow_verify.main()

    captured = capsys.readouterr()
    assert "[1/3] 准备隔离 Hermes Home" in captured.err
    assert "[2/3] 启动 MCP server" in captured.err
    assert "[3/3] 运行真实 Hermes patrol" in captured.err
    assert "PASS: hermes slow integration verify hermes-slow-integration" in captured.out
    assert '"tool_calls_count": 5' in captured.out
