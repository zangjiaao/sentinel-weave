import json
from pathlib import Path
import subprocess
import sys

from security_analyst_agent.db import connect_db
from security_analyst_agent.runbook_verify import run_scenario


def test_hermes_memory_spike_runbook_creates_cases_via_actions() -> None:
    manifest = json.loads(Path("docs/runbooks/manifests/hermes-memory-spike.json").read_text(encoding="utf-8"))

    first_round_tools = [item["tool"] for item in manifest["rounds"][0]["actions"]]
    assert "case.upsert" in first_round_tools
    assert "case.link-alert" in first_round_tools


def test_hermes_memory_spike_runbook_persists_runtime_evidence_and_timeline() -> None:
    manifest = json.loads(Path("docs/runbooks/manifests/hermes-memory-spike.json").read_text(encoding="utf-8"))

    later_round_tools = {
        item["tool"]
        for round_spec in manifest["rounds"][1:]
        for item in round_spec["actions"]
    }
    assert "evidence.upsert" in later_round_tools
    assert "timeline.upsert" in later_round_tools


def test_hermes_memory_spike_runbook_verifier_passes(tmp_path) -> None:
    db_path = tmp_path / "runbook-verify.db"

    summary = run_scenario("hermes-memory-spike", db_path=db_path)

    assert summary["scenario"] == "hermes-memory-spike"
    assert summary["rounds_applied"] == 6
    assert summary["round_count"] == 6
    assert summary["round1_detail_evidence_ids"] == []
    assert summary["round1_link_supporting_evidence_ids"] == []
    assert summary["high_attacker_ips"] == ["198.51.100.23", "198.51.100.77", "198.51.100.91"]
    assert summary["noise_ips"] == ["192.0.2.123", "192.0.2.91"]
    assert summary["compromised_host"] == {
        "entity_key": "203.0.113.10",
        "risk_level": "high",
        "verdict": "compromised_host",
    }

    conn = connect_db(db_path)
    run_rows = conn.execute(
        """
        select run_id, analysis_cutoff_at, status
        from patrol_runs
        where trigger_source = 'runbook_verify'
        order by started_at asc
        """
    ).fetchall()
    assert len(run_rows) == 6
    assert len({row["run_id"] for row in run_rows}) == 6
    assert all(row["analysis_cutoff_at"] for row in run_rows)
    assert all(row["status"] == "success" for row in run_rows)
    assert conn.execute("select count(*) from link_decisions").fetchone()[0] >= 2
    assert conn.execute("select count(*) from case_assessments").fetchone()[0] >= 2
    assert conn.execute("select count(*) from entity_assessments where is_current = 1").fetchone()[0] == 6
    alert_decisions = {
        row["decision"] for row in conn.execute("select distinct decision from alert_decisions").fetchall()
    }
    assert "link_alert" not in alert_decisions
    assert "risk_update" not in alert_decisions
    conn.close()


def test_runbook_verifier_module_cli_outputs_summary(tmp_path) -> None:
    db_path = tmp_path / "runbook-verify-cli.db"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "security_analyst_agent.runbook_verify",
            "--scenario",
            "hermes-memory-spike",
            "--db-path",
            str(db_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "PASS: runbook scenario hermes-memory-spike" in result.stdout
    body = json.loads(result.stdout.splitlines()[-1])
    assert body["scenario"] == "hermes-memory-spike"
    assert body["rounds_applied"] == 6
