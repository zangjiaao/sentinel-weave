import json
import subprocess
import sys

import pytest

from security_analyst_agent.config import PROJECT_ROOT
from security_analyst_agent.db import connect_db
from security_analyst_agent.memory_spike import (
    apply_memory_spike_round,
    bootstrap_memory_spike_database,
    load_memory_spike_rounds,
)
from security_analyst_agent.tool_dispatch import dispatch_tool


def test_load_memory_spike_rounds_returns_six_rounds() -> None:
    rounds = load_memory_spike_rounds()
    assert [item["round_id"] for item in rounds] == [
        "round_01_recon",
        "round_02_exploit",
        "round_03_new_ip",
        "round_04_lateral_prep",
        "round_05_silent_period",
        "round_06_reactivation",
    ]


def test_load_expanded_memory_spike_rounds_returns_ten_rounds() -> None:
    rounds = load_memory_spike_rounds(PROJECT_ROOT / "fixtures" / "spike_memory_expanded")
    assert len(rounds) == 10
    assert rounds[0]["round_id"] == "round_01_dual_recon"
    assert rounds[-1]["round_id"] == "round_10_chain_b_reactivation"


def test_load_realistic_memory_spike_rounds_returns_five_rounds() -> None:
    rounds = load_memory_spike_rounds(PROJECT_ROOT / "fixtures" / "spike_memory_realistic")
    assert len(rounds) == 5
    assert rounds[0]["round_id"] == "round_01_realistic"
    assert len(rounds[0]["alerts"]) == 1000


def test_bootstrap_memory_spike_loads_base_bundle(tmp_path) -> None:
    db_path = tmp_path / "memory-spike.db"
    bootstrap_memory_spike_database(db_path)

    conn = connect_db(db_path)
    assert conn.execute("select count(*) from assets").fetchone()[0] == 3
    assert conn.execute("select count(*) from alerts").fetchone()[0] == 0
    assert conn.execute("select count(*) from cases").fetchone()[0] == 0
    assert conn.execute("select count(*) from verify_spike_round_runs").fetchone()[0] == 0


def test_bootstrap_expanded_memory_spike_loads_expanded_assets(tmp_path) -> None:
    db_path = tmp_path / "memory-spike-expanded.db"
    bootstrap_memory_spike_database(db_path, fixture_dir=PROJECT_ROOT / "fixtures" / "spike_memory_expanded")

    conn = connect_db(db_path)
    assert conn.execute("select count(*) from assets").fetchone()[0] == 6
    assert conn.execute("select count(*) from alerts").fetchone()[0] == 0
    assert conn.execute("select count(*) from cases").fetchone()[0] == 0
    assert conn.execute("select count(*) from verify_spike_round_runs").fetchone()[0] == 0


def test_bootstrap_and_apply_realistic_round(tmp_path) -> None:
    db_path = tmp_path / "memory-spike-realistic.db"
    fixture_dir = PROJECT_ROOT / "fixtures" / "spike_memory_realistic"
    bootstrap_memory_spike_database(db_path, fixture_dir=fixture_dir)
    body = apply_memory_spike_round(db_path, "round_01_realistic", fixture_dir=fixture_dir)

    conn = connect_db(db_path)
    assert body["applied"] is True
    assert conn.execute("select count(*) from alerts").fetchone()[0] == 1000
    assert conn.execute("select count(*) from verify_spike_round_runs").fetchone()[0] == 1


def test_apply_memory_spike_rounds_are_incremental_and_idempotent(tmp_path) -> None:
    db_path = tmp_path / "memory-spike.db"
    bootstrap_memory_spike_database(db_path)

    first = apply_memory_spike_round(db_path, "round_01_recon")
    second = apply_memory_spike_round(db_path, "round_02_exploit")
    repeated = apply_memory_spike_round(db_path, "round_02_exploit")

    conn = connect_db(db_path)
    assert first["applied"] is True
    assert second["applied"] is True
    assert repeated["applied"] is False
    assert conn.execute("select count(*) from alerts").fetchone()[0] == 8
    assert conn.execute("select count(*) from cases").fetchone()[0] == 0
    assert conn.execute("select count(*) from case_alert_links").fetchone()[0] == 0
    assert conn.execute("select count(*) from timeline_events").fetchone()[0] == 0
    assert conn.execute("select count(*) from evidence").fetchone()[0] == 0


def test_apply_memory_spike_rounds_leave_case_creation_to_agent(tmp_path) -> None:
    db_path = tmp_path / "memory-spike.db"
    bootstrap_memory_spike_database(db_path)

    first = apply_memory_spike_round(db_path, "round_01_recon")

    conn = connect_db(db_path)
    assert first["upserted_cases"] == 0
    assert conn.execute("select count(*) from cases").fetchone()[0] == 0
    assert conn.execute("select count(*) from case_alert_links").fetchone()[0] == 0
    assert first["inserted_timeline_events"] == 0
    assert first["inserted_evidence"] == 0
    assert conn.execute("select count(*) from timeline_events").fetchone()[0] == 0
    assert conn.execute("select count(*) from evidence").fetchone()[0] == 0


def test_apply_memory_spike_round_requires_previous_round(tmp_path) -> None:
    db_path = tmp_path / "memory-spike.db"
    bootstrap_memory_spike_database(db_path)

    with pytest.raises(ValueError, match="previous round must be applied first"):
        apply_memory_spike_round(db_path, "round_03_new_ip")


def test_memory_spike_module_supports_bootstrap_and_apply_round(tmp_path) -> None:
    db_path = tmp_path / "memory-spike.db"

    bootstrap = subprocess.run(
        [
            sys.executable,
            "-m",
            "security_analyst_agent.memory_spike",
            "bootstrap",
            "--db-path",
            str(db_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert bootstrap.returncode == 0
    assert "bootstrapped memory spike" in bootstrap.stdout

    apply_round = subprocess.run(
        [
            sys.executable,
            "-m",
            "security_analyst_agent.memory_spike",
            "apply-round",
            "--db-path",
            str(db_path),
            "--round-id",
            "round_01_recon",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert apply_round.returncode == 0
    body = json.loads(apply_round.stdout)
    assert body["round_id"] == "round_01_recon"
    assert body["applied"] is True


def test_round1_explain_link_does_not_pull_future_evidence_with_cutoff(tmp_path) -> None:
    db_path = tmp_path / "memory-spike.db"
    bootstrap_memory_spike_database(db_path)
    apply_memory_spike_round(db_path, "round_01_recon")
    apply_memory_spike_round(db_path, "round_02_exploit")
    apply_memory_spike_round(db_path, "round_03_new_ip")

    conn = connect_db(db_path)
    conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at)
        values (?, ?, ?, ?, ?, ?)
        """,
        (
            "run_cutoff_mem_001",
            "ingest_event",
            "running",
            "memory spike cutoff",
            "2026-04-14T12:00:00+08:00",
            "2026-04-10T23:59:59+08:00",
        ),
    )
    conn.commit()

    result = dispatch_tool(
        conn,
        "case.explain-link",
        {"case_id": "case_demo_001", "target_type": "alert", "target_id": "alt_r1_api_scan"},
        source="mcp",
    )
    assert result["ok"] is True
    evidence_ids = result["data"]["link_decision"]["supporting_evidence_ids"]
    assert evidence_ids == []
    conn.close()
