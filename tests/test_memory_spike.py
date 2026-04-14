import json
import subprocess
import sys

import pytest

from security_analyst_agent.db import connect_db
from security_analyst_agent.memory_spike import (
    apply_memory_spike_round,
    bootstrap_memory_spike_database,
    load_memory_spike_rounds,
)


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


def test_bootstrap_memory_spike_loads_base_bundle(tmp_path) -> None:
    db_path = tmp_path / "memory-spike.db"
    bootstrap_memory_spike_database(db_path)

    conn = connect_db(db_path)
    assert conn.execute("select count(*) from assets").fetchone()[0] == 3
    assert conn.execute("select count(*) from alerts").fetchone()[0] == 0
    assert conn.execute("select count(*) from cases").fetchone()[0] == 0
    assert conn.execute("select count(*) from spike_round_runs").fetchone()[0] == 0


def test_apply_memory_spike_rounds_are_incremental_and_idempotent(tmp_path) -> None:
    db_path = tmp_path / "memory-spike.db"
    bootstrap_memory_spike_database(db_path)

    first = apply_memory_spike_round(db_path, "round_01_recon")
    second = apply_memory_spike_round(db_path, "round_02_exploit")
    repeated = apply_memory_spike_round(db_path, "round_02_exploit")

    conn = connect_db(db_path)
    case = conn.execute(
        "select overall_severity, current_stage from cases where case_id = ?",
        ("case_demo_001",),
    ).fetchone()

    assert first["applied"] is True
    assert second["applied"] is True
    assert repeated["applied"] is False
    assert conn.execute("select count(*) from alerts").fetchone()[0] == 8
    assert case["overall_severity"] == "high"
    assert case["current_stage"] == "persistence"


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
