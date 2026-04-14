import subprocess

from security_analyst_agent.bootstrap import bootstrap_spike_database
from security_analyst_agent.db import connect_db
from security_analyst_agent.ingest import ingest_alert_bundle
from security_analyst_agent.patrol_trigger import trigger_patrol_from_ingest


def _build_alert(alert_id: str) -> dict:
    return {
        "alert_id": alert_id,
        "case_id": None,
        "occurred_at": "2026-04-14T01:00:00+08:00",
        "title": f"ingested alert {alert_id}",
        "status": "new",
        "severity": "medium",
        "attack_stage": "recon",
        "src_ip": "198.51.100.88",
        "dst_ip": "203.0.113.10",
        "asset_id": "asset_api_prod",
    }


def test_ingest_alert_bundle_writes_pending_events(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)

    result = ingest_alert_bundle(db_path, [_build_alert("alt_ingest_001")], source="manual_import")
    assert result["inserted_alerts"] == 1
    assert result["pending_events"] == 1

    conn = connect_db(db_path)
    alert = conn.execute("select alert_id, status from alerts where alert_id = ?", ("alt_ingest_001",)).fetchone()
    event = conn.execute(
        "select alert_id, trigger_state from alert_ingest_events where alert_id = ?",
        ("alt_ingest_001",),
    ).fetchone()
    assert alert["status"] == "new"
    assert event["trigger_state"] == "pending"
    conn.close()


def test_trigger_patrol_processes_pending_events_with_single_run(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    ingest_alert_bundle(db_path, [_build_alert("alt_ingest_002"), _build_alert("alt_ingest_003")], source="siem")

    commands: list[list[str]] = []

    def fake_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="ok", stderr="")

    result = trigger_patrol_from_ingest(db_path, job_id="job_demo_001", command_runner=fake_runner)
    assert result["triggered"] is True
    assert result["processed_events"] == 2
    assert result["status"] == "success"
    assert commands == [["hermes", "cron", "run", "job_demo_001"], ["hermes", "cron", "tick"]]

    conn = connect_db(db_path)
    pending_count = conn.execute(
        "select count(*) from alert_ingest_events where trigger_state in ('pending', 'failed')"
    ).fetchone()[0]
    run_status = conn.execute("select status from patrol_runs where run_id = ?", (result["run_id"],)).fetchone()
    run_times = conn.execute(
        "select started_at, analysis_cutoff_at from patrol_runs where run_id = ?",
        (result["run_id"],),
    ).fetchone()
    state = conn.execute(
        "select state_value_json from patrol_state where state_key = 'last_patrol_status'"
    ).fetchone()
    assert pending_count == 0
    assert run_status["status"] == "success"
    assert run_times["analysis_cutoff_at"] == run_times["started_at"]
    assert state is not None
    assert "success" in state["state_value_json"]
    conn.close()


def test_trigger_patrol_marks_failed_and_retries(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    ingest_alert_bundle(db_path, [_build_alert("alt_ingest_004")], source="siem")

    def fail_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=command, returncode=1, stdout="", stderr="boom")

    failed = trigger_patrol_from_ingest(db_path, job_id="job_demo_002", command_runner=fail_runner)
    assert failed["status"] == "failed"

    conn = connect_db(db_path)
    failed_state = conn.execute(
        "select trigger_state from alert_ingest_events where alert_id = ?",
        ("alt_ingest_004",),
    ).fetchone()
    assert failed_state["trigger_state"] == "failed"
    conn.close()

    def success_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="ok", stderr="")

    retried = trigger_patrol_from_ingest(db_path, job_id="job_demo_002", command_runner=success_runner)
    assert retried["status"] == "success"
    assert retried["processed_events"] == 1
