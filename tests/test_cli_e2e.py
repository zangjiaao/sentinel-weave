import json

from typer.testing import CliRunner

from security_analyst_agent.bootstrap import bootstrap_spike_database, materialize_spike_runtime_demo
from security_analyst_agent.cli import app
from security_analyst_agent.db import connect_db


def test_cli_alert_fetch_returns_json(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    runner = CliRunner()
    payload = json.dumps({"status": ["new", "open"], "limit": 5})
    result = runner.invoke(app, ["alert.fetch", "--db-path", str(db_path), "--payload", payload])
    body = json.loads(result.stdout)
    assert result.exit_code == 0
    assert body["ok"] is True
    assert "alerts" in body["data"]


def test_cli_all_core_tools_return_unified_shape(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    materialize_spike_runtime_demo(db_path)
    runner = CliRunner()
    cases = [
        ("alert.fetch", {"status": ["open"], "limit": 2}),
        ("alert.detail", {"alert_id": "alt_day2_webshell_01"}),
        ("alert.ack", {"alert_ids": ["alt_day1_scan_01"], "status": "triaged"}),
        ("asset.search", {"indicators": ["203.0.113.10"]}),
        ("case.get", {"case_id": "case_demo_001"}),
        ("case.timeline", {"case_id": "case_demo_001", "include_evidence": True}),
        ("case.explain-link", {"case_id": "case_demo_001", "target_type": "alert", "target_id": "alt_day3_shell_01"}),
        (
            "case.upsert",
            {
                "case_id": "case_cli_001",
                "title": "CLI E2E new case",
                "status": "open",
                "overall_severity": "medium",
                "current_stage": "recon",
                "primary_actor_id": "actor_cli_001",
            },
        ),
        (
            "case.link-alert",
            {
                "case_id": "case_cli_001",
                "alert_id": "alt_day1_scan_01",
                "confidence": 0.66,
                "reason": "cli e2e reassignment",
            },
        ),
        (
            "case.update-risk",
            {
                "case_id": "case_cli_001",
                "overall_severity": "high",
                "current_stage": "persistence",
                "status": "investigating",
            },
        ),
        (
            "evidence.upsert",
            {
                "evidence_id": "evi_cli_001",
                "case_id": "case_cli_001",
                "occurred_at": "2026-04-15T12:00:00+08:00",
                "evidence_type": "webshell",
                "summary": "cli e2e evidence",
            },
        ),
        (
            "timeline.upsert",
            {
                "timeline_event_id": "tl_cli_001",
                "case_id": "case_cli_001",
                "occurred_at": "2026-04-15T12:01:00+08:00",
                "stage": "persistence",
                "title": "cli e2e timeline",
                "related_alert_ids": ["alt_day1_scan_01"],
                "related_evidence_ids": ["evi_cli_001"],
            },
        ),
        (
            "assessment.upsert",
            {
                "entity_type": "ip",
                "entity_key": "198.51.100.23",
                "entity_label": "198.51.100.23",
                "related_case_id": "case_cli_001",
                "risk_level": "high",
                "assessment_confidence": 0.93,
                "verdict": "attacker",
                "reason_summary": "cli e2e structured assessment",
                "supporting_alert_ids": ["alt_day1_scan_01"],
                "supporting_evidence_ids": [],
            },
        ),
        ("intel.lookup", {"indicator": "198.51.100.23", "indicator_type": "ip"}),
        ("notify.send", {"case_id": "case_demo_001", "channel": "email", "template": "high_severity"}),
        ("notify.preview", {"case_id": "case_demo_001", "channel": "feishu", "template": "high_risk_case_brief"}),
        ("report.draft", {"case_id": "case_demo_001", "template": "incident_report_v1", "tone": "professional"}),
    ]
    required_keys = {"ok", "summary", "data", "warnings", "refs", "page", "meta"}

    for tool_name, payload in cases:
        result = runner.invoke(
            app,
            [tool_name, "--db-path", str(db_path), "--payload", json.dumps(payload, ensure_ascii=False)],
        )
        assert result.exit_code == 0
        body = json.loads(result.stdout)
        assert required_keys.issubset(body.keys())


def test_cli_alert_ingest_returns_ingestion_counts(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    runner = CliRunner()
    payload = {
        "source": "manual_import",
        "alerts": [
            {
                "alert_id": "alt_cli_ingest_001",
                "case_id": None,
                "occurred_at": "2026-04-14T02:00:00+08:00",
                "title": "cli ingest alert",
                "status": "new",
                "severity": "medium",
                "attack_stage": "recon",
                "src_ip": "198.51.100.188",
                "dst_ip": "203.0.113.10",
                "asset_id": "asset_api_prod",
            }
        ],
    }
    result = runner.invoke(
        app,
        [
            "alert.ingest",
            "--db-path",
            str(db_path),
            "--payload",
            json.dumps(payload, ensure_ascii=False),
            "--no-trigger-now",
        ],
    )
    body = json.loads(result.stdout)
    assert result.exit_code == 0
    assert body["inserted_alerts"] == 1
    assert body["pending_events"] == 1
    assert body["trigger"]["status"] == "disabled"


def test_cli_alert_ingest_can_trigger_patrol_in_dry_run_mode(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    runner = CliRunner()
    payload = {
        "source": "manual_import",
        "alerts": [
            {
                "alert_id": "alt_cli_ingest_002",
                "case_id": None,
                "occurred_at": "2026-04-14T02:05:00+08:00",
                "title": "cli ingest alert with trigger",
                "status": "new",
                "severity": "medium",
                "attack_stage": "recon",
                "src_ip": "198.51.100.189",
                "dst_ip": "203.0.113.10",
                "asset_id": "asset_api_prod",
            }
        ],
    }
    result = runner.invoke(
        app,
        [
            "alert.ingest",
            "--db-path",
            str(db_path),
            "--payload",
            json.dumps(payload, ensure_ascii=False),
            "--trigger-now",
            "--trigger-dry-run",
            "--job-id",
            "job_cli_002",
        ],
    )
    body = json.loads(result.stdout)
    assert result.exit_code == 0
    assert body["inserted_alerts"] == 1
    assert body["trigger"]["triggered"] is True
    assert body["trigger"]["status"] == "dry_run_success"


def test_cli_patrol_trigger_supports_dry_run(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute(
        """
        insert into alert_ingest_events (event_id, alert_id, source, ingested_at, trigger_state)
        values (?, ?, ?, ?, ?)
        """,
        (
            "evt_cli_001",
            "alt_day1_scan_01",
            "manual_import",
            "2026-04-14T02:10:00+08:00",
            "pending",
        ),
    )
    conn.commit()
    conn.close()

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "patrol.trigger",
            "--db-path",
            str(db_path),
            "--job-id",
            "job_cli_001",
            "--dry-run",
        ],
    )
    body = json.loads(result.stdout)
    assert result.exit_code == 0
    assert body["triggered"] is True
    assert body["status"] == "dry_run_success"
