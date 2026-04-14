from security_analyst_agent.schemas.alert_tools import AlertFetchRequest
from security_analyst_agent.schemas.common import ToolResponse
from security_analyst_agent.tools.alert_tools import alert_ack, alert_detail, alert_fetch


def test_alert_fetch_request_defaults_limit_to_20() -> None:
    request = AlertFetchRequest.model_validate({})
    assert request.limit == 20


def test_tool_response_requires_summary() -> None:
    response = ToolResponse(ok=True, summary="ok", data={})
    assert response.summary == "ok"
    assert response.meta.partial is False


def test_alert_fetch_returns_ranked_queue(db_conn) -> None:
    result = alert_fetch(db_conn, {"status": ["new", "open"], "limit": 10})
    assert result["ok"] is True
    assert result["data"]["alerts"][0]["alert_id"] == "alt_day3_shell_01"


def test_alert_detail_returns_parser_and_evidence_refs(db_conn) -> None:
    result = alert_detail(db_conn, {"alert_id": "alt_day2_webshell_01"})
    assert result["data"]["alert"]["attack_stage"] == "persistence"
    assert "parser_profile_version_id" in result["data"]["alert"]


def test_alert_ack_updates_status_and_removes_from_queue(db_conn) -> None:
    ack_result = alert_ack(
        db_conn,
        {
            "alert_ids": ["alt_day1_scan_01", "alt_day2_webshell_01"],
            "status": "triaged",
        },
    )
    assert ack_result["ok"] is True
    assert ack_result["data"]["ack"]["updated_count"] == 2

    fetch_result = alert_fetch(db_conn, {"status": ["new", "open"], "limit": 10})
    ids = {item["alert_id"] for item in fetch_result["data"]["alerts"]}
    assert "alt_day1_scan_01" not in ids
    assert "alt_day2_webshell_01" not in ids


def test_alert_fetch_respects_active_analysis_cutoff(db_conn) -> None:
    db_conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at)
        values (?, ?, ?, ?, ?, ?)
        """,
        (
            "run_cutoff_001",
            "ingest_event",
            "running",
            "cutoff test",
            "2026-04-14T09:00:00+08:00",
            "2026-04-10T23:59:59+08:00",
        ),
    )
    result = alert_fetch(db_conn, {"status": ["new", "open"], "limit": 10})
    assert result["ok"] is True
    assert [item["alert_id"] for item in result["data"]["alerts"]] == ["alt_day1_scan_01"]


def test_alert_detail_respects_active_analysis_cutoff(db_conn) -> None:
    db_conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at)
        values (?, ?, ?, ?, ?, ?)
        """,
        (
            "run_cutoff_002",
            "ingest_event",
            "running",
            "cutoff test detail",
            "2026-04-14T09:01:00+08:00",
            "2026-04-10T23:59:59+08:00",
        ),
    )
    result = alert_detail(db_conn, {"alert_id": "alt_day1_scan_01"})
    evidence_ids = result["refs"]["evidence_ids"]
    assert "evi_webshell_01" not in evidence_ids
    assert "evi_shell_conn_01" not in evidence_ids
