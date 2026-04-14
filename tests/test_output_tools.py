from security_analyst_agent.tools.output_tools import notify_preview, notify_send, report_draft


def test_notify_preview_contains_why_now(db_conn) -> None:
    result = notify_preview(
        db_conn,
        {"case_id": "case_demo_001", "channel": "feishu", "template": "high_risk_case_brief"},
    )
    assert "why_now" in result["data"]["preview"]


def test_report_draft_contains_timeline_section(db_conn) -> None:
    result = report_draft(
        db_conn,
        {"case_id": "case_demo_001", "template": "incident_report_v1", "tone": "professional"},
    )
    assert "timeline" in result["data"]["report"]["outline"]


def test_notify_send_simulates_delivery_with_dedupe(db_conn) -> None:
    first = notify_send(
        db_conn,
        {"case_id": "case_demo_001", "channel": "email", "template": "high_severity"},
    )
    second = notify_send(
        db_conn,
        {"case_id": "case_demo_001", "channel": "email", "template": "high_severity"},
    )

    assert first["ok"] is True
    assert first["data"]["notification"]["status"] == "sent_simulated"
    assert second["ok"] is True
    assert second["data"]["notification"]["status"] == "deduped"
