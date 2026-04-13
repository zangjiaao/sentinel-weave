from security_analyst_agent.tools.output_tools import notify_preview, report_draft


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
