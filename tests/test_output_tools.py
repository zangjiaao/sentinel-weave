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
    assert ":stage:" in first["data"]["notification"]["dedupe_key"]
    assert second["ok"] is True
    assert second["data"]["notification"]["status"] == "deduped"


def test_notify_send_routes_merged_case_to_canonical_case_with_stage_dedupe(db_conn) -> None:
    db_conn.execute(
        """
        insert into cases (
          case_id, title, status, overall_severity, current_stage, primary_actor_id,
          canonical_case_id, merged_into_case_id, merge_state, merge_updated_at
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "case_notify_parent",
            "notify parent",
            "open",
            "high",
            "command_execution",
            None,
            "case_notify_parent",
            None,
            "standalone",
            "2026-04-18T00:00:00+00:00",
        ),
    )
    db_conn.execute(
        """
        insert into cases (
          case_id, title, status, overall_severity, current_stage, primary_actor_id,
          canonical_case_id, merged_into_case_id, merge_state, merge_updated_at
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "case_notify_child",
            "notify child",
            "closed",
            "high",
            "persistence",
            None,
            "case_notify_parent",
            "case_notify_parent",
            "merged",
            "2026-04-18T00:00:00+00:00",
        ),
    )
    db_conn.commit()

    first = notify_send(
        db_conn,
        {"case_id": "case_notify_child", "channel": "email", "template": "high_severity"},
    )
    second = notify_send(
        db_conn,
        {"case_id": "case_notify_parent", "channel": "email", "template": "high_severity"},
    )

    assert first["ok"] is True
    assert first["data"]["notification"]["case_id"] == "case_notify_parent"
    assert first["data"]["notification"]["dedupe_key"] == "case_notify_parent:email:high_severity:stage:command_execution"
    assert second["ok"] is True
    assert second["data"]["notification"]["status"] == "deduped"

    outbox_rows = db_conn.execute(
        """
        select case_id, dedupe_key, status
        from notification_outbox
        where dedupe_key like 'case_notify_parent:email:high_severity%'
        order by created_at asc
        """
    ).fetchall()
    assert len(outbox_rows) == 1
    assert outbox_rows[0]["case_id"] == "case_notify_parent"
    assert outbox_rows[0]["status"] == "sent_simulated"
