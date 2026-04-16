from security_analyst_agent.tools.case_tools import (
    case_explain_link,
    case_get,
    case_link_alert,
    case_link_alert_batch,
    case_timeline,
    case_update_risk,
    case_upsert_batch,
    case_upsert,
)


def test_case_get_returns_actor_and_target_summary(db_conn) -> None:
    result = case_get(db_conn, {"case_id": "case_demo_001"})
    assert result["data"]["case"]["overall_severity"] == "high"
    assert result["data"]["case"]["primary_actor_id"] == "actor_demo_001"
    assert result["data"]["case"]["memory_digest"] is not None
    digest_row = db_conn.execute(
        "select case_id from case_digests where case_id = ?",
        ("case_demo_001",),
    ).fetchone()
    assert digest_row is not None


def test_case_timeline_returns_ordered_attack_steps(db_conn) -> None:
    result = case_timeline(db_conn, {"case_id": "case_demo_001", "include_evidence": True})
    stages = [item["stage"] for item in result["data"]["events"]]
    assert stages == ["recon", "persistence", "command_execution"]


def test_case_explain_link_shows_positive_factors(db_conn) -> None:
    result = case_explain_link(
        db_conn,
        {"case_id": "case_demo_001", "target_type": "alert", "target_id": "alt_day3_shell_01"},
    )
    assert result["data"]["link_decision"]["is_linked"] is True
    assert result["data"]["link_decision"]["positive_factors"]


def test_case_explain_link_for_round1_alert_has_no_future_evidence(db_conn) -> None:
    result = case_explain_link(
        db_conn,
        {"case_id": "case_demo_001", "target_type": "alert", "target_id": "alt_day1_scan_01"},
    )
    evidence_ids = result["data"]["link_decision"]["supporting_evidence_ids"]
    assert "evi_webshell_01" not in evidence_ids
    assert "evi_shell_conn_01" not in evidence_ids


def test_case_upsert_creates_new_case(db_conn) -> None:
    result = case_upsert(
        db_conn,
        {
            "case_id": "case_new_001",
            "title": "新发现可疑横向移动",
            "status": "open",
            "overall_severity": "medium",
            "current_stage": "lateral_prep",
            "primary_actor_id": "actor_new_001",
        },
    )
    assert result["ok"] is True
    assert result["data"]["case"]["case_id"] == "case_new_001"
    assert result["data"]["case"]["overall_severity"] == "medium"


def test_case_upsert_batch_creates_multiple_cases(db_conn) -> None:
    result = case_upsert_batch(
        db_conn,
        {
            "items": [
                {
                    "case_id": "case_batch_upsert_001",
                    "title": "批量案件一",
                    "status": "open",
                    "overall_severity": "medium",
                    "current_stage": "recon",
                    "primary_actor_id": "actor_batch_001",
                },
                {
                    "case_id": "case_batch_upsert_002",
                    "title": "批量案件二",
                    "status": "investigating",
                    "overall_severity": "high",
                    "current_stage": "persistence",
                    "primary_actor_id": "actor_batch_002",
                },
            ]
        },
    )
    assert result["ok"] is True
    assert len(result["data"]["cases"]) == 2
    assert result["data"]["failures"] == []


def test_case_link_alert_updates_active_case_link(db_conn) -> None:
    case_upsert(
        db_conn,
        {
            "case_id": "case_new_002",
            "title": "新案件用于关联测试",
            "status": "open",
            "overall_severity": "low",
            "current_stage": "recon",
            "primary_actor_id": "actor_new_002",
        },
    )
    result = case_link_alert(
        db_conn,
        {
            "case_id": "case_new_002",
            "alert_id": "alt_day1_scan_01",
            "confidence": 0.73,
            "reason": "same target and staged behavior",
        },
    )
    assert result["ok"] is True
    assert result["data"]["link"]["alert_id"] == "alt_day1_scan_01"

    linked_alert = db_conn.execute(
        """
        select case_id
        from case_alert_links
        where alert_id = ? and is_active = 1
        """,
        ("alt_day1_scan_01",),
    ).fetchone()
    assert linked_alert["case_id"] == "case_new_002"

    timeline_event = db_conn.execute(
        """
        select timeline_event_id, case_id, stage, title, related_alert_ids, related_evidence_ids
        from timeline_events
        where timeline_event_id = ?
        """,
        ("tl_link_alt_day1_scan_01",),
    ).fetchone()
    assert timeline_event is not None
    assert timeline_event["case_id"] == "case_new_002"
    assert timeline_event["stage"] == "recon"
    assert timeline_event["title"] == "扫描多个公网 Web 入口"


def test_case_link_alert_is_idempotent_for_timeline_event(db_conn) -> None:
    case_upsert(
        db_conn,
        {
            "case_id": "case_new_003",
            "title": "时间线幂等测试",
            "status": "open",
            "overall_severity": "low",
            "current_stage": "recon",
            "primary_actor_id": "actor_new_003",
        },
    )
    payload = {
        "case_id": "case_new_003",
        "alert_id": "alt_day2_webshell_01",
        "confidence": 0.8,
        "reason": "idempotency check",
    }
    first = case_link_alert(db_conn, payload)
    second = case_link_alert(db_conn, payload)

    assert first["ok"] is True
    assert second["ok"] is True
    count = db_conn.execute(
        "select count(*) from timeline_events where timeline_event_id = ?",
        ("tl_link_alt_day2_webshell_01",),
    ).fetchone()[0]
    assert count == 1


def test_case_link_alert_keeps_single_active_case_per_alert(db_conn) -> None:
    case_upsert(
        db_conn,
        {
            "case_id": "case_new_004",
            "title": "重关联历史测试-1",
            "status": "open",
            "overall_severity": "low",
            "current_stage": "recon",
            "primary_actor_id": "actor_new_004",
        },
    )
    case_upsert(
        db_conn,
        {
            "case_id": "case_new_005",
            "title": "重关联历史测试-2",
            "status": "open",
            "overall_severity": "medium",
            "current_stage": "persistence",
            "primary_actor_id": "actor_new_005",
        },
    )
    case_link_alert(
        db_conn,
        {
            "case_id": "case_new_004",
            "alert_id": "alt_day3_shell_01",
            "confidence": 0.8,
            "reason": "first assignment",
        },
    )
    case_link_alert(
        db_conn,
        {
            "case_id": "case_new_005",
            "alert_id": "alt_day3_shell_01",
            "confidence": 0.9,
            "reason": "reassignment",
        },
    )

    active_rows = db_conn.execute(
        """
        select case_id
        from case_alert_links
        where alert_id = ? and is_active = 1
        """,
        ("alt_day3_shell_01",),
    ).fetchall()
    assert len(active_rows) == 1
    assert active_rows[0]["case_id"] == "case_new_005"

    inactive_rows = db_conn.execute(
        """
        select case_id
        from case_alert_links
        where alert_id = ? and is_active = 0
        """,
        ("alt_day3_shell_01",),
    ).fetchall()
    assert any(row["case_id"] == "case_new_004" for row in inactive_rows)


def test_case_link_alert_writes_link_decision_in_dedicated_table(db_conn) -> None:
    case_upsert(
        db_conn,
        {
            "case_id": "case_new_006",
            "title": "link decision audit table test",
            "status": "open",
            "overall_severity": "medium",
            "current_stage": "recon",
            "primary_actor_id": "actor_new_006",
        },
    )
    case_link_alert(
        db_conn,
        {
            "case_id": "case_new_006",
            "alert_id": "alt_day2_webshell_01",
            "confidence": 0.88,
            "reason": "dedicated link decision log",
        },
    )
    link_row = db_conn.execute(
        """
        select alert_id, case_id, link_confidence, reason_summary
        from link_decisions
        where alert_id = ?
        order by occurred_at desc
        limit 1
        """,
        ("alt_day2_webshell_01",),
    ).fetchone()
    assert link_row is not None
    assert link_row["case_id"] == "case_new_006"
    assert link_row["reason_summary"] == "dedicated link decision log"

    old_style = db_conn.execute(
        """
        select count(*)
        from alert_decisions
        where decision = 'link_alert'
        """
    ).fetchone()[0]
    assert old_style == 0


def test_case_link_alert_batch_links_multiple_alerts(db_conn) -> None:
    case_upsert(
        db_conn,
        {
            "case_id": "case_batch_001",
            "title": "批量关联测试案件",
            "status": "open",
            "overall_severity": "medium",
            "current_stage": "recon",
            "primary_actor_id": "actor_batch_001",
        },
    )
    result = case_link_alert_batch(
        db_conn,
        {
            "items": [
                {
                    "case_id": "case_batch_001",
                    "alert_id": "alt_day1_scan_01",
                    "confidence": 0.8,
                    "reason": "batch-link-1",
                },
                {
                    "case_id": "case_batch_001",
                    "alert_id": "alt_day2_webshell_01",
                    "confidence": 0.9,
                    "reason": "batch-link-2",
                },
            ]
        },
    )

    assert result["ok"] is True
    assert len(result["data"]["links"]) == 2
    assert result["data"]["failures"] == []


def test_case_update_risk_updates_case_fields(db_conn) -> None:
    result = case_update_risk(
        db_conn,
        {
            "case_id": "case_demo_001",
            "overall_severity": "critical",
            "current_stage": "lateral_prep",
            "status": "investigating",
        },
    )
    assert result["ok"] is True
    assert result["data"]["case"]["overall_severity"] == "critical"
    assert result["data"]["case"]["status"] == "investigating"


def test_case_update_risk_blocks_stage_downgrade_by_default(db_conn) -> None:
    case_update_risk(
        db_conn,
        {
            "case_id": "case_demo_001",
            "overall_severity": "high",
            "current_stage": "lateral_prep",
            "status": "open",
        },
    )
    result = case_update_risk(
        db_conn,
        {
            "case_id": "case_demo_001",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "status": "open",
        },
    )
    assert result["ok"] is True
    assert "stage_downgrade_blocked" in result["warnings"]
    assert result["data"]["case"]["current_stage"] == "lateral_prep"


def test_case_update_risk_allows_stage_downgrade_with_force_flag(db_conn) -> None:
    case_update_risk(
        db_conn,
        {
            "case_id": "case_demo_001",
            "overall_severity": "high",
            "current_stage": "lateral_prep",
            "status": "open",
        },
    )
    result = case_update_risk(
        db_conn,
        {
            "case_id": "case_demo_001",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "status": "open",
            "force_downgrade": True,
        },
    )
    assert result["ok"] is True
    assert "stage_downgrade_blocked" not in result["warnings"]
    assert result["data"]["case"]["current_stage"] == "command_execution"


def test_case_update_risk_writes_case_assessment_log(db_conn) -> None:
    case_update_risk(
        db_conn,
        {
            "case_id": "case_demo_001",
            "overall_severity": "high",
            "current_stage": "persistence",
            "status": "investigating",
        },
    )
    row = db_conn.execute(
        """
        select case_id, risk_level, current_stage, verdict
        from case_assessments
        where case_id = ?
        order by occurred_at desc
        limit 1
        """,
        ("case_demo_001",),
    ).fetchone()
    assert row is not None
    assert row["risk_level"] == "high"
    assert row["current_stage"] == "lateral_prep"
