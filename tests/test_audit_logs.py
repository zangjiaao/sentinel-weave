import json

from typer.testing import CliRunner

from security_analyst_agent.bootstrap import bootstrap_spike_database, materialize_spike_runtime_demo
from security_analyst_agent.cli import app
from security_analyst_agent.db import connect_db
from security_analyst_agent.tool_dispatch import dispatch_tool


def _insert_open_alert_for_case(
    conn,
    *,
    alert_id: str,
    case_id: str,
    occurred_at: str,
    stage: str,
    src_ip: str,
    severity: str = "high",
    confidence: float = 0.9,
    asset_id: str = "asset_api_prod",
    dst_ip: str = "203.0.113.10",
) -> None:
    conn.execute(
        """
        insert into alerts (
          alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert_id,
            occurred_at,
            f"audit {alert_id}",
            "open",
            severity,
            stage,
            src_ip,
            dst_ip,
            asset_id,
        ),
    )
    conn.execute(
        """
        insert into case_alert_links (
          case_id, alert_id, linked_at, confidence, reason, is_active, unlinked_at
        ) values (?, ?, ?, ?, ?, 1, null)
        on conflict(case_id, alert_id) do update set
          linked_at = excluded.linked_at,
          confidence = excluded.confidence,
          reason = excluded.reason,
          is_active = 1,
          unlinked_at = null
        """,
        (case_id, alert_id, occurred_at, confidence, "audit_seed"),
    )


def test_dispatch_tool_writes_audit_logs(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    materialize_spike_runtime_demo(db_path)
    conn = connect_db(db_path)

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_audit_001",
            "title": "audit case",
            "status": "open",
            "overall_severity": "medium",
            "current_stage": "recon",
            "primary_actor_id": "actor_audit",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "case.link-alert",
        {
            "case_id": "case_audit_001",
            "alert_id": "alt_day1_scan_01",
            "confidence": 0.7,
            "reason": "audit link",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "notify.send",
        {
            "case_id": "case_demo_001",
            "channel": "email",
            "template": "high_severity",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "case.update-risk",
        {
            "case_id": "case_audit_001",
            "overall_severity": "high",
            "current_stage": "persistence",
            "status": "investigating",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "evidence.upsert",
        {
            "evidence_id": "evi_audit_001",
            "case_id": "case_audit_001",
            "occurred_at": "2026-04-15T13:00:00+08:00",
            "evidence_type": "webshell",
            "summary": "audit evidence",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "timeline.upsert",
        {
            "timeline_event_id": "tl_audit_001",
            "case_id": "case_audit_001",
            "occurred_at": "2026-04-15T13:01:00+08:00",
            "stage": "persistence",
            "title": "audit timeline",
            "related_alert_ids": ["alt_day1_scan_01"],
            "related_evidence_ids": ["evi_audit_001"],
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "assessment.upsert",
        {
            "entity_type": "ip",
            "entity_key": "198.51.100.23",
            "entity_label": "198.51.100.23",
            "related_case_id": "case_audit_001",
            "risk_level": "high",
            "assessment_confidence": 0.93,
            "verdict": "attacker",
            "reason_summary": "audit coverage",
            "supporting_alert_ids": ["alt_day1_scan_01"],
            "supporting_evidence_ids": [],
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "alert.ack",
        {"alert_ids": ["alt_day2_webshell_01"], "status": "triaged"},
        source="cli",
    )

    tool_call_count = conn.execute("select count(*) from agent_tool_calls").fetchone()[0]
    alert_decision_count = conn.execute("select count(*) from alert_decisions").fetchone()[0]
    link_decision_count = conn.execute("select count(*) from link_decisions").fetchone()[0]
    case_assessment_count = conn.execute("select count(*) from case_assessments").fetchone()[0]
    entity_assessment_count = conn.execute("select count(*) from entity_assessments").fetchone()[0]
    case_change_count = conn.execute("select count(*) from case_changes").fetchone()[0]
    escalation_count = conn.execute("select count(*) from escalation_decisions").fetchone()[0]

    assert tool_call_count >= 8
    assert alert_decision_count == 0
    assert link_decision_count >= 1
    assert case_assessment_count >= 1
    assert entity_assessment_count >= 1
    assert case_change_count >= 3
    assert escalation_count >= 1
    conn.close()


def test_dispatch_tool_returns_payload_validation_error_and_audits_it(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    materialize_spike_runtime_demo(db_path)
    conn = connect_db(db_path)

    result = dispatch_tool(conn, "case.update-risk", {}, source="mcp")
    assert result["ok"] is False
    assert "payload" in result["summary"]
    assert "payload_validation_error" in result["warnings"]

    row = conn.execute(
        """
        select run_id, result_ok, result_summary, result_json
        from agent_tool_calls
        where tool_name = 'case.update-risk'
        order by occurred_at desc, rowid desc
        limit 1
        """
    ).fetchone()
    assert row is not None
    assert row["result_ok"] == 0
    assert "payload_validation_error" in row["result_json"]
    conn.close()


def test_dispatch_tool_skips_empty_batch_payload_for_mcp_without_failure(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    materialize_spike_runtime_demo(db_path)
    conn = connect_db(db_path)

    result = dispatch_tool(conn, "case.upsert-batch", {}, source="mcp")
    assert result["ok"] is True
    assert "empty batch payload skipped" in result["summary"]
    assert "empty_batch_payload_skipped" in result["warnings"]

    row = conn.execute(
        """
        select result_ok, result_summary, result_json
        from agent_tool_calls
        where tool_name = 'case.upsert-batch'
        order by occurred_at desc, rowid desc
        limit 1
        """
    ).fetchone()
    assert row is not None
    assert row["result_ok"] == 1
    assert row["result_summary"] == "empty batch payload skipped"
    assert "empty_batch_payload_skipped" in row["result_json"]
    conn.close()


def test_audit_cli_commands_return_rows(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    runner = CliRunner()
    runner.invoke(
        app,
        [
            "alert.fetch",
            "--db-path",
            str(db_path),
            "--payload",
            json.dumps({"status": ["open"], "limit": 1}),
        ],
    )

    cases = [
        "audit.tool-calls",
        "audit.alert-decisions",
        "audit.link-decisions",
        "audit.case-assessments",
        "audit.entity-assessments",
        "audit.case-changes",
        "audit.escalations",
    ]
    for command in cases:
        result = runner.invoke(app, [command, "--db-path", str(db_path), "--limit", "10"])
        assert result.exit_code == 0
        body = json.loads(result.stdout)
        assert "rows" in body


def test_context_cli_commands_return_rows(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    runner = CliRunner()
    runner.invoke(
        app,
        [
            "case.upsert",
            "--db-path",
            str(db_path),
            "--payload",
            json.dumps(
                {
                    "case_id": "case_ctx_001",
                    "title": "context digest case",
                    "status": "open",
                    "overall_severity": "medium",
                    "current_stage": "recon",
                    "primary_actor_id": "actor_ctx_001",
                }
            ),
        ],
    )

    digest_result = runner.invoke(
        app,
        ["context.case-digest", "--db-path", str(db_path), "--case-id", "case_ctx_001"],
    )
    state_result = runner.invoke(app, ["context.patrol-state", "--db-path", str(db_path)])

    assert digest_result.exit_code == 0
    assert state_result.exit_code == 0
    assert "rows" in json.loads(digest_result.stdout)
    assert "rows" in json.loads(state_result.stdout)


def test_context_patrol_state_is_derived_from_patrol_runs(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 20}, source="mcp")
    alert_ids = [row["alert_id"] for row in conn.execute("select alert_id from alerts where status in ('new', 'open')")]
    dispatch_tool(conn, "alert.ack", {"alert_ids": alert_ids, "status": "triaged"}, source="mcp")
    conn.close()

    runner = CliRunner()
    result = runner.invoke(app, ["context.patrol-state", "--db-path", str(db_path)])
    assert result.exit_code == 0
    rows = json.loads(result.stdout)["rows"]
    values = {row["state_key"]: row["state_value_json"] for row in rows}
    assert "last_patrol_run_id" in values
    assert values["last_patrol_status"] == "success"


def test_alert_decisions_no_longer_store_link_or_risk_semantics(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    materialize_spike_runtime_demo(db_path)
    conn = connect_db(db_path)
    dispatch_tool(
        conn,
        "case.link-alert",
        {
            "case_id": "case_demo_001",
            "alert_id": "alt_day1_scan_01",
            "confidence": 0.8,
            "reason": "semantic split check",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "case.update-risk",
        {
            "case_id": "case_demo_001",
            "overall_severity": "high",
            "current_stage": "persistence",
            "status": "investigating",
        },
        source="cli",
    )

    decisions = conn.execute("select decision from alert_decisions").fetchall()
    assert all(row["decision"] != "link_alert" for row in decisions)
    assert conn.execute("select count(*) from link_decisions").fetchone()[0] >= 1
    assert conn.execute("select count(*) from case_assessments").fetchone()[0] >= 1
    conn.close()


def test_mcp_alert_fetch_starts_auto_patrol_run_and_tags_run_id(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)

    dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 5}, source="mcp")

    call_row = conn.execute(
        """
        select tool_name, run_id, source
        from agent_tool_calls
        order by occurred_at desc
        limit 1
        """
    ).fetchone()
    run_row = conn.execute(
        """
        select run_id, trigger_source, status, analysis_cutoff_at
        from patrol_runs
        where trigger_source = 'mcp_auto'
        order by started_at desc
        limit 1
        """
    ).fetchone()

    assert call_row["tool_name"] == "alert.fetch"
    assert call_row["source"] == "mcp"
    assert call_row["run_id"] is not None
    assert run_row is not None
    assert run_row["run_id"] == call_row["run_id"]
    assert run_row["status"] == "running"
    assert run_row["analysis_cutoff_at"] is not None
    conn.close()


def test_cli_alert_ack_not_bound_to_mcp_auto_run_id(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)

    dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 5}, source="mcp")
    dispatch_tool(
        conn,
        "alert.ack",
        {"alert_ids": ["alt_day2_webshell_01"], "status": "triaged"},
        source="cli",
    )

    decision_row = conn.execute(
        """
        select decision, reason, run_id
        from alert_decisions
        where alert_id = ?
        order by occurred_at desc
        limit 1
        """,
        ("alt_day2_webshell_01",),
    ).fetchone()
    assert decision_row is None
    conn.close()


def test_alert_ack_logs_only_noop_and_missing_decisions(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged' where alert_id = 'alt_day2_webshell_01'")
    conn.commit()

    dispatch_tool(
        conn,
        "alert.ack",
        {"alert_ids": ["alt_day2_webshell_01", "alt_missing_001"], "status": "triaged"},
        source="cli",
    )

    decisions = conn.execute(
        """
        select alert_id, decision, reason
        from alert_decisions
        order by occurred_at asc
        """
    ).fetchall()
    assert len(decisions) == 2
    assert {row["decision"] for row in decisions} == {"ack_triaged_noop", "ack_missing_alert"}
    assert {row["reason"] for row in decisions} == {
        "tool:alert.ack_already_status",
        "tool:alert.ack_alert_not_found",
    }
    conn.close()


def test_mcp_auto_run_closes_immediately_on_empty_fetch(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'closed'")
    conn.commit()

    dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 20}, source="mcp")

    run_row = conn.execute(
        """
        select trigger_source, status, finished_at, summary
        from patrol_runs
        where trigger_source = 'mcp_auto'
        order by started_at desc
        limit 1
        """
    ).fetchone()
    assert run_row is not None
    assert run_row["status"] == "success"
    assert run_row["finished_at"] is not None
    assert run_row["summary"] == "auto_closed_empty_fetch"
    conn.close()


def test_mcp_alert_fetch_reuses_active_auto_run_without_creating_new_run(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)

    dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 5}, source="mcp")
    dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 5}, source="mcp")

    run_rows = conn.execute(
        """
        select run_id, status
        from patrol_runs
        where trigger_source = 'mcp_auto'
        order by started_at asc
        """
    ).fetchall()
    assert len(run_rows) == 1
    assert run_rows[0]["status"] == "running"

    call_rows = conn.execute(
        """
        select run_id
        from agent_tool_calls
        where source = 'mcp' and tool_name = 'alert.fetch'
        order by occurred_at asc, rowid asc
        """
    ).fetchall()
    assert len(call_rows) == 2
    assert call_rows[0]["run_id"] == call_rows[1]["run_id"]
    conn.close()


def test_mcp_auto_run_closes_after_alert_ack_when_queue_drained(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)

    dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 100}, source="mcp")
    alert_ids = [row["alert_id"] for row in conn.execute("select alert_id from alerts where status in ('new', 'open')")]
    dispatch_tool(conn, "alert.ack", {"alert_ids": alert_ids, "status": "triaged"}, source="mcp")

    run_row = conn.execute(
        """
        select trigger_source, status, finished_at, summary
        from patrol_runs
        where trigger_source = 'mcp_auto'
        order by started_at desc
        limit 1
        """
    ).fetchone()
    assert run_row is not None
    assert run_row["status"] == "success"
    assert run_row["finished_at"] is not None
    assert run_row["summary"] == "auto_closed_after_alert_ack"
    conn.close()


def test_mcp_tail_calls_after_ack_inherit_recent_auto_run_id(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)

    dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 100}, source="mcp")
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_tail_runid_001",
            "title": "tail run id case",
            "status": "open",
            "overall_severity": "medium",
            "current_stage": "recon",
        },
        source="mcp",
    )
    alert_ids = [row["alert_id"] for row in conn.execute("select alert_id from alerts where status in ('new', 'open')")]
    dispatch_tool(conn, "alert.ack", {"alert_ids": alert_ids, "status": "triaged"}, source="mcp")

    closed_run = conn.execute(
        """
        select run_id, status
        from patrol_runs
        where trigger_source = 'mcp_auto'
        order by started_at desc
        limit 1
        """
    ).fetchone()
    assert closed_run is not None
    assert closed_run["status"] == "success"

    dispatch_tool(
        conn,
        "timeline.upsert",
        {
            "timeline_event_id": "tl_tail_runid_001",
            "case_id": "case_tail_runid_001",
            "occurred_at": "2026-04-12T11:03:00+08:00",
            "stage": "command_execution",
            "title": "tail tool call should inherit run id",
            "related_alert_ids": [alert_ids[0]],
            "related_evidence_ids": [],
        },
        source="mcp",
    )
    dispatch_tool(
        conn,
        "case.update-risk",
        {
            "case_id": "case_tail_runid_001",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "status": "open",
            "force_downgrade": False,
        },
        source="mcp",
    )

    tail_calls = conn.execute(
        """
        select tool_name, run_id
        from agent_tool_calls
        where tool_name in ('timeline.upsert', 'case.update-risk')
        order by occurred_at desc
        limit 2
        """
    ).fetchall()
    assert len(tail_calls) == 2
    assert all(row["run_id"] == closed_run["run_id"] for row in tail_calls)
    conn.close()


def test_mcp_case_update_risk_auto_escalates_on_persistence_with_continuity_signal(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 20}, source="mcp")
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_auto_escalate_001",
            "title": "auto escalation persistence case",
            "status": "open",
            "overall_severity": "medium",
            "current_stage": "recon",
        },
        source="mcp",
    )
    dispatch_tool(
        conn,
        "evidence.upsert",
        {
            "evidence_id": "evi_auto_escalate_webshell_001",
            "case_id": "case_auto_escalate_001",
            "occurred_at": "2026-04-11T14:20:00+08:00",
            "evidence_type": "webshell",
            "summary": "webshell evidence for continuity signal",
        },
        source="mcp",
    )
    dispatch_tool(
        conn,
        "case.update-risk",
        {
            "case_id": "case_auto_escalate_001",
            "overall_severity": "high",
            "current_stage": "persistence",
            "status": "open",
            "force_downgrade": False,
        },
        source="mcp",
    )

    notification_row = conn.execute(
        """
        select case_id, channel, template, status
        from notification_outbox
        where case_id = ?
        order by created_at desc
        limit 1
        """,
        ("case_auto_escalate_001",),
    ).fetchone()
    assert notification_row is not None
    assert notification_row["channel"] == "email"
    assert notification_row["template"] == "high_severity"
    assert notification_row["status"] == "sent_simulated"

    escalation_row = conn.execute(
        """
        select triggered, reason
        from escalation_decisions
        where case_id = ?
        order by occurred_at desc
        limit 1
        """,
        ("case_auto_escalate_001",),
    ).fetchone()
    assert escalation_row is not None
    assert escalation_row["triggered"] == 1
    assert escalation_row["reason"] == "threshold_met"
    conn.close()


def test_mcp_case_update_risk_does_not_auto_escalate_without_continuity_signal(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 20}, source="mcp")
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_auto_escalate_002",
            "title": "auto escalation should not trigger",
            "status": "open",
            "overall_severity": "medium",
            "current_stage": "recon",
        },
        source="mcp",
    )
    dispatch_tool(
        conn,
        "case.update-risk",
        {
            "case_id": "case_auto_escalate_002",
            "overall_severity": "high",
            "current_stage": "persistence",
            "status": "open",
            "force_downgrade": False,
        },
        source="mcp",
    )

    notification_count = conn.execute(
        "select count(*) from notification_outbox where case_id = ?",
        ("case_auto_escalate_002",),
    ).fetchone()[0]
    escalation_count = conn.execute(
        "select count(*) from escalation_decisions where case_id = ?",
        ("case_auto_escalate_002",),
    ).fetchone()[0]
    assert notification_count == 0
    assert escalation_count == 0
    conn.close()


def test_mcp_auto_escalation_dedupes_to_single_canonical_notification(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_chain_a",
            "title": "chain a",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "persistence",
        },
        source="mcp",
    )
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_chain_b",
            "title": "chain b",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "command_execution",
        },
        source="mcp",
    )
    dispatch_tool(
        conn,
        "evidence.upsert",
        {
            "evidence_id": "evi_chain_anchor",
            "case_id": "case_chain_a",
            "occurred_at": "2026-04-11T14:20:00+08:00",
            "evidence_type": "webshell",
            "summary": "continuity anchor",
        },
        source="mcp",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_chain_a",
        case_id="case_chain_a",
        occurred_at="2026-04-12T10:00:00+08:00",
        stage="persistence",
        src_ip="198.51.100.23",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_chain_b",
        case_id="case_chain_b",
        occurred_at="2026-04-12T10:05:00+08:00",
        stage="command_execution",
        src_ip="198.51.100.77",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    conn.commit()

    dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 20}, source="mcp")
    dispatch_tool(
        conn,
        "case.update-risk",
        {
            "case_id": "case_chain_a",
            "overall_severity": "high",
            "current_stage": "persistence",
            "status": "open",
            "force_downgrade": False,
        },
        source="mcp",
    )
    dispatch_tool(
        conn,
        "case.update-risk",
        {
            "case_id": "case_chain_b",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "status": "open",
            "force_downgrade": False,
        },
        source="mcp",
    )

    notification_count_before_ack = conn.execute("select count(*) from notification_outbox").fetchone()[0]
    assert notification_count_before_ack == 0

    dispatch_tool(
        conn,
        "alert.ack",
        {
            "alert_ids": ["alt_chain_a", "alt_chain_b"],
            "status": "triaged",
        },
        source="mcp",
    )

    notifications = conn.execute(
        """
        select case_id, channel, template, status, dedupe_key
        from notification_outbox
        order by created_at asc
        """
    ).fetchall()
    assert len(notifications) == 1
    assert notifications[0]["case_id"] == "case_chain_a"
    assert notifications[0]["channel"] == "email"
    assert notifications[0]["template"] == "high_severity"
    assert notifications[0]["status"] == "sent_simulated"
    assert notifications[0]["dedupe_key"].endswith(":stage:command_execution")

    escalation_rows = conn.execute(
        """
        select case_id, triggered, reason
        from escalation_decisions
        order by occurred_at asc
        """
    ).fetchall()
    assert len(escalation_rows) == 1
    assert escalation_rows[0]["case_id"] == "case_chain_a"
    assert escalation_rows[0]["triggered"] == 1
    assert escalation_rows[0]["reason"] == "threshold_met"
    conn.close()


def test_mcp_stage_progression_escalates_once_per_advanced_stage(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 20}, source="mcp")
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_stage_progress_001",
            "title": "stage progression",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "recon",
        },
        source="mcp",
    )
    dispatch_tool(
        conn,
        "evidence.upsert",
        {
            "evidence_id": "evi_stage_progress_webshell",
            "case_id": "case_stage_progress_001",
            "occurred_at": "2026-04-11T14:20:00+08:00",
            "evidence_type": "webshell",
            "summary": "stage progression continuity",
        },
        source="mcp",
    )

    dispatch_tool(
        conn,
        "case.update-risk",
        {
            "case_id": "case_stage_progress_001",
            "overall_severity": "high",
            "current_stage": "persistence",
            "status": "open",
            "force_downgrade": False,
        },
        source="mcp",
    )
    dispatch_tool(
        conn,
        "case.update-risk",
        {
            "case_id": "case_stage_progress_001",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "status": "open",
            "force_downgrade": False,
        },
        source="mcp",
    )
    dispatch_tool(
        conn,
        "case.update-risk",
        {
            "case_id": "case_stage_progress_001",
            "overall_severity": "high",
            "current_stage": "lateral_prep",
            "status": "open",
            "force_downgrade": False,
        },
        source="mcp",
    )
    dispatch_tool(
        conn,
        "case.update-risk",
        {
            "case_id": "case_stage_progress_001",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "status": "open",
            "force_downgrade": True,
        },
        source="mcp",
    )

    notifications = conn.execute(
        """
        select dedupe_key
        from notification_outbox
        where case_id = ?
        order by created_at asc
        """,
        ("case_stage_progress_001",),
    ).fetchall()
    assert [row["dedupe_key"] for row in notifications] == [
        "case_stage_progress_001:email:high_severity:stage:persistence",
        "case_stage_progress_001:email:high_severity:stage:command_execution",
        "case_stage_progress_001:email:high_severity:stage:lateral_prep",
    ]

    escalation_rows = conn.execute(
        """
        select triggered, reason, dedupe_key, detail_json
        from escalation_decisions
        where case_id = ?
        order by occurred_at asc
        """,
        ("case_stage_progress_001",),
    ).fetchall()
    assert len(escalation_rows) == 4
    assert [row["triggered"] for row in escalation_rows] == [1, 1, 1, 0]
    assert [row["reason"] for row in escalation_rows] == [
        "threshold_met",
        "threshold_met",
        "threshold_met",
        "dedupe_hit",
    ]
    assert escalation_rows[-1]["dedupe_key"].endswith(":stage:command_execution")
    assert "deduped_stage_not_advanced" in escalation_rows[-1]["detail_json"]
    conn.close()


def test_entity_assessments_audit_filters_high_risk_attackers(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    dispatch_tool(
        conn,
        "assessment.upsert",
        {
            "entity_type": "ip",
            "entity_key": "198.51.100.23",
            "entity_label": "198.51.100.23",
            "related_case_id": "case_demo_001",
            "risk_level": "high",
            "assessment_confidence": 0.93,
            "verdict": "attacker",
            "reason_summary": "high risk attacker",
            "supporting_alert_ids": ["alt_day2_webshell_01"],
            "supporting_evidence_ids": ["evi_webshell_01"],
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "assessment.upsert",
        {
            "entity_type": "ip",
            "entity_key": "192.0.2.91",
            "entity_label": "192.0.2.91",
            "related_case_id": "case_noise_001",
            "risk_level": "low",
            "assessment_confidence": 0.55,
            "verdict": "noise",
            "reason_summary": "scan noise",
            "supporting_alert_ids": [],
            "supporting_evidence_ids": [],
        },
        source="cli",
    )
    conn.close()

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "audit.entity-assessments",
            "--db-path",
            str(db_path),
            "--entity-type",
            "ip",
            "--risk-level",
            "high",
        ],
    )
    assert result.exit_code == 0
    rows = json.loads(result.stdout)["rows"]
    keys = {row["entity_key"] for row in rows}
    assert "198.51.100.23" in keys
    assert "192.0.2.91" not in keys


def test_audit_compact_archives_old_rows_and_keeps_recent_rows(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.executescript(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values
          ('call_old_001', '2025-01-01T00:00:00+00:00', null, 'cli', 'alert.fetch', '{}', 1, 'ok', '{}', 1),
          ('call_new_001', '2099-01-01T00:00:00+00:00', null, 'cli', 'alert.fetch', '{}', 1, 'ok', '{}', 1);

        insert into case_changes (
          change_id, occurred_at, run_id, case_id, action, before_json, after_json, reason
        ) values
          ('cchg_old_001', '2025-01-01T00:00:00+00:00', null, 'case_demo_001', 'case_update_risk', '{}', '{}', 'old'),
          ('cchg_new_001', '2099-01-01T00:00:00+00:00', null, 'case_demo_001', 'case_update_risk', '{}', '{}', 'new');

        insert into link_decisions (
          decision_id, occurred_at, run_id, alert_id, case_id, link_confidence, reason_summary,
          positive_factors_json, negative_factors_json, uncertainties_json, supporting_evidence_ids_json, analysis_cutoff_at
        ) values
          ('ldec_old_001', '2025-01-01T00:00:00+00:00', null, 'alt_day1_scan_01', 'case_demo_001', 0.7, 'old', '[]', '[]', '[]', '[]', null),
          ('ldec_new_001', '2099-01-01T00:00:00+00:00', null, 'alt_day1_scan_01', 'case_demo_001', 0.7, 'new', '[]', '[]', '[]', '[]', null);

        insert into alert_decisions (
          decision_id, occurred_at, run_id, alert_id, decision, case_id, confidence, reason, detail_json
        ) values
          ('adec_old_001', '2025-01-01T00:00:00+00:00', null, 'alt_day1_scan_01', 'ack_missing_alert', null, null, 'old', '{}'),
          ('adec_new_001', '2099-01-01T00:00:00+00:00', null, 'alt_day1_scan_01', 'ack_missing_alert', null, null, 'new', '{}');
        """
    )
    conn.commit()
    conn.close()

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "audit.compact",
            "--db-path",
            str(db_path),
        ],
    )
    assert result.exit_code == 0
    body = json.loads(result.stdout)
    moved = {item["table"]: item["archived_rows"] for item in body["tables"]}
    assert moved["agent_tool_calls"] == 1
    assert moved["case_changes"] == 1
    assert moved["link_decisions"] == 1
    assert moved["alert_decisions"] == 1

    conn = connect_db(db_path)
    assert conn.execute("select count(*) from agent_tool_calls where call_id = 'call_old_001'").fetchone()[0] == 0
    assert conn.execute("select count(*) from agent_tool_calls where call_id = 'call_new_001'").fetchone()[0] == 1
    assert conn.execute("select count(*) from agent_tool_calls_archive where call_id = 'call_old_001'").fetchone()[0] == 1
    assert conn.execute("select count(*) from case_changes_archive where change_id = 'cchg_old_001'").fetchone()[0] == 1
    assert conn.execute("select count(*) from link_decisions_archive where decision_id = 'ldec_old_001'").fetchone()[0] == 1
    assert conn.execute("select count(*) from alert_decisions_archive where decision_id = 'adec_old_001'").fetchone()[0] == 1
    conn.close()
