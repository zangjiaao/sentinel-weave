import json

from typer.testing import CliRunner

from security_analyst_agent.bootstrap import bootstrap_spike_database
from security_analyst_agent.cli import app
from security_analyst_agent.db import connect_db
from security_analyst_agent.tool_dispatch import dispatch_tool


def test_dispatch_tool_writes_audit_logs(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
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
        "alert.ack",
        {"alert_ids": ["alt_day2_webshell_01"], "status": "triaged"},
        source="cli",
    )

    tool_call_count = conn.execute("select count(*) from agent_tool_calls").fetchone()[0]
    alert_decision_count = conn.execute("select count(*) from alert_decisions").fetchone()[0]
    case_change_count = conn.execute("select count(*) from case_changes").fetchone()[0]
    escalation_count = conn.execute("select count(*) from escalation_decisions").fetchone()[0]

    assert tool_call_count >= 4
    assert alert_decision_count >= 2
    assert case_change_count >= 1
    assert escalation_count >= 1
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
        select run_id, trigger_source, status
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
    assert decision_row["decision"] == "ack_triaged"
    assert decision_row["reason"] == "tool:alert.ack"
    assert decision_row["run_id"] is None
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
