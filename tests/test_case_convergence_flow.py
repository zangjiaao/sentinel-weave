from security_analyst_agent.bootstrap import bootstrap_spike_database
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
            f"convergence {alert_id}",
            "open",
            "high",
            stage,
            src_ip,
            "203.0.113.10",
            "asset_api_prod",
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
        (case_id, alert_id, occurred_at, 0.9, "convergence_seed"),
    )


def test_mcp_auto_run_triggers_case_convergence_after_ack(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_conv_a",
            "title": "case convergence A",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "persistence",
            "primary_actor_id": "actor_conv_a",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_conv_b",
            "title": "case convergence B",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "primary_actor_id": "actor_conv_b",
        },
        source="cli",
    )
    conn.execute(
        """
        insert into evidence (evidence_id, case_id, occurred_at, evidence_type, summary)
        values (?, ?, ?, ?, ?)
        """,
        (
            "evi_conv_anchor",
            "case_conv_a",
            "2026-04-10T09:00:00+08:00",
            "webshell",
            "anchor evidence for canonical reselect",
        ),
    )
    conn.commit()

    for round_idx in range(1, 4):
        base_ts = f"2026-04-1{round_idx}T10:0{round_idx}:00+08:00"
        _insert_open_alert_for_case(
            conn,
            alert_id=f"alt_conv_a_r{round_idx}",
            case_id="case_conv_a",
            occurred_at=base_ts,
            stage="persistence",
            src_ip="198.51.100.23",
        )
        _insert_open_alert_for_case(
            conn,
            alert_id=f"alt_conv_b_r{round_idx}",
            case_id="case_conv_b",
            occurred_at=base_ts,
            stage="command_execution",
            src_ip="198.51.100.77",
        )
        conn.commit()

        dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 100}, source="mcp")
        open_alert_ids = [
            row["alert_id"] for row in conn.execute("select alert_id from alerts where status in ('new', 'open')")
        ]
        dispatch_tool(conn, "alert.ack", {"alert_ids": open_alert_ids, "status": "triaged"}, source="mcp")

    relation = conn.execute(
        """
        select status, streak_count
        from case_relations
        where left_case_id = ? and right_case_id = ?
        """,
        ("case_conv_a", "case_conv_b"),
    ).fetchone()
    assert relation is not None
    assert relation["status"] == "confirmed"
    assert relation["streak_count"] >= 3

    merge_event = conn.execute(
        """
        select new_canonical_case_id
        from case_merge_events
        order by occurred_at desc
        limit 1
        """
    ).fetchone()
    assert merge_event is not None
    assert merge_event["new_canonical_case_id"] == "case_conv_a"

    case_b = conn.execute(
        """
        select canonical_case_id, merged_into_case_id, merge_state
        from cases
        where case_id = ?
        """,
        ("case_conv_b",),
    ).fetchone()
    assert case_b["canonical_case_id"] == "case_conv_a"
    assert case_b["merged_into_case_id"] == "case_conv_a"
    assert case_b["merge_state"] == "merged"
    conn.close()
