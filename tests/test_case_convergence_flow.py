from security_analyst_agent.bootstrap import bootstrap_spike_database
from security_analyst_agent.db import connect_db
from security_analyst_agent.services.case_convergence import run_case_convergence_for_run
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
            f"convergence {alert_id}",
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
        (case_id, alert_id, occurred_at, confidence, "convergence_seed"),
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
    assert relation["streak_count"] >= 1

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
        select status, canonical_case_id, merged_into_case_id, merge_state
        from cases
        where case_id = ?
        """,
        ("case_conv_b",),
    ).fetchone()
    assert case_b["status"] == "closed"
    assert case_b["canonical_case_id"] == "case_conv_a"
    assert case_b["merged_into_case_id"] == "case_conv_a"
    assert case_b["merge_state"] == "merged"
    retargeted = conn.execute(
        """
        select count(*)
        from case_alert_links
        where case_id = 'case_conv_a'
          and alert_id like 'alt_conv_b_r%'
          and is_active = 1
        """
    ).fetchone()[0]
    stale_child_links = conn.execute(
        """
        select count(*)
        from case_alert_links
        where case_id = 'case_conv_b'
          and alert_id like 'alt_conv_b_r%'
          and is_active = 1
        """
    ).fetchone()[0]
    assert retargeted == 3
    assert stale_child_links == 0
    conn.close()


def test_case_convergence_ignores_low_confidence_noise_links_for_relation_score(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_conv_noise_a",
            "title": "case convergence with noise A",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "persistence",
            "primary_actor_id": "actor_conv_noise_a",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_conv_noise_b",
            "title": "case convergence with noise B",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "primary_actor_id": "actor_conv_noise_b",
        },
        source="cli",
    )

    _insert_open_alert_for_case(
        conn,
        alert_id="alt_conv_noise_a_signal",
        case_id="case_conv_noise_a",
        occurred_at="2026-04-12T10:00:00+08:00",
        stage="persistence",
        src_ip="198.51.100.23",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_conv_noise_a_low",
        case_id="case_conv_noise_a",
        occurred_at="2026-04-12T10:05:00+08:00",
        stage="recon",
        src_ip="203.0.113.200",
        severity="low",
        confidence=0.3,
        asset_id="asset_static_www",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_conv_noise_b_signal",
        case_id="case_conv_noise_b",
        occurred_at="2026-04-12T10:07:00+08:00",
        stage="command_execution",
        src_ip="198.51.100.77",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    conn.commit()

    dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 100}, source="mcp")
    open_alert_ids = [row["alert_id"] for row in conn.execute("select alert_id from alerts where status in ('new', 'open')")]
    dispatch_tool(conn, "alert.ack", {"alert_ids": open_alert_ids, "status": "triaged"}, source="mcp")

    relation = conn.execute(
        """
        select score, status, streak_count
        from case_relations
        where left_case_id = ? and right_case_id = ?
        """,
        ("case_conv_noise_a", "case_conv_noise_b"),
    ).fetchone()
    assert relation is not None
    assert relation["score"] >= 0.78
    assert relation["status"] == "confirmed"
    assert relation["streak_count"] == 1
    conn.close()


def test_case_convergence_promotes_bridge_candidate_from_confirmed_cluster(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_bridge_a",
            "title": "bridge case A",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "persistence",
            "primary_actor_id": "actor_bridge_a",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_bridge_b",
            "title": "bridge case B",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "primary_actor_id": "actor_bridge_b",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_bridge_c",
            "title": "bridge case C",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "lateral_prep",
            "primary_actor_id": "actor_bridge_c",
        },
        source="cli",
    )

    for round_idx in range(1, 4):
        base_ts = f"2026-04-1{round_idx}T12:0{round_idx}:00+08:00"
        _insert_open_alert_for_case(
            conn,
            alert_id=f"alt_bridge_a_r{round_idx}",
            case_id="case_bridge_a",
            occurred_at=base_ts,
            stage="persistence",
            src_ip="198.51.100.23",
        )
        _insert_open_alert_for_case(
            conn,
            alert_id=f"alt_bridge_b_r{round_idx}",
            case_id="case_bridge_b",
            occurred_at=base_ts,
            stage="command_execution",
            src_ip="198.51.100.77",
        )
        if round_idx >= 2:
            _insert_open_alert_for_case(
                conn,
                alert_id=f"alt_bridge_c_r{round_idx}",
                case_id="case_bridge_c",
                occurred_at=base_ts,
                stage="lateral_prep",
                src_ip="198.51.100.77",
            )
        conn.commit()

        dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 100}, source="mcp")
        open_alert_ids = [
            row["alert_id"] for row in conn.execute("select alert_id from alerts where status in ('new', 'open')")
        ]
        dispatch_tool(conn, "alert.ack", {"alert_ids": open_alert_ids, "status": "triaged"}, source="mcp")

    bridge_relation = conn.execute(
        """
        select score, streak_count, status
        from case_relations
        where left_case_id = ? and right_case_id = ?
        """,
        ("case_bridge_b", "case_bridge_c"),
    ).fetchone()
    assert bridge_relation is not None
    assert bridge_relation["score"] >= 0.82
    assert bridge_relation["status"] == "confirmed"

    case_c = conn.execute(
        """
        select status, canonical_case_id, merged_into_case_id, merge_state
        from cases
        where case_id = ?
        """,
        ("case_bridge_c",),
    ).fetchone()
    assert case_c is not None
    assert case_c["status"] == "closed"
    assert case_c["merge_state"] == "merged"
    conn.close()


def test_case_convergence_fast_tracks_obvious_reactivation_chain(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_fast_a",
            "title": "fast chain A",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "persistence",
            "primary_actor_id": "actor_fast_a",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_fast_b",
            "title": "fast chain B",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "primary_actor_id": "actor_fast_b",
        },
        source="cli",
    )
    conn.execute(
        """
        insert into evidence (evidence_id, case_id, occurred_at, evidence_type, summary)
        values (?, ?, ?, ?, ?)
        """,
        (
            "evi_fast_anchor",
            "case_fast_a",
            "2026-04-12T10:00:00+08:00",
            "webshell",
            "fast-track anchor evidence",
        ),
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_fast_a",
        case_id="case_fast_a",
        occurred_at="2026-04-12T11:00:00+08:00",
        stage="persistence",
        src_ip="198.51.100.23",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_fast_b",
        case_id="case_fast_b",
        occurred_at="2026-04-12T11:30:00+08:00",
        stage="command_execution",
        src_ip="198.51.100.91",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    conn.commit()

    dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 100}, source="mcp")
    open_alert_ids = [row["alert_id"] for row in conn.execute("select alert_id from alerts where status in ('new', 'open')")]
    dispatch_tool(conn, "alert.ack", {"alert_ids": open_alert_ids, "status": "triaged"}, source="mcp")

    relation = conn.execute(
        """
        select status, streak_count
        from case_relations
        where left_case_id = ? and right_case_id = ?
        """,
        ("case_fast_a", "case_fast_b"),
    ).fetchone()
    assert relation is not None
    assert relation["status"] == "confirmed"
    assert relation["streak_count"] == 1

    canonical_rows = conn.execute(
        """
        select case_id, canonical_case_id, merge_state
        from cases
        where case_id in ('case_fast_a', 'case_fast_b')
        order by case_id
        """
    ).fetchall()
    canonical_ids = {row["canonical_case_id"] for row in canonical_rows}
    assert len(canonical_ids) == 1
    assert any(row["merge_state"] == "merged" for row in canonical_rows)
    conn.close()


def test_case_convergence_skips_noise_only_recon_cases(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_noise_only",
            "title": "noise-only case",
            "status": "open",
            "overall_severity": "low",
            "current_stage": "recon",
            "primary_actor_id": "actor_noise_only",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_signal_high",
            "title": "signal case",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "primary_actor_id": "actor_signal_high",
        },
        source="cli",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_noise_only_01",
        case_id="case_noise_only",
        occurred_at="2026-04-12T10:00:00+08:00",
        stage="recon",
        src_ip="203.0.113.200",
        severity="low",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_signal_high_01",
        case_id="case_signal_high",
        occurred_at="2026-04-12T10:30:00+08:00",
        stage="command_execution",
        src_ip="198.51.100.91",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    conn.commit()

    dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 100}, source="mcp")
    open_alert_ids = [row["alert_id"] for row in conn.execute("select alert_id from alerts where status in ('new', 'open')")]
    dispatch_tool(conn, "alert.ack", {"alert_ids": open_alert_ids, "status": "triaged"}, source="mcp")

    relation = conn.execute(
        """
        select relation_id
        from case_relations
        where (left_case_id = 'case_noise_only' and right_case_id = 'case_signal_high')
           or (left_case_id = 'case_signal_high' and right_case_id = 'case_noise_only')
        """
    ).fetchone()
    assert relation is None
    conn.close()


def test_case_convergence_rolls_up_canonical_stage_and_severity(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_rollup_anchor",
            "title": "rollup anchor",
            "status": "open",
            "overall_severity": "medium",
            "current_stage": "persistence",
            "primary_actor_id": "actor_rollup_anchor",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_rollup_child",
            "title": "rollup child",
            "status": "open",
            "overall_severity": "critical",
            "current_stage": "command_execution",
            "primary_actor_id": "actor_rollup_child",
        },
        source="cli",
    )
    conn.execute(
        """
        insert into evidence (evidence_id, case_id, occurred_at, evidence_type, summary)
        values (?, ?, ?, ?, ?)
        """,
        (
            "evi_rollup_anchor",
            "case_rollup_anchor",
            "2026-04-12T10:00:00+08:00",
            "webshell",
            "canonical anchor",
        ),
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_rollup_anchor",
        case_id="case_rollup_anchor",
        occurred_at="2026-04-12T11:00:00+08:00",
        stage="persistence",
        src_ip="198.51.100.23",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_rollup_child",
        case_id="case_rollup_child",
        occurred_at="2026-04-12T11:30:00+08:00",
        stage="command_execution",
        src_ip="198.51.100.91",
        severity="critical",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    conn.commit()

    dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 100}, source="mcp")
    open_alert_ids = [row["alert_id"] for row in conn.execute("select alert_id from alerts where status in ('new', 'open')")]
    dispatch_tool(conn, "alert.ack", {"alert_ids": open_alert_ids, "status": "triaged"}, source="mcp")

    canonical_case = conn.execute(
        """
        select current_stage, overall_severity, status
        from cases
        where case_id = ?
        """,
        ("case_rollup_anchor",),
    ).fetchone()
    assert canonical_case is not None
    assert canonical_case["current_stage"] == "command_execution"
    assert canonical_case["overall_severity"] == "critical"
    assert canonical_case["status"] == "open"
    conn.close()


def test_case_convergence_rollup_prefers_highest_stage_over_latest_timestamp(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_stage_highwater",
            "title": "stage highwater",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "exploit",
            "primary_actor_id": "actor_stage_highwater",
        },
        source="cli",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_stage_highwater_lateral",
        case_id="case_stage_highwater",
        occurred_at="2026-04-12T10:00:00+08:00",
        stage="lateral_prep",
        src_ip="198.51.100.120",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_stage_highwater_cmd",
        case_id="case_stage_highwater",
        occurred_at="2026-04-12T11:00:00+08:00",
        stage="command_execution",
        src_ip="198.51.100.120",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    conn.commit()

    run_case_convergence_for_run(conn, run_id="run_stage_highwater_1")
    case_row = conn.execute(
        """
        select current_stage
        from cases
        where case_id = 'case_stage_highwater'
        """
    ).fetchone()
    assert case_row is not None
    assert case_row["current_stage"] == "lateral_prep"
    conn.close()


def test_case_convergence_rolls_up_current_entity_assessment_to_canonical_case(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_entity_rollup_anchor",
            "title": "entity rollup anchor",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "persistence",
            "primary_actor_id": "actor_entity_rollup_anchor",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_entity_rollup_child",
            "title": "entity rollup child",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "primary_actor_id": "actor_entity_rollup_child",
        },
        source="cli",
    )
    conn.execute(
        """
        insert into evidence (evidence_id, case_id, occurred_at, evidence_type, summary)
        values (?, ?, ?, ?, ?)
        """,
        (
            "evi_entity_rollup_anchor",
            "case_entity_rollup_anchor",
            "2026-04-12T09:00:00+08:00",
            "webshell",
            "entity rollup merge anchor",
        ),
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_entity_rollup_anchor",
        case_id="case_entity_rollup_anchor",
        occurred_at="2026-04-12T10:00:00+08:00",
        stage="persistence",
        src_ip="198.51.100.199",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_entity_rollup_child",
        case_id="case_entity_rollup_child",
        occurred_at="2026-04-12T10:10:00+08:00",
        stage="command_execution",
        src_ip="198.51.100.199",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    dispatch_tool(
        conn,
        "assessment.upsert-batch",
        {
            "items": [
                {
                    "entity_type": "ip",
                    "entity_key": "198.51.100.199",
                    "entity_label": "198.51.100.199",
                    "related_case_id": "case_entity_rollup_anchor",
                    "risk_level": "medium",
                    "assessment_confidence": 0.72,
                    "verdict": "attacker",
                    "reason_summary": "anchor verdict",
                    "supporting_alert_ids": ["alt_entity_rollup_anchor"],
                    "supporting_evidence_ids": [],
                }
            ]
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "assessment.upsert-batch",
        {
            "items": [
                {
                    "entity_type": "ip",
                    "entity_key": "198.51.100.199",
                    "entity_label": "198.51.100.199",
                    "related_case_id": "case_entity_rollup_child",
                    "risk_level": "high",
                    "assessment_confidence": 0.91,
                    "verdict": "attacker",
                    "reason_summary": "child verdict",
                    "supporting_alert_ids": ["alt_entity_rollup_child"],
                    "supporting_evidence_ids": [],
                }
            ]
        },
        source="cli",
    )
    conn.commit()

    summary = run_case_convergence_for_run(conn, run_id="run_entity_rollup_1")
    assert summary["merge_events_count"] >= 1

    merged_child = conn.execute(
        """
        select merge_state, merged_into_case_id
        from cases
        where case_id = 'case_entity_rollup_child'
        """
    ).fetchone()
    assert merged_child is not None
    assert merged_child["merge_state"] == "merged"
    assert merged_child["merged_into_case_id"] == "case_entity_rollup_anchor"

    current_rows = conn.execute(
        """
        select related_case_id, risk_level, assessment_confidence
        from entity_assessments
        where entity_type = 'ip'
          and entity_key = '198.51.100.199'
          and is_current = 1
        """
    ).fetchall()
    assert len(current_rows) == 1
    assert current_rows[0]["related_case_id"] == "case_entity_rollup_anchor"
    assert current_rows[0]["risk_level"] == "high"
    assert current_rows[0]["assessment_confidence"] >= 0.9
    conn.close()


def test_case_convergence_suppresses_global_current_when_case_scoped_exists(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_entity_global_suppress",
            "title": "entity global suppress",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "primary_actor_id": "actor_entity_global_suppress",
        },
        source="cli",
    )
    conn.execute(
        """
        insert into entity_assessments (
          assessment_id,
          occurred_at,
          run_id,
          entity_type,
          entity_key,
          entity_label,
          related_case_id,
          risk_level,
          assessment_confidence,
          verdict,
          reason_summary,
          supporting_alert_ids_json,
          supporting_evidence_ids_json,
          first_seen_at,
          last_seen_at,
          analysis_cutoff_at,
          is_current
        ) values
          (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
          (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "eass_case_current_001",
            "2026-04-12T10:00:00+08:00",
            "run_seed_case_current",
            "ip",
            "198.51.100.250",
            "198.51.100.250",
            "case_entity_global_suppress",
            "high",
            0.9,
            "attacker",
            "seed case scoped",
            "[]",
            "[]",
            "2026-04-12T10:00:00+08:00",
            "2026-04-12T10:00:00+08:00",
            None,
            1,
            "eass_global_current_001",
            "2026-04-12T10:01:00+08:00",
            "run_seed_global_current",
            "ip",
            "198.51.100.250",
            "198.51.100.250",
            None,
            "high",
            0.8,
            "attacker",
            "seed global current",
            "[]",
            "[]",
            "2026-04-12T10:01:00+08:00",
            "2026-04-12T10:01:00+08:00",
            None,
            1,
        ),
    )
    conn.commit()

    summary = run_case_convergence_for_run(conn, run_id="run_entity_global_suppress_1")
    assert summary["suppressed_global_entity_currents_count"] >= 1

    current_rows = conn.execute(
        """
        select related_case_id
        from entity_assessments
        where entity_type = 'ip'
          and entity_key = '198.51.100.250'
          and is_current = 1
        """
    ).fetchall()
    assert len(current_rows) == 1
    assert current_rows[0]["related_case_id"] == "case_entity_global_suppress"
    conn.close()


def test_case_convergence_rolls_up_case_actor_and_primary_actor_to_canonical(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_actor_rollup_anchor",
            "title": "actor rollup anchor",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "lateral_prep",
            "primary_actor_id": "legacy_anchor_actor",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_actor_rollup_child",
            "title": "actor rollup child",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "primary_actor_id": "legacy_child_actor",
        },
        source="cli",
    )
    conn.execute(
        """
        insert into evidence (evidence_id, case_id, occurred_at, evidence_type, summary)
        values (?, ?, ?, ?, ?)
        """,
        (
            "evi_actor_rollup_anchor",
            "case_actor_rollup_anchor",
            "2026-04-11T14:20:00+08:00",
            "webshell",
            "anchor evidence",
        ),
    )

    _insert_open_alert_for_case(
        conn,
        alert_id="alt_actor_rollup_anchor_lateral",
        case_id="case_actor_rollup_anchor",
        occurred_at="2026-04-12T11:20:00+08:00",
        stage="lateral_prep",
        src_ip="198.51.100.77",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_actor_rollup_child_reactivation",
        case_id="case_actor_rollup_child",
        occurred_at="2026-04-14T08:30:00+08:00",
        stage="command_execution",
        src_ip="198.51.100.91",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )

    dispatch_tool(
        conn,
        "actor.case-upsert",
        {
            "case_actor_id": "actor_rollup_anchor",
            "case_id": "case_actor_rollup_anchor",
            "label": "198.51.100.77",
            "status": "active",
            "profile_confidence": 0.7,
            "risk_level": "high",
            "is_primary": True,
            "current_stage": "lateral_prep",
            "summary": "anchor actor",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "actor.case-upsert",
        {
            "case_actor_id": "actor_rollup_child",
            "case_id": "case_actor_rollup_child",
            "label": "198.51.100.91",
            "status": "active",
            "profile_confidence": 0.85,
            "risk_level": "high",
            "is_primary": True,
            "current_stage": "command_execution",
            "summary": "child actor",
        },
        source="cli",
    )
    conn.commit()

    run_case_convergence_for_run(conn, run_id="run_actor_rollup_1")
    run_case_convergence_for_run(conn, run_id="run_actor_rollup_2")
    run_case_convergence_for_run(conn, run_id="run_actor_rollup_3")

    canonical_case = conn.execute(
        """
        select case_id, current_stage, primary_actor_id
        from cases
        where case_id = 'case_actor_rollup_anchor'
        """
    ).fetchone()
    assert canonical_case is not None
    assert canonical_case["current_stage"] == "lateral_prep"
    assert canonical_case["primary_actor_id"] == "actor_rollup_child"

    child_case = conn.execute(
        """
        select merge_state, merged_into_case_id, status
        from cases
        where case_id = 'case_actor_rollup_child'
        """
    ).fetchone()
    assert child_case is not None
    assert child_case["merge_state"] == "merged"
    assert child_case["merged_into_case_id"] == "case_actor_rollup_anchor"
    assert child_case["status"] == "closed"

    actor_rows = conn.execute(
        """
        select case_actor_id, case_id, is_primary
        from case_actor_profiles
        where case_actor_id in ('actor_rollup_anchor', 'actor_rollup_child')
        order by case_actor_id asc
        """
    ).fetchall()
    assert len(actor_rows) == 2
    assert {row["case_id"] for row in actor_rows} == {"case_actor_rollup_anchor"}
    primary_actor_ids = [row["case_actor_id"] for row in actor_rows if row["is_primary"] == 1]
    assert primary_actor_ids == ["actor_rollup_child"]
    conn.close()


def test_case_convergence_backfills_high_signal_alert_actor_coverage_with_single_actor(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_actor_backfill_org",
            "title": "actor backfill org",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "primary_actor_id": None,
        },
        source="cli",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_actor_backfill_high_1",
        case_id="case_actor_backfill_org",
        occurred_at="2026-04-12T11:03:00+08:00",
        stage="command_execution",
        src_ip="198.51.100.77",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_actor_backfill_high_2",
        case_id="case_actor_backfill_org",
        occurred_at="2026-04-14T08:30:00+08:00",
        stage="command_execution",
        src_ip="198.51.100.91",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_actor_backfill_low_noise",
        case_id="case_actor_backfill_org",
        occurred_at="2026-04-14T08:35:00+08:00",
        stage="recon",
        src_ip="192.0.2.56",
        severity="low",
        confidence=0.6,
        asset_id="asset_admin_portal",
    )
    conn.commit()

    summary = run_case_convergence_for_run(conn, run_id="run_actor_backfill_1")
    assert summary["backfilled_case_actor_count"] == 1
    assert summary["backfilled_actor_link_count"] == 2
    assert summary["backfilled_actor_observation_count"] == 2

    summary_repeat = run_case_convergence_for_run(conn, run_id="run_actor_backfill_2")
    assert summary_repeat["backfilled_case_actor_count"] == 0
    assert summary_repeat["backfilled_actor_link_count"] == 0
    assert summary_repeat["backfilled_actor_observation_count"] == 0

    case_row = conn.execute(
        """
        select primary_actor_id
        from cases
        where case_id = 'case_actor_backfill_org'
        """
    ).fetchone()
    assert case_row is not None
    assert case_row["primary_actor_id"] is not None

    actor_rows = conn.execute(
        """
        select case_actor_id, is_primary
        from case_actor_profiles
        where case_id = 'case_actor_backfill_org'
        order by case_actor_id asc
        """
    ).fetchall()
    assert len(actor_rows) == 1
    assert actor_rows[0]["is_primary"] == 1

    mapped_alerts = conn.execute(
        """
        select case_actor_links.target_id
        from case_actor_links
        join case_actor_profiles on case_actor_profiles.case_actor_id = case_actor_links.case_actor_id
        where case_actor_profiles.case_id = 'case_actor_backfill_org'
          and case_actor_links.target_type = 'alert'
        order by case_actor_links.target_id asc
        """
    ).fetchall()
    assert [row["target_id"] for row in mapped_alerts] == [
        "alt_actor_backfill_high_1",
        "alt_actor_backfill_high_2",
    ]

    observation_ips = conn.execute(
        """
        select observation_key
        from case_actor_observations
        where case_actor_id = ?
          and observation_type = 'src_ip'
        order by observation_key asc
        """,
        (case_row["primary_actor_id"],),
    ).fetchall()
    assert [row["observation_key"] for row in observation_ips] == ["198.51.100.77", "198.51.100.91"]
    conn.close()


def test_case_convergence_defers_primary_actor_rollup_for_recon_stage_case(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_actor_defer_recon",
            "title": "actor defer recon",
            "status": "open",
            "overall_severity": "medium",
            "current_stage": "recon",
            "primary_actor_id": None,
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "actor.case-upsert",
        {
            "case_actor_id": "actor_defer_recon_001",
            "case_id": "case_actor_defer_recon",
            "label": "recon actor",
            "status": "active",
            "profile_confidence": 0.92,
            "risk_level": "medium",
            "is_primary": True,
            "current_stage": "recon",
            "summary": "recon-only actor should stay pending",
        },
        source="cli",
    )
    conn.commit()

    run_case_convergence_for_run(conn, run_id="run_actor_defer_recon_1")

    case_row = conn.execute(
        """
        select primary_actor_id
        from cases
        where case_id = 'case_actor_defer_recon'
        """
    ).fetchone()
    assert case_row is not None
    assert case_row["primary_actor_id"] is None

    actor_primary_count = conn.execute(
        """
        select count(*)
        from case_actor_profiles
        where case_id = 'case_actor_defer_recon' and is_primary = 1
        """
    ).fetchone()[0]
    assert actor_primary_count == 0
    conn.close()


def test_case_convergence_backfills_compromised_host_assessment_for_high_signal_case(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_asset_backfill",
            "title": "asset backfill",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "primary_actor_id": None,
        },
        source="cli",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_asset_backfill_1",
        case_id="case_asset_backfill",
        occurred_at="2026-04-12T11:03:00+08:00",
        stage="command_execution",
        src_ip="198.51.100.77",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_asset_backfill_2",
        case_id="case_asset_backfill",
        occurred_at="2026-04-12T11:10:00+08:00",
        stage="persistence",
        src_ip="198.51.100.91",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    conn.commit()

    summary = run_case_convergence_for_run(conn, run_id="run_asset_backfill_1")
    assert summary["backfilled_compromised_host_assessments_count"] >= 1

    row = conn.execute(
        """
        select related_case_id, risk_level, verdict, is_current
        from entity_assessments
        where entity_type = 'asset'
          and entity_key = 'asset_api_prod'
          and related_case_id = 'case_asset_backfill'
          and is_current = 1
        order by occurred_at desc
        limit 1
        """
    ).fetchone()
    assert row is not None
    assert row["risk_level"] == "high"
    assert row["verdict"] == "compromised_host"
    assert row["is_current"] == 1
    conn.close()


def test_case_convergence_includes_active_status_case_in_relation_and_merge(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_active_conv_anchor",
            "title": "active conv anchor",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "persistence",
            "primary_actor_id": "actor_active_conv_anchor",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_active_conv_child",
            "title": "active conv child",
            "status": "active",
            "overall_severity": "high",
            "current_stage": "lateral_prep",
            "primary_actor_id": "actor_active_conv_child",
        },
        source="cli",
    )
    conn.execute(
        """
        insert into evidence (evidence_id, case_id, occurred_at, evidence_type, summary)
        values (?, ?, ?, ?, ?)
        """,
        (
            "evi_active_conv_anchor",
            "case_active_conv_anchor",
            "2026-04-12T09:40:00+08:00",
            "webshell",
            "active status merge anchor",
        ),
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_active_conv_anchor",
        case_id="case_active_conv_anchor",
        occurred_at="2026-04-12T10:00:00+08:00",
        stage="persistence",
        src_ip="198.51.100.23",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_active_conv_child",
        case_id="case_active_conv_child",
        occurred_at="2026-04-12T10:10:00+08:00",
        stage="lateral_prep",
        src_ip="198.51.100.23",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    conn.commit()

    run_case_convergence_for_run(conn, run_id="run_active_case_merge_1")
    run_case_convergence_for_run(conn, run_id="run_active_case_merge_2")
    summary = run_case_convergence_for_run(conn, run_id="run_active_case_merge_3")
    assert summary["confirmed_relations_count"] >= 1
    assert summary["merge_events_count"] >= 1

    merged_child = conn.execute(
        """
        select canonical_case_id, merged_into_case_id, merge_state, status
        from cases
        where case_id = 'case_active_conv_child'
        """
    ).fetchone()
    assert merged_child is not None
    assert merged_child["canonical_case_id"] == "case_active_conv_anchor"
    assert merged_child["merged_into_case_id"] == "case_active_conv_anchor"
    assert merged_child["merge_state"] == "merged"
    assert merged_child["status"] == "closed"
    conn.close()


def test_case_convergence_can_reattach_case_after_stronger_new_relation(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_reassign_a",
            "title": "reassign A",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "persistence",
            "primary_actor_id": "actor_reassign_a",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_reassign_c",
            "title": "reassign C",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "primary_actor_id": "actor_reassign_c",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_reassign_b",
            "title": "reassign B",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "primary_actor_id": "actor_reassign_b",
        },
        source="cli",
    )

    conn.execute(
        """
        insert into evidence (evidence_id, case_id, occurred_at, evidence_type, summary)
        values (?, ?, ?, ?, ?)
        """,
        (
            "evi_reassign_anchor_a",
            "case_reassign_a",
            "2026-04-12T09:50:00+08:00",
            "webshell",
            "round1 canonical anchor",
        ),
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_reassign_a_r1",
        case_id="case_reassign_a",
        occurred_at="2026-04-12T10:00:00+08:00",
        stage="persistence",
        src_ip="198.51.100.23",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_reassign_c_r1",
        case_id="case_reassign_c",
        occurred_at="2026-04-12T10:20:00+08:00",
        stage="command_execution",
        src_ip="198.51.100.77",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    conn.commit()

    dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 100}, source="mcp")
    open_alert_ids = [row["alert_id"] for row in conn.execute("select alert_id from alerts where status in ('new', 'open')")]
    dispatch_tool(conn, "alert.ack", {"alert_ids": open_alert_ids, "status": "triaged"}, source="mcp")

    round1_case_c = conn.execute(
        """
        select canonical_case_id, merged_into_case_id, merge_state, status
        from cases
        where case_id = ?
        """,
        ("case_reassign_c",),
    ).fetchone()
    assert round1_case_c is not None
    assert round1_case_c["canonical_case_id"] == "case_reassign_a"
    assert round1_case_c["merged_into_case_id"] == "case_reassign_a"
    assert round1_case_c["merge_state"] == "merged"

    conn.execute(
        """
        insert into evidence (evidence_id, case_id, occurred_at, evidence_type, summary)
        values (?, ?, ?, ?, ?)
        """,
        (
            "evi_reassign_anchor_b",
            "case_reassign_b",
            "2026-04-13T10:50:00+08:00",
            "webshell",
            "round2 canonical anchor",
        ),
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_reassign_c_r2",
        case_id="case_reassign_c",
        occurred_at="2026-04-13T11:00:00+08:00",
        stage="command_execution",
        src_ip="198.51.100.66",
        severity="critical",
        confidence=0.9,
        asset_id="asset_admin_portal",
        dst_ip="203.0.113.80",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_reassign_b_r2",
        case_id="case_reassign_b",
        occurred_at="2026-04-13T11:05:00+08:00",
        stage="command_execution",
        src_ip="198.51.100.66",
        severity="critical",
        confidence=0.9,
        asset_id="asset_admin_portal",
        dst_ip="203.0.113.80",
    )
    conn.commit()

    dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 100}, source="mcp")
    open_alert_ids = [row["alert_id"] for row in conn.execute("select alert_id from alerts where status in ('new', 'open')")]
    dispatch_tool(conn, "alert.ack", {"alert_ids": open_alert_ids, "status": "triaged"}, source="mcp")

    stale_relation = conn.execute(
        """
        select status, last_reason
        from case_relations
        where left_case_id = ? and right_case_id = ?
        """,
        ("case_reassign_a", "case_reassign_c"),
    ).fetchone()
    assert stale_relation is not None
    assert stale_relation["status"] == "candidate"
    assert "superseded_by_newer_relation" in str(stale_relation["last_reason"])

    round2_case_c = conn.execute(
        """
        select canonical_case_id, merged_into_case_id, merge_state, status
        from cases
        where case_id = ?
        """,
        ("case_reassign_c",),
    ).fetchone()
    assert round2_case_c is not None
    assert round2_case_c["canonical_case_id"] == "case_reassign_b"
    assert round2_case_c["merged_into_case_id"] == "case_reassign_b"
    assert round2_case_c["merge_state"] == "merged"
    assert round2_case_c["status"] == "closed"

    case_a = conn.execute(
        """
        select canonical_case_id, merged_into_case_id, merge_state, status
        from cases
        where case_id = ?
        """,
        ("case_reassign_a",),
    ).fetchone()
    assert case_a is not None
    assert case_a["canonical_case_id"] == "case_reassign_a"
    assert case_a["merged_into_case_id"] is None
    assert case_a["merge_state"] == "standalone"
    assert case_a["status"] == "open"
    conn.close()


def test_case_convergence_filters_low_signal_noise_when_retargeting_to_canonical(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_clean_anchor",
            "title": "clean anchor",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "persistence",
            "primary_actor_id": "actor_clean_anchor",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_clean_child",
            "title": "clean child",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "primary_actor_id": "actor_clean_child",
        },
        source="cli",
    )
    conn.execute(
        """
        insert into evidence (evidence_id, case_id, occurred_at, evidence_type, summary)
        values (?, ?, ?, ?, ?)
        """,
        (
            "evi_clean_anchor",
            "case_clean_anchor",
            "2026-04-12T09:50:00+08:00",
            "webshell",
            "anchor evidence for canonical reselect",
        ),
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_clean_anchor_high",
        case_id="case_clean_anchor",
        occurred_at="2026-04-12T10:00:00+08:00",
        stage="persistence",
        src_ip="198.51.100.23",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_clean_child_high",
        case_id="case_clean_child",
        occurred_at="2026-04-12T10:10:00+08:00",
        stage="command_execution",
        src_ip="198.51.100.91",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_clean_child_noise",
        case_id="case_clean_child",
        occurred_at="2026-04-12T10:11:00+08:00",
        stage="recon",
        src_ip="192.0.2.56",
        severity="low",
        confidence=0.5,
        asset_id="asset_admin_portal",
        dst_ip="203.0.113.11",
    )
    conn.commit()

    dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 100}, source="mcp")
    open_alert_ids = [row["alert_id"] for row in conn.execute("select alert_id from alerts where status in ('new', 'open')")]
    dispatch_tool(conn, "alert.ack", {"alert_ids": open_alert_ids, "status": "triaged"}, source="mcp")

    canonical_case_id = conn.execute(
        """
        select canonical_case_id
        from cases
        where case_id = ?
        """,
        ("case_clean_anchor",),
    ).fetchone()["canonical_case_id"]
    active_high_links = conn.execute(
        """
        select count(*)
        from case_alert_links
        where case_id = ?
          and alert_id in ('alt_clean_anchor_high', 'alt_clean_child_high')
          and is_active = 1
        """,
        (canonical_case_id,),
    ).fetchone()[0]
    active_noise_links = conn.execute(
        """
        select count(*)
        from case_alert_links
        where alert_id = 'alt_clean_child_noise'
          and is_active = 1
        """
    ).fetchone()[0]
    assert active_high_links == 2
    assert active_noise_links == 0
    conn.close()


def test_case_convergence_absorbs_recon_case_into_followup_attack_chain(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_absorb_recon",
            "title": "absorb recon",
            "status": "open",
            "overall_severity": "medium",
            "current_stage": "recon",
            "primary_actor_id": "actor_absorb_recon",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_absorb_attack",
            "title": "absorb attack",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "persistence",
            "primary_actor_id": "actor_absorb_attack",
        },
        source="cli",
    )
    conn.execute(
        """
        insert into evidence (evidence_id, case_id, occurred_at, evidence_type, summary)
        values (?, ?, ?, ?, ?)
        """,
        (
            "evi_absorb_anchor",
            "case_absorb_attack",
            "2026-04-11T14:20:00+08:00",
            "webshell",
            "attack chain anchor",
        ),
    )
    conn.commit()

    for round_idx in range(1, 4):
        base_ts = f"2026-04-1{round_idx}T10:0{round_idx}:00+08:00"
        _insert_open_alert_for_case(
            conn,
            alert_id=f"alt_absorb_recon_api_r{round_idx}",
            case_id="case_absorb_recon",
            occurred_at=base_ts,
            stage="recon",
            src_ip="198.51.100.23",
            severity="medium",
            confidence=0.9,
            asset_id="asset_api_prod",
            dst_ip="203.0.113.10",
        )
        _insert_open_alert_for_case(
            conn,
            alert_id=f"alt_absorb_recon_admin_r{round_idx}",
            case_id="case_absorb_recon",
            occurred_at=base_ts,
            stage="recon",
            src_ip="198.51.100.23",
            severity="medium",
            confidence=0.9,
            asset_id="asset_admin_portal",
            dst_ip="203.0.113.11",
        )
        _insert_open_alert_for_case(
            conn,
            alert_id=f"alt_absorb_attack_r{round_idx}",
            case_id="case_absorb_attack",
            occurred_at=base_ts,
            stage="persistence",
            src_ip="198.51.100.23",
            severity="high",
            confidence=0.9,
            asset_id="asset_api_prod",
            dst_ip="203.0.113.10",
        )
        conn.commit()

        dispatch_tool(conn, "alert.fetch", {"status": ["new", "open"], "limit": 100}, source="mcp")
        open_alert_ids = [
            row["alert_id"] for row in conn.execute("select alert_id from alerts where status in ('new', 'open')")
        ]
        dispatch_tool(conn, "alert.ack", {"alert_ids": open_alert_ids, "status": "triaged"}, source="mcp")

    relation = conn.execute(
        """
        select status, streak_count, score
        from case_relations
        where left_case_id = ? and right_case_id = ?
        """,
        ("case_absorb_attack", "case_absorb_recon"),
    ).fetchone()
    assert relation is not None
    assert relation["status"] == "confirmed"
    assert relation["streak_count"] >= 3
    assert relation["score"] >= 0.78

    recon_case = conn.execute(
        """
        select merge_state, canonical_case_id, merged_into_case_id, status
        from cases
        where case_id = ?
        """,
        ("case_absorb_recon",),
    ).fetchone()
    assert recon_case is not None
    assert recon_case["merge_state"] == "merged"
    assert recon_case["canonical_case_id"] == "case_absorb_attack"
    assert recon_case["merged_into_case_id"] == "case_absorb_attack"
    assert recon_case["status"] == "closed"
    conn.close()


def test_case_convergence_keeps_quiet_merged_case_attached_when_not_in_current_cluster(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_detach_anchor",
            "title": "detach anchor",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "primary_actor_id": "actor_detach_anchor",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_detach_child",
            "title": "detach child",
            "status": "closed",
            "overall_severity": "high",
            "current_stage": "persistence",
            "primary_actor_id": "actor_detach_child",
        },
        source="cli",
    )
    conn.execute(
        """
        update cases
        set canonical_case_id = 'case_detach_anchor',
            merged_into_case_id = 'case_detach_anchor',
            merge_state = 'merged'
        where case_id = 'case_detach_child'
        """
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_detach_anchor_1",
        case_id="case_detach_anchor",
        occurred_at="2026-04-12T11:30:00+08:00",
        stage="command_execution",
        src_ip="198.51.100.91",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    conn.commit()

    summary = run_case_convergence_for_run(conn, run_id="run_detach_guard_1")
    assert summary["detached_cases_count"] == 0

    child_row = conn.execute(
        """
        select status, canonical_case_id, merged_into_case_id, merge_state
        from cases
        where case_id = 'case_detach_child'
        """
    ).fetchone()
    assert child_row is not None
    assert child_row["status"] == "closed"
    assert child_row["canonical_case_id"] == "case_detach_anchor"
    assert child_row["merged_into_case_id"] == "case_detach_anchor"
    assert child_row["merge_state"] == "merged"
    conn.close()


def test_case_convergence_reabsorbs_orphan_case_to_previous_canonical(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute("update alerts set status = 'triaged'")
    conn.commit()

    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_orphan_anchor",
            "title": "orphan anchor",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "command_execution",
            "primary_actor_id": "actor_orphan_anchor",
        },
        source="cli",
    )
    dispatch_tool(
        conn,
        "case.upsert",
        {
            "case_id": "case_orphan_child",
            "title": "orphan child",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "persistence",
            "primary_actor_id": "actor_orphan_child",
        },
        source="cli",
    )
    _insert_open_alert_for_case(
        conn,
        alert_id="alt_orphan_anchor_1",
        case_id="case_orphan_anchor",
        occurred_at="2026-04-12T12:00:00+08:00",
        stage="command_execution",
        src_ip="198.51.100.23",
        severity="high",
        confidence=0.9,
        asset_id="asset_api_prod",
    )
    conn.execute(
        """
        insert into entity_assessments (
          assessment_id,
          occurred_at,
          run_id,
          entity_type,
          entity_key,
          entity_label,
          related_case_id,
          risk_level,
          assessment_confidence,
          verdict,
          reason_summary,
          supporting_alert_ids_json,
          supporting_evidence_ids_json,
          first_seen_at,
          last_seen_at,
          analysis_cutoff_at,
          is_current
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """,
        (
            "eass_orphan_case_001",
            "2026-04-12T12:05:00+08:00",
            "run_orphan_seed",
            "ip",
            "198.51.100.23",
            "198.51.100.23",
            "case_orphan_child",
            "high",
            0.92,
            "attacker",
            "orphan scoped current",
            "[]",
            "[]",
            "2026-04-12T12:00:00+08:00",
            "2026-04-12T12:05:00+08:00",
            None,
        ),
    )
    conn.execute(
        """
        insert into case_merge_events (
          event_id,
          occurred_at,
          run_id,
          cluster_id,
          old_canonical_case_id,
          new_canonical_case_id,
          affected_case_ids_json,
          reason,
          detail_json
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "merge_orphan_seed_001",
            "2026-04-12T12:06:00+08:00",
            "run_orphan_seed",
            "case_orphan_anchor|case_orphan_child",
            "case_orphan_child",
            "case_orphan_anchor",
            "[\"case_orphan_anchor\", \"case_orphan_child\"]",
            "auto_case_convergence",
            "{\"seed\":true}",
        ),
    )
    conn.commit()

    summary = run_case_convergence_for_run(conn, run_id="run_orphan_absorb_1")
    assert summary["orphan_absorbed_cases_count"] >= 1

    child_row = conn.execute(
        """
        select status, canonical_case_id, merged_into_case_id, merge_state
        from cases
        where case_id = 'case_orphan_child'
        """
    ).fetchone()
    assert child_row is not None
    assert child_row["status"] == "closed"
    assert child_row["canonical_case_id"] == "case_orphan_anchor"
    assert child_row["merged_into_case_id"] == "case_orphan_anchor"
    assert child_row["merge_state"] == "merged"

    current_rows = conn.execute(
        """
        select related_case_id
        from entity_assessments
        where entity_type = 'ip'
          and entity_key = '198.51.100.23'
          and is_current = 1
        """
    ).fetchall()
    assert len(current_rows) == 1
    assert current_rows[0]["related_case_id"] == "case_orphan_anchor"

    latest_merge = conn.execute(
        """
        select reason
        from case_merge_events
        order by occurred_at desc, rowid desc
        limit 1
        """
    ).fetchone()
    assert latest_merge is not None
    assert latest_merge["reason"] == "auto_case_convergence_orphan_absorb"
    conn.close()
