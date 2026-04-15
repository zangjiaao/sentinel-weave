from security_analyst_agent.tools.case_tools import case_timeline, case_upsert
from security_analyst_agent.tools.derived_tools import evidence_upsert, timeline_upsert


def test_evidence_upsert_creates_runtime_evidence(db_conn) -> None:
    case_upsert(
        db_conn,
        {
            "case_id": "case_runtime_001",
            "title": "runtime evidence case",
            "status": "open",
            "overall_severity": "medium",
            "current_stage": "recon",
            "primary_actor_id": "actor_runtime_001",
        },
    )

    result = evidence_upsert(
        db_conn,
        {
            "evidence_id": "evi_runtime_001",
            "case_id": "case_runtime_001",
            "occurred_at": "2026-04-15T10:00:00+08:00",
            "evidence_type": "webshell",
            "summary": "runtime-created webshell evidence",
        },
    )

    assert result["ok"] is True
    row = db_conn.execute(
        """
        select evidence_id, case_id, occurred_at, evidence_type, summary
        from evidence
        where evidence_id = ?
        """,
        ("evi_runtime_001",),
    ).fetchone()
    assert row is not None
    assert row["case_id"] == "case_runtime_001"
    assert row["evidence_type"] == "webshell"


def test_timeline_upsert_creates_runtime_timeline_with_evidence(db_conn) -> None:
    case_upsert(
        db_conn,
        {
            "case_id": "case_runtime_002",
            "title": "runtime timeline case",
            "status": "open",
            "overall_severity": "high",
            "current_stage": "persistence",
            "primary_actor_id": "actor_runtime_002",
        },
    )
    evidence_upsert(
        db_conn,
        {
            "evidence_id": "evi_runtime_002",
            "case_id": "case_runtime_002",
            "occurred_at": "2026-04-15T11:00:00+08:00",
            "evidence_type": "shell_connection",
            "summary": "runtime shell connection evidence",
        },
    )

    result = timeline_upsert(
        db_conn,
        {
            "timeline_event_id": "tl_runtime_002",
            "case_id": "case_runtime_002",
            "occurred_at": "2026-04-15T11:01:00+08:00",
            "stage": "command_execution",
            "title": "runtime timeline event",
            "related_alert_ids": ["alt_day3_shell_01"],
            "related_evidence_ids": ["evi_runtime_002"],
        },
    )

    assert result["ok"] is True
    timeline = case_timeline(db_conn, {"case_id": "case_runtime_002", "include_evidence": True})
    assert timeline["data"]["events"][-1]["timeline_event_id"] == "tl_runtime_002"
    assert timeline["data"]["events"][-1]["related_evidence_ids"] == ["evi_runtime_002"]
    assert timeline["data"]["events"][-1]["evidence"][0]["summary"] == "runtime shell connection evidence"
