import json
import sqlite3


def load_case(conn: sqlite3.Connection, case_id: str) -> dict | None:
    row = conn.execute(
        """
        select case_id, title, status, overall_severity, current_stage, primary_actor_id
        from cases
        where case_id = ?
        """,
        (case_id,),
    ).fetchone()
    return dict(row) if row else None


def load_case_timeline(conn: sqlite3.Connection, case_id: str) -> list[dict]:
    rows = conn.execute(
        """
        select timeline_event_id, case_id, occurred_at, stage, title, related_alert_ids, related_evidence_ids
        from timeline_events
        where case_id = ?
        order by occurred_at asc
        """,
        (case_id,),
    ).fetchall()
    events: list[dict] = []
    for row in rows:
        event = dict(row)
        event["related_alert_ids"] = json.loads(event["related_alert_ids"])
        event["related_evidence_ids"] = json.loads(event["related_evidence_ids"])
        events.append(event)
    return events


def load_alert(conn: sqlite3.Connection, alert_id: str) -> dict | None:
    row = conn.execute(
        """
        select alert_id, case_id, occurred_at, title, attack_stage, src_ip, dst_ip, asset_id
        from alerts
        where alert_id = ?
        """,
        (alert_id,),
    ).fetchone()
    return dict(row) if row else None


def load_evidence_by_ids(conn: sqlite3.Connection, evidence_ids: list[str]) -> list[dict]:
    if not evidence_ids:
        return []
    placeholders = ", ".join("?" for _ in evidence_ids)
    rows = conn.execute(
        f"""
        select evidence_id, case_id, evidence_type, summary
        from evidence
        where evidence_id in ({placeholders})
        order by evidence_id asc
        """,
        tuple(evidence_ids),
    ).fetchall()
    return [dict(row) for row in rows]

