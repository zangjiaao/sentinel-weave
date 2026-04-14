import json
import sqlite3
from typing import Any


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
        select
          alerts.alert_id,
          case_alert_links.case_id as case_id,
          alerts.occurred_at,
          alerts.title,
          alerts.attack_stage,
          alerts.src_ip,
          alerts.dst_ip,
          alerts.asset_id
        from alerts
        left join case_alert_links
          on case_alert_links.alert_id = alerts.alert_id
         and case_alert_links.is_active = 1
        where alerts.alert_id = ?
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


def upsert_case(conn: sqlite3.Connection, case: dict[str, Any]) -> None:
    conn.execute(
        """
        insert into cases (case_id, title, status, overall_severity, current_stage, primary_actor_id)
        values (?, ?, ?, ?, ?, ?)
        on conflict(case_id) do update set
          title=excluded.title,
          status=excluded.status,
          overall_severity=excluded.overall_severity,
          current_stage=excluded.current_stage,
          primary_actor_id=excluded.primary_actor_id
        """,
        (
            case["case_id"],
            case["title"],
            case["status"],
            case["overall_severity"],
            case["current_stage"],
            case.get("primary_actor_id"),
        ),
    )


def link_alert_to_case(
    conn: sqlite3.Connection,
    case_id: str,
    alert_id: str,
    confidence: float,
    reason: str,
    linked_at: str,
) -> None:
    conn.execute(
        """
        update case_alert_links
        set is_active = 0, unlinked_at = ?
        where alert_id = ? and is_active = 1 and case_id <> ?
        """,
        (linked_at, alert_id, case_id),
    )
    conn.execute(
        """
        insert into case_alert_links (case_id, alert_id, linked_at, confidence, reason, is_active, unlinked_at)
        values (?, ?, ?, ?, ?, ?, ?)
        on conflict(case_id, alert_id) do update set
          linked_at=excluded.linked_at,
          confidence=excluded.confidence,
          reason=excluded.reason,
          is_active=1,
          unlinked_at=null
        """,
        (case_id, alert_id, linked_at, confidence, reason, 1, None),
    )


def append_timeline_event_for_alert(
    conn: sqlite3.Connection,
    case_id: str,
    alert: dict[str, Any],
) -> str:
    timeline_event_id = f"tl_link_{alert['alert_id']}"
    conn.execute(
        """
        insert into timeline_events (
          timeline_event_id,
          case_id,
          occurred_at,
          stage,
          title,
          related_alert_ids,
          related_evidence_ids
        ) values (?, ?, ?, ?, ?, ?, ?)
        on conflict(timeline_event_id) do nothing
        """,
        (
            timeline_event_id,
            case_id,
            alert["occurred_at"],
            alert["attack_stage"],
            alert["title"],
            json.dumps([alert["alert_id"]], ensure_ascii=False),
            json.dumps([], ensure_ascii=False),
        ),
    )
    return timeline_event_id


def update_case_risk(
    conn: sqlite3.Connection,
    case_id: str,
    overall_severity: str,
    current_stage: str,
    status: str,
) -> None:
    conn.execute(
        """
        update cases
        set overall_severity = ?, current_stage = ?, status = ?
        where case_id = ?
        """,
        (overall_severity, current_stage, status, case_id),
    )
