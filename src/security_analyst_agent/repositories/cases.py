import json
import sqlite3
from datetime import datetime, timezone
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_case(conn: sqlite3.Connection, case_id: str) -> dict | None:
    row = conn.execute(
        """
        select
          case_id,
          title,
          status,
          overall_severity,
          current_stage,
          primary_actor_id,
          canonical_case_id,
          merged_into_case_id,
          merge_state,
          merge_updated_at
        from cases
        where case_id = ?
        """,
        (case_id,),
    ).fetchone()
    return dict(row) if row else None


def resolve_canonical_case_id(conn: sqlite3.Connection, case_id: str) -> str:
    current_case_id = case_id
    visited: set[str] = set()
    while current_case_id and current_case_id not in visited:
        visited.add(current_case_id)
        row = conn.execute(
            """
            select canonical_case_id
            from cases
            where case_id = ?
            """,
            (current_case_id,),
        ).fetchone()
        if row is None:
            return case_id
        canonical_case_id = row["canonical_case_id"]
        if not canonical_case_id or canonical_case_id == current_case_id:
            return current_case_id
        current_case_id = canonical_case_id
    return case_id


def reselect_cluster_canonical_case(conn: sqlite3.Connection, case_ids: list[str], run_id: str) -> str:
    del run_id
    deduped_case_ids = list(dict.fromkeys(case_ids))
    if not deduped_case_ids:
        raise ValueError("case_ids must not be empty")

    best_case_id = deduped_case_ids[0]
    best_score = (-1, -1, -1, -1, "", "")
    for case_id in deduped_case_ids:
        timeline_count = conn.execute(
            "select count(*) from timeline_events where case_id = ?",
            (case_id,),
        ).fetchone()[0]
        evidence_count = conn.execute(
            "select count(*) from evidence where case_id = ?",
            (case_id,),
        ).fetchone()[0]
        alert_count = conn.execute(
            """
            select count(*)
            from case_alert_links
            where case_id = ? and is_active = 1
            """,
            (case_id,),
        ).fetchone()[0]
        relation_count = conn.execute(
            """
            select count(*)
            from case_relations
            where status in ('candidate', 'confirmed')
              and (left_case_id = ? or right_case_id = ?)
            """,
            (case_id, case_id),
        ).fetchone()[0]
        last_activity = conn.execute(
            """
            select max(activity_at) as last_activity
            from (
              select max(occurred_at) as activity_at from timeline_events where case_id = ?
              union all
              select max(occurred_at) as activity_at from evidence where case_id = ?
              union all
              select max(alerts.occurred_at) as activity_at
              from case_alert_links
              join alerts on alerts.alert_id = case_alert_links.alert_id
              where case_alert_links.case_id = ? and case_alert_links.is_active = 1
            )
            """,
            (case_id, case_id, case_id),
        ).fetchone()["last_activity"] or ""
        score = (
            int(timeline_count),
            int(evidence_count),
            int(alert_count),
            int(relation_count),
            str(last_activity),
            case_id,
        )
        if score > best_score:
            best_case_id = case_id
            best_score = score
    return best_case_id


def load_case_timeline(conn: sqlite3.Connection, case_id: str, analysis_cutoff_at: str | None = None) -> list[dict]:
    rows = conn.execute(
        """
        select timeline_event_id, case_id, occurred_at, stage, title, related_alert_ids, related_evidence_ids
        from timeline_events
        where case_id = ?
          and (? is null or occurred_at <= ?)
        order by occurred_at asc
        """,
        (case_id, analysis_cutoff_at, analysis_cutoff_at),
    ).fetchall()
    events: list[dict] = []
    for row in rows:
        event = dict(row)
        event["related_alert_ids"] = json.loads(event["related_alert_ids"])
        event["related_evidence_ids"] = json.loads(event["related_evidence_ids"])
        events.append(event)
    return events


def load_alert(conn: sqlite3.Connection, alert_id: str, analysis_cutoff_at: str | None = None) -> dict | None:
    row = conn.execute(
        """
        select
          alerts.alert_id,
          (
            select case_alert_links.case_id
            from case_alert_links
            where case_alert_links.alert_id = alerts.alert_id
              and (
                (? is null and case_alert_links.is_active = 1)
                or (
                  ? is not null
                  and case_alert_links.linked_at <= ?
                  and (case_alert_links.unlinked_at is null or case_alert_links.unlinked_at > ?)
                )
              )
            order by case_alert_links.linked_at desc, case_alert_links.rowid desc
            limit 1
          ) as case_id,
          alerts.occurred_at,
          alerts.title,
          alerts.attack_stage,
          alerts.src_ip,
          alerts.dst_ip,
          alerts.asset_id
        from alerts
        where alerts.alert_id = ?
          and (? is null or alerts.occurred_at <= ?)
        """,
        (
            analysis_cutoff_at,
            analysis_cutoff_at,
            analysis_cutoff_at,
            analysis_cutoff_at,
            alert_id,
            analysis_cutoff_at,
            analysis_cutoff_at,
        ),
    ).fetchone()
    return dict(row) if row else None


def load_evidence_by_ids(
    conn: sqlite3.Connection,
    evidence_ids: list[str],
    analysis_cutoff_at: str | None = None,
) -> list[dict]:
    if not evidence_ids:
        return []
    placeholders = ", ".join("?" for _ in evidence_ids)
    rows = conn.execute(
        f"""
        select evidence_id, case_id, occurred_at, evidence_type, summary
        from evidence
        where evidence_id in ({placeholders})
          and (? is null or occurred_at <= ?)
        order by evidence_id asc
        """,
        (*tuple(evidence_ids), analysis_cutoff_at, analysis_cutoff_at),
    ).fetchall()
    return [dict(row) for row in rows]


def load_timeline_event(conn: sqlite3.Connection, timeline_event_id: str) -> dict | None:
    row = conn.execute(
        """
        select timeline_event_id, case_id, occurred_at, stage, title, related_alert_ids, related_evidence_ids
        from timeline_events
        where timeline_event_id = ?
        """,
        (timeline_event_id,),
    ).fetchone()
    if row is None:
        return None
    event = dict(row)
    event["related_alert_ids"] = json.loads(event["related_alert_ids"])
    event["related_evidence_ids"] = json.loads(event["related_evidence_ids"])
    return event


def load_alert_ids_existing(conn: sqlite3.Connection, alert_ids: list[str]) -> set[str]:
    if not alert_ids:
        return set()
    placeholders = ", ".join("?" for _ in alert_ids)
    rows = conn.execute(
        f"""
        select alert_id
        from alerts
        where alert_id in ({placeholders})
        """,
        tuple(alert_ids),
    ).fetchall()
    return {row["alert_id"] for row in rows}


def load_evidence_ids_existing(conn: sqlite3.Connection, evidence_ids: list[str]) -> set[str]:
    if not evidence_ids:
        return set()
    placeholders = ", ".join("?" for _ in evidence_ids)
    rows = conn.execute(
        f"""
        select evidence_id
        from evidence
        where evidence_id in ({placeholders})
        """,
        tuple(evidence_ids),
    ).fetchall()
    return {row["evidence_id"] for row in rows}


def load_supporting_evidence_ids_for_alert(
    conn: sqlite3.Connection,
    *,
    case_id: str,
    alert_id: str,
    analysis_cutoff_at: str | None = None,
) -> list[str]:
    rows = conn.execute(
        """
        select distinct related_evidence_ids.value as evidence_id
        from timeline_events
        join json_each(timeline_events.related_alert_ids) as related_alert_ids
        join json_each(timeline_events.related_evidence_ids) as related_evidence_ids
        where timeline_events.case_id = ?
          and related_alert_ids.value = ?
          and (? is null or timeline_events.occurred_at <= ?)
        order by related_evidence_ids.value asc
        """,
        (case_id, alert_id, analysis_cutoff_at, analysis_cutoff_at),
    ).fetchall()
    return [row["evidence_id"] for row in rows]


def load_case_alert_ids(
    conn: sqlite3.Connection, case_id: str, analysis_cutoff_at: str | None = None
) -> list[str]:
    if analysis_cutoff_at:
        rows = conn.execute(
            """
            select alert_id
            from case_alert_links
            where case_id = ?
              and linked_at <= ?
              and (unlinked_at is null or unlinked_at > ?)
            order by linked_at asc
            """,
            (case_id, analysis_cutoff_at, analysis_cutoff_at),
        ).fetchall()
        return [row["alert_id"] for row in rows]

    rows = conn.execute(
        """
        select alert_id
        from case_alert_links
        where case_id = ? and is_active = 1
        order by linked_at asc
        """,
        (case_id,),
    ).fetchall()
    return [row["alert_id"] for row in rows]


def upsert_case(conn: sqlite3.Connection, case: dict[str, Any]) -> None:
    now = _now_iso()
    conn.execute(
        """
        insert into cases (
          case_id,
          title,
          status,
          overall_severity,
          current_stage,
          primary_actor_id,
          canonical_case_id,
          merged_into_case_id,
          merge_state,
          merge_updated_at
        )
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        on conflict(case_id) do update set
          title=excluded.title,
          status=excluded.status,
          overall_severity=excluded.overall_severity,
          current_stage=excluded.current_stage,
          primary_actor_id=excluded.primary_actor_id,
          canonical_case_id=coalesce(cases.canonical_case_id, excluded.canonical_case_id),
          merge_state=coalesce(cases.merge_state, excluded.merge_state),
          merge_updated_at=coalesce(cases.merge_updated_at, excluded.merge_updated_at)
        """,
        (
            case["case_id"],
            case["title"],
            case["status"],
            case["overall_severity"],
            case["current_stage"],
            case.get("primary_actor_id"),
            case["case_id"],
            None,
            "standalone",
            now,
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
        on conflict(timeline_event_id) do update set
          case_id=excluded.case_id,
          occurred_at=excluded.occurred_at,
          stage=excluded.stage,
          title=excluded.title,
          related_alert_ids=excluded.related_alert_ids,
          related_evidence_ids=excluded.related_evidence_ids
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


def upsert_evidence(conn: sqlite3.Connection, evidence: dict[str, Any]) -> None:
    conn.execute(
        """
        insert into evidence (evidence_id, case_id, occurred_at, evidence_type, summary)
        values (?, ?, ?, ?, ?)
        on conflict(evidence_id) do update set
          case_id=excluded.case_id,
          occurred_at=excluded.occurred_at,
          evidence_type=excluded.evidence_type,
          summary=excluded.summary
        """,
        (
            evidence["evidence_id"],
            evidence["case_id"],
            evidence["occurred_at"],
            evidence["evidence_type"],
            evidence["summary"],
        ),
    )


def upsert_timeline_event(conn: sqlite3.Connection, timeline_event: dict[str, Any]) -> None:
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
        on conflict(timeline_event_id) do update set
          case_id=excluded.case_id,
          occurred_at=excluded.occurred_at,
          stage=excluded.stage,
          title=excluded.title,
          related_alert_ids=excluded.related_alert_ids,
          related_evidence_ids=excluded.related_evidence_ids
        """,
        (
            timeline_event["timeline_event_id"],
            timeline_event["case_id"],
            timeline_event["occurred_at"],
            timeline_event["stage"],
            timeline_event["title"],
            json.dumps(timeline_event["related_alert_ids"], ensure_ascii=False),
            json.dumps(timeline_event["related_evidence_ids"], ensure_ascii=False),
        ),
    )


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
