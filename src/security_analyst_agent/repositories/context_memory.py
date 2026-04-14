import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from security_analyst_agent.repositories.cases import load_case


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_case_digest(
    conn: sqlite3.Connection, case_id: str, analysis_cutoff_at: str | None = None
) -> dict[str, Any] | None:
    case = load_case(conn, case_id)
    if case is None:
        return None

    alert_stats = conn.execute(
        """
        select
          count(*) as active_alert_count,
          count(distinct alerts.asset_id) as distinct_asset_count,
          max(alerts.occurred_at) as latest_alert_at
        from case_alert_links
        join alerts on alerts.alert_id = case_alert_links.alert_id
        where case_alert_links.case_id = ?
          and (
            (? is null and case_alert_links.is_active = 1)
            or (
              ? is not null
              and case_alert_links.linked_at <= ?
              and (case_alert_links.unlinked_at is null or case_alert_links.unlinked_at > ?)
            )
          )
          and (? is null or alerts.occurred_at <= ?)
        """,
        (
            case_id,
            analysis_cutoff_at,
            analysis_cutoff_at,
            analysis_cutoff_at,
            analysis_cutoff_at,
            analysis_cutoff_at,
            analysis_cutoff_at,
        ),
    ).fetchone()
    timeline_stats = conn.execute(
        """
        select max(occurred_at) as latest_timeline_at
        from timeline_events
        where case_id = ?
          and (? is null or occurred_at <= ?)
        """,
        (case_id, analysis_cutoff_at, analysis_cutoff_at),
    ).fetchone()

    active_alert_count = int(alert_stats["active_alert_count"] or 0)
    distinct_asset_count = int(alert_stats["distinct_asset_count"] or 0)
    latest_alert_at = alert_stats["latest_alert_at"]
    latest_timeline_at = timeline_stats["latest_timeline_at"]

    digest_text = (
        f"case={case_id}, status={case['status']}, severity={case['overall_severity']}, "
        f"stage={case['current_stage']}, active_alerts={active_alert_count}, "
        f"assets={distinct_asset_count}"
    )
    facts = {
        "case_id": case_id,
        "status": case["status"],
        "overall_severity": case["overall_severity"],
        "current_stage": case["current_stage"],
        "active_alert_count": active_alert_count,
        "distinct_asset_count": distinct_asset_count,
        "latest_alert_at": latest_alert_at,
        "latest_timeline_at": latest_timeline_at,
    }
    return {
        "digest_text": digest_text,
        "facts": facts,
        "updated_at": _now_iso(),
    }


def load_case_digest(conn: sqlite3.Connection, case_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        """
        select case_id, digest_text, facts_json, updated_at
        from case_digests
        where case_id = ?
        """,
        (case_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "case_id": row["case_id"],
        "digest_text": row["digest_text"],
        "facts": json.loads(row["facts_json"]),
        "updated_at": row["updated_at"],
    }


def upsert_case_digest(conn: sqlite3.Connection, case_id: str) -> dict[str, Any] | None:
    digest = build_case_digest(conn, case_id)
    if digest is None:
        return None
    conn.execute(
        """
        insert into case_digests (case_id, digest_text, facts_json, updated_at)
        values (?, ?, ?, ?)
        on conflict(case_id) do update set
          digest_text = excluded.digest_text,
          facts_json = excluded.facts_json,
          updated_at = excluded.updated_at
        """,
        (
            case_id,
            digest["digest_text"],
            json.dumps(digest["facts"], ensure_ascii=False),
            digest["updated_at"],
        ),
    )
    return digest


def set_patrol_state(conn: sqlite3.Connection, state_key: str, state_value: Any) -> None:
    conn.execute(
        """
        insert into patrol_state (state_key, state_value_json, updated_at)
        values (?, ?, ?)
        on conflict(state_key) do update set
          state_value_json = excluded.state_value_json,
          updated_at = excluded.updated_at
        """,
        (state_key, json.dumps(state_value, ensure_ascii=False), _now_iso()),
    )
