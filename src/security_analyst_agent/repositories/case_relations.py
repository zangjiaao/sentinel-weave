from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

CANDIDATE_THRESHOLD = 0.68
MERGE_THRESHOLD = 0.78
REQUIRED_STREAK = 3
DEFAULT_RELATION_TYPE = "possible_same_intrusion"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_case_pair(case_a: str, case_b: str) -> tuple[str, str]:
    if case_a == case_b:
        return case_a, case_b
    return tuple(sorted((case_a, case_b)))


def _relation_id(left_case_id: str, right_case_id: str, relation_type: str) -> str:
    return f"rel_{left_case_id}__{right_case_id}__{relation_type}"


def upsert_case_relation_candidate(
    conn: sqlite3.Connection,
    run_id: str,
    case_a: str,
    case_b: str,
    score: float,
    reason: str,
    supporting_alert_ids: list[str],
    supporting_evidence_ids: list[str],
    *,
    relation_type: str = DEFAULT_RELATION_TYPE,
    candidate_threshold: float = CANDIDATE_THRESHOLD,
    merge_threshold: float = MERGE_THRESHOLD,
    required_streak: int = REQUIRED_STREAK,
) -> dict[str, Any]:
    left_case_id, right_case_id = normalize_case_pair(case_a, case_b)
    now = _now_iso()
    existing = conn.execute(
        """
        select relation_id, streak_count, last_run_id, first_seen_at
        from case_relations
        where left_case_id = ? and right_case_id = ? and relation_type = ?
        """,
        (left_case_id, right_case_id, relation_type),
    ).fetchone()

    last_run_id = existing["last_run_id"] if existing else None
    previous_streak = int(existing["streak_count"]) if existing else 0
    is_new_run = run_id != last_run_id

    if score >= merge_threshold:
        streak_count = previous_streak + 1 if is_new_run else max(previous_streak, 1)
        status = "confirmed" if streak_count >= required_streak else "candidate"
    elif score >= candidate_threshold:
        streak_count = 0
        status = "candidate"
    else:
        streak_count = 0
        status = "rejected"

    relation_id = existing["relation_id"] if existing else _relation_id(left_case_id, right_case_id, relation_type)
    first_seen_at = existing["first_seen_at"] if existing else now
    conn.execute(
        """
        insert into case_relations (
          relation_id,
          left_case_id,
          right_case_id,
          relation_type,
          score,
          streak_count,
          status,
          last_run_id,
          last_reason,
          supporting_alert_ids_json,
          supporting_evidence_ids_json,
          first_seen_at,
          last_seen_at
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        on conflict(left_case_id, right_case_id, relation_type) do update set
          score = excluded.score,
          streak_count = excluded.streak_count,
          status = excluded.status,
          last_run_id = excluded.last_run_id,
          last_reason = excluded.last_reason,
          supporting_alert_ids_json = excluded.supporting_alert_ids_json,
          supporting_evidence_ids_json = excluded.supporting_evidence_ids_json,
          last_seen_at = excluded.last_seen_at
        """,
        (
            relation_id,
            left_case_id,
            right_case_id,
            relation_type,
            score,
            streak_count,
            status,
            run_id,
            reason,
            json.dumps(supporting_alert_ids, ensure_ascii=False),
            json.dumps(supporting_evidence_ids, ensure_ascii=False),
            first_seen_at,
            now,
        ),
    )

    row = conn.execute(
        """
        select relation_id, left_case_id, right_case_id, relation_type, score, streak_count, status,
               last_run_id, last_reason, supporting_alert_ids_json, supporting_evidence_ids_json,
               first_seen_at, last_seen_at
        from case_relations
        where left_case_id = ? and right_case_id = ? and relation_type = ?
        """,
        (left_case_id, right_case_id, relation_type),
    ).fetchone()
    result = dict(row)
    result["supporting_alert_ids"] = json.loads(result.pop("supporting_alert_ids_json"))
    result["supporting_evidence_ids"] = json.loads(result.pop("supporting_evidence_ids_json"))
    return result


def list_confirmed_case_relations(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        select relation_id, left_case_id, right_case_id, relation_type, score, streak_count, status, last_run_id
        from case_relations
        where status = 'confirmed'
        order by last_seen_at asc, relation_id asc
        """
    ).fetchall()
    return [dict(row) for row in rows]
