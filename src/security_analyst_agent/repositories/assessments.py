from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from uuid import uuid4


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def upsert_entity_assessment(
    conn: sqlite3.Connection,
    *,
    entity_type: str,
    entity_key: str,
    entity_label: str,
    related_case_id: str | None,
    risk_level: str,
    assessment_confidence: float,
    verdict: str,
    reason_summary: str,
    supporting_alert_ids: list[str],
    supporting_evidence_ids: list[str],
    first_seen_at: str | None,
    last_seen_at: str | None,
    run_id: str | None,
    analysis_cutoff_at: str | None,
) -> dict[str, object]:
    occurred_at = _now_iso()
    is_current_target = 1
    conn.execute(
        """
        update entity_assessments
        set is_current = 0
        where entity_type = ?
          and entity_key = ?
          and coalesce(related_case_id, '') = coalesce(?, '')
          and is_current = 1
        """,
        (entity_type, entity_key, related_case_id),
    )
    if related_case_id:
        conn.execute(
            """
            update entity_assessments
            set is_current = 0
            where entity_type = ?
              and entity_key = ?
              and related_case_id is null
              and is_current = 1
            """,
            (entity_type, entity_key),
        )
    else:
        has_case_scoped_current = conn.execute(
            """
            select 1
            from entity_assessments
            where entity_type = ?
              and entity_key = ?
              and related_case_id is not null
              and is_current = 1
            limit 1
            """,
            (entity_type, entity_key),
        ).fetchone()
        if has_case_scoped_current is not None:
            is_current_target = 0

    assessment_id = f"eass_{uuid4().hex[:12]}"
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
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
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
            json.dumps(supporting_alert_ids, ensure_ascii=False),
            json.dumps(supporting_evidence_ids, ensure_ascii=False),
            first_seen_at,
            last_seen_at,
            analysis_cutoff_at,
            is_current_target,
        ),
    )
    return {
        "assessment_id": assessment_id,
        "occurred_at": occurred_at,
        "run_id": run_id,
        "entity_type": entity_type,
        "entity_key": entity_key,
        "entity_label": entity_label,
        "related_case_id": related_case_id,
        "risk_level": risk_level,
        "assessment_confidence": assessment_confidence,
        "verdict": verdict,
        "reason_summary": reason_summary,
        "supporting_alert_ids": supporting_alert_ids,
        "supporting_evidence_ids": supporting_evidence_ids,
        "first_seen_at": first_seen_at,
        "last_seen_at": last_seen_at,
        "analysis_cutoff_at": analysis_cutoff_at,
        "is_current": is_current_target,
    }
