from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from security_analyst_agent.repositories.audit import insert_case_change_log
from security_analyst_agent.repositories.cases import (
    load_alert_ids_existing,
    load_case,
    load_evidence_by_ids,
    load_evidence_ids_existing,
    load_timeline_event,
    upsert_evidence,
    upsert_timeline_event,
)
from security_analyst_agent.repositories.context_memory import upsert_case_digest
from security_analyst_agent.schemas.common import ToolResponse
from security_analyst_agent.schemas.derived_tools import EvidenceUpsertRequest, TimelineUpsertRequest


def evidence_upsert(conn: sqlite3.Connection, payload: dict) -> dict:
    request = EvidenceUpsertRequest.model_validate(payload)
    case = load_case(conn, request.case_id)
    if case is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到案件 {request.case_id}",
            data={"evidence": None},
            warnings=[f"case_not_found:{request.case_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)

    before_rows = load_evidence_by_ids(conn, [request.evidence_id])
    before_evidence = before_rows[0] if before_rows else None
    evidence_body = request.model_dump(mode="python")
    if evidence_body["occurred_at"] is None:
        evidence_body["occurred_at"] = datetime.now(timezone.utc).isoformat()

    upsert_evidence(conn, evidence_body)
    after_evidence = load_evidence_by_ids(conn, [request.evidence_id])[0]
    upsert_case_digest(conn, request.case_id)
    insert_case_change_log(
        conn,
        case_id=request.case_id,
        action="evidence_upsert",
        before_state=before_evidence,
        after_state=after_evidence,
        reason="tool:evidence.upsert",
    )
    conn.commit()

    response = ToolResponse(
        ok=True,
        summary=f"已写入证据 {request.evidence_id}",
        data={"evidence": after_evidence},
        refs={"case_ids": [request.case_id], "evidence_ids": [request.evidence_id]},
    )
    return response.model_dump(mode="json", by_alias=True)


def timeline_upsert(conn: sqlite3.Connection, payload: dict) -> dict:
    request = TimelineUpsertRequest.model_validate(payload)
    case = load_case(conn, request.case_id)
    if case is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到案件 {request.case_id}",
            data={"timeline_event": None},
            warnings=[f"case_not_found:{request.case_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)

    existing_alert_ids = load_alert_ids_existing(conn, request.related_alert_ids)
    missing_alert_ids = sorted(set(request.related_alert_ids) - existing_alert_ids)
    if missing_alert_ids:
        response = ToolResponse(
            ok=False,
            summary=f"存在未找到的告警引用: {', '.join(missing_alert_ids)}",
            data={"timeline_event": None},
            warnings=[f"alert_not_found:{item}" for item in missing_alert_ids],
        )
        return response.model_dump(mode="json", by_alias=True)

    existing_evidence_ids = load_evidence_ids_existing(conn, request.related_evidence_ids)
    missing_evidence_ids = sorted(set(request.related_evidence_ids) - existing_evidence_ids)
    if missing_evidence_ids:
        response = ToolResponse(
            ok=False,
            summary=f"存在未找到的证据引用: {', '.join(missing_evidence_ids)}",
            data={"timeline_event": None},
            warnings=[f"evidence_not_found:{item}" for item in missing_evidence_ids],
        )
        return response.model_dump(mode="json", by_alias=True)

    before_event = load_timeline_event(conn, request.timeline_event_id)
    event_body = request.model_dump(mode="python")
    upsert_timeline_event(conn, event_body)
    after_event = load_timeline_event(conn, request.timeline_event_id)
    upsert_case_digest(conn, request.case_id)
    insert_case_change_log(
        conn,
        case_id=request.case_id,
        action="timeline_upsert",
        before_state=before_event,
        after_state=after_event,
        reason="tool:timeline.upsert",
    )
    conn.commit()

    response = ToolResponse(
        ok=True,
        summary=f"已写入时间线节点 {request.timeline_event_id}",
        data={"timeline_event": after_event},
        refs={
            "case_ids": [request.case_id],
            "alert_ids": request.related_alert_ids,
            "evidence_ids": request.related_evidence_ids,
            "timeline_event_ids": [request.timeline_event_id],
        },
    )
    return response.model_dump(mode="json", by_alias=True)
