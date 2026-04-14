import sqlite3
from datetime import datetime, timezone

from security_analyst_agent.repositories.cases import (
    append_timeline_event_for_alert,
    link_alert_to_case,
    load_alert,
    load_case,
    load_case_timeline,
    load_evidence_by_ids,
    update_case_risk,
    upsert_case,
)
from security_analyst_agent.repositories.audit import insert_alert_decision_log, insert_case_change_log
from security_analyst_agent.repositories.context_memory import build_case_digest, load_case_digest, upsert_case_digest
from security_analyst_agent.schemas.case_tools import (
    CaseExplainLinkRequest,
    CaseGetRequest,
    CaseLinkAlertRequest,
    CaseTimelineRequest,
    CaseUpdateRiskRequest,
    CaseUpsertRequest,
)
from security_analyst_agent.schemas.common import ToolResponse
from security_analyst_agent.services.link_explainer import explain_alert_link

_STAGE_ORDER = {
    "recon": 1,
    "exploit": 2,
    "persistence": 3,
    "command_execution": 4,
    "lateral_prep": 5,
}


def _resolve_stage_with_guard(current_stage: str, requested_stage: str, force_downgrade: bool) -> tuple[str, bool]:
    current_rank = _STAGE_ORDER.get(current_stage)
    requested_rank = _STAGE_ORDER.get(requested_stage)
    if current_rank is None or requested_rank is None:
        return requested_stage, False
    if requested_rank < current_rank and not force_downgrade:
        return current_stage, True
    return requested_stage, False


def case_get(conn: sqlite3.Connection, payload: dict) -> dict:
    request = CaseGetRequest.model_validate(payload)
    case = load_case(conn, request.case_id)
    if case is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到案件 {request.case_id}",
            data={"case": None},
            warnings=[f"case_not_found:{request.case_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)

    case_with_memory = dict(case)
    memory_digest = load_case_digest(conn, request.case_id)
    if memory_digest is None:
        memory_digest = upsert_case_digest(conn, request.case_id) or build_case_digest(conn, request.case_id)
    case_with_memory["memory_digest"] = memory_digest

    response = ToolResponse(
        ok=True,
        summary=f"读取案件 {request.case_id}",
        data={"case": case_with_memory},
        refs={"case_ids": [request.case_id]},
    )
    return response.model_dump(mode="json", by_alias=True)


def case_timeline(conn: sqlite3.Connection, payload: dict) -> dict:
    request = CaseTimelineRequest.model_validate(payload)
    events = load_case_timeline(conn, request.case_id)
    if request.include_evidence:
        for event in events:
            event["evidence"] = load_evidence_by_ids(conn, event["related_evidence_ids"])

    response = ToolResponse(
        ok=True,
        summary=f"返回案件 {request.case_id} 时间线，共 {len(events)} 个节点",
        data={"events": events},
        refs={
            "case_ids": [request.case_id],
            "alert_ids": [item for event in events for item in event["related_alert_ids"]],
            "evidence_ids": [item for event in events for item in event["related_evidence_ids"]],
        },
    )
    return response.model_dump(mode="json", by_alias=True)


def case_explain_link(conn: sqlite3.Connection, payload: dict) -> dict:
    request = CaseExplainLinkRequest.model_validate(payload)
    if request.target_type != "alert":
        response = ToolResponse(
            ok=False,
            summary=f"暂不支持的 target_type: {request.target_type}",
            data={"link_decision": None},
            warnings=[f"unsupported_target_type:{request.target_type}"],
        )
        return response.model_dump(mode="json", by_alias=True)

    alert = load_alert(conn, request.target_id)
    if alert is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到告警 {request.target_id}",
            data={"link_decision": None},
            warnings=[f"alert_not_found:{request.target_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)

    decision = explain_alert_link(alert, request.case_id)
    response = ToolResponse(
        ok=True,
        summary=f"生成关联解释：{request.target_id}",
        data={"link_decision": decision},
        refs={
            "case_ids": [request.case_id],
            "alert_ids": [request.target_id],
            "evidence_ids": decision["supporting_evidence_ids"],
        },
    )
    return response.model_dump(mode="json", by_alias=True)


def case_upsert(conn: sqlite3.Connection, payload: dict) -> dict:
    request = CaseUpsertRequest.model_validate(payload)
    before_case = load_case(conn, request.case_id)
    case_body = request.model_dump(mode="python")
    upsert_case(conn, case_body)
    case = load_case(conn, request.case_id)
    upsert_case_digest(conn, request.case_id)
    insert_case_change_log(
        conn,
        case_id=request.case_id,
        action="case_upsert",
        before_state=before_case,
        after_state=case,
        reason="tool:case.upsert",
    )
    conn.commit()
    response = ToolResponse(
        ok=True,
        summary=f"已写入案件 {request.case_id}",
        data={"case": case},
        refs={"case_ids": [request.case_id]},
    )
    return response.model_dump(mode="json", by_alias=True)


def case_link_alert(conn: sqlite3.Connection, payload: dict) -> dict:
    request = CaseLinkAlertRequest.model_validate(payload)
    case = load_case(conn, request.case_id)
    if case is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到案件 {request.case_id}",
            data={"link": None},
            warnings=[f"case_not_found:{request.case_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)

    alert = load_alert(conn, request.alert_id)
    if alert is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到告警 {request.alert_id}",
            data={"link": None},
            warnings=[f"alert_not_found:{request.alert_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)

    linked_at = datetime.now(timezone.utc).isoformat()
    previous_case_id = alert.get("case_id")
    link_alert_to_case(
        conn=conn,
        case_id=request.case_id,
        alert_id=request.alert_id,
        confidence=request.confidence,
        reason=request.reason,
        linked_at=linked_at,
    )
    timeline_event_id = append_timeline_event_for_alert(conn=conn, case_id=request.case_id, alert=alert)
    upsert_case_digest(conn, request.case_id)
    insert_alert_decision_log(
        conn,
        alert_id=request.alert_id,
        decision="link_alert",
        case_id=request.case_id,
        confidence=request.confidence,
        reason=request.reason,
        detail={
            "previous_case_id": previous_case_id,
            "timeline_event_id": timeline_event_id,
        },
    )
    conn.commit()

    response = ToolResponse(
        ok=True,
        summary=f"已关联告警 {request.alert_id} 到案件 {request.case_id}",
        data={
            "link": {
                "case_id": request.case_id,
                "alert_id": request.alert_id,
                "confidence": request.confidence,
                "reason": request.reason,
                "linked_at": linked_at,
                "timeline_event_id": timeline_event_id,
            }
        },
        refs={
            "case_ids": [request.case_id],
            "alert_ids": [request.alert_id],
            "timeline_event_ids": [timeline_event_id],
        },
    )
    return response.model_dump(mode="json", by_alias=True)


def case_update_risk(conn: sqlite3.Connection, payload: dict) -> dict:
    request = CaseUpdateRiskRequest.model_validate(payload)
    case = load_case(conn, request.case_id)
    if case is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到案件 {request.case_id}",
            data={"case": None},
            warnings=[f"case_not_found:{request.case_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)

    before_case = dict(case)
    effective_stage, downgraded_blocked = _resolve_stage_with_guard(
        current_stage=before_case["current_stage"],
        requested_stage=request.current_stage,
        force_downgrade=request.force_downgrade,
    )

    update_case_risk(
        conn=conn,
        case_id=request.case_id,
        overall_severity=request.overall_severity,
        current_stage=effective_stage,
        status=request.status,
    )
    updated_case = load_case(conn, request.case_id)
    upsert_case_digest(conn, request.case_id)
    insert_case_change_log(
        conn,
        case_id=request.case_id,
        action="case_update_risk",
        before_state=before_case,
        after_state=updated_case,
        reason="tool:case.update-risk_stage_guard" if downgraded_blocked else "tool:case.update-risk",
    )
    conn.commit()
    warnings = ["stage_downgrade_blocked"] if downgraded_blocked else []
    summary = (
        f"已更新案件风险 {request.case_id}（阶段回退已阻止，保持 {before_case['current_stage']}）"
        if downgraded_blocked
        else f"已更新案件风险 {request.case_id}"
    )
    response = ToolResponse(
        ok=True,
        summary=summary,
        data={"case": updated_case},
        refs={"case_ids": [request.case_id]},
        warnings=warnings,
    )
    return response.model_dump(mode="json", by_alias=True)
