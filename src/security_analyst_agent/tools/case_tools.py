import sqlite3

from security_analyst_agent.repositories.cases import (
    load_alert,
    load_case,
    load_case_timeline,
    load_evidence_by_ids,
)
from security_analyst_agent.schemas.case_tools import CaseExplainLinkRequest, CaseGetRequest, CaseTimelineRequest
from security_analyst_agent.schemas.common import ToolResponse
from security_analyst_agent.services.link_explainer import explain_alert_link


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

    response = ToolResponse(
        ok=True,
        summary=f"读取案件 {request.case_id}",
        data={"case": case},
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

    decision = explain_alert_link(alert)
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

