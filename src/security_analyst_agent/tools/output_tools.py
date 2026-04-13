import sqlite3

from security_analyst_agent.repositories.cases import load_case, load_case_timeline
from security_analyst_agent.schemas.common import ToolResponse
from security_analyst_agent.schemas.output_tools import NotifyPreviewRequest, ReportDraftRequest
from security_analyst_agent.services.output import build_notify_preview, build_report


def notify_preview(conn: sqlite3.Connection, payload: dict) -> dict:
    request = NotifyPreviewRequest.model_validate(payload)
    case = load_case(conn, request.case_id)
    if case is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到案件 {request.case_id}",
            data={"preview": None},
            warnings=[f"case_not_found:{request.case_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)

    preview = build_notify_preview(case, request.channel)
    response = ToolResponse(
        ok=True,
        summary=f"生成通知预览: {request.case_id}",
        data={"preview": preview},
        refs={"case_ids": [request.case_id]},
    )
    return response.model_dump(mode="json", by_alias=True)


def report_draft(conn: sqlite3.Connection, payload: dict) -> dict:
    request = ReportDraftRequest.model_validate(payload)
    case = load_case(conn, request.case_id)
    if case is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到案件 {request.case_id}",
            data={"report": None},
            warnings=[f"case_not_found:{request.case_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)

    timeline = load_case_timeline(conn, request.case_id)
    report = build_report(case, timeline, request.tone)
    response = ToolResponse(
        ok=True,
        summary=f"生成报告草稿: {request.case_id}",
        data={"report": report},
        refs={
            "case_ids": [request.case_id],
            "timeline_event_ids": [item["timeline_event_id"] for item in timeline],
        },
    )
    return response.model_dump(mode="json", by_alias=True)

