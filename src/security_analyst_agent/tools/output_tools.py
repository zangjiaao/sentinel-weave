import sqlite3
from datetime import datetime, timezone
from uuid import uuid4

from security_analyst_agent.repositories.cases import load_case, load_case_timeline
from security_analyst_agent.repositories.audit import insert_escalation_log
from security_analyst_agent.schemas.common import ToolResponse
from security_analyst_agent.schemas.output_tools import NotifyPreviewRequest, NotifySendRequest, ReportDraftRequest
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


def notify_send(conn: sqlite3.Connection, payload: dict) -> dict:
    request = NotifySendRequest.model_validate(payload)
    case = load_case(conn, request.case_id)
    if case is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到案件 {request.case_id}",
            data={"notification": None},
            warnings=[f"case_not_found:{request.case_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)

    preview = build_notify_preview(case, request.channel)
    dedupe_key = f"{request.case_id}:{request.channel}:{request.template}"
    existing = conn.execute(
        """
        select notification_id
        from notification_outbox
        where dedupe_key = ? and status in ('queued', 'sent_simulated')
        order by created_at desc
        limit 1
        """,
        (dedupe_key,),
    ).fetchone()

    if existing:
        insert_escalation_log(
            conn,
            case_id=request.case_id,
            triggered=False,
            channel=request.channel,
            template=request.template,
            notification_id=existing["notification_id"],
            dedupe_key=dedupe_key,
            reason="dedupe_hit",
            detail={"status": "deduped"},
        )
        conn.commit()
        response = ToolResponse(
            ok=True,
            summary=f"模拟通知去重命中: {request.case_id}",
            data={
                "notification": {
                    "notification_id": existing["notification_id"],
                    "case_id": request.case_id,
                    "channel": request.channel,
                    "template": request.template,
                    "status": "deduped",
                    "dedupe_key": dedupe_key,
                }
            },
            refs={"case_ids": [request.case_id]},
            warnings=["dedupe_hit"],
        )
        return response.model_dump(mode="json", by_alias=True)

    now = datetime.now(timezone.utc).isoformat()
    notification_id = f"notif_{uuid4().hex[:12]}"
    conn.execute(
        """
        insert into notification_outbox (
          notification_id, case_id, channel, template, title, body, dedupe_key, status, created_at, sent_at
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            notification_id,
            request.case_id,
            request.channel,
            request.template,
            preview["title"],
            preview["body"],
            dedupe_key,
            "sent_simulated",
            now,
            now,
        ),
    )
    insert_escalation_log(
        conn,
        case_id=request.case_id,
        triggered=True,
        channel=request.channel,
        template=request.template,
        notification_id=notification_id,
        dedupe_key=dedupe_key,
        reason="threshold_met",
        detail={"status": "sent_simulated"},
    )
    conn.commit()

    response = ToolResponse(
        ok=True,
        summary=f"已模拟发送通知: {request.case_id}",
        data={
            "notification": {
                "notification_id": notification_id,
                "case_id": request.case_id,
                "channel": request.channel,
                "template": request.template,
                "status": "sent_simulated",
                "dedupe_key": dedupe_key,
                "title": preview["title"],
                "recommended_recipients": preview["recommended_recipients"],
            }
        },
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
