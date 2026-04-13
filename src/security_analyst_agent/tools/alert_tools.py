import sqlite3

from security_analyst_agent.repositories.alerts import (
    fetch_alerts,
    get_alert_by_id,
    get_case_evidence_summaries,
)
from security_analyst_agent.schemas.alert_tools import AlertDetailRequest, AlertFetchRequest
from security_analyst_agent.schemas.common import ToolResponse


def alert_fetch(conn: sqlite3.Connection, payload: dict) -> dict:
    request = AlertFetchRequest.model_validate(payload)
    alerts = fetch_alerts(conn, request.limit, request.status, request.min_severity)
    response = ToolResponse(
        ok=True,
        summary=f"返回 {len(alerts)} 条待研判告警摘要",
        data={"alerts": alerts},
        refs={"alert_ids": [item["alert_id"] for item in alerts]},
    )
    return response.model_dump(mode="json", by_alias=True)


def alert_detail(conn: sqlite3.Connection, payload: dict) -> dict:
    request = AlertDetailRequest.model_validate(payload)
    alert = get_alert_by_id(conn, request.alert_id)
    if alert is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到告警 {request.alert_id}",
            data={"alert": None},
            warnings=[f"alert_not_found:{request.alert_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)

    evidence_rows = get_case_evidence_summaries(conn, alert["case_id"])
    alert["parser_profile_version_id"] = "waf_nginx_v1"
    alert["evidence_summary"] = "；".join(item["summary"] for item in evidence_rows) if evidence_rows else "暂无证据摘要"
    response = ToolResponse(
        ok=True,
        summary=f"读取告警 {alert['alert_id']}",
        data={"alert": alert},
        refs={
            "alert_ids": [alert["alert_id"]],
            "evidence_ids": [item["evidence_id"] for item in evidence_rows],
        },
    )
    return response.model_dump(mode="json", by_alias=True)

