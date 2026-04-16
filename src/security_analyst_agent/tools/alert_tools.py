import sqlite3

from security_analyst_agent.repositories.alerts import (
    ack_alerts,
    fetch_alerts,
    get_alert_by_id,
    get_alert_evidence_summaries,
    get_case_evidence_summaries,
)
from security_analyst_agent.repositories.audit import insert_alert_decision_log, load_active_analysis_cutoff
from security_analyst_agent.schemas.alert_tools import (
    AlertAckRequest,
    AlertDetailBatchRequest,
    AlertDetailRequest,
    AlertFetchRequest,
)
from security_analyst_agent.schemas.common import ToolResponse


def alert_fetch(conn: sqlite3.Connection, payload: dict) -> dict:
    request = AlertFetchRequest.model_validate(payload)
    analysis_cutoff_at = load_active_analysis_cutoff(conn)
    alerts = fetch_alerts(
        conn,
        request.limit,
        request.status,
        request.min_severity,
        analysis_cutoff_at=analysis_cutoff_at,
    )
    response = ToolResponse(
        ok=True,
        summary=f"返回 {len(alerts)} 条待研判告警摘要",
        data={"alerts": alerts},
        refs={"alert_ids": [item["alert_id"] for item in alerts]},
    )
    return response.model_dump(mode="json", by_alias=True)


def _load_alert_detail(
    conn: sqlite3.Connection,
    alert_id: str,
    analysis_cutoff_at: str | None,
) -> tuple[dict | None, list[dict]]:
    alert = get_alert_by_id(conn, alert_id, analysis_cutoff_at=analysis_cutoff_at)
    if alert is None:
        return None, []

    evidence_rows = get_alert_evidence_summaries(
        conn,
        case_id=alert["case_id"],
        alert_id=alert["alert_id"],
        analysis_cutoff_at=analysis_cutoff_at,
    )
    if not evidence_rows:
        evidence_rows = get_case_evidence_summaries(
            conn,
            alert["case_id"],
            analysis_cutoff_at=analysis_cutoff_at,
        )
    alert["parser_profile_version_id"] = "waf_nginx_v1"
    alert["evidence_summary"] = "；".join(item["summary"] for item in evidence_rows) if evidence_rows else "暂无证据摘要"
    return alert, evidence_rows


def alert_detail(conn: sqlite3.Connection, payload: dict) -> dict:
    request = AlertDetailRequest.model_validate(payload)
    analysis_cutoff_at = load_active_analysis_cutoff(conn)
    alert, evidence_rows = _load_alert_detail(conn, request.alert_id, analysis_cutoff_at=analysis_cutoff_at)
    if alert is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到告警 {request.alert_id}",
            data={"alert": None},
            warnings=[f"alert_not_found:{request.alert_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)

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


def alert_detail_batch(conn: sqlite3.Connection, payload: dict) -> dict:
    request = AlertDetailBatchRequest.model_validate(payload)
    analysis_cutoff_at = load_active_analysis_cutoff(conn)
    alert_ids = list(dict.fromkeys(request.alert_ids))

    alerts: list[dict] = []
    missing_alert_ids: list[str] = []
    evidence_ids: list[str] = []

    for alert_id in alert_ids:
        alert, evidence_rows = _load_alert_detail(conn, alert_id, analysis_cutoff_at=analysis_cutoff_at)
        if alert is None:
            missing_alert_ids.append(alert_id)
            continue
        alerts.append(alert)
        evidence_ids.extend(item["evidence_id"] for item in evidence_rows)

    warnings = [f"alert_not_found:{alert_id}" for alert_id in missing_alert_ids]
    response = ToolResponse(
        ok=len(alerts) > 0,
        summary=f"批量读取告警详情：成功 {len(alerts)} 条，缺失 {len(missing_alert_ids)} 条",
        data={
            "alerts": alerts,
            "missing_alert_ids": missing_alert_ids,
        },
        refs={
            "alert_ids": [item["alert_id"] for item in alerts],
            "evidence_ids": list(dict.fromkeys(evidence_ids)),
        },
        warnings=warnings,
    )
    return response.model_dump(mode="json", by_alias=True)


def alert_ack(conn: sqlite3.Connection, payload: dict) -> dict:
    request = AlertAckRequest.model_validate(payload)
    ack = ack_alerts(conn, request.alert_ids, request.status)
    conn.commit()

    warnings = []
    if ack["missing_count"] > 0:
        warnings.append("alert_not_found")

    for alert_id in ack["updated_alert_ids"]:
        insert_alert_decision_log(
            conn,
            alert_id=alert_id,
            decision=f"ack_{request.status}",
            case_id=None,
            confidence=None,
            reason="tool:alert.ack",
        )
    for alert_id in ack["already_status_alert_ids"]:
        insert_alert_decision_log(
            conn,
            alert_id=alert_id,
            decision=f"ack_{request.status}_noop",
            case_id=None,
            confidence=None,
            reason="tool:alert.ack_already_status",
        )
    for alert_id in ack["missing_alert_ids"]:
        insert_alert_decision_log(
            conn,
            alert_id=alert_id,
            decision="ack_missing_alert",
            case_id=None,
            confidence=None,
            reason="tool:alert.ack_alert_not_found",
        )

    response = ToolResponse(
        ok=True,
        summary=f"已确认 {ack['updated_count']} 条告警为 {request.status}",
        data={"ack": ack},
        refs={"alert_ids": ack["updated_alert_ids"] + ack["already_status_alert_ids"]},
        warnings=warnings,
    )
    return response.model_dump(mode="json", by_alias=True)
