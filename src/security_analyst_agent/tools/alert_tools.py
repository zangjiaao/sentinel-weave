import sqlite3

from security_analyst_agent.repositories.alerts import (
    ack_alerts,
    count_alerts,
    count_alert_clusters,
    count_alerts_covered_by_clusters,
    fetch_alerts,
    fetch_alert_clusters,
    get_alert_by_id,
    get_alert_evidence_summaries,
    get_case_evidence_summaries,
    summarize_alert_hotspots,
    summarize_alert_cluster_buckets,
)
from security_analyst_agent.repositories.audit import insert_alert_decision_log, load_active_analysis_cutoff
from security_analyst_agent.schemas.alert_tools import (
    AlertAckRequest,
    AlertDetailBatchRequest,
    AlertDetailRequest,
    AlertFetchRequest,
)
from security_analyst_agent.schemas.common import ToolResponse


def _is_homogeneous_noise_clusters(clusters: list[dict]) -> bool:
    if not clusters:
        return False
    for cluster in clusters:
        if cluster.get("priority_bucket") != "p2":
            return False
        if int(cluster.get("high_severity_count", 0)) > 0:
            return False
    return True


def _build_cluster_guardrails_and_actions(
    *,
    request: AlertFetchRequest,
    clusters: list[dict],
    page_next_cursor: str | None,
) -> tuple[dict[str, object], list[dict[str, object]], bool]:
    max_detail_batch_size = max(1, min(5, request.limit))
    recommended_detail_batch_size = min(2, max_detail_batch_size)
    should_ack_homogeneous_noise = _is_homogeneous_noise_clusters(clusters)

    detail_alert_ids: list[str] = []
    if clusters:
        first_cluster_ids = list(clusters[0].get("sample_alert_ids", []))
        detail_alert_ids = first_cluster_ids[:recommended_detail_batch_size]
    detail_fanout_guardrail_applied = len(detail_alert_ids) > 0 and len(detail_alert_ids) < len(
        list(clusters[0].get("sample_alert_ids", [])) if clusters else []
    )

    processing_guardrails = {
        "recommended_detail_batch_size": recommended_detail_batch_size,
        "max_detail_batch_size": max_detail_batch_size,
        "should_ack_homogeneous_noise": should_ack_homogeneous_noise,
        "detail_fanout_guardrail_applied": detail_fanout_guardrail_applied,
    }

    recommended_next_actions: list[dict[str, object]] = []
    if detail_alert_ids:
        recommended_next_actions.append(
            {
                "tool_name": "alert.detail-batch",
                "reason": "优先补证当前页高优先级簇样本，控制单轮 fan-out",
                "payload": {"alert_ids": detail_alert_ids},
            }
        )
    recommended_next_actions.append(
        {
            "tool_name": "alert.fetch",
            "reason": "继续消化聚类积压，按游标推进",
            "payload": {
                "mode": "clusters",
                "status": request.status,
                "limit": request.limit,
                "cluster_min_count": request.cluster_min_count,
                "cursor": page_next_cursor,
            },
        }
    )
    return processing_guardrails, recommended_next_actions, detail_fanout_guardrail_applied


def alert_fetch(conn: sqlite3.Connection, payload: dict) -> dict:
    request = AlertFetchRequest.model_validate(payload)
    analysis_cutoff_at = load_active_analysis_cutoff(conn)
    requested_mode = request.mode
    total_candidates: int | None = None
    if requested_mode in {"auto", "clusters"}:
        total_candidates = count_alerts(
            conn,
            statuses=request.status,
            min_severity=request.min_severity,
            analysis_cutoff_at=analysis_cutoff_at,
        )
    effective_mode = requested_mode
    if requested_mode == "auto":
        threshold = request.auto_cluster_threshold
        if (total_candidates or 0) >= threshold:
            effective_mode = "clusters"
        else:
            effective_mode = "alerts"

    warnings: list[str] = []
    alerts: list[dict] = []
    clusters: list[dict] = []
    refs_alert_ids: list[str] = []
    page_has_more = False
    page_next_cursor: str | None = None
    total_cluster_candidates: int | None = None
    priority_buckets: dict[str, dict[str, int]] | None = None
    backlog_schedule: dict[str, int | str | None] | None = None
    hotspot_summary: dict[str, object] | None = None
    processing_guardrails: dict[str, object] | None = None
    recommended_next_actions: list[dict[str, object]] | None = None
    if effective_mode == "clusters":
        cluster_offset = 0
        if request.cursor:
            try:
                cluster_offset = int(request.cursor)
                if cluster_offset < 0:
                    raise ValueError("cursor must be non-negative")
            except ValueError:
                warnings.append("invalid_cluster_cursor_reset")
                cluster_offset = 0

        total_cluster_candidates = count_alert_clusters(
            conn,
            statuses=request.status,
            min_severity=request.min_severity,
            analysis_cutoff_at=analysis_cutoff_at,
            cluster_min_count=request.cluster_min_count,
        )
        clusters = fetch_alert_clusters(
            conn,
            limit=request.limit,
            offset=cluster_offset,
            statuses=request.status,
            min_severity=request.min_severity,
            analysis_cutoff_at=analysis_cutoff_at,
            cluster_min_count=request.cluster_min_count,
            sample_size=request.cluster_sample_size,
        )
        priority_buckets = summarize_alert_cluster_buckets(
            conn,
            statuses=request.status,
            min_severity=request.min_severity,
            analysis_cutoff_at=analysis_cutoff_at,
            cluster_min_count=request.cluster_min_count,
        )
        hotspot_summary = summarize_alert_hotspots(
            conn,
            statuses=request.status,
            min_severity=request.min_severity,
            analysis_cutoff_at=analysis_cutoff_at,
            top_n=request.hotspot_top_n,
        )
        refs_alert_ids = list(dict.fromkeys([item for cluster in clusters for item in cluster["sample_alert_ids"]]))
        covered_alert_count = count_alerts_covered_by_clusters(
            conn,
            statuses=request.status,
            min_severity=request.min_severity,
            analysis_cutoff_at=analysis_cutoff_at,
            cluster_min_count=request.cluster_min_count,
        )
        omitted_alert_count = max((total_candidates or 0) - covered_alert_count, 0)
        if omitted_alert_count > 0:
            warnings.append("cluster_filter_omitted_low_volume_alerts")
        page_has_more = cluster_offset + len(clusters) < (total_cluster_candidates or 0)
        page_next_cursor = str(cluster_offset + len(clusters)) if page_has_more else None
        remaining_cluster_count = max((total_cluster_candidates or 0) - (cluster_offset + len(clusters)), 0)
        next_priority_bucket: str | None = None
        if page_has_more:
            next_page_preview = fetch_alert_clusters(
                conn,
                limit=1,
                offset=cluster_offset + len(clusters),
                statuses=request.status,
                min_severity=request.min_severity,
                analysis_cutoff_at=analysis_cutoff_at,
                cluster_min_count=request.cluster_min_count,
                sample_size=1,
            )
            if next_page_preview:
                next_priority_bucket = str(next_page_preview[0]["priority_bucket"])
        backlog_schedule = {
            "current_offset": cluster_offset,
            "returned_clusters": len(clusters),
            "remaining_cluster_count": remaining_cluster_count,
            "next_cursor": page_next_cursor,
            "next_priority_bucket": next_priority_bucket,
        }
        if page_has_more:
            warnings.append("cluster_backlog_remaining")
        processing_guardrails, recommended_next_actions, detail_fanout_guardrail_applied = (
            _build_cluster_guardrails_and_actions(
                request=request,
                clusters=clusters,
                page_next_cursor=page_next_cursor,
            )
        )
        if detail_fanout_guardrail_applied:
            warnings.append("detail_fanout_guardrail_applied")
        summary = (
            f"返回 {len(clusters)} 个告警聚合簇（当前偏移 {cluster_offset}，"
            f"总簇 {total_cluster_candidates or 0}，覆盖 {covered_alert_count} 条告警）"
        )
    else:
        alerts = fetch_alerts(
            conn,
            request.limit,
            request.status,
            request.min_severity,
            analysis_cutoff_at=analysis_cutoff_at,
        )
        refs_alert_ids = [item["alert_id"] for item in alerts]
        omitted_alert_count = 0
        if total_candidates is None:
            total_candidates = len(alerts)
        summary = f"返回 {len(alerts)} 条待研判告警摘要"

    response = ToolResponse(
        ok=True,
        summary=summary,
        data={
            "mode": effective_mode,
            "alerts": alerts,
            "clusters": clusters,
            "total_candidates": total_candidates,
            "total_cluster_candidates": total_cluster_candidates,
            "priority_buckets": priority_buckets,
            "backlog_schedule": backlog_schedule,
            "hotspot_summary": hotspot_summary,
            "processing_guardrails": processing_guardrails,
            "recommended_next_actions": recommended_next_actions,
            "omitted_alert_count": omitted_alert_count,
        },
        refs={"alert_ids": refs_alert_ids},
        warnings=warnings,
        page={"next_cursor": page_next_cursor, "has_more": page_has_more},
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
