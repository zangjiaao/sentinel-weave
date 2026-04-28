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
    AlertIpContextRequest,
    AlertSuspectIpTopkRequest,
)
from security_analyst_agent.schemas.common import ToolResponse

_SEVERITY_ORDER_SQL = (
    "case {column} "
    "when 'low' then 1 "
    "when 'medium' then 2 "
    "when 'high' then 3 "
    "when 'critical' then 4 "
    "else 0 end"
)


def _severity_order_sql(column: str) -> str:
    return _SEVERITY_ORDER_SQL.format(column=column)


def _severity_rank_min(min_severity: str | None) -> int:
    if not min_severity:
        return 0
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(str(min_severity).lower(), 0)


def _build_filtered_alert_where(
    *,
    alias: str,
    statuses: list[str],
    min_severity: str | None,
    analysis_cutoff_at: str | None,
) -> tuple[str, list[object]]:
    conditions: list[str] = []
    params: list[object] = []
    if statuses:
        placeholders = ", ".join("?" for _ in statuses)
        conditions.append(f"{alias}.status in ({placeholders})")
        params.extend(statuses)

    min_rank = _severity_rank_min(min_severity)
    if min_rank > 0:
        conditions.append(f"{_severity_order_sql(f'lower({alias}.severity)')} >= ?")
        params.append(min_rank)

    if analysis_cutoff_at:
        conditions.append(f"{alias}.occurred_at <= ?")
        params.append(analysis_cutoff_at)

    where_clause = ""
    if conditions:
        where_clause = "where " + " and ".join(conditions)
    return where_clause, params


def _load_ingest_batch_summary(
    conn: sqlite3.Connection,
    *,
    analysis_cutoff_at: str | None,
    top_n: int,
) -> dict[str, object]:
    queue_event_count = int(
        conn.execute(
            """
            select count(*)
            from alert_ingest_events
            where trigger_state in ('pending', 'processing')
            """
        ).fetchone()[0]
    )
    queue_alert_count = int(
        conn.execute(
            """
            select count(distinct alert_id)
            from alert_ingest_events
            where trigger_state in ('pending', 'processing')
            """
        ).fetchone()[0]
    )
    if queue_alert_count <= 0:
        return {
            "analysis_scope": "current_ingest_queue",
            "has_current_queue": False,
            "queue_event_count": queue_event_count,
            "queue_alert_count": 0,
            "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
            "top_src_ips": [],
            "top_assets": [],
            "top_stages": [],
        }

    params: tuple[object, ...]
    cutoff_clause = ""
    if analysis_cutoff_at:
        cutoff_clause = "and alerts.occurred_at <= ?"
        params = (analysis_cutoff_at,)
    else:
        params = ()

    row = conn.execute(
        f"""
        with queue_alert_ids as (
          select distinct alert_id
          from alert_ingest_events
          where trigger_state in ('pending', 'processing')
        )
        select
          count(*) as total_alert_count,
          sum(case when lower(alerts.severity) = 'critical' then 1 else 0 end) as critical_count,
          sum(case when lower(alerts.severity) = 'high' then 1 else 0 end) as high_count,
          sum(case when lower(alerts.severity) = 'medium' then 1 else 0 end) as medium_count,
          sum(case when lower(alerts.severity) = 'low' then 1 else 0 end) as low_count,
          sum(case when lower(alerts.severity) not in ('critical', 'high', 'medium', 'low') then 1 else 0 end)
            as unknown_count
        from alerts
        join queue_alert_ids on queue_alert_ids.alert_id = alerts.alert_id
        where 1 = 1
          {cutoff_clause}
        """,
        params,
    ).fetchone()

    top_src_ips_rows = conn.execute(
        f"""
        with queue_alert_ids as (
          select distinct alert_id
          from alert_ingest_events
          where trigger_state in ('pending', 'processing')
        )
        select
          coalesce(alerts.src_ip, 'unknown') as src_ip,
          count(*) as alert_count,
          sum(case when lower(alerts.severity) in ('high', 'critical') then 1 else 0 end) as high_severity_count
        from alerts
        join queue_alert_ids on queue_alert_ids.alert_id = alerts.alert_id
        where 1 = 1
          {cutoff_clause}
        group by coalesce(alerts.src_ip, 'unknown')
        order by high_severity_count desc, alert_count desc, src_ip asc
        limit ?
        """,
        (*params, top_n),
    ).fetchall()
    top_assets_rows = conn.execute(
        f"""
        with queue_alert_ids as (
          select distinct alert_id
          from alert_ingest_events
          where trigger_state in ('pending', 'processing')
        )
        select
          coalesce(alerts.asset_id, 'unknown') as asset_id,
          count(*) as alert_count,
          sum(case when lower(alerts.severity) in ('high', 'critical') then 1 else 0 end) as high_severity_count
        from alerts
        join queue_alert_ids on queue_alert_ids.alert_id = alerts.alert_id
        where 1 = 1
          {cutoff_clause}
        group by coalesce(alerts.asset_id, 'unknown')
        order by high_severity_count desc, alert_count desc, asset_id asc
        limit ?
        """,
        (*params, top_n),
    ).fetchall()
    top_stage_rows = conn.execute(
        f"""
        with queue_alert_ids as (
          select distinct alert_id
          from alert_ingest_events
          where trigger_state in ('pending', 'processing')
        )
        select
          coalesce(lower(alerts.attack_stage), 'unknown') as attack_stage,
          count(*) as alert_count
        from alerts
        join queue_alert_ids on queue_alert_ids.alert_id = alerts.alert_id
        where 1 = 1
          {cutoff_clause}
        group by coalesce(lower(alerts.attack_stage), 'unknown')
        order by alert_count desc, attack_stage asc
        limit ?
        """,
        (*params, top_n),
    ).fetchall()

    return {
        "analysis_scope": "current_ingest_queue",
        "has_current_queue": True,
        "queue_event_count": queue_event_count,
        "queue_alert_count": queue_alert_count,
        "severity_breakdown": {
            "critical": int(row["critical_count"] or 0),
            "high": int(row["high_count"] or 0),
            "medium": int(row["medium_count"] or 0),
            "low": int(row["low_count"] or 0),
            "unknown": int(row["unknown_count"] or 0),
        },
        "top_src_ips": [
            {
                "src_ip": str(item["src_ip"]),
                "alert_count": int(item["alert_count"]),
                "high_severity_count": int(item["high_severity_count"] or 0),
            }
            for item in top_src_ips_rows
        ],
        "top_assets": [
            {
                "asset_id": str(item["asset_id"]),
                "alert_count": int(item["alert_count"]),
                "high_severity_count": int(item["high_severity_count"] or 0),
            }
            for item in top_assets_rows
        ],
        "top_stages": [
            {"attack_stage": str(item["attack_stage"]), "alert_count": int(item["alert_count"])}
            for item in top_stage_rows
        ],
    }


def _fetch_suspect_ip_rows(
    conn: sqlite3.Connection,
    *,
    statuses: list[str],
    min_severity: str | None,
    analysis_cutoff_at: str | None,
    top_k: int,
    min_alert_count: int,
    queue_only: bool,
) -> tuple[list[dict], bool]:
    where_clause, params = _build_filtered_alert_where(
        alias="alerts",
        statuses=statuses,
        min_severity=min_severity,
        analysis_cutoff_at=analysis_cutoff_at,
    )
    queue_only_applied = queue_only and int(
        conn.execute(
            """
            select count(*)
            from alert_ingest_events
            where trigger_state in ('pending', 'processing')
            """
        ).fetchone()[0]
    ) > 0
    queue_join = ""
    if queue_only_applied:
        queue_join = """
        join (
          select distinct alert_id
          from alert_ingest_events
          where trigger_state in ('pending', 'processing')
        ) as queue_alert_ids on queue_alert_ids.alert_id = alerts.alert_id
        """

    rows = conn.execute(
        f"""
        with scoped_alerts as (
          select
            alerts.alert_id,
            alerts.occurred_at,
            coalesce(alerts.src_ip, '') as src_ip,
            coalesce(alerts.asset_id, 'unknown') as asset_id,
            lower(alerts.severity) as severity,
            coalesce(lower(alerts.attack_stage), 'unknown') as attack_stage
          from alerts
          {queue_join}
          {where_clause}
        )
        select
          scoped_alerts.src_ip as src_ip,
          count(*) as alert_count,
          sum(case when scoped_alerts.severity in ('high', 'critical') then 1 else 0 end) as high_severity_count,
          sum(case when scoped_alerts.severity = 'critical' then 1 else 0 end) as critical_count,
          count(distinct scoped_alerts.asset_id) as asset_spread,
          count(distinct case when scoped_alerts.attack_stage not in ('unknown', 'recon', '') then scoped_alerts.attack_stage end)
            as non_recon_stage_count,
          min(scoped_alerts.occurred_at) as first_occurred_at,
          max(scoped_alerts.occurred_at) as last_occurred_at,
          (
            sum(case when scoped_alerts.severity = 'critical' then 1 else 0 end) * 10
            + sum(case when scoped_alerts.severity in ('high', 'critical') then 1 else 0 end) * 4
            + count(distinct case when scoped_alerts.attack_stage not in ('unknown', 'recon', '') then scoped_alerts.attack_stage end) * 6
            + count(distinct scoped_alerts.asset_id) * 2
            + case when count(*) > 40 then 40 else count(*) end
          ) as suspect_score
        from scoped_alerts
        where scoped_alerts.src_ip <> ''
        group by scoped_alerts.src_ip
        having count(*) >= ?
        order by suspect_score desc, high_severity_count desc, alert_count desc, scoped_alerts.src_ip asc
        limit ?
        """,
        (*params, min_alert_count, top_k),
    ).fetchall()
    return [dict(row) for row in rows], queue_only_applied


def _build_suspect_reason_codes(item: dict) -> list[str]:
    reason_codes: list[str] = []
    if int(item.get("critical_count", 0)) > 0:
        reason_codes.append("critical_activity_detected")
    if int(item.get("high_severity_count", 0)) > 0:
        reason_codes.append("high_severity_activity_detected")
    if int(item.get("non_recon_stage_count", 0)) >= 1:
        reason_codes.append("post_recon_progression_detected")
    if int(item.get("asset_spread", 0)) >= 2:
        reason_codes.append("cross_asset_spread_detected")
    if int(item.get("alert_count", 0)) >= 8:
        reason_codes.append("high_frequency_activity")
    if not reason_codes:
        reason_codes.append("requires_followup_sampling")
    return reason_codes


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
                "queue_only": request.queue_only,
                "limit": request.limit,
                "cluster_min_count": request.cluster_min_count,
                "cursor": page_next_cursor,
            },
        }
    )
    return processing_guardrails, recommended_next_actions, detail_fanout_guardrail_applied


def _build_ack_recommendations(clusters: list[dict]) -> list[dict[str, object]]:
    recommendations: list[dict[str, object]] = []
    for cluster in clusters:
        ack_score = 0
        reason_codes: list[str] = []
        priority_bucket = str(cluster.get("priority_bucket", "p2"))
        max_severity = str(cluster.get("max_severity", "low"))
        high_severity_count = int(cluster.get("high_severity_count", 0))
        alert_count = int(cluster.get("alert_count", 0))
        attack_stage = str(cluster.get("attack_stage", "unknown"))

        if priority_bucket == "p2":
            ack_score += 45
            reason_codes.append("low_priority_cluster")
        else:
            reason_codes.append("high_priority_cluster")

        if max_severity in {"low", "medium"}:
            ack_score += 25
            reason_codes.append("low_or_medium_severity_only")
        else:
            ack_score -= 40
            reason_codes.append("high_or_critical_severity_present")

        if high_severity_count == 0:
            ack_score += 20
            reason_codes.append("no_high_severity_alerts")
        else:
            ack_score -= 30
            reason_codes.append("contains_high_severity_alerts")

        if alert_count >= 10:
            ack_score += 20
            reason_codes.append("repeated_alert_pattern")
        elif alert_count >= 5:
            ack_score += 10
            reason_codes.append("small_repeated_pattern")

        if attack_stage == "recon":
            ack_score += 10
            reason_codes.append("recon_stage_noise_likely")

        ack_score = max(0, min(100, ack_score))
        should_suggest_ack = ack_score >= 75
        recommendations.append(
            {
                "cluster_id": cluster.get("cluster_id"),
                "verdict": "suggest_ack_triaged" if should_suggest_ack else "needs_manual_review",
                "ack_score": ack_score,
                "confidence": round(ack_score / 100.0, 2),
                "suggested_status": "triaged" if should_suggest_ack else None,
                "reason_codes": reason_codes,
                "estimated_alert_count": alert_count,
                "sample_alert_ids": list(cluster.get("sample_alert_ids", [])),
            }
        )
    return recommendations


def alert_fetch(conn: sqlite3.Connection, payload: dict) -> dict:
    request = AlertFetchRequest.model_validate(payload)
    analysis_cutoff_at = load_active_analysis_cutoff(conn)
    ingest_batch_summary = _load_ingest_batch_summary(
        conn,
        analysis_cutoff_at=analysis_cutoff_at,
        top_n=request.hotspot_top_n,
    )
    queue_only_applied = request.queue_only and bool(ingest_batch_summary.get("has_current_queue"))
    requested_mode = request.mode
    total_candidates: int | None = None
    if requested_mode in {"auto", "clusters"}:
        total_candidates = count_alerts(
            conn,
            statuses=request.status,
            min_severity=request.min_severity,
            analysis_cutoff_at=analysis_cutoff_at,
            queue_only=queue_only_applied,
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
    ack_recommendations: list[dict[str, object]] | None = None
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
            queue_only=queue_only_applied,
            cluster_min_count=request.cluster_min_count,
        )
        clusters = fetch_alert_clusters(
            conn,
            limit=request.limit,
            offset=cluster_offset,
            statuses=request.status,
            min_severity=request.min_severity,
            analysis_cutoff_at=analysis_cutoff_at,
            queue_only=queue_only_applied,
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
            queue_only=queue_only_applied,
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
                queue_only=queue_only_applied,
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
        if request.include_strategy_hints:
            processing_guardrails, recommended_next_actions, detail_fanout_guardrail_applied = (
                _build_cluster_guardrails_and_actions(
                    request=request,
                    clusters=clusters,
                    page_next_cursor=page_next_cursor,
                )
            )
            ack_recommendations = _build_ack_recommendations(clusters)
            if any(item.get("verdict") == "suggest_ack_triaged" for item in ack_recommendations):
                warnings.append("ack_recommendations_available")
            if detail_fanout_guardrail_applied:
                warnings.append("detail_fanout_guardrail_applied")

        should_fallback_to_alerts = cluster_offset == 0 and len(clusters) == 0 and (total_candidates or 0) > 0
        if should_fallback_to_alerts:
            fallback_alerts = fetch_alerts(
                conn,
                request.limit,
                request.status,
                request.min_severity,
                analysis_cutoff_at=analysis_cutoff_at,
                queue_only=queue_only_applied,
            )
            if fallback_alerts:
                alerts = fallback_alerts
                refs_alert_ids = [item["alert_id"] for item in fallback_alerts]
                effective_mode = "alerts"
                warnings.append("clusters_empty_fallback_to_alerts")
                summary = (
                    f"聚类结果为空，回退返回 {len(fallback_alerts)} 条告警摘要"
                    f"（候选告警 {total_candidates or 0}）"
                )
            else:
                summary = (
                    f"返回 {len(clusters)} 个告警聚合簇（当前偏移 {cluster_offset}，"
                    f"总簇 {total_cluster_candidates or 0}，覆盖 {covered_alert_count} 条告警）"
                )
        else:
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
            queue_only=queue_only_applied,
        )
        refs_alert_ids = [item["alert_id"] for item in alerts]
        omitted_alert_count = 0
        if total_candidates is None:
            total_candidates = len(alerts)
        summary = f"返回 {len(alerts)} 条待研判告警摘要"
    if not bool(ingest_batch_summary.get("has_current_queue")):
        warnings.append("no_current_ingest_queue_snapshot")
    if request.queue_only and not queue_only_applied:
        warnings.append("queue_only_fallback_to_filtered_alerts")

    response = ToolResponse(
        ok=True,
        summary=summary,
        data={
            "mode": effective_mode,
            "queue_only_requested": request.queue_only,
            "queue_only_applied": queue_only_applied,
            "alerts": alerts,
            "clusters": clusters,
            "total_candidates": total_candidates,
            "total_cluster_candidates": total_cluster_candidates,
            "priority_buckets": priority_buckets,
            "backlog_schedule": backlog_schedule,
            "hotspot_summary": hotspot_summary,
            "processing_guardrails": processing_guardrails,
            "recommended_next_actions": recommended_next_actions,
            "ack_recommendations": ack_recommendations,
            "omitted_alert_count": omitted_alert_count,
            "ingest_batch_summary": ingest_batch_summary,
            "strategy_hints_included": bool(request.include_strategy_hints),
        },
        refs={"alert_ids": refs_alert_ids},
        warnings=warnings,
        page={"next_cursor": page_next_cursor, "has_more": page_has_more},
    )
    return response.model_dump(mode="json", by_alias=True)


def alert_suspect_ip_topk(conn: sqlite3.Connection, payload: dict) -> dict:
    request = AlertSuspectIpTopkRequest.model_validate(payload)
    analysis_cutoff_at = load_active_analysis_cutoff(conn)
    rows, queue_only_applied = _fetch_suspect_ip_rows(
        conn,
        statuses=request.status,
        min_severity=request.min_severity,
        analysis_cutoff_at=analysis_cutoff_at,
        top_k=request.top_k,
        min_alert_count=request.min_alert_count,
        queue_only=request.queue_only,
    )

    suspects: list[dict[str, object]] = []
    refs_alert_ids: list[str] = []
    for row in rows:
        sample_rows = conn.execute(
            f"""
            select
              alerts.alert_id,
              alerts.occurred_at,
              alerts.severity,
              alerts.attack_stage,
              alerts.asset_id
            from alerts
            where alerts.src_ip = ?
              and (? is null or alerts.occurred_at <= ?)
            order by {_severity_order_sql('lower(alerts.severity)')} desc, alerts.occurred_at desc, alerts.alert_id asc
            limit 5
            """,
            (row["src_ip"], analysis_cutoff_at, analysis_cutoff_at),
        ).fetchall()
        sample_alert_ids = [str(item["alert_id"]) for item in sample_rows]
        refs_alert_ids.extend(sample_alert_ids)
        suspects.append(
            {
                "src_ip": str(row["src_ip"]),
                "suspect_score": int(row["suspect_score"]),
                "alert_count": int(row["alert_count"]),
                "high_severity_count": int(row["high_severity_count"]),
                "critical_count": int(row["critical_count"]),
                "asset_spread": int(row["asset_spread"]),
                "non_recon_stage_count": int(row["non_recon_stage_count"]),
                "first_occurred_at": row["first_occurred_at"],
                "last_occurred_at": row["last_occurred_at"],
                "reason_codes": _build_suspect_reason_codes(row),
                "sample_alert_ids": sample_alert_ids,
            }
        )

    warnings: list[str] = []
    if request.queue_only and not queue_only_applied:
        warnings.append("queue_only_fallback_to_filtered_alerts")

    response = ToolResponse(
        ok=True,
        summary=f"返回 {len(suspects)} 个可疑攻击源 IP 候选",
        data={
            "suspects": suspects,
            "scope": {
                "queue_only_requested": request.queue_only,
                "queue_only_applied": queue_only_applied,
                "status": request.status,
                "min_severity": request.min_severity,
                "min_alert_count": request.min_alert_count,
                "top_k": request.top_k,
            },
        },
        refs={"alert_ids": list(dict.fromkeys(refs_alert_ids))},
        warnings=warnings,
    )
    return response.model_dump(mode="json", by_alias=True)


def alert_ip_context(conn: sqlite3.Connection, payload: dict) -> dict:
    request = AlertIpContextRequest.model_validate(payload)
    analysis_cutoff_at = load_active_analysis_cutoff(conn)
    where_clause, where_params = _build_filtered_alert_where(
        alias="alerts",
        statuses=request.status,
        min_severity=request.min_severity,
        analysis_cutoff_at=analysis_cutoff_at,
    )

    queue_only_applied = request.queue_only and int(
        conn.execute(
            """
            select count(*)
            from alert_ingest_events
            where trigger_state in ('pending', 'processing')
            """
        ).fetchone()[0]
    ) > 0
    queue_join = ""
    if queue_only_applied:
        queue_join = """
        join (
          select distinct alert_id
          from alert_ingest_events
          where trigger_state in ('pending', 'processing')
        ) as queue_alert_ids on queue_alert_ids.alert_id = alerts.alert_id
        """

    rows = conn.execute(
        f"""
        select
          alerts.alert_id,
          alerts.occurred_at,
          alerts.title,
          alerts.status,
          lower(alerts.severity) as severity,
          coalesce(lower(alerts.attack_stage), 'unknown') as attack_stage,
          alerts.asset_id,
          alerts.dst_ip
        from alerts
        {queue_join}
        {where_clause}
          {"and" if where_clause else "where"} alerts.src_ip = ?
        order by alerts.occurred_at desc, alerts.alert_id desc
        limit ?
        """,
        (*where_params, request.src_ip, request.limit),
    ).fetchall()
    alerts = [dict(row) for row in rows]

    summary_row = conn.execute(
        f"""
        select
          count(*) as alert_count,
          sum(case when lower(alerts.severity) in ('high', 'critical') then 1 else 0 end) as high_severity_count,
          sum(case when lower(alerts.severity) = 'critical' then 1 else 0 end) as critical_count,
          count(distinct coalesce(alerts.asset_id, 'unknown')) as asset_spread
        from alerts
        {queue_join}
        {where_clause}
          {"and" if where_clause else "where"} alerts.src_ip = ?
        """,
        (*where_params, request.src_ip),
    ).fetchone()
    stage_rows = conn.execute(
        f"""
        select
          coalesce(lower(alerts.attack_stage), 'unknown') as attack_stage,
          count(*) as alert_count
        from alerts
        {queue_join}
        {where_clause}
          {"and" if where_clause else "where"} alerts.src_ip = ?
        group by coalesce(lower(alerts.attack_stage), 'unknown')
        order by alert_count desc, attack_stage asc
        """,
        (*where_params, request.src_ip),
    ).fetchall()
    top_asset_rows = conn.execute(
        f"""
        select
          coalesce(alerts.asset_id, 'unknown') as asset_id,
          count(*) as alert_count
        from alerts
        {queue_join}
        {where_clause}
          {"and" if where_clause else "where"} alerts.src_ip = ?
        group by coalesce(alerts.asset_id, 'unknown')
        order by alert_count desc, asset_id asc
        limit 5
        """,
        (*where_params, request.src_ip),
    ).fetchall()

    warnings: list[str] = []
    if request.queue_only and not queue_only_applied:
        warnings.append("queue_only_fallback_to_filtered_alerts")

    response = ToolResponse(
        ok=True,
        summary=f"读取 src_ip={request.src_ip} 的告警上下文：{int(summary_row['alert_count'] or 0)} 条",
        data={
            "src_ip": request.src_ip,
            "queue_only_applied": queue_only_applied,
            "summary": {
                "alert_count": int(summary_row["alert_count"] or 0),
                "high_severity_count": int(summary_row["high_severity_count"] or 0),
                "critical_count": int(summary_row["critical_count"] or 0),
                "asset_spread": int(summary_row["asset_spread"] or 0),
                "stage_breakdown": [
                    {"attack_stage": str(item["attack_stage"]), "alert_count": int(item["alert_count"])}
                    for item in stage_rows
                ],
                "top_assets": [
                    {"asset_id": str(item["asset_id"]), "alert_count": int(item["alert_count"])}
                    for item in top_asset_rows
                ],
            },
            "alerts": alerts,
        },
        refs={"alert_ids": [item["alert_id"] for item in alerts]},
        warnings=warnings,
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
