import sqlite3

_SEVERITY_RANK_SQL = (
    "case alerts.severity "
    "when 'low' then 1 "
    "when 'medium' then 2 "
    "when 'high' then 3 "
    "when 'critical' then 4 "
    "else 0 end"
)

_SEVERITY_LABEL_BY_RANK = {
    4: "critical",
    3: "high",
    2: "medium",
    1: "low",
}
_P0_STAGES = ("command_execution", "lateral_prep", "reactivation")


def _build_cluster_group_cte(where_clause: str) -> str:
    return f"""
    with filtered_alerts as (
      select
        alerts.alert_id,
        alerts.occurred_at,
        alerts.title,
        alerts.status,
        alerts.severity,
        lower(alerts.attack_stage) as attack_stage,
        alerts.src_ip,
        alerts.dst_ip,
        alerts.asset_id,
        {_SEVERITY_RANK_SQL} as severity_rank
      from alerts
      {where_clause}
    ),
    grouped_clusters as (
      select
        coalesce(filtered_alerts.src_ip, '') as src_ip_key,
        coalesce(filtered_alerts.asset_id, '') as asset_id_key,
        filtered_alerts.attack_stage as attack_stage_key,
        count(*) as alert_count,
        min(filtered_alerts.occurred_at) as first_occurred_at,
        max(filtered_alerts.occurred_at) as last_occurred_at,
        max(filtered_alerts.severity_rank) as max_severity_rank,
        sum(case when filtered_alerts.severity_rank >= 3 then 1 else 0 end) as high_severity_count
      from filtered_alerts
      group by src_ip_key, asset_id_key, attack_stage_key
      having count(*) >= ? or max(filtered_alerts.severity_rank) >= 3
    )
    """


def _build_alert_filters(
    *,
    statuses: list[str],
    min_severity: str | None,
    analysis_cutoff_at: str | None,
    queue_only: bool = False,
) -> tuple[list[str], list[object]]:
    conditions: list[str] = []
    params: list[object] = []

    if statuses:
        placeholders = ", ".join("?" for _ in statuses)
        conditions.append(f"alerts.status in ({placeholders})")
        params.extend(statuses)

    if min_severity:
        rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        min_rank = rank.get(min_severity.lower(), 1)
        conditions.append(f"{_SEVERITY_RANK_SQL} >= ?")
        params.append(min_rank)

    if analysis_cutoff_at:
        conditions.append("alerts.occurred_at <= ?")
        params.append(analysis_cutoff_at)

    if queue_only:
        conditions.append(
            """
            alerts.alert_id in (
              select distinct alert_ingest_events.alert_id
              from alert_ingest_events
              where alert_ingest_events.trigger_state in ('pending', 'processing', 'failed')
            )
            """.strip()
        )

    return conditions, params


def _build_where_clause(conditions: list[str]) -> str:
    if not conditions:
        return ""
    return f"where {' and '.join(conditions)}"


def count_alerts(
    conn: sqlite3.Connection,
    statuses: list[str],
    min_severity: str | None = None,
    analysis_cutoff_at: str | None = None,
    queue_only: bool = False,
) -> int:
    conditions, params = _build_alert_filters(
        statuses=statuses,
        min_severity=min_severity,
        analysis_cutoff_at=analysis_cutoff_at,
        queue_only=queue_only,
    )
    row = conn.execute(
        f"""
        select count(*)
        from alerts
        {_build_where_clause(conditions)}
        """,
        tuple(params),
    ).fetchone()
    if row is None:
        return 0
    return int(row[0])


def fetch_alerts(
    conn: sqlite3.Connection,
    limit: int,
    statuses: list[str],
    min_severity: str | None = None,
    analysis_cutoff_at: str | None = None,
    queue_only: bool = False,
) -> list[dict]:
    conditions, params = _build_alert_filters(
        statuses=statuses,
        min_severity=min_severity,
        analysis_cutoff_at=analysis_cutoff_at,
        queue_only=queue_only,
    )
    params.append(limit)
    rows = conn.execute(
        f"""
        select
          alerts.alert_id,
          (
            select case_alert_links.case_id
            from case_alert_links
            where case_alert_links.alert_id = alerts.alert_id
              and (
                (? is null and case_alert_links.is_active = 1)
                or (
                  ? is not null
                  and case_alert_links.linked_at <= ?
                  and (case_alert_links.unlinked_at is null or case_alert_links.unlinked_at > ?)
                )
              )
            order by case_alert_links.linked_at desc, case_alert_links.rowid desc
            limit 1
          ) as case_id,
          alerts.occurred_at,
          alerts.title,
          alerts.status,
          alerts.severity,
          alerts.attack_stage,
          alerts.src_ip,
          alerts.dst_ip,
          alerts.asset_id
        from alerts
        {_build_where_clause(conditions)}
        order by alerts.occurred_at desc
        limit ?
        """,
        (
            analysis_cutoff_at,
            analysis_cutoff_at,
            analysis_cutoff_at,
            analysis_cutoff_at,
            *params,
        ),
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_alert_clusters(
    conn: sqlite3.Connection,
    *,
    limit: int,
    offset: int = 0,
    statuses: list[str],
    min_severity: str | None = None,
    analysis_cutoff_at: str | None = None,
    queue_only: bool = False,
    cluster_min_count: int = 2,
    sample_size: int = 3,
) -> list[dict]:
    conditions, params = _build_alert_filters(
        statuses=statuses,
        min_severity=min_severity,
        analysis_cutoff_at=analysis_cutoff_at,
        queue_only=queue_only,
    )
    where_clause = _build_where_clause(conditions)

    cluster_group_cte = _build_cluster_group_cte(where_clause)
    p0_stage_placeholders = ", ".join("?" for _ in _P0_STAGES)
    rows = conn.execute(
        f"""
        {cluster_group_cte}
        select
          grouped_clusters.src_ip_key,
          grouped_clusters.asset_id_key,
          grouped_clusters.attack_stage_key,
          grouped_clusters.alert_count,
          grouped_clusters.first_occurred_at,
          grouped_clusters.last_occurred_at,
          grouped_clusters.max_severity_rank,
          grouped_clusters.high_severity_count,
          case
            when grouped_clusters.attack_stage_key in ({p0_stage_placeholders}) or grouped_clusters.max_severity_rank >= 4 then 0
            when grouped_clusters.attack_stage_key = 'persistence' or grouped_clusters.max_severity_rank >= 3 then 1
            else 2
          end as priority_rank
        from grouped_clusters
        order by priority_rank asc, grouped_clusters.max_severity_rank desc, grouped_clusters.alert_count desc, grouped_clusters.last_occurred_at desc
        limit ?
        offset ?
        """,
        (*params, cluster_min_count, *_P0_STAGES, limit, offset),
    ).fetchall()

    clusters: list[dict] = []
    for row in rows:
        src_ip_key = str(row["src_ip_key"] or "")
        asset_id_key = str(row["asset_id_key"] or "")
        attack_stage_key = str(row["attack_stage_key"] or "")
        sample_rows = conn.execute(
            f"""
            select
              alerts.alert_id,
              alerts.occurred_at,
              alerts.title,
              alerts.status,
              alerts.severity,
              alerts.attack_stage,
              alerts.src_ip,
              alerts.dst_ip,
              alerts.asset_id
            from alerts
            {where_clause}
              {"and" if where_clause else "where"} ((alerts.src_ip is null and ? = '') or alerts.src_ip = ?)
              and ((alerts.asset_id is null and ? = '') or alerts.asset_id = ?)
              and lower(alerts.attack_stage) = ?
            order by alerts.occurred_at desc
            limit ?
            """,
            (*params, src_ip_key, src_ip_key, asset_id_key, asset_id_key, attack_stage_key, sample_size),
        ).fetchall()
        samples = [dict(item) for item in sample_rows]
        max_severity_rank = int(row["max_severity_rank"])
        cluster_id = (
            f"clu::{attack_stage_key or 'unknown'}::"
            f"{src_ip_key or 'unknown'}::{asset_id_key or 'unknown'}"
        )
        clusters.append(
            {
                "cluster_id": cluster_id,
                "priority_bucket": "p0" if int(row["priority_rank"]) == 0 else "p1" if int(row["priority_rank"]) == 1 else "p2",
                "attack_stage": attack_stage_key,
                "src_ip": src_ip_key or None,
                "asset_id": asset_id_key or None,
                "alert_count": int(row["alert_count"]),
                "high_severity_count": int(row["high_severity_count"]),
                "max_severity": _SEVERITY_LABEL_BY_RANK.get(max_severity_rank, "low"),
                "first_occurred_at": row["first_occurred_at"],
                "last_occurred_at": row["last_occurred_at"],
                "sample_alert_ids": [item["alert_id"] for item in samples],
                "sample_alerts": samples,
            }
        )
    return clusters


def count_alert_clusters(
    conn: sqlite3.Connection,
    *,
    statuses: list[str],
    min_severity: str | None = None,
    analysis_cutoff_at: str | None = None,
    queue_only: bool = False,
    cluster_min_count: int = 2,
) -> int:
    conditions, params = _build_alert_filters(
        statuses=statuses,
        min_severity=min_severity,
        analysis_cutoff_at=analysis_cutoff_at,
        queue_only=queue_only,
    )
    where_clause = _build_where_clause(conditions)
    row = conn.execute(
        f"""
        {_build_cluster_group_cte(where_clause)}
        select count(*)
        from grouped_clusters
        """,
        (*params, cluster_min_count),
    ).fetchone()
    if row is None:
        return 0
    return int(row[0])


def count_alerts_covered_by_clusters(
    conn: sqlite3.Connection,
    *,
    statuses: list[str],
    min_severity: str | None = None,
    analysis_cutoff_at: str | None = None,
    queue_only: bool = False,
    cluster_min_count: int = 2,
) -> int:
    conditions, params = _build_alert_filters(
        statuses=statuses,
        min_severity=min_severity,
        analysis_cutoff_at=analysis_cutoff_at,
        queue_only=queue_only,
    )
    where_clause = _build_where_clause(conditions)
    row = conn.execute(
        f"""
        {_build_cluster_group_cte(where_clause)}
        select coalesce(sum(alert_count), 0)
        from grouped_clusters
        """,
        (*params, cluster_min_count),
    ).fetchone()
    if row is None:
        return 0
    return int(row[0])


def summarize_alert_cluster_buckets(
    conn: sqlite3.Connection,
    *,
    statuses: list[str],
    min_severity: str | None = None,
    analysis_cutoff_at: str | None = None,
    cluster_min_count: int = 2,
) -> dict[str, dict[str, int]]:
    conditions, params = _build_alert_filters(
        statuses=statuses,
        min_severity=min_severity,
        analysis_cutoff_at=analysis_cutoff_at,
    )
    where_clause = _build_where_clause(conditions)
    p0_stage_placeholders = ", ".join("?" for _ in _P0_STAGES)
    row = conn.execute(
        f"""
        {_build_cluster_group_cte(where_clause)}
        select
          coalesce(sum(case when grouped_clusters.attack_stage_key in ({p0_stage_placeholders}) or grouped_clusters.max_severity_rank >= 4 then 1 else 0 end), 0) as p0_cluster_count,
          coalesce(sum(case when grouped_clusters.attack_stage_key in ({p0_stage_placeholders}) or grouped_clusters.max_severity_rank >= 4 then grouped_clusters.alert_count else 0 end), 0) as p0_alert_count,
          coalesce(sum(case when grouped_clusters.attack_stage_key not in ({p0_stage_placeholders}) and (grouped_clusters.attack_stage_key = 'persistence' or grouped_clusters.max_severity_rank >= 3) then 1 else 0 end), 0) as p1_cluster_count,
          coalesce(sum(case when grouped_clusters.attack_stage_key not in ({p0_stage_placeholders}) and (grouped_clusters.attack_stage_key = 'persistence' or grouped_clusters.max_severity_rank >= 3) then grouped_clusters.alert_count else 0 end), 0) as p1_alert_count,
          coalesce(sum(case when grouped_clusters.attack_stage_key not in ({p0_stage_placeholders}) and grouped_clusters.attack_stage_key <> 'persistence' and grouped_clusters.max_severity_rank < 3 then 1 else 0 end), 0) as p2_cluster_count,
          coalesce(sum(case when grouped_clusters.attack_stage_key not in ({p0_stage_placeholders}) and grouped_clusters.attack_stage_key <> 'persistence' and grouped_clusters.max_severity_rank < 3 then grouped_clusters.alert_count else 0 end), 0) as p2_alert_count
        from grouped_clusters
        """,
        (
            *params,
            cluster_min_count,
            *_P0_STAGES,
            *_P0_STAGES,
            *_P0_STAGES,
            *_P0_STAGES,
            *_P0_STAGES,
            *_P0_STAGES,
        ),
    ).fetchone()
    if row is None:
        return {
            "p0": {"cluster_count": 0, "alert_count": 0},
            "p1": {"cluster_count": 0, "alert_count": 0},
            "p2": {"cluster_count": 0, "alert_count": 0},
        }
    return {
        "p0": {"cluster_count": int(row["p0_cluster_count"]), "alert_count": int(row["p0_alert_count"])},
        "p1": {"cluster_count": int(row["p1_cluster_count"]), "alert_count": int(row["p1_alert_count"])},
        "p2": {"cluster_count": int(row["p2_cluster_count"]), "alert_count": int(row["p2_alert_count"])},
    }


def summarize_alert_hotspots(
    conn: sqlite3.Connection,
    *,
    statuses: list[str],
    min_severity: str | None = None,
    analysis_cutoff_at: str | None = None,
    top_n: int = 3,
) -> dict[str, object]:
    conditions, params = _build_alert_filters(
        statuses=statuses,
        min_severity=min_severity,
        analysis_cutoff_at=analysis_cutoff_at,
    )
    where_clause = _build_where_clause(conditions)
    top_attack_stages_rows = conn.execute(
        f"""
        select
          coalesce(lower(alerts.attack_stage), 'unknown') as attack_stage,
          count(*) as alert_count
        from alerts
        {where_clause}
        group by coalesce(lower(alerts.attack_stage), 'unknown')
        order by alert_count desc, attack_stage asc
        limit ?
        """,
        (*params, top_n),
    ).fetchall()
    top_assets_rows = conn.execute(
        f"""
        select
          coalesce(alerts.asset_id, 'unknown') as asset_id,
          count(*) as alert_count
        from alerts
        {where_clause}
        group by coalesce(alerts.asset_id, 'unknown')
        order by alert_count desc, asset_id asc
        limit ?
        """,
        (*params, top_n),
    ).fetchall()
    top_src_ips_rows = conn.execute(
        f"""
        select
          coalesce(alerts.src_ip, 'unknown') as src_ip,
          count(*) as alert_count
        from alerts
        {where_clause}
        group by coalesce(alerts.src_ip, 'unknown')
        order by alert_count desc, src_ip asc
        limit ?
        """,
        (*params, top_n),
    ).fetchall()
    high_severity_row = conn.execute(
        f"""
        select
          coalesce(sum(case when {_SEVERITY_RANK_SQL} >= 3 then 1 else 0 end), 0)
            as high_severity_alert_count
        from alerts
        {where_clause}
        """,
        tuple(params),
    ).fetchone()

    return {
        "top_attack_stages": [
            {"attack_stage": str(row["attack_stage"]), "alert_count": int(row["alert_count"])}
            for row in top_attack_stages_rows
        ],
        "top_assets": [
            {"asset_id": str(row["asset_id"]), "alert_count": int(row["alert_count"])}
            for row in top_assets_rows
        ],
        "top_src_ips": [
            {"src_ip": str(row["src_ip"]), "alert_count": int(row["alert_count"])}
            for row in top_src_ips_rows
        ],
        "high_severity_alert_count": int(high_severity_row["high_severity_alert_count"]) if high_severity_row else 0,
        "top_n": int(top_n),
    }


def get_alert_by_id(conn: sqlite3.Connection, alert_id: str, analysis_cutoff_at: str | None = None) -> dict | None:
    row = conn.execute(
        """
        select
          alerts.alert_id,
          (
            select case_alert_links.case_id
            from case_alert_links
            where case_alert_links.alert_id = alerts.alert_id
              and (
                (? is null and case_alert_links.is_active = 1)
                or (
                  ? is not null
                  and case_alert_links.linked_at <= ?
                  and (case_alert_links.unlinked_at is null or case_alert_links.unlinked_at > ?)
                )
              )
            order by case_alert_links.linked_at desc, case_alert_links.rowid desc
            limit 1
          ) as case_id,
          alerts.occurred_at,
          alerts.title,
          alerts.status,
          alerts.severity,
          alerts.attack_stage,
          alerts.src_ip,
          alerts.dst_ip,
          alerts.asset_id
        from alerts
        where alerts.alert_id = ?
          and (? is null or alerts.occurred_at <= ?)
        """,
        (
            analysis_cutoff_at,
            analysis_cutoff_at,
            analysis_cutoff_at,
            analysis_cutoff_at,
            alert_id,
            analysis_cutoff_at,
            analysis_cutoff_at,
        ),
    ).fetchone()
    return dict(row) if row else None


def get_case_evidence_summaries(
    conn: sqlite3.Connection,
    case_id: str | None,
    analysis_cutoff_at: str | None = None,
) -> list[dict]:
    if not case_id:
        return []
    rows = conn.execute(
        """
        select evidence_id, summary
        from evidence
        where case_id = ?
          and (? is null or occurred_at <= ?)
        order by evidence_id asc
        """,
        (case_id, analysis_cutoff_at, analysis_cutoff_at),
    ).fetchall()
    return [dict(row) for row in rows]


def get_alert_evidence_summaries(
    conn: sqlite3.Connection,
    *,
    case_id: str | None,
    alert_id: str,
    analysis_cutoff_at: str | None = None,
) -> list[dict]:
    if not case_id:
        return []
    rows = conn.execute(
        """
        select distinct evidence.evidence_id, evidence.summary
        from timeline_events
        join json_each(timeline_events.related_alert_ids) as related_alert_ids
        join json_each(timeline_events.related_evidence_ids) as related_evidence_ids
        join evidence on evidence.evidence_id = related_evidence_ids.value
        where timeline_events.case_id = ?
          and related_alert_ids.value = ?
          and evidence.case_id = ?
          and (? is null or timeline_events.occurred_at <= ?)
          and (? is null or evidence.occurred_at <= ?)
        order by evidence.evidence_id asc
        """,
        (
            case_id,
            alert_id,
            case_id,
            analysis_cutoff_at,
            analysis_cutoff_at,
            analysis_cutoff_at,
            analysis_cutoff_at,
        ),
    ).fetchall()
    return [dict(row) for row in rows]


def ack_alerts(conn: sqlite3.Connection, alert_ids: list[str], status: str) -> dict:
    deduped_alert_ids = list(dict.fromkeys(alert_ids))
    placeholders = ", ".join("?" for _ in deduped_alert_ids)
    rows = conn.execute(
        f"""
        select alert_id, status
        from alerts
        where alert_id in ({placeholders})
        """,
        tuple(deduped_alert_ids),
    ).fetchall()

    current_status_by_alert_id = {row["alert_id"]: row["status"] for row in rows}
    existing_alert_ids = set(current_status_by_alert_id)
    missing_alert_ids = [alert_id for alert_id in deduped_alert_ids if alert_id not in existing_alert_ids]
    updated_alert_ids = [
        alert_id
        for alert_id in deduped_alert_ids
        if current_status_by_alert_id.get(alert_id) is not None and current_status_by_alert_id[alert_id] != status
    ]
    already_status_alert_ids = [
        alert_id
        for alert_id in deduped_alert_ids
        if current_status_by_alert_id.get(alert_id) is not None and current_status_by_alert_id[alert_id] == status
    ]

    if updated_alert_ids:
        update_placeholders = ", ".join("?" for _ in updated_alert_ids)
        conn.execute(
            f"""
            update alerts
            set status = ?
            where alert_id in ({update_placeholders})
            """,
            (status, *updated_alert_ids),
        )

    return {
        "target_status": status,
        "requested_count": len(deduped_alert_ids),
        "updated_count": len(updated_alert_ids),
        "already_status_count": len(already_status_alert_ids),
        "missing_count": len(missing_alert_ids),
        "updated_alert_ids": updated_alert_ids,
        "already_status_alert_ids": already_status_alert_ids,
        "missing_alert_ids": missing_alert_ids,
    }
