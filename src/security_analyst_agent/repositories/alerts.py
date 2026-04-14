import sqlite3


def fetch_alerts(
    conn: sqlite3.Connection, limit: int, statuses: list[str], min_severity: str | None = None
) -> list[dict]:
    conditions: list[str] = []
    params: list[object] = []

    if statuses:
        placeholders = ", ".join("?" for _ in statuses)
        conditions.append(f"alerts.status in ({placeholders})")
        params.extend(statuses)

    if min_severity:
        rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        min_rank = rank.get(min_severity.lower(), 1)
        conditions.append(
            "case alerts.severity when 'low' then 1 when 'medium' then 2 when 'high' then 3 when 'critical' then 4 else 0 end >= ?"
        )
        params.append(min_rank)

    where_clause = f"where {' and '.join(conditions)}" if conditions else ""
    params.append(limit)
    rows = conn.execute(
        f"""
        select
          alerts.alert_id,
          case_alert_links.case_id as case_id,
          alerts.occurred_at,
          alerts.title,
          alerts.status,
          alerts.severity,
          alerts.attack_stage,
          alerts.src_ip,
          alerts.dst_ip,
          alerts.asset_id
        from alerts
        left join case_alert_links
          on case_alert_links.alert_id = alerts.alert_id
         and case_alert_links.is_active = 1
        {where_clause}
        order by alerts.occurred_at desc
        limit ?
        """,
        tuple(params),
    ).fetchall()
    return [dict(row) for row in rows]


def get_alert_by_id(conn: sqlite3.Connection, alert_id: str) -> dict | None:
    row = conn.execute(
        """
        select
          alerts.alert_id,
          case_alert_links.case_id as case_id,
          alerts.occurred_at,
          alerts.title,
          alerts.status,
          alerts.severity,
          alerts.attack_stage,
          alerts.src_ip,
          alerts.dst_ip,
          alerts.asset_id
        from alerts
        left join case_alert_links
          on case_alert_links.alert_id = alerts.alert_id
         and case_alert_links.is_active = 1
        where alerts.alert_id = ?
        """,
        (alert_id,),
    ).fetchone()
    return dict(row) if row else None


def get_case_evidence_summaries(conn: sqlite3.Connection, case_id: str | None) -> list[dict]:
    if not case_id:
        return []
    rows = conn.execute(
        """
        select evidence_id, summary
        from evidence
        where case_id = ?
        order by evidence_id asc
        """,
        (case_id,),
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
