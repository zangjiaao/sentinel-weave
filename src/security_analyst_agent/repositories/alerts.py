import sqlite3


def fetch_alerts(
    conn: sqlite3.Connection, limit: int, statuses: list[str], min_severity: str | None = None
) -> list[dict]:
    conditions: list[str] = []
    params: list[object] = []

    if statuses:
        placeholders = ", ".join("?" for _ in statuses)
        conditions.append(f"status in ({placeholders})")
        params.extend(statuses)

    if min_severity:
        rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        min_rank = rank.get(min_severity.lower(), 1)
        conditions.append(
            "case severity when 'low' then 1 when 'medium' then 2 when 'high' then 3 when 'critical' then 4 else 0 end >= ?"
        )
        params.append(min_rank)

    where_clause = f"where {' and '.join(conditions)}" if conditions else ""
    params.append(limit)
    rows = conn.execute(
        f"""
        select alert_id, case_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id
        from alerts
        {where_clause}
        order by occurred_at desc
        limit ?
        """,
        tuple(params),
    ).fetchall()
    return [dict(row) for row in rows]


def get_alert_by_id(conn: sqlite3.Connection, alert_id: str) -> dict | None:
    row = conn.execute(
        """
        select alert_id, case_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id
        from alerts
        where alert_id = ?
        """,
        (alert_id,),
    ).fetchone()
    return dict(row) if row else None


def get_case_evidence_summaries(conn: sqlite3.Connection, case_id: str) -> list[dict]:
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

