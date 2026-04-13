import sqlite3


def search_assets(
    conn: sqlite3.Connection,
    query: str | None,
    indicators: list[str],
    include_inactive: bool,
    limit: int,
) -> list[dict]:
    conditions: list[str] = []
    params: list[object] = []

    if not include_inactive:
        conditions.append("internet_exposed = 1")

    indicator_terms = [item.strip() for item in indicators if item.strip()]
    if indicator_terms:
        placeholders = ", ".join("?" for _ in indicator_terms)
        conditions.append(f"(public_ip in ({placeholders}) or domain in ({placeholders}))")
        params.extend(indicator_terms)
        params.extend(indicator_terms)

    if query:
        conditions.append("(asset_name like ? or system_name like ?)")
        params.extend([f"%{query}%", f"%{query}%"])

    where_clause = f"where {' and '.join(conditions)}" if conditions else ""
    params.append(limit)
    rows = conn.execute(
        f"""
        select asset_id, asset_name, system_name, owner_team, internet_exposed, public_ip, domain
        from assets
        {where_clause}
        order by asset_id asc
        limit ?
        """,
        tuple(params),
    ).fetchall()
    return [dict(row) for row in rows]

