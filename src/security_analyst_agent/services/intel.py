import sqlite3


def lookup_cached_indicator(conn: sqlite3.Connection, indicator: str, indicator_type: str) -> dict | None:
    row = conn.execute(
        """
        select indicator, indicator_type, verdict, confidence, queried_at
        from intel_cache
        where indicator = ? and indicator_type = ?
        """,
        (indicator, indicator_type),
    ).fetchone()
    return dict(row) if row else None

