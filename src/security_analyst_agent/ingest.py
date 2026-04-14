from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from typing import Any
from uuid import uuid4

from security_analyst_agent.db import connect_db, create_schema


def _upsert_alerts(conn: sqlite3.Connection, alerts: list[dict[str, Any]]) -> int:
    if not alerts:
        return 0
    columns = [
        "alert_id",
        "occurred_at",
        "title",
        "status",
        "severity",
        "attack_stage",
        "src_ip",
        "dst_ip",
        "asset_id",
    ]
    placeholders = ", ".join("?" for _ in columns)
    update_columns = [column for column in columns if column != "alert_id"]
    update_clause = ", ".join(f"{column}=excluded.{column}" for column in update_columns)
    values = [tuple(alert.get(column) for column in columns) for alert in alerts]
    conn.executemany(
        f"""
        insert into alerts ({', '.join(columns)})
        values ({placeholders})
        on conflict(alert_id) do update set {update_clause}
        """,
        values,
    )
    return len(values)


def _insert_ingest_events(conn: sqlite3.Connection, alerts: list[dict[str, Any]], source: str, ingested_at: str) -> int:
    if not alerts:
        return 0
    rows = [
        (
            f"evt_{uuid4().hex[:12]}",
            alert["alert_id"],
            source,
            ingested_at,
            "pending",
        )
        for alert in alerts
    ]
    conn.executemany(
        """
        insert into alert_ingest_events (event_id, alert_id, source, ingested_at, trigger_state)
        values (?, ?, ?, ?, ?)
        """,
        rows,
    )
    return len(rows)


def ingest_alert_bundle(
    db_path: Path,
    alerts: list[dict[str, Any]],
    source: str = "manual_import",
) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    ingested_at = datetime.now(timezone.utc).isoformat()
    try:
        inserted_alerts = _upsert_alerts(conn, alerts)
        pending_events = _insert_ingest_events(conn, alerts, source=source, ingested_at=ingested_at)
        conn.commit()
    finally:
        conn.close()

    return {
        "inserted_alerts": inserted_alerts,
        "pending_events": pending_events,
        "source": source,
        "ingested_at": ingested_at,
    }
