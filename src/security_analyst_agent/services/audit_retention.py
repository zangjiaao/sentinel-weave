from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import sqlite3
from typing import Any


@dataclass(frozen=True)
class AuditTableRetention:
    table: str
    archive_table: str
    key_column: str
    default_retention_days: int


RETENTION_TABLES: tuple[AuditTableRetention, ...] = (
    AuditTableRetention(
        table="agent_outputs",
        archive_table="agent_outputs_archive",
        key_column="output_id",
        default_retention_days=30,
    ),
    AuditTableRetention(
        table="agent_tool_calls",
        archive_table="agent_tool_calls_archive",
        key_column="call_id",
        default_retention_days=30,
    ),
    AuditTableRetention(
        table="case_changes",
        archive_table="case_changes_archive",
        key_column="change_id",
        default_retention_days=90,
    ),
    AuditTableRetention(
        table="link_decisions",
        archive_table="link_decisions_archive",
        key_column="decision_id",
        default_retention_days=90,
    ),
    AuditTableRetention(
        table="alert_decisions",
        archive_table="alert_decisions_archive",
        key_column="decision_id",
        default_retention_days=90,
    ),
)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _resolve_now(now_iso: str | None) -> datetime:
    if not now_iso:
        return _now_utc()
    parsed = datetime.fromisoformat(now_iso)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _load_table_columns(conn: sqlite3.Connection, table_name: str) -> list[str]:
    rows = conn.execute(f"pragma table_info({table_name})").fetchall()
    return [row["name"] for row in rows]


def compact_audit_logs(
    conn: sqlite3.Connection,
    *,
    retention_days: dict[str, int] | None = None,
    dry_run: bool = False,
    vacuum: bool = False,
    now_iso: str | None = None,
) -> dict[str, Any]:
    retention_days = retention_days or {}
    now_dt = _resolve_now(now_iso)
    archived_at = now_dt.isoformat()
    table_summaries: list[dict[str, Any]] = []

    for spec in RETENTION_TABLES:
        days = int(retention_days.get(spec.table, spec.default_retention_days))
        if days < 0:
            days = 0
        cutoff = (now_dt - timedelta(days=days)).isoformat()
        eligible_count = int(
            conn.execute(
                f"select count(*) from {spec.table} where occurred_at < ?",
                (cutoff,),
            ).fetchone()[0]
        )
        archived_count = 0
        deleted_count = 0
        if not dry_run and eligible_count > 0:
            columns = _load_table_columns(conn, spec.table)
            archive_columns = [column for column in columns if column != "archived_at"]
            column_list = ", ".join(archive_columns)
            select_columns = ", ".join(f"src.{column}" for column in archive_columns)
            conn.execute(
                f"""
                insert or ignore into {spec.archive_table} ({column_list}, archived_at)
                select {select_columns}, ?
                from {spec.table} as src
                where src.occurred_at < ?
                """,
                (archived_at, cutoff),
            )
            archived_count = eligible_count
            conn.execute(
                f"delete from {spec.table} where occurred_at < ?",
                (cutoff,),
            )
            deleted_count = eligible_count

        table_summaries.append(
            {
                "table": spec.table,
                "archive_table": spec.archive_table,
                "retention_days": days,
                "cutoff": cutoff,
                "eligible_rows": eligible_count,
                "archived_rows": archived_count,
                "deleted_rows": deleted_count,
            }
        )

    if not dry_run:
        conn.commit()
        if vacuum:
            conn.execute("vacuum")

    return {
        "dry_run": dry_run,
        "vacuum": vacuum,
        "now": archived_at,
        "tables": table_summaries,
    }
