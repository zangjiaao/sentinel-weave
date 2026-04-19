import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

from security_analyst_agent.config import DEFAULT_DB_PATH, FIXTURE_DIR
from security_analyst_agent.db import connect_db, create_schema
from security_analyst_agent.tools.case_tools import case_link_alert, case_update_risk, case_upsert
from security_analyst_agent.tools.derived_tools import evidence_upsert, timeline_upsert


def _read_fixture(fixture_dir: Path, filename: str) -> list[dict]:
    return json.loads((fixture_dir / filename).read_text(encoding="utf-8"))


def _reset_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        delete from entity_assessments;
        delete from case_assessments;
        delete from link_decisions;
        delete from link_decisions_archive;
        delete from escalation_decisions;
        delete from case_changes;
        delete from case_changes_archive;
        delete from alert_decisions;
        delete from alert_decisions_archive;
        delete from agent_outputs;
        delete from agent_outputs_archive;
        delete from agent_tool_calls;
        delete from agent_tool_calls_archive;
        delete from patrol_state;
        delete from case_digests;
        delete from notification_outbox;
        delete from case_merge_events;
        delete from case_relations;
        delete from case_alert_links;
        delete from patrol_runs;
        delete from patrol_run_costs;
        delete from alert_ingest_events;
        delete from verify_spike_round_runs;
        delete from spike_round_runs;
        delete from intel_cache;
        delete from evidence;
        delete from timeline_events;
        delete from alerts;
        delete from cases;
        delete from assets;
        """
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _insert_many(conn: sqlite3.Connection, table_name: str, rows: list[dict]) -> None:
    if not rows:
        return
    columns = list(rows[0].keys())
    placeholders = ", ".join("?" for _ in columns)
    sql = f"insert into {table_name} ({', '.join(columns)}) values ({placeholders})"
    values = [tuple(row[column] for column in columns) for row in rows]
    conn.executemany(sql, values)


def _split_alert_rows_and_links(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    alert_rows: list[dict] = []
    link_rows: list[dict] = []
    for row in rows:
        alert_row = dict(row)
        case_id = alert_row.pop("case_id", None)
        alert_rows.append(alert_row)
        if case_id:
            link_rows.append(
                {
                    "case_id": case_id,
                    "alert_id": alert_row["alert_id"],
                    "linked_at": alert_row["occurred_at"],
                    "confidence": 1.0,
                    "reason": "fixture_seed",
                    "is_active": 1,
                    "unlinked_at": None,
                }
            )
    return alert_rows, link_rows


def _prepare_evidence_rows(evidence_rows: list[dict], timeline_rows: list[dict]) -> list[dict]:
    evidence_occurred_at: dict[str, str] = {}
    for event in timeline_rows:
        for evidence_id in event["related_evidence_ids"]:
            occurred_at = event["occurred_at"]
            if evidence_id not in evidence_occurred_at or occurred_at < evidence_occurred_at[evidence_id]:
                evidence_occurred_at[evidence_id] = occurred_at

    prepared_rows: list[dict] = []
    for row in evidence_rows:
        prepared = dict(row)
        prepared["occurred_at"] = prepared.get("occurred_at") or evidence_occurred_at.get(
            prepared["evidence_id"], _now_iso()
        )
        prepared_rows.append(prepared)
    return prepared_rows


def bootstrap_spike_database(db_path: Path, fixture_dir: Path = FIXTURE_DIR) -> None:
    conn = connect_db(db_path)
    create_schema(conn)

    _reset_tables(conn)
    alert_rows, _ = _split_alert_rows_and_links(_read_fixture(fixture_dir, "alerts.json"))
    _insert_many(conn, "assets", _read_fixture(fixture_dir, "assets.json"))
    _insert_many(conn, "alerts", alert_rows)
    _insert_many(conn, "intel_cache", _read_fixture(fixture_dir, "intel_cache.json"))
    conn.commit()
    conn.close()


def materialize_spike_runtime_demo(db_path: Path) -> None:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        case_upsert(
            conn,
            {
                "case_id": "case_demo_001",
                "title": "多阶段 Web 入侵与后续横向准备",
                "status": "open",
                "overall_severity": "high",
                "current_stage": "recon",
                "primary_actor_id": "actor_demo_001",
            },
        )
        case_link_alert(
            conn,
            {
                "case_id": "case_demo_001",
                "alert_id": "alt_day1_scan_01",
                "confidence": 0.82,
                "reason": "same-source reconnaissance on exposed API target",
            },
        )
        case_link_alert(
            conn,
            {
                "case_id": "case_demo_001",
                "alert_id": "alt_day2_webshell_01",
                "confidence": 0.92,
                "reason": "exploit activity continues from the same target path",
            },
        )
        case_link_alert(
            conn,
            {
                "case_id": "case_demo_001",
                "alert_id": "alt_day3_shell_01",
                "confidence": 0.91,
                "reason": "new IP continues controlling the same compromised host",
            },
        )
        evidence_upsert(
            conn,
            {
                "evidence_id": "evi_webshell_01",
                "case_id": "case_demo_001",
                "occurred_at": "2026-04-11T14:23:00+08:00",
                "evidence_type": "webshell",
                "summary": "漏洞利用后在统一认证 API 主机写入 webshell",
            },
        )
        evidence_upsert(
            conn,
            {
                "evidence_id": "evi_shell_conn_01",
                "case_id": "case_demo_001",
                "occurred_at": "2026-04-12T11:03:00+08:00",
                "evidence_type": "shell_connection",
                "summary": "攻击者使用新源 IP 继续连接已落地 webshell",
            },
        )
        timeline_upsert(
            conn,
            {
                "timeline_event_id": "tl_link_alt_day2_webshell_01",
                "case_id": "case_demo_001",
                "occurred_at": "2026-04-11T14:20:00+08:00",
                "stage": "persistence",
                "title": "漏洞利用后写入 webshell",
                "related_alert_ids": ["alt_day2_webshell_01"],
                "related_evidence_ids": ["evi_webshell_01"],
            },
        )
        timeline_upsert(
            conn,
            {
                "timeline_event_id": "tl_link_alt_day3_shell_01",
                "case_id": "case_demo_001",
                "occurred_at": "2026-04-12T11:03:00+08:00",
                "stage": "command_execution",
                "title": "新 IP 连接 webshell",
                "related_alert_ids": ["alt_day3_shell_01"],
                "related_evidence_ids": ["evi_shell_conn_01", "evi_webshell_01"],
            },
        )
        case_update_risk(
            conn,
            {
                "case_id": "case_demo_001",
                "overall_severity": "high",
                "current_stage": "lateral_prep",
                "status": "open",
            },
        )
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap spike SQLite database")
    parser.add_argument("--db-path", type=Path, default=DEFAULT_DB_PATH)
    args = parser.parse_args()
    bootstrap_spike_database(args.db_path)
    print(f"bootstrapped: {args.db_path}")


if __name__ == "__main__":
    main()
