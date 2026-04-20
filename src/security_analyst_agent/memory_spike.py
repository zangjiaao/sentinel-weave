from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any

from security_analyst_agent.config import DEFAULT_MEMORY_SPIKE_DB_PATH, SPIKE_MEMORY_DIR
from security_analyst_agent.db import connect_db, create_schema


RESET_TABLES = (
    "verify_spike_round_runs",
    "spike_round_runs",
    "entity_assessments",
    "case_assessments",
    "link_decisions",
    "link_decisions_archive",
    "escalation_decisions",
    "case_changes",
    "case_changes_archive",
    "alert_decisions",
    "alert_decisions_archive",
    "agent_tool_calls",
    "agent_tool_calls_archive",
    "patrol_state",
    "case_digests",
    "notification_outbox",
    "case_merge_events",
    "case_relations",
    "case_alert_links",
    "patrol_runs",
    "alert_ingest_events",
    "intel_cache",
    "evidence",
    "timeline_events",
    "alerts",
    "cases",
    "assets",
)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _reset_tables(conn: sqlite3.Connection) -> None:
    for table_name in RESET_TABLES:
        conn.execute(f"delete from {table_name}")


def _insert_many(conn: sqlite3.Connection, table_name: str, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    columns = list(rows[0].keys())
    placeholders = ", ".join("?" for _ in columns)
    sql = f"insert into {table_name} ({', '.join(columns)}) values ({placeholders})"
    values = [tuple(row[column] for column in columns) for row in rows]
    conn.executemany(sql, values)


def _upsert_many(
    conn: sqlite3.Connection,
    table_name: str,
    rows: list[dict[str, Any]],
    key_columns: list[str],
) -> None:
    if not rows:
        return
    columns = list(rows[0].keys())
    placeholders = ", ".join("?" for _ in columns)
    update_columns = [column for column in columns if column not in key_columns]
    update_clause = ", ".join(f"{column}=excluded.{column}" for column in update_columns)
    sql = (
        f"insert into {table_name} ({', '.join(columns)}) values ({placeholders}) "
        f"on conflict({', '.join(key_columns)}) do update set {update_clause}"
    )
    values = [tuple(row[column] for column in columns) for row in rows]
    conn.executemany(sql, values)


def _prepare_timeline_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    prepared: list[dict[str, Any]] = []
    for row in rows:
        prepared_row = dict(row)
        prepared_row["related_alert_ids"] = json.dumps(row["related_alert_ids"], ensure_ascii=False)
        prepared_row["related_evidence_ids"] = json.dumps(row["related_evidence_ids"], ensure_ascii=False)
        prepared.append(prepared_row)
    return prepared


def _prepare_evidence_rows(
    evidence_rows: list[dict[str, Any]], timeline_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    evidence_occurred_at: dict[str, str] = {}
    for event in timeline_rows:
        for evidence_id in event["related_evidence_ids"]:
            occurred_at = event["occurred_at"]
            if evidence_id not in evidence_occurred_at or occurred_at < evidence_occurred_at[evidence_id]:
                evidence_occurred_at[evidence_id] = occurred_at

    prepared_rows: list[dict[str, Any]] = []
    for row in evidence_rows:
        prepared = dict(row)
        prepared["occurred_at"] = prepared.get("occurred_at") or evidence_occurred_at.get(
            prepared["evidence_id"], datetime.now(timezone.utc).isoformat()
        )
        prepared_rows.append(prepared)
    return prepared_rows


def _split_alert_rows_and_links(
    rows: list[dict[str, Any]], *, seed_case_links: bool = True
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    alert_rows: list[dict[str, Any]] = []
    link_rows: list[dict[str, Any]] = []
    for row in rows:
        alert_row = dict(row)
        case_id = alert_row.pop("case_id", None)
        alert_rows.append(alert_row)
        if seed_case_links and case_id:
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


def load_memory_spike_rounds(fixture_dir: Path = SPIKE_MEMORY_DIR) -> list[dict[str, Any]]:
    rounds = _read_json(fixture_dir / "rounds.json")
    assert isinstance(rounds, list)
    return rounds


def bootstrap_memory_spike_database(db_path: Path, fixture_dir: Path = SPIKE_MEMORY_DIR) -> None:
    conn = connect_db(db_path)
    create_schema(conn)
    bundle = _read_json(fixture_dir / "base_bundle.json")
    alert_rows, link_rows = _split_alert_rows_and_links(bundle["alerts"], seed_case_links=False)
    _reset_tables(conn)
    _insert_many(conn, "assets", bundle["assets"])
    _insert_many(conn, "cases", bundle["cases"])
    _insert_many(conn, "alerts", alert_rows)
    _insert_many(conn, "case_alert_links", link_rows)
    _insert_many(conn, "intel_cache", bundle["intel_cache"])
    conn.commit()
    conn.close()


def _load_round_map(fixture_dir: Path) -> dict[str, dict[str, Any]]:
    return {item["round_id"]: item for item in load_memory_spike_rounds(fixture_dir)}


def _round_is_applied(conn: sqlite3.Connection, round_id: str) -> bool:
    row = conn.execute("select 1 from verify_spike_round_runs where round_id = ?", (round_id,)).fetchone()
    return row is not None


def apply_memory_spike_round(
    db_path: Path,
    round_id: str,
    fixture_dir: Path = SPIKE_MEMORY_DIR,
) -> dict[str, Any]:
    round_map = _load_round_map(fixture_dir)
    if round_id not in round_map:
        raise ValueError(f"unknown round_id: {round_id}")

    conn = connect_db(db_path)
    create_schema(conn)
    batch = round_map[round_id]

    if _round_is_applied(conn, round_id):
        conn.close()
        return {"round_id": round_id, "applied": False, "reason": "already_applied"}

    previous_round_id = batch["previous_round_id"]
    if previous_round_id and not _round_is_applied(conn, previous_round_id):
        conn.close()
        raise ValueError("previous round must be applied first")

    alert_rows, link_rows = _split_alert_rows_and_links(batch["alerts"], seed_case_links=False)
    _insert_many(conn, "alerts", alert_rows)
    _insert_many(conn, "case_alert_links", link_rows)
    _upsert_many(conn, "intel_cache", batch["intel_cache_upsert"], ["indicator", "indicator_type"])
    conn.execute(
        "insert into verify_spike_round_runs (round_id, applied_at) values (?, ?)",
        (round_id, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()

    return {
        "round_id": round_id,
        "applied": True,
        "inserted_alerts": len(batch["alerts"]),
        "upserted_cases": 0,
        "inserted_timeline_events": 0,
        "inserted_evidence": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Memory spike bootstrap/apply-round helper")
    subparsers = parser.add_subparsers(dest="command", required=True)

    bootstrap_parser = subparsers.add_parser("bootstrap")
    bootstrap_parser.add_argument("--db-path", type=Path, default=DEFAULT_MEMORY_SPIKE_DB_PATH)
    bootstrap_parser.add_argument("--fixture-dir", type=Path, default=SPIKE_MEMORY_DIR)

    apply_parser = subparsers.add_parser("apply-round")
    apply_parser.add_argument("--db-path", type=Path, default=DEFAULT_MEMORY_SPIKE_DB_PATH)
    apply_parser.add_argument("--fixture-dir", type=Path, default=SPIKE_MEMORY_DIR)
    apply_parser.add_argument("--round-id", required=True)

    args = parser.parse_args()
    if args.command == "bootstrap":
        bootstrap_memory_spike_database(args.db_path, fixture_dir=args.fixture_dir)
        print(f"bootstrapped memory spike: {args.db_path}")
        return

    body = apply_memory_spike_round(args.db_path, args.round_id, fixture_dir=args.fixture_dir)
    print(json.dumps(body, ensure_ascii=False))


if __name__ == "__main__":
    main()
