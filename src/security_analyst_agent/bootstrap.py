import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

from security_analyst_agent.config import DEFAULT_DB_PATH, FIXTURE_DIR
from security_analyst_agent.db import connect_db, create_schema


def _read_fixture(fixture_dir: Path, filename: str) -> list[dict]:
    return json.loads((fixture_dir / filename).read_text(encoding="utf-8"))


def _reset_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        delete from entity_assessments;
        delete from case_assessments;
        delete from link_decisions;
        delete from escalation_decisions;
        delete from case_changes;
        delete from alert_decisions;
        delete from agent_tool_calls;
        delete from patrol_state;
        delete from case_digests;
        delete from notification_outbox;
        delete from case_alert_links;
        delete from patrol_runs;
        delete from alert_ingest_events;
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

    timeline_rows = _read_fixture(fixture_dir, "timeline.json")
    for row in timeline_rows:
        row["related_alert_ids"] = json.dumps(row["related_alert_ids"], ensure_ascii=False)
        row["related_evidence_ids"] = json.dumps(row["related_evidence_ids"], ensure_ascii=False)

    _reset_tables(conn)
    alert_rows, link_rows = _split_alert_rows_and_links(_read_fixture(fixture_dir, "alerts.json"))
    _insert_many(conn, "assets", _read_fixture(fixture_dir, "assets.json"))
    _insert_many(conn, "cases", _read_fixture(fixture_dir, "cases.json"))
    _insert_many(conn, "alerts", alert_rows)
    _insert_many(conn, "case_alert_links", link_rows)
    _insert_many(conn, "timeline_events", timeline_rows)
    _insert_many(
        conn,
        "evidence",
        _prepare_evidence_rows(_read_fixture(fixture_dir, "evidence.json"), timeline_rows),
    )
    _insert_many(conn, "intel_cache", _read_fixture(fixture_dir, "intel_cache.json"))
    conn.commit()
    conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap spike SQLite database")
    parser.add_argument("--db-path", type=Path, default=DEFAULT_DB_PATH)
    args = parser.parse_args()
    bootstrap_spike_database(args.db_path)
    print(f"bootstrapped: {args.db_path}")


if __name__ == "__main__":
    main()
