from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import subprocess
from typing import Callable
from uuid import uuid4

from security_analyst_agent.config import DEFAULT_HERMES_CRON_JOB_ID
from security_analyst_agent.db import connect_db, create_schema
from security_analyst_agent.repositories.context_memory import set_patrol_state

CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_pending_event_ids(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        """
        select event_id
        from alert_ingest_events
        where trigger_state in ('pending', 'failed')
        order by ingested_at asc
        """
    ).fetchall()
    return [row["event_id"] for row in rows]


def _create_patrol_run(conn: sqlite3.Connection, trigger_source: str, summary: str) -> str:
    run_id = f"run_{uuid4().hex[:12]}"
    started_at = _now_iso()
    conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at)
        values (?, ?, ?, ?, ?, ?)
        """,
        (run_id, trigger_source, "running", summary, started_at, started_at),
    )
    return run_id


def trigger_patrol_from_ingest(
    db_path: Path,
    job_id: str = DEFAULT_HERMES_CRON_JOB_ID,
    command_runner: CommandRunner | None = None,
    dry_run: bool = False,
) -> dict[str, object]:
    conn = connect_db(db_path)
    create_schema(conn)
    runner = command_runner or _default_runner
    event_ids = _load_pending_event_ids(conn)
    if not event_ids:
        conn.close()
        return {
            "triggered": False,
            "processed_events": 0,
            "status": "noop",
            "run_id": None,
            "job_id": job_id,
        }

    summary = f"triggered by {len(event_ids)} ingest events"
    run_id = _create_patrol_run(conn, trigger_source="ingest_event", summary=summary)
    conn.execute(
        f"update alert_ingest_events set trigger_state = 'processing' where event_id in ({', '.join('?' for _ in event_ids)})",
        tuple(event_ids),
    )
    conn.commit()

    status = "failed"
    detail = "unknown_failure"
    finished_at = _now_iso()
    try:
        if dry_run:
            status = "dry_run_success"
            detail = "dry run completed without hermes commands"
        else:
            run_result = runner(["hermes", "cron", "run", job_id])
            tick_result = runner(["hermes", "cron", "tick"])
            if run_result.returncode == 0 and tick_result.returncode == 0:
                status = "success"
                detail = "hermes cron run/tick completed"
            else:
                detail = (
                    f"run_rc={run_result.returncode}, tick_rc={tick_result.returncode}, "
                    f"run_err={run_result.stderr.strip()}, tick_err={tick_result.stderr.strip()}"
                )
    except Exception as exc:
        detail = f"exception: {exc}"

    final_event_state = "processed" if status in {"success", "dry_run_success"} else "failed"
    conn.execute(
        f"""
        update alert_ingest_events
        set trigger_state = ?, processed_at = ?
        where event_id in ({', '.join('?' for _ in event_ids)})
        """,
        (final_event_state, finished_at, *event_ids),
    )
    conn.execute(
        """
        update patrol_runs
        set status = ?, summary = ?, finished_at = ?
        where run_id = ?
        """,
        (status, detail, finished_at, run_id),
    )
    set_patrol_state(conn, "last_patrol_run_id", run_id)
    set_patrol_state(conn, "last_patrol_status", status)
    set_patrol_state(conn, "last_patrol_finished_at", finished_at)
    set_patrol_state(conn, "last_patrol_processed_events", len(event_ids))
    set_patrol_state(conn, "last_patrol_job_id", job_id)
    conn.commit()
    conn.close()

    return {
        "triggered": True,
        "processed_events": len(event_ids),
        "status": status,
        "run_id": run_id,
        "job_id": job_id,
    }
