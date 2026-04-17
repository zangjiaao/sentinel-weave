from __future__ import annotations

from datetime import datetime, timezone
import inspect
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
from typing import Callable, cast
from uuid import uuid4

from security_analyst_agent.config import (
    DEFAULT_HERMES_CRON_JOB_ID,
    DEFAULT_HERMES_HOME,
    DEFAULT_HERMES_PATROL_HOME,
    PROJECT_ROOT,
)
from security_analyst_agent.db import connect_db, create_schema

CommandRunner = Callable[[list[str], dict[str, str] | None], subprocess.CompletedProcess[str]]
LegacyCommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]

RUNTIME_FILES_TO_COPY = ("config.yaml", ".env", "auth.json")


def _default_runner(command: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False, env=env)


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


def _ensure_patrol_hermes_home(patrol_home: Path, source_home: Path) -> None:
    patrol_home.mkdir(parents=True, exist_ok=True)
    for filename in RUNTIME_FILES_TO_COPY:
        source_path = source_home / filename
        if source_path.exists():
            shutil.copy2(source_path, patrol_home / filename)

    soul_template = PROJECT_ROOT / "hermes" / "SOUL.patrol.template.md"
    if not soul_template.exists():
        soul_template = PROJECT_ROOT / "hermes" / "SOUL.template.md"
    shutil.copy2(soul_template, patrol_home / "SOUL.md")

    source_skill_dir = PROJECT_ROOT / "skills" / "secagent-patrol"
    target_skill_dir = patrol_home / "skills" / "secagent-patrol"
    target_skill_dir.parent.mkdir(parents=True, exist_ok=True)
    if target_skill_dir.exists():
        shutil.rmtree(target_skill_dir)
    shutil.copytree(source_skill_dir, target_skill_dir)


def _build_hermes_env(patrol_home: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["HERMES_HOME"] = str(patrol_home)
    return env


def _run_with_compat_runner(
    runner: CommandRunner | LegacyCommandRunner,
    command: list[str],
    env: dict[str, str] | None,
) -> subprocess.CompletedProcess[str]:
    try:
        signature = inspect.signature(runner)
    except (TypeError, ValueError):
        signature = None
    if signature and len(signature.parameters) >= 2:
        return cast(CommandRunner, runner)(command, env)
    return cast(LegacyCommandRunner, runner)(command)


def trigger_patrol_from_ingest(
    db_path: Path,
    job_id: str = DEFAULT_HERMES_CRON_JOB_ID,
    command_runner: CommandRunner | LegacyCommandRunner | None = None,
    dry_run: bool = False,
    hermes_home: Path | None = None,
    source_hermes_home: Path | None = None,
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
            patrol_runtime_home = hermes_home or DEFAULT_HERMES_PATROL_HOME
            source_runtime_home = source_hermes_home or DEFAULT_HERMES_HOME
            _ensure_patrol_hermes_home(patrol_runtime_home, source_runtime_home)
            env = _build_hermes_env(patrol_runtime_home)

            run_result = _run_with_compat_runner(runner, ["hermes", "cron", "run", job_id], env)
            tick_result = _run_with_compat_runner(runner, ["hermes", "cron", "tick"], env)
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
    conn.commit()
    conn.close()

    return {
        "triggered": True,
        "processed_events": len(event_ids),
        "status": status,
        "run_id": run_id,
        "job_id": job_id,
    }
