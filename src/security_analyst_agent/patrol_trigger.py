from __future__ import annotations

from datetime import datetime, timezone
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
from typing import Callable, cast
from uuid import uuid4

from security_analyst_agent.config import (
    DEFAULT_HERMES_CRON_JOB_ID,
    DEFAULT_HERMES_HOME,
    DEFAULT_HERMES_PATROL_MAX_TURNS,
    DEFAULT_HERMES_PATROL_HOME,
    DEFAULT_HERMES_PATROL_PROMPT_PATH,
    DEFAULT_HERMES_PATROL_TRIGGER_MODE,
    DEFAULT_OPENAI_PATROL_MODEL,
    PROJECT_ROOT,
)
from security_analyst_agent.db import connect_db, create_schema
from security_analyst_agent.openai_patrol_runner import OpenAIClientFactory, run_openai_patrol

CommandRunner = Callable[[list[str], dict[str, str] | None], subprocess.CompletedProcess[str]]
LegacyCommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]

RUNTIME_FILES_TO_COPY = ("config.yaml", ".env", "auth.json")
DEFAULT_PATROL_CHAT_QUERY = (
    "Run exactly one patrol pass against the current alert queue. First call alert.fetch. "
    "Triaged alerts must be acked in one batch when possible. "
    "Return with exact markdown headers: "
    "## Patrol Action Summary, ## Remaining Uncertainty, ## Memory Summary."
)
DEFAULT_PATROL_SKILL = "secagent-patrol"
DEFAULT_PATROL_LOOP_PATH = PROJECT_ROOT / "hermes" / "patrol-loop.json"
DEFAULT_PATROL_MEMORY_FLUSH_QUERY = (
    "Patrol run has just finished. Do not call MCP secagent tools. "
    "If there are durable cross-run facts (user preference, stable environment convention, or reliable workflow rule), "
    "save at most one compact memory entry using memory tool. "
    "If nothing is worth persisting, reply exactly [NO_MEMORY]."
)
DEFAULT_PATROL_LIGHTWEIGHT_SIGNAL_QUERY_TEMPLATE = (
    "New ingest events detected (count={event_count}, sample_event_ids={sample_event_ids}). "
    "Continue current patrol session and run exactly one patrol pass against the current alert queue. "
    "Start with alert.fetch. Prefer representative sampling and avoid repetitive fan-out. "
    "Ack triaged alerts in batch when appropriate. "
    "If there is no material update, return exactly [SILENT]."
)
DEFAULT_MEMORY_FLUSH_MIN_INTERVAL_SECONDS = 3600
PATROL_SESSION_STATE_KEY = "hermes_patrol_session"
PATROL_MEMORY_FLUSH_STATE_KEY = "hermes_patrol_memory_flush"
PATROL_OPENAI_SESSION_STATE_KEY = "openai_patrol_session"
_SESSION_ID_PATTERN = re.compile(r"session_id:\s*([^\s]+)")


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


def _load_patrol_chat_query(prompt_path: Path) -> str:
    if prompt_path.exists():
        text = prompt_path.read_text(encoding="utf-8").strip()
        if text:
            return text
    return DEFAULT_PATROL_CHAT_QUERY


def _build_patrol_chat_command(
    *,
    query: str,
    max_turns: int,
    continue_latest: bool,
    resume_session_id: str | None = None,
) -> list[str]:
    command = [
        "hermes",
        "chat",
        "-q",
        query,
        "-Q",
        "--max-turns",
        str(max_turns),
        "--source",
        "tool",
        "-s",
        DEFAULT_PATROL_SKILL,
    ]
    if resume_session_id:
        command.extend(["--resume", resume_session_id])
    elif continue_latest:
        command.append("--continue")
    return command


def _trim_command_error(result: subprocess.CompletedProcess[str]) -> str:
    message = (result.stderr or result.stdout or "").strip()
    if len(message) <= 300:
        return message
    return f"{message[:300]}..."


def _load_write_memory_on_finish(loop_path: Path = DEFAULT_PATROL_LOOP_PATH) -> bool:
    if not loop_path.exists():
        return False
    try:
        data = json.loads(loop_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    return bool(data.get("write_memory_on_finish", False))


def _load_memory_flush_min_interval_seconds(loop_path: Path = DEFAULT_PATROL_LOOP_PATH) -> int:
    if not loop_path.exists():
        return DEFAULT_MEMORY_FLUSH_MIN_INTERVAL_SECONDS
    try:
        data = json.loads(loop_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return DEFAULT_MEMORY_FLUSH_MIN_INTERVAL_SECONDS
    value = data.get("memory_flush_min_interval_seconds", DEFAULT_MEMORY_FLUSH_MIN_INTERVAL_SECONDS)
    if not isinstance(value, int):
        return DEFAULT_MEMORY_FLUSH_MIN_INTERVAL_SECONDS
    return max(value, 0)


def _load_patrol_state_value(conn: sqlite3.Connection, state_key: str) -> dict | None:
    row = conn.execute(
        """
        select state_value_json
        from patrol_state
        where state_key = ?
        """,
        (state_key,),
    ).fetchone()
    if row is None:
        return None
    try:
        state = json.loads(row["state_value_json"])
    except (TypeError, json.JSONDecodeError):
        return None
    if isinstance(state, dict):
        return state
    if isinstance(state, str) and state.strip():
        return {"session_id": state.strip()}
    return None


def _upsert_patrol_state_value(conn: sqlite3.Connection, state_key: str, state_value: dict) -> None:
    conn.execute(
        """
        insert into patrol_state (state_key, state_value_json, updated_at)
        values (?, ?, ?)
        on conflict(state_key) do update set
          state_value_json = excluded.state_value_json,
          updated_at = excluded.updated_at
        """,
        (state_key, json.dumps(state_value, ensure_ascii=False), _now_iso()),
    )


def _extract_session_id(result: subprocess.CompletedProcess[str]) -> str | None:
    text = f"{result.stdout or ''}\n{result.stderr or ''}"
    matched = _SESSION_ID_PATTERN.search(text)
    if not matched:
        return None
    session_id = matched.group(1).strip()
    if not session_id:
        return None
    return session_id


def _build_lightweight_patrol_query(event_ids: list[str]) -> str:
    sample_ids = event_ids[:5]
    sample_repr = "[" + ", ".join(sample_ids) + "]" if sample_ids else "[]"
    return DEFAULT_PATROL_LIGHTWEIGHT_SIGNAL_QUERY_TEMPLATE.format(
        event_count=len(event_ids),
        sample_event_ids=sample_repr,
    )


def _should_flush_memory(conn: sqlite3.Connection, *, now: datetime, min_interval_seconds: int) -> bool:
    if min_interval_seconds <= 0:
        return True
    state = _load_patrol_state_value(conn, PATROL_MEMORY_FLUSH_STATE_KEY)
    if not state:
        return True
    last_flush_at = state.get("last_flush_at")
    if not isinstance(last_flush_at, str) or not last_flush_at.strip():
        return True
    try:
        last_flush = datetime.fromisoformat(last_flush_at)
    except ValueError:
        return True
    elapsed = (now - last_flush).total_seconds()
    return elapsed >= float(min_interval_seconds)


def trigger_patrol_from_ingest(
    db_path: Path,
    job_id: str = DEFAULT_HERMES_CRON_JOB_ID,
    command_runner: CommandRunner | LegacyCommandRunner | None = None,
    dry_run: bool = False,
    hermes_home: Path | None = None,
    source_hermes_home: Path | None = None,
    trigger_mode: str = DEFAULT_HERMES_PATROL_TRIGGER_MODE,
    patrol_max_turns: int = DEFAULT_HERMES_PATROL_MAX_TURNS,
    patrol_prompt_path: Path = DEFAULT_HERMES_PATROL_PROMPT_PATH,
    write_memory_on_finish: bool | None = None,
    openai_model: str = DEFAULT_OPENAI_PATROL_MODEL,
    openai_client_factory: OpenAIClientFactory | None = None,
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
            normalized_mode = trigger_mode.strip().lower()
            env: dict[str, str] | None = None
            if normalized_mode in {"chat", "cron"}:
                patrol_runtime_home = hermes_home or DEFAULT_HERMES_PATROL_HOME
                source_runtime_home = source_hermes_home or DEFAULT_HERMES_HOME
                _ensure_patrol_hermes_home(patrol_runtime_home, source_runtime_home)
                env = _build_hermes_env(patrol_runtime_home)
            memory_enabled = (
                write_memory_on_finish if write_memory_on_finish is not None else _load_write_memory_on_finish()
            )
            if normalized_mode == "chat":
                existing_session_state = _load_patrol_state_value(conn, PATROL_SESSION_STATE_KEY) or {}
                existing_session_id = existing_session_state.get("session_id")
                has_existing_session = isinstance(existing_session_id, str) and existing_session_id.strip() != ""
                bootstrap_query = _load_patrol_chat_query(patrol_prompt_path)
                if has_existing_session:
                    primary_query = _build_lightweight_patrol_query(event_ids)
                else:
                    primary_query = bootstrap_query

                primary_result = _run_with_compat_runner(
                    runner,
                    _build_patrol_chat_command(
                        query=primary_query,
                        max_turns=patrol_max_turns,
                        continue_latest=False,
                        resume_session_id=str(existing_session_id) if has_existing_session else None,
                    ),
                    env,
                )
                if primary_result.returncode == 0:
                    status = "success"
                    if has_existing_session:
                        detail = "hermes chat session resumed by session_id with lightweight trigger query"
                    else:
                        detail = "hermes chat started new patrol session"
                else:
                    if has_existing_session:
                        continue_result = _run_with_compat_runner(
                            runner,
                            _build_patrol_chat_command(
                                query=primary_query,
                                max_turns=patrol_max_turns,
                                continue_latest=True,
                            ),
                            env,
                        )
                        if continue_result.returncode == 0:
                            status = "success"
                            detail = (
                                "hermes chat session resumed by latest-session fallback "
                                f"(resume_rc={primary_result.returncode})"
                            )
                            primary_result = continue_result
                        else:
                            recovered_result = _run_with_compat_runner(
                                runner,
                                _build_patrol_chat_command(
                                    query=bootstrap_query,
                                    max_turns=patrol_max_turns,
                                    continue_latest=False,
                                ),
                                env,
                            )
                            if recovered_result.returncode == 0:
                                status = "success"
                                detail = (
                                    "hermes chat recovered by starting a new session "
                                    f"(resume_rc={primary_result.returncode}, continue_rc={continue_result.returncode})"
                                )
                                primary_result = recovered_result
                            else:
                                detail = (
                                    "resume_rc="
                                    f"{primary_result.returncode}, continue_rc={continue_result.returncode}, "
                                    f"fresh_rc={recovered_result.returncode}, "
                                    f"resume_err={_trim_command_error(primary_result)}, "
                                    f"continue_err={_trim_command_error(continue_result)}, "
                                    f"fresh_err={_trim_command_error(recovered_result)}"
                                )
                    else:
                        detail = (
                            f"fresh_rc={primary_result.returncode}, "
                            f"fresh_err={_trim_command_error(primary_result)}"
                        )
                if status == "success":
                    session_id = _extract_session_id(primary_result)
                    if session_id:
                        _upsert_patrol_state_value(
                            conn,
                            PATROL_SESSION_STATE_KEY,
                            {
                                "session_id": session_id,
                                "last_run_id": run_id,
                                "last_success_at": finished_at,
                            },
                        )
                if status == "success" and memory_enabled:
                    memory_interval_seconds = _load_memory_flush_min_interval_seconds()
                    now_dt = datetime.now(timezone.utc)
                    if _should_flush_memory(conn, now=now_dt, min_interval_seconds=memory_interval_seconds):
                        memory_session_state = _load_patrol_state_value(conn, PATROL_SESSION_STATE_KEY) or {}
                        memory_session_id = memory_session_state.get("session_id")
                        use_resume_for_memory = isinstance(memory_session_id, str) and memory_session_id.strip() != ""
                        memory_result = _run_with_compat_runner(
                            runner,
                            _build_patrol_chat_command(
                                query=DEFAULT_PATROL_MEMORY_FLUSH_QUERY,
                                max_turns=2,
                                continue_latest=not use_resume_for_memory,
                                resume_session_id=str(memory_session_id) if use_resume_for_memory else None,
                            ),
                            env,
                        )
                        if memory_result.returncode == 0:
                            detail = f"{detail}; memory_flush=ok"
                            memory_session_id = _extract_session_id(memory_result)
                            if memory_session_id:
                                _upsert_patrol_state_value(
                                    conn,
                                    PATROL_SESSION_STATE_KEY,
                                    {
                                        "session_id": memory_session_id,
                                        "last_run_id": run_id,
                                        "last_success_at": finished_at,
                                    },
                                )
                            _upsert_patrol_state_value(
                                conn,
                                PATROL_MEMORY_FLUSH_STATE_KEY,
                                {
                                    "last_flush_at": now_dt.isoformat(),
                                    "last_run_id": run_id,
                                },
                            )
                        else:
                            detail = (
                                f"{detail}; memory_flush_failed rc={memory_result.returncode}, "
                                f"err={_trim_command_error(memory_result)}"
                            )
                    else:
                        detail = f"{detail}; memory_flush=skipped_not_due"
            elif normalized_mode == "openai":
                openai_session_state = _load_patrol_state_value(conn, PATROL_OPENAI_SESSION_STATE_KEY) or {}
                existing_response_id = openai_session_state.get("response_id")
                has_existing_response = isinstance(existing_response_id, str) and existing_response_id.strip() != ""
                bootstrap_query = _load_patrol_chat_query(patrol_prompt_path)
                if has_existing_response:
                    primary_query = _build_lightweight_patrol_query(event_ids)
                else:
                    primary_query = bootstrap_query

                openai_result = run_openai_patrol(
                    conn,
                    model=openai_model,
                    instructions=bootstrap_query,
                    query=primary_query,
                    previous_response_id=str(existing_response_id) if has_existing_response else None,
                    max_turns=patrol_max_turns,
                    client_factory=openai_client_factory,
                )
                status = openai_result.status
                detail = openai_result.detail
                if status == "success":
                    _upsert_patrol_state_value(
                        conn,
                        PATROL_OPENAI_SESSION_STATE_KEY,
                        {
                            "response_id": openai_result.response_id,
                            "last_run_id": run_id,
                            "last_success_at": finished_at,
                            "model": openai_model,
                        },
                    )
            elif normalized_mode == "cron":
                run_result = _run_with_compat_runner(runner, ["hermes", "cron", "run", job_id], env)
                tick_result = _run_with_compat_runner(runner, ["hermes", "cron", "tick"], env)
                if run_result.returncode == 0 and tick_result.returncode == 0:
                    status = "success"
                    detail = "hermes cron run/tick completed"
                else:
                    detail = (
                        f"run_rc={run_result.returncode}, tick_rc={tick_result.returncode}, "
                        f"run_err={_trim_command_error(run_result)}, tick_err={_trim_command_error(tick_result)}"
                    )
            else:
                detail = f"unsupported trigger mode: {trigger_mode}"
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
