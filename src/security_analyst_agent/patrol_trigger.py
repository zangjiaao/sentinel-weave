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
    DEFAULT_OPENAI_PATROL_RETRY_FRESH_ON_NO_TOOL,
    DEFAULT_OPENAI_PATROL_RESUME_COMPACT_INSTRUCTIONS,
    DEFAULT_OPENAI_PATROL_SESSION_MAX_INPUT_TOKENS,
    DEFAULT_OPENAI_PATROL_SESSION_MAX_RUNS,
    DEFAULT_OPENAI_PATROL_TOOL_PROFILE,
    PROJECT_ROOT,
)
from security_analyst_agent.db import connect_db, create_schema
from security_analyst_agent.openai_patrol_runner import OpenAIClientFactory, run_openai_patrol
from security_analyst_agent.services.case_convergence import run_case_convergence_for_run

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
DEFAULT_PATROL_SOUL_TEMPLATE_PATH = PROJECT_ROOT / "hermes" / "SOUL.patrol.template.md"
DEFAULT_PATROL_FALLBACK_SOUL_TEMPLATE_PATH = PROJECT_ROOT / "hermes" / "SOUL.template.md"
DEFAULT_PATROL_SKILL_PATH = PROJECT_ROOT / "skills" / "secagent-patrol" / "SKILL.md"
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


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


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


def _load_text_file(path: Path) -> str:
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8").strip()
    return text


def _load_patrol_soul_text() -> str:
    text = _load_text_file(DEFAULT_PATROL_SOUL_TEMPLATE_PATH)
    if text:
        return text
    return _load_text_file(DEFAULT_PATROL_FALLBACK_SOUL_TEMPLATE_PATH)


def _build_openai_patrol_instructions(prompt_path: Path) -> str:
    base_prompt = _load_patrol_chat_query(prompt_path)
    sections = [base_prompt]

    soul_text = _load_patrol_soul_text()
    if soul_text:
        sections.append(soul_text)

    skill_text = _load_text_file(DEFAULT_PATROL_SKILL_PATH)
    if skill_text:
        sections.append(skill_text)

    return "\n\n".join(section for section in sections if section.strip())


def _build_openai_patrol_resume_instructions() -> str:
    return (
        "Continue existing security patrol session in neutral evidence-driven mode.\n"
        "Process current pending alerts only.\n"
        "Avoid premature conclusions; keep uncertain findings as unknown/watch.\n"
        "Do not link low-severity recon-only alerts into cases by default.\n"
        "Hard rules: alert.detail-batch alert_ids must come from this run's alert.fetch.\n"
        "Hard rules: batch write tools (case.upsert-batch/case.link-alert-batch/assessment.upsert-batch) require non-empty items.\n"
        "If a tool returns payload_validation_error or detail_batch_requires_fetch_context, do not retry the same payload.\n"
        "Use concise batched tool calls and return [SILENT] when no material update."
    )


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


def _state_int(state: dict, key: str, default: int = 0) -> int:
    value = state.get(key)
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return default
        try:
            return int(float(text))
        except ValueError:
            return default
    return default


def _is_no_backend_tool_failure(detail: str) -> bool:
    return "no backend tool calls" in detail.lower()


def _format_openai_usage_suffix(
    *,
    turns: int,
    tool_calls: int,
    usage_input_tokens: int,
    usage_output_tokens: int,
    usage_cached_input_tokens: int,
) -> str:
    return (
        "turns="
        f"{turns}, tool_calls={tool_calls}, usage_in={usage_input_tokens}, "
        f"usage_out={usage_output_tokens}, usage_cached_in={usage_cached_input_tokens}"
    )


def _derive_openai_tool_budget(event_count: int) -> dict[str, int | bool]:
    if event_count >= 500:
        return {
            "max_tool_calls": 10,
            "max_read_tool_calls": 7,
            "max_write_tool_calls": 3,
            "enforce_read_phase_gate": True,
        }
    if event_count >= 200:
        return {
            "max_tool_calls": 14,
            "max_read_tool_calls": 10,
            "max_write_tool_calls": 4,
            "enforce_read_phase_gate": True,
        }
    return {
        "max_tool_calls": 20,
        "max_read_tool_calls": 14,
        "max_write_tool_calls": 6,
        "enforce_read_phase_gate": False,
    }


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

    normalized_mode = trigger_mode.strip().lower()
    status = "failed"
    detail = "unknown_failure"
    usage_model: str | None = None
    usage_turns: int | None = None
    usage_tool_calls: int | None = None
    usage_input_tokens: int | None = None
    usage_output_tokens: int | None = None
    usage_cached_input_tokens: int | None = None
    finished_at = _now_iso()
    try:
        if dry_run:
            status = "dry_run_success"
            detail = "dry run completed without hermes commands"
        else:
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
                previous_run_count = _state_int(openai_session_state, "run_count", default=0)
                previous_input_tokens = _state_int(openai_session_state, "cumulative_input_tokens", default=0)
                previous_output_tokens = _state_int(openai_session_state, "cumulative_output_tokens", default=0)
                previous_cached_input_tokens = _state_int(
                    openai_session_state,
                    "cumulative_cached_input_tokens",
                    default=0,
                )
                previous_fetch_resume_payload = openai_session_state.get("fetch_resume_payload")
                if not isinstance(previous_fetch_resume_payload, dict):
                    previous_fetch_resume_payload = None
                rollover_reasons: list[str] = []
                if has_existing_response:
                    if (
                        DEFAULT_OPENAI_PATROL_SESSION_MAX_RUNS > 0
                        and previous_run_count >= DEFAULT_OPENAI_PATROL_SESSION_MAX_RUNS
                    ):
                        rollover_reasons.append("max_runs")
                    if (
                        DEFAULT_OPENAI_PATROL_SESSION_MAX_INPUT_TOKENS > 0
                        and previous_input_tokens >= DEFAULT_OPENAI_PATROL_SESSION_MAX_INPUT_TOKENS
                    ):
                        rollover_reasons.append("max_input_tokens")
                should_reuse_response = has_existing_response and not rollover_reasons
                bootstrap_query = _load_patrol_chat_query(patrol_prompt_path)
                use_compact_resume_instructions = (
                    should_reuse_response and DEFAULT_OPENAI_PATROL_RESUME_COMPACT_INSTRUCTIONS
                )
                if use_compact_resume_instructions:
                    instructions = _build_openai_patrol_resume_instructions()
                else:
                    instructions = _build_openai_patrol_instructions(patrol_prompt_path)
                if should_reuse_response:
                    primary_query = _build_lightweight_patrol_query(event_ids)
                else:
                    primary_query = bootstrap_query
                budget = _derive_openai_tool_budget(len(event_ids))

                openai_result = run_openai_patrol(
                    conn,
                    model=openai_model,
                    instructions=instructions,
                    query=primary_query,
                    previous_response_id=str(existing_response_id) if should_reuse_response else None,
                    max_turns=patrol_max_turns,
                    max_tool_calls=int(budget["max_tool_calls"]),
                    max_read_tool_calls=int(budget["max_read_tool_calls"]),
                    max_write_tool_calls=int(budget["max_write_tool_calls"]),
                    enforce_read_phase_gate=bool(budget["enforce_read_phase_gate"]),
                    first_fetch_payload_override=previous_fetch_resume_payload,
                    client_factory=openai_client_factory,
                    tool_profile=DEFAULT_OPENAI_PATROL_TOOL_PROFILE,
                )
                retried_fresh_after_no_tool = False
                if (
                    openai_result.status != "success"
                    and DEFAULT_OPENAI_PATROL_RETRY_FRESH_ON_NO_TOOL
                    and _is_no_backend_tool_failure(openai_result.detail)
                ):
                    retried_fresh_after_no_tool = True
                    openai_result = run_openai_patrol(
                        conn,
                        model=openai_model,
                        instructions=_build_openai_patrol_instructions(patrol_prompt_path),
                        query=bootstrap_query,
                        previous_response_id=None,
                        max_turns=patrol_max_turns,
                        max_tool_calls=int(budget["max_tool_calls"]),
                        max_read_tool_calls=int(budget["max_read_tool_calls"]),
                        max_write_tool_calls=int(budget["max_write_tool_calls"]),
                        enforce_read_phase_gate=bool(budget["enforce_read_phase_gate"]),
                        first_fetch_payload_override=previous_fetch_resume_payload,
                        client_factory=openai_client_factory,
                        tool_profile=DEFAULT_OPENAI_PATROL_TOOL_PROFILE,
                    )
                status = openai_result.status
                usage_model = openai_model
                usage_turns = int(openai_result.turns)
                usage_tool_calls = int(openai_result.tool_calls)
                usage_input_tokens = int(openai_result.usage_input_tokens)
                usage_output_tokens = int(openai_result.usage_output_tokens)
                usage_cached_input_tokens = int(openai_result.usage_cached_input_tokens)
                detail_parts = [
                    openai_result.detail,
                    _format_openai_usage_suffix(
                        turns=openai_result.turns,
                        tool_calls=openai_result.tool_calls,
                        usage_input_tokens=openai_result.usage_input_tokens,
                        usage_output_tokens=openai_result.usage_output_tokens,
                        usage_cached_input_tokens=openai_result.usage_cached_input_tokens,
                    ),
                ]
                if rollover_reasons:
                    detail_parts.append(f"session_rollover={'+'.join(rollover_reasons)}")
                if retried_fresh_after_no_tool:
                    detail_parts.append("retried_fresh_after_no_tool=1")
                detail_parts.append(
                    "tool_budget="
                    f"total:{budget['max_tool_calls']}/read:{budget['max_read_tool_calls']}/"
                    f"write:{budget['max_write_tool_calls']}"
                )
                if openai_result.fetch_resume_payload:
                    detail_parts.append("fetch_backlog=has_more")
                detail = "; ".join(detail_parts)
                if status == "success":
                    if should_reuse_response and not retried_fresh_after_no_tool:
                        next_run_count = previous_run_count + 1
                        next_cumulative_input_tokens = previous_input_tokens + openai_result.usage_input_tokens
                        next_cumulative_output_tokens = previous_output_tokens + openai_result.usage_output_tokens
                        next_cumulative_cached_input_tokens = (
                            previous_cached_input_tokens + openai_result.usage_cached_input_tokens
                        )
                    else:
                        next_run_count = 1
                        next_cumulative_input_tokens = openai_result.usage_input_tokens
                        next_cumulative_output_tokens = openai_result.usage_output_tokens
                        next_cumulative_cached_input_tokens = openai_result.usage_cached_input_tokens
                    next_state = {
                        "response_id": openai_result.response_id,
                        "last_run_id": run_id,
                        "last_success_at": finished_at,
                        "model": openai_model,
                        "run_count": next_run_count,
                        "cumulative_input_tokens": next_cumulative_input_tokens,
                        "cumulative_output_tokens": next_cumulative_output_tokens,
                        "cumulative_cached_input_tokens": next_cumulative_cached_input_tokens,
                        "last_usage": {
                            "input_tokens": openai_result.usage_input_tokens,
                            "output_tokens": openai_result.usage_output_tokens,
                            "cached_input_tokens": openai_result.usage_cached_input_tokens,
                            "turns": openai_result.turns,
                            "tool_calls": openai_result.tool_calls,
                        },
                    }
                    if rollover_reasons:
                        next_state["last_rollover_reason"] = "+".join(rollover_reasons)
                    if retried_fresh_after_no_tool:
                        next_state["last_recovery"] = "fresh_retry_after_no_tool"
                    if openai_result.fetch_resume_payload:
                        next_state["fetch_resume_payload"] = openai_result.fetch_resume_payload
                        next_state["fetch_backlog_has_more"] = True
                    else:
                        next_state["fetch_backlog_has_more"] = False
                    _upsert_patrol_state_value(
                        conn,
                        PATROL_OPENAI_SESSION_STATE_KEY,
                        next_state,
                    )
                elif has_existing_response and _is_no_backend_tool_failure(openai_result.detail):
                    _upsert_patrol_state_value(
                        conn,
                        PATROL_OPENAI_SESSION_STATE_KEY,
                        {
                            "response_id": None,
                            "last_run_id": run_id,
                            "last_failure_at": finished_at,
                            "last_failure_reason": "no_backend_tool_calls",
                            "model": openai_model,
                            "run_count": previous_run_count,
                            "cumulative_input_tokens": previous_input_tokens,
                            "cumulative_output_tokens": previous_output_tokens,
                            "cumulative_cached_input_tokens": previous_cached_input_tokens,
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

    if status == "success":
        try:
            convergence_summary = run_case_convergence_for_run(conn, run_id=run_id)
            detail = (
                f"{detail}; case_convergence=ok("
                f"confirmed_relations={convergence_summary.get('confirmed_relations_count', 0)}, "
                f"merge_events={convergence_summary.get('merge_events_count', 0)}, "
                f"orphan_absorbed={convergence_summary.get('orphan_absorbed_cases_count', 0)})"
            )
        except Exception as exc:
            detail = f"{detail}; case_convergence_failed={type(exc).__name__}:{exc}"

    finished_at = _now_iso()
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

    run_row = conn.execute(
        """
        select trigger_source, started_at
        from patrol_runs
        where run_id = ?
        limit 1
        """,
        (run_id,),
    ).fetchone()
    started_at = str(run_row["started_at"]) if run_row is not None and run_row["started_at"] else finished_at
    trigger_source = str(run_row["trigger_source"]) if run_row is not None and run_row["trigger_source"] else "unknown"
    started_dt = _parse_iso_datetime(started_at)
    finished_dt = _parse_iso_datetime(finished_at)
    duration_ms = (
        max(int((finished_dt - started_dt).total_seconds() * 1000), 0)
        if started_dt is not None and finished_dt is not None
        else None
    )
    if usage_tool_calls is None:
        usage_tool_calls = int(
            conn.execute("select count(*) from agent_tool_calls where run_id = ?", (run_id,)).fetchone()[0]
        )
    usage_total_tokens = (
        int(usage_input_tokens or 0)
        + int(usage_output_tokens or 0)
        + int(usage_cached_input_tokens or 0)
    )
    if usage_input_tokens is None and usage_output_tokens is None and usage_cached_input_tokens is None:
        usage_total_tokens = None
    conn.execute(
        """
        insert into patrol_run_costs (
          run_id,
          trigger_source,
          trigger_mode,
          model,
          status,
          started_at,
          finished_at,
          duration_ms,
          turns,
          tool_calls,
          usage_input_tokens,
          usage_output_tokens,
          usage_cached_input_tokens,
          usage_total_tokens,
          recorded_at
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        on conflict(run_id) do update set
          trigger_source = excluded.trigger_source,
          trigger_mode = excluded.trigger_mode,
          model = excluded.model,
          status = excluded.status,
          started_at = excluded.started_at,
          finished_at = excluded.finished_at,
          duration_ms = excluded.duration_ms,
          turns = excluded.turns,
          tool_calls = excluded.tool_calls,
          usage_input_tokens = excluded.usage_input_tokens,
          usage_output_tokens = excluded.usage_output_tokens,
          usage_cached_input_tokens = excluded.usage_cached_input_tokens,
          usage_total_tokens = excluded.usage_total_tokens,
          recorded_at = excluded.recorded_at
        """,
        (
            run_id,
            trigger_source,
            normalized_mode if normalized_mode else "unknown",
            usage_model,
            status,
            started_at,
            finished_at,
            duration_ms,
            usage_turns,
            usage_tool_calls,
            usage_input_tokens,
            usage_output_tokens,
            usage_cached_input_tokens,
            usage_total_tokens,
            _now_iso(),
        ),
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
