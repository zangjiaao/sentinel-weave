import json
import sqlite3
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

_UNSET = object()
_BOUND_RUN_ID: ContextVar[object] = ContextVar("audit_bound_run_id", default=_UNSET)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_active_patrol_run(conn: sqlite3.Connection) -> sqlite3.Row | None:
    return conn.execute(
        """
        select run_id, trigger_source, status, started_at
        from patrol_runs
        where status = 'running'
        order by started_at desc
        limit 1
        """
    ).fetchone()


def load_active_patrol_run_id(conn: sqlite3.Connection) -> str | None:
    row = _load_active_patrol_run(conn)
    return row["run_id"] if row else None


def bind_run_id(run_id: str | None):
    return _BOUND_RUN_ID.set(run_id)


def reset_bound_run_id(token: object) -> None:
    _BOUND_RUN_ID.reset(token)


def _resolve_run_id(conn: sqlite3.Connection) -> str | None:
    bound = _BOUND_RUN_ID.get()
    if bound is not _UNSET:
        return bound if isinstance(bound, str) else None
    return load_active_patrol_run_id(conn)


def _create_auto_patrol_run(conn: sqlite3.Connection, *, summary: str) -> str:
    run_id = f"run_{uuid4().hex[:12]}"
    conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at)
        values (?, ?, ?, ?, ?)
        """,
        (run_id, "mcp_auto", "running", summary, now_iso()),
    )
    return run_id


def _finish_auto_patrol_run(conn: sqlite3.Connection, *, run_id: str, summary: str) -> None:
    conn.execute(
        """
        update patrol_runs
        set status = 'success', summary = ?, finished_at = ?
        where run_id = ? and trigger_source = 'mcp_auto' and status = 'running'
        """,
        (summary, now_iso(), run_id),
    )


def finalize_mcp_auto_run_after_tool(
    conn: sqlite3.Connection,
    *,
    source: str,
    run_id: str | None,
    tool_name: str,
    result: dict[str, Any],
) -> None:
    if source != "mcp" or not run_id:
        return

    row = conn.execute(
        """
        select run_id, trigger_source, status
        from patrol_runs
        where run_id = ?
        """,
        (run_id,),
    ).fetchone()
    if row is None or row["trigger_source"] != "mcp_auto" or row["status"] != "running":
        return

    if tool_name == "alert.fetch":
        alerts = result.get("data", {}).get("alerts")
        if isinstance(alerts, list) and len(alerts) == 0:
            _finish_auto_patrol_run(conn, run_id=run_id, summary="auto_closed_empty_fetch")
        return

    if tool_name == "alert.ack":
        pending_count = conn.execute(
            "select count(*) from alerts where status in ('new', 'open')"
        ).fetchone()[0]
        if int(pending_count) == 0:
            _finish_auto_patrol_run(conn, run_id=run_id, summary="auto_closed_after_alert_ack")


def resolve_run_id_for_dispatch(conn: sqlite3.Connection, *, source: str, tool_name: str) -> str | None:
    if source != "mcp":
        return None

    active = _load_active_patrol_run(conn)
    if tool_name == "alert.fetch":
        if active and active["trigger_source"] == "ingest_event":
            return active["run_id"]
        if active and active["trigger_source"] == "mcp_auto":
            _finish_auto_patrol_run(
                conn,
                run_id=active["run_id"],
                summary="auto_closed_on_next_alert_fetch",
            )
        return _create_auto_patrol_run(conn, summary="auto_started_by_mcp_alert_fetch")

    return active["run_id"] if active else None


def insert_tool_call_log(
    conn: sqlite3.Connection,
    *,
    source: str,
    tool_name: str,
    payload: dict[str, Any],
    result: dict[str, Any],
    latency_ms: int,
) -> str:
    run_id = _resolve_run_id(conn)
    call_id = f"call_{uuid4().hex[:12]}"
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id,
          occurred_at,
          run_id,
          source,
          tool_name,
          payload_json,
          result_ok,
          result_summary,
          result_json,
          latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            call_id,
            now_iso(),
            run_id,
            source,
            tool_name,
            json.dumps(payload, ensure_ascii=False),
            1 if result.get("ok") else 0,
            result.get("summary", ""),
            json.dumps(result, ensure_ascii=False),
            latency_ms,
        ),
    )
    return call_id


def insert_alert_decision_log(
    conn: sqlite3.Connection,
    *,
    alert_id: str,
    decision: str,
    case_id: str | None,
    confidence: float | None,
    reason: str,
    detail: dict[str, Any] | None = None,
) -> str:
    decision_id = f"adec_{uuid4().hex[:12]}"
    conn.execute(
        """
        insert into alert_decisions (
          decision_id,
          occurred_at,
          run_id,
          alert_id,
          decision,
          case_id,
          confidence,
          reason,
          detail_json
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            decision_id,
            now_iso(),
            _resolve_run_id(conn),
            alert_id,
            decision,
            case_id,
            confidence,
            reason,
            json.dumps(detail or {}, ensure_ascii=False),
        ),
    )
    return decision_id


def insert_case_change_log(
    conn: sqlite3.Connection,
    *,
    case_id: str,
    action: str,
    before_state: dict[str, Any] | None,
    after_state: dict[str, Any] | None,
    reason: str,
) -> str:
    change_id = f"cchg_{uuid4().hex[:12]}"
    conn.execute(
        """
        insert into case_changes (
          change_id,
          occurred_at,
          run_id,
          case_id,
          action,
          before_json,
          after_json,
          reason
        ) values (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            change_id,
            now_iso(),
            _resolve_run_id(conn),
            case_id,
            action,
            json.dumps(before_state or {}, ensure_ascii=False),
            json.dumps(after_state or {}, ensure_ascii=False),
            reason,
        ),
    )
    return change_id


def insert_escalation_log(
    conn: sqlite3.Connection,
    *,
    case_id: str,
    triggered: bool,
    channel: str,
    template: str,
    notification_id: str | None,
    dedupe_key: str,
    reason: str,
    detail: dict[str, Any] | None = None,
) -> str:
    escalation_id = f"escl_{uuid4().hex[:12]}"
    conn.execute(
        """
        insert into escalation_decisions (
          escalation_id,
          occurred_at,
          run_id,
          case_id,
          triggered,
          channel,
          template,
          notification_id,
          dedupe_key,
          reason,
          detail_json
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            escalation_id,
            now_iso(),
            _resolve_run_id(conn),
            case_id,
            1 if triggered else 0,
            channel,
            template,
            notification_id,
            dedupe_key,
            reason,
            json.dumps(detail or {}, ensure_ascii=False),
        ),
    )
    return escalation_id
