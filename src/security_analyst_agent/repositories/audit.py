import json
import sqlite3
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from security_analyst_agent.services.case_convergence import run_case_convergence_for_run

_UNSET = object()
_BOUND_RUN_ID: ContextVar[object] = ContextVar("audit_bound_run_id", default=_UNSET)
_BOUND_ANALYSIS_CUTOFF_AT: ContextVar[object] = ContextVar("audit_bound_analysis_cutoff_at", default=_UNSET)
_RECENT_FINISHED_MCP_AUTO_RUN_GRACE_SECONDS = 120
_AUTO_ESCALATION_STAGE_ORDER = {
    "recon": 1,
    "exploit": 2,
    "persistence": 3,
    "command_execution": 4,
    "lateral_prep": 5,
}
_AUTO_ESCALATION_MIN_STAGE = "persistence"
_AUTO_ESCALATION_CHANNEL = "email"
_AUTO_ESCALATION_TEMPLATE = "high_severity"
_AUTO_ESCALATION_MIN_ALERT_CONFIDENCE = 0.8
_AUTO_ESCALATION_CONTINUITY_EVIDENCE_TYPES = ("webshell", "webshell_exploitation", "shell_connection")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_active_patrol_run(conn: sqlite3.Connection) -> sqlite3.Row | None:
    return conn.execute(
        """
        select run_id, trigger_source, status, started_at, analysis_cutoff_at
        from patrol_runs
        where status = 'running'
        order by started_at desc
        limit 1
        """
    ).fetchone()


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


def _load_recent_finished_mcp_auto_run(
    conn: sqlite3.Connection, *, grace_seconds: int
) -> sqlite3.Row | None:
    row = conn.execute(
        """
        select run_id, analysis_cutoff_at, finished_at
        from patrol_runs
        where trigger_source = 'mcp_auto' and status = 'success' and finished_at is not null
        order by finished_at desc
        limit 1
        """
    ).fetchone()
    if row is None:
        return None
    finished_at = _parse_iso_datetime(row["finished_at"])
    if finished_at is None:
        return None
    delta_seconds = (datetime.now(timezone.utc) - finished_at).total_seconds()
    if delta_seconds < 0 or delta_seconds > grace_seconds:
        return None
    return row


def load_active_patrol_run_id(conn: sqlite3.Connection) -> str | None:
    row = _load_active_patrol_run(conn)
    return row["run_id"] if row else None


def load_analysis_cutoff_for_run(conn: sqlite3.Connection, run_id: str | None) -> str | None:
    if not run_id:
        return None
    row = conn.execute(
        "select analysis_cutoff_at from patrol_runs where run_id = ?",
        (run_id,),
    ).fetchone()
    if row is None:
        return None
    return row["analysis_cutoff_at"]


def load_active_analysis_cutoff(conn: sqlite3.Connection) -> str | None:
    bound = _BOUND_ANALYSIS_CUTOFF_AT.get()
    if bound is not _UNSET:
        return bound if isinstance(bound, str) else None
    row = _load_active_patrol_run(conn)
    if row is None:
        return None
    return row["analysis_cutoff_at"]


def bind_run_context(run_id: str | None, analysis_cutoff_at: str | None) -> tuple[object, object]:
    return (_BOUND_RUN_ID.set(run_id), _BOUND_ANALYSIS_CUTOFF_AT.set(analysis_cutoff_at))


def reset_bound_run_context(token: tuple[object, object]) -> None:
    run_id_token, cutoff_token = token
    _BOUND_ANALYSIS_CUTOFF_AT.reset(cutoff_token)
    _BOUND_RUN_ID.reset(run_id_token)


def bind_run_id(run_id: str | None):
    return bind_run_context(run_id, None)


def reset_bound_run_id(token: object) -> None:
    if isinstance(token, tuple) and len(token) == 2:
        reset_bound_run_context(token)
        return
    _BOUND_RUN_ID.reset(token)


def _resolve_run_id(conn: sqlite3.Connection) -> str | None:
    bound = _BOUND_RUN_ID.get()
    if bound is not _UNSET:
        return bound if isinstance(bound, str) else None
    return load_active_patrol_run_id(conn)


def _resolve_analysis_cutoff(conn: sqlite3.Connection) -> str | None:
    return load_active_analysis_cutoff(conn)


def _create_auto_patrol_run(conn: sqlite3.Connection, *, summary: str) -> str:
    run_id = f"run_{uuid4().hex[:12]}"
    started_at = now_iso()
    conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at)
        values (?, ?, ?, ?, ?, ?)
        """,
        (run_id, "mcp_auto", "running", summary, started_at, started_at),
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


def _stage_rank(stage: str | None) -> int:
    if not stage:
        return 0
    return _AUTO_ESCALATION_STAGE_ORDER.get(str(stage).lower(), 0)


def _extract_case_ids_from_result(result: dict[str, Any]) -> list[str]:
    case_ids: list[str] = []
    refs = result.get("refs")
    if isinstance(refs, dict):
        refs_case_ids = refs.get("case_ids")
        if isinstance(refs_case_ids, list):
            case_ids.extend(str(item) for item in refs_case_ids if item)

    data = result.get("data")
    if isinstance(data, dict):
        case_obj = data.get("case")
        if isinstance(case_obj, dict):
            case_id = case_obj.get("case_id")
            if case_id:
                case_ids.append(str(case_id))

    return list(dict.fromkeys(case_ids))


def _case_has_continuity_signal(conn: sqlite3.Connection, *, case_id: str) -> bool:
    has_webshell_evidence = (
        conn.execute(
            f"""
            select 1
            from evidence
            where case_id = ?
              and evidence_type in ({", ".join("?" for _ in _AUTO_ESCALATION_CONTINUITY_EVIDENCE_TYPES)})
            limit 1
            """,
            (case_id, *_AUTO_ESCALATION_CONTINUITY_EVIDENCE_TYPES),
        ).fetchone()
        is not None
    )
    if has_webshell_evidence:
        return True

    has_timeline_event = (
        conn.execute(
            """
            select 1
            from timeline_events
            where case_id = ?
            limit 1
            """,
            (case_id,),
        ).fetchone()
        is not None
    )
    if has_timeline_event:
        return True

    has_strong_alert_link = (
        conn.execute(
            """
            select 1
            from case_alert_links
            where case_id = ?
              and is_active = 1
              and confidence >= ?
            limit 1
            """,
            (case_id, _AUTO_ESCALATION_MIN_ALERT_CONFIDENCE),
        ).fetchone()
        is not None
    )
    return has_strong_alert_link


def _should_auto_escalate_case(conn: sqlite3.Connection, *, case_id: str) -> bool:
    row = conn.execute(
        """
        select status, overall_severity, current_stage, merge_state
        from cases
        where case_id = ?
        """,
        (case_id,),
    ).fetchone()
    if row is None:
        return False

    status = str(row["status"]).lower()
    severity = str(row["overall_severity"]).lower()
    stage = str(row["current_stage"]).lower()
    merge_state = str(row["merge_state"]).lower() if row["merge_state"] else ""
    if status == "closed" or merge_state == "merged":
        return False
    if severity not in {"high", "critical"}:
        return False
    if _stage_rank(stage) < _stage_rank(_AUTO_ESCALATION_MIN_STAGE):
        return False
    return _case_has_continuity_signal(conn, case_id=case_id)


def _send_auto_escalation_notification(conn: sqlite3.Connection, *, case_id: str) -> None:
    from security_analyst_agent.repositories.cases import load_case
    from security_analyst_agent.services.output import build_notify_preview

    case = load_case(conn, case_id)
    if case is None:
        return

    dedupe_key = f"{case_id}:{_AUTO_ESCALATION_CHANNEL}:{_AUTO_ESCALATION_TEMPLATE}"
    existing = conn.execute(
        """
        select notification_id
        from notification_outbox
        where dedupe_key = ? and status in ('queued', 'sent_simulated')
        order by created_at desc
        limit 1
        """,
        (dedupe_key,),
    ).fetchone()
    if existing is not None:
        insert_escalation_log(
            conn,
            case_id=case_id,
            triggered=False,
            channel=_AUTO_ESCALATION_CHANNEL,
            template=_AUTO_ESCALATION_TEMPLATE,
            notification_id=existing["notification_id"],
            dedupe_key=dedupe_key,
            reason="dedupe_hit",
            detail={"status": "deduped", "auto_policy": "stage_persistence_with_continuity"},
        )
        return

    preview = build_notify_preview(case, _AUTO_ESCALATION_CHANNEL)
    created_at = now_iso()
    notification_id = f"notif_{uuid4().hex[:12]}"
    conn.execute(
        """
        insert into notification_outbox (
          notification_id, case_id, channel, template, title, body, dedupe_key, status, created_at, sent_at
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            notification_id,
            case_id,
            _AUTO_ESCALATION_CHANNEL,
            _AUTO_ESCALATION_TEMPLATE,
            preview["title"],
            preview["body"],
            dedupe_key,
            "sent_simulated",
            created_at,
            created_at,
        ),
    )
    insert_escalation_log(
        conn,
        case_id=case_id,
        triggered=True,
        channel=_AUTO_ESCALATION_CHANNEL,
        template=_AUTO_ESCALATION_TEMPLATE,
        notification_id=notification_id,
        dedupe_key=dedupe_key,
        reason="threshold_met",
        detail={"status": "sent_simulated", "auto_policy": "stage_persistence_with_continuity"},
    )


def _auto_escalate_after_case_update(conn: sqlite3.Connection, *, result: dict[str, Any]) -> None:
    if not result.get("ok"):
        return
    for case_id in _extract_case_ids_from_result(result):
        if _should_auto_escalate_case(conn, case_id=case_id):
            _send_auto_escalation_notification(conn, case_id=case_id)


def finalize_mcp_auto_run_after_tool(
    conn: sqlite3.Connection,
    *,
    source: str,
    run_id: str | None,
    tool_name: str,
    result: dict[str, Any],
) -> None:
    if source != "mcp":
        return

    if tool_name == "case.update-risk":
        _auto_escalate_after_case_update(conn, result=result)

    if not run_id:
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
            run_case_convergence_for_run(conn, run_id=run_id)


def resolve_run_context_for_dispatch(
    conn: sqlite3.Connection, *, source: str, tool_name: str
) -> tuple[str | None, str | None]:
    if source != "mcp":
        return None, None

    active = _load_active_patrol_run(conn)
    if tool_name == "alert.fetch":
        if active and active["trigger_source"] == "ingest_event":
            return active["run_id"], active["analysis_cutoff_at"]
        if active and active["trigger_source"] == "mcp_auto":
            _finish_auto_patrol_run(
                conn,
                run_id=active["run_id"],
                summary="auto_closed_on_next_alert_fetch",
            )
        run_id = _create_auto_patrol_run(conn, summary="auto_started_by_mcp_alert_fetch")
        return run_id, load_analysis_cutoff_for_run(conn, run_id)

    if active:
        return active["run_id"], active["analysis_cutoff_at"]

    recent = _load_recent_finished_mcp_auto_run(
        conn,
        grace_seconds=_RECENT_FINISHED_MCP_AUTO_RUN_GRACE_SECONDS,
    )
    if recent:
        return recent["run_id"], recent["analysis_cutoff_at"]
    return None, None


def resolve_run_id_for_dispatch(conn: sqlite3.Connection, *, source: str, tool_name: str) -> str | None:
    run_id, _ = resolve_run_context_for_dispatch(conn, source=source, tool_name=tool_name)
    return run_id


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


def insert_link_decision_log(
    conn: sqlite3.Connection,
    *,
    alert_id: str,
    case_id: str,
    link_confidence: float,
    reason_summary: str,
    positive_factors: list[dict[str, Any]] | None = None,
    negative_factors: list[dict[str, Any]] | None = None,
    uncertainties: list[str] | None = None,
    supporting_evidence_ids: list[str] | None = None,
) -> str:
    decision_id = f"ldec_{uuid4().hex[:12]}"
    conn.execute(
        """
        insert into link_decisions (
          decision_id,
          occurred_at,
          run_id,
          alert_id,
          case_id,
          link_confidence,
          reason_summary,
          positive_factors_json,
          negative_factors_json,
          uncertainties_json,
          supporting_evidence_ids_json,
          analysis_cutoff_at
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            decision_id,
            now_iso(),
            _resolve_run_id(conn),
            alert_id,
            case_id,
            link_confidence,
            reason_summary,
            json.dumps(positive_factors or [], ensure_ascii=False),
            json.dumps(negative_factors or [], ensure_ascii=False),
            json.dumps(uncertainties or [], ensure_ascii=False),
            json.dumps(supporting_evidence_ids or [], ensure_ascii=False),
            _resolve_analysis_cutoff(conn),
        ),
    )
    return decision_id


def insert_case_assessment_log(
    conn: sqlite3.Connection,
    *,
    case_id: str,
    risk_level: str,
    assessment_confidence: float | None,
    current_stage: str,
    verdict: str,
    reason_summary: str,
    supporting_alert_ids: list[str] | None = None,
    supporting_evidence_ids: list[str] | None = None,
) -> str:
    assessment_id = f"cass_{uuid4().hex[:12]}"
    conn.execute(
        """
        insert into case_assessments (
          assessment_id,
          occurred_at,
          run_id,
          case_id,
          risk_level,
          assessment_confidence,
          current_stage,
          verdict,
          reason_summary,
          supporting_alert_ids_json,
          supporting_evidence_ids_json,
          analysis_cutoff_at
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            assessment_id,
            now_iso(),
            _resolve_run_id(conn),
            case_id,
            risk_level,
            assessment_confidence,
            current_stage,
            verdict,
            reason_summary,
            json.dumps(supporting_alert_ids or [], ensure_ascii=False),
            json.dumps(supporting_evidence_ids or [], ensure_ascii=False),
            _resolve_analysis_cutoff(conn),
        ),
    )
    return assessment_id


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
