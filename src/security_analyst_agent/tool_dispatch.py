import sqlite3
import time
from typing import Callable

from pydantic import ValidationError

from security_analyst_agent.repositories.audit import (
    bind_run_context,
    finalize_mcp_auto_run_after_tool,
    insert_tool_call_log,
    reset_bound_run_context,
    resolve_run_context_for_dispatch,
)
from security_analyst_agent.tools.alert_tools import alert_ack, alert_detail, alert_detail_batch, alert_fetch
from security_analyst_agent.tools.assessment_tools import assessment_upsert, assessment_upsert_batch
from security_analyst_agent.tools.asset_tools import asset_search
from security_analyst_agent.tools.actor_tools import (
    actor_case_add_observation,
    actor_case_add_observation_batch,
    actor_case_find_candidates,
    actor_case_get,
    actor_case_link,
    actor_case_link_batch,
    actor_case_list,
    actor_case_upsert,
)
from security_analyst_agent.tools.case_tools import (
    case_explain_link,
    case_get,
    case_link_alert,
    case_link_alert_batch,
    case_timeline,
    case_update_risk,
    case_upsert_batch,
    case_upsert,
)
from security_analyst_agent.tools.derived_tools import evidence_upsert, timeline_upsert
from security_analyst_agent.tools.intel_tools import intel_lookup
from security_analyst_agent.tools.output_tools import notify_preview, notify_send, report_draft

ToolHandler = Callable[[sqlite3.Connection, dict], dict]

TOOL_HANDLERS: dict[str, ToolHandler] = {
    "alert.fetch": alert_fetch,
    "alert.detail": alert_detail,
    "alert.detail-batch": alert_detail_batch,
    "alert.ack": alert_ack,
    "asset.search": asset_search,
    "actor.case-list": actor_case_list,
    "actor.case-get": actor_case_get,
    "actor.case-find-candidates": actor_case_find_candidates,
    "actor.case-upsert": actor_case_upsert,
    "actor.case-add-observation": actor_case_add_observation,
    "actor.case-add-observation-batch": actor_case_add_observation_batch,
    "actor.case-link": actor_case_link,
    "actor.case-link-batch": actor_case_link_batch,
    "case.get": case_get,
    "case.timeline": case_timeline,
    "case.explain-link": case_explain_link,
    "case.upsert": case_upsert,
    "case.upsert-batch": case_upsert_batch,
    "case.link-alert": case_link_alert,
    "case.link-alert-batch": case_link_alert_batch,
    "case.update-risk": case_update_risk,
    "evidence.upsert": evidence_upsert,
    "timeline.upsert": timeline_upsert,
    "assessment.upsert": assessment_upsert,
    "assessment.upsert-batch": assessment_upsert_batch,
    "intel.lookup": intel_lookup,
    "notify.send": notify_send,
    "notify.preview": notify_preview,
    "report.draft": report_draft,
}


def _validation_error_summary(exc: ValidationError) -> str:
    errors = exc.errors()
    if not errors:
        return "payload 校验失败"
    first = errors[0]
    location = ".".join(str(item) for item in first.get("loc", []))
    message = str(first.get("msg") or "invalid payload")
    if location:
        return f"payload 校验失败：{location} {message}"
    return f"payload 校验失败：{message}"


_SOFT_NOOP_BATCH_TOOLS = {
    "case.upsert-batch",
    "case.link-alert-batch",
    "assessment.upsert-batch",
    "actor.case-link-batch",
    "actor.case-add-observation-batch",
}


def _is_soft_noop_batch_validation(tool_name: str, payload: dict, exc: ValidationError, *, source: str) -> bool:
    if source != "mcp":
        return False
    if tool_name not in _SOFT_NOOP_BATCH_TOOLS:
        return False
    if not isinstance(payload, dict):
        return False
    items = payload.get("items")
    if isinstance(items, list) and len(items) > 0:
        return False
    errors = exc.errors()
    if not errors:
        return False
    for error in errors:
        location = tuple(error.get("loc", ()))
        if not location:
            continue
        first_location = str(location[0])
        if first_location != "items":
            continue
        error_type = str(error.get("type", "")).lower()
        if error_type in {"missing", "list_too_short", "too_short", "value_error.missing"}:
            return True
    return False


def dispatch_tool(conn: sqlite3.Connection, tool_name: str, payload: dict, source: str = "unknown") -> dict:
    if tool_name not in TOOL_HANDLERS:
        raise ValueError(f"unsupported tool: {tool_name}")

    run_id, analysis_cutoff_at = resolve_run_context_for_dispatch(conn, source=source, tool_name=tool_name)
    token = bind_run_context(run_id, analysis_cutoff_at)
    try:
        start = time.perf_counter()
        result: dict
        try:
            result = TOOL_HANDLERS[tool_name](conn, payload)
        except ValidationError as exc:
            latency_ms = int((time.perf_counter() - start) * 1000)
            if _is_soft_noop_batch_validation(tool_name, payload, exc, source=source):
                noop_result = {
                    "ok": True,
                    "summary": "empty batch payload skipped",
                    "data": {"tool": tool_name, "skipped": True, "reason": "empty_batch_payload"},
                    "warnings": ["empty_batch_payload_skipped"],
                    "refs": {},
                    "page": {"next_cursor": None, "has_more": False},
                    "meta": {},
                }
                finalize_mcp_auto_run_after_tool(
                    conn,
                    source=source,
                    run_id=run_id,
                    tool_name=tool_name,
                    result=noop_result,
                )
                insert_tool_call_log(
                    conn,
                    source=source,
                    tool_name=tool_name,
                    payload=payload,
                    result=noop_result,
                    latency_ms=latency_ms,
                )
                conn.commit()
                return noop_result
            validation_result = {
                "ok": False,
                "summary": _validation_error_summary(exc),
                "data": {"tool": tool_name, "validation_errors": exc.errors()},
                "warnings": ["payload_validation_error"],
                "refs": {},
                "page": {"next_cursor": None, "has_more": False},
                "meta": {},
            }
            finalize_mcp_auto_run_after_tool(
                conn,
                source=source,
                run_id=run_id,
                tool_name=tool_name,
                result=validation_result,
            )
            insert_tool_call_log(
                conn,
                source=source,
                tool_name=tool_name,
                payload=payload,
                result=validation_result,
                latency_ms=latency_ms,
            )
            conn.commit()
            return validation_result
        except Exception:
            latency_ms = int((time.perf_counter() - start) * 1000)
            fallback_result = {
                "ok": False,
                "summary": "tool execution exception",
                "data": {"tool": tool_name},
                "warnings": ["tool_exception"],
                "refs": {},
                "page": {"next_cursor": None, "has_more": False},
                "meta": {},
            }
            insert_tool_call_log(
                conn,
                source=source,
                tool_name=tool_name,
                payload=payload,
                result=fallback_result,
                latency_ms=latency_ms,
            )
            conn.commit()
            raise

        latency_ms = int((time.perf_counter() - start) * 1000)
        finalize_mcp_auto_run_after_tool(
            conn,
            source=source,
            run_id=run_id,
            tool_name=tool_name,
            result=result,
        )
        insert_tool_call_log(
            conn,
            source=source,
            tool_name=tool_name,
            payload=payload,
            result=result,
            latency_ms=latency_ms,
        )
        conn.commit()
        return result
    finally:
        reset_bound_run_context(token)
