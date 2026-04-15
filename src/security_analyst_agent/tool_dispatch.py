import sqlite3
import time
from typing import Callable

from security_analyst_agent.repositories.audit import (
    bind_run_context,
    finalize_mcp_auto_run_after_tool,
    insert_tool_call_log,
    reset_bound_run_context,
    resolve_run_context_for_dispatch,
)
from security_analyst_agent.tools.alert_tools import alert_ack, alert_detail, alert_fetch
from security_analyst_agent.tools.assessment_tools import assessment_upsert
from security_analyst_agent.tools.asset_tools import asset_search
from security_analyst_agent.tools.actor_tools import (
    actor_case_add_observation,
    actor_case_find_candidates,
    actor_case_get,
    actor_case_link,
    actor_case_list,
    actor_case_upsert,
)
from security_analyst_agent.tools.case_tools import (
    case_explain_link,
    case_get,
    case_link_alert,
    case_timeline,
    case_update_risk,
    case_upsert,
)
from security_analyst_agent.tools.derived_tools import evidence_upsert, timeline_upsert
from security_analyst_agent.tools.intel_tools import intel_lookup
from security_analyst_agent.tools.output_tools import notify_preview, notify_send, report_draft

ToolHandler = Callable[[sqlite3.Connection, dict], dict]

TOOL_HANDLERS: dict[str, ToolHandler] = {
    "alert.fetch": alert_fetch,
    "alert.detail": alert_detail,
    "alert.ack": alert_ack,
    "asset.search": asset_search,
    "actor.case-list": actor_case_list,
    "actor.case-get": actor_case_get,
    "actor.case-find-candidates": actor_case_find_candidates,
    "actor.case-upsert": actor_case_upsert,
    "actor.case-add-observation": actor_case_add_observation,
    "actor.case-link": actor_case_link,
    "case.get": case_get,
    "case.timeline": case_timeline,
    "case.explain-link": case_explain_link,
    "case.upsert": case_upsert,
    "case.link-alert": case_link_alert,
    "case.update-risk": case_update_risk,
    "evidence.upsert": evidence_upsert,
    "timeline.upsert": timeline_upsert,
    "assessment.upsert": assessment_upsert,
    "intel.lookup": intel_lookup,
    "notify.send": notify_send,
    "notify.preview": notify_preview,
    "report.draft": report_draft,
}


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
