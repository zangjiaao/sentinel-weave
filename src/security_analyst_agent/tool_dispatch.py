import json
import sqlite3
import time
from typing import Any, Callable

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
    case_list,
    case_link_alert,
    case_link_alert_batch,
    case_search,
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
    "case.list": case_list,
    "case.search": case_search,
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


def _extract_alert_ids_from_fetch_result(result: dict[str, Any]) -> list[str]:
    collected: list[str] = []
    refs = result.get("refs")
    if isinstance(refs, dict):
        refs_alert_ids = refs.get("alert_ids")
        if isinstance(refs_alert_ids, list):
            collected.extend(str(item) for item in refs_alert_ids if item)

    data = result.get("data")
    if isinstance(data, dict):
        alerts = data.get("alerts")
        if isinstance(alerts, list):
            for alert_item in alerts:
                if not isinstance(alert_item, dict):
                    continue
                alert_id = alert_item.get("alert_id")
                if alert_id:
                    collected.append(str(alert_id))

        clusters = data.get("clusters")
        if isinstance(clusters, list):
            for cluster_item in clusters:
                if not isinstance(cluster_item, dict):
                    continue
                sample_alert_ids = cluster_item.get("sample_alert_ids")
                if isinstance(sample_alert_ids, list):
                    collected.extend(str(item) for item in sample_alert_ids if item)

    return list(dict.fromkeys(collected))


def _validate_alert_detail_batch_ids(
    conn: sqlite3.Connection,
    *,
    payload: dict,
    source: str,
    run_id: str | None,
) -> dict[str, Any] | None:
    if source != "mcp":
        return None
    if not isinstance(payload, dict):
        return None
    raw_alert_ids = payload.get("alert_ids")
    if not isinstance(raw_alert_ids, list):
        return None
    requested_alert_ids = list(dict.fromkeys(str(item) for item in raw_alert_ids if item))
    if not requested_alert_ids:
        return None
    if not run_id:
        return {
            "ok": False,
            "summary": "alert.detail-batch 需要先调用 alert.fetch 获取有效 alert_id",
            "data": {
                "tool": "alert.detail-batch",
                "invalid_alert_ids": requested_alert_ids,
                "allowed_alert_ids_sample": [],
            },
            "warnings": ["detail_batch_requires_fetch_context"],
            "refs": {},
            "page": {"next_cursor": None, "has_more": False},
            "meta": {},
        }

    fetch_rows = conn.execute(
        """
        select call_id, result_json
        from agent_tool_calls
        where run_id = ?
          and source = 'mcp'
          and tool_name = 'alert.fetch'
          and result_ok = 1
        order by occurred_at asc, rowid asc
        """,
        (run_id,),
    ).fetchall()
    allowed_alert_ids: list[str] = []
    for row in fetch_rows:
        try:
            result_body = json.loads(row["result_json"] or "{}")
        except json.JSONDecodeError:
            continue
        if not isinstance(result_body, dict):
            continue
        allowed_alert_ids.extend(_extract_alert_ids_from_fetch_result(result_body))
    allowed_alert_ids = list(dict.fromkeys(allowed_alert_ids))
    if not allowed_alert_ids:
        return {
            "ok": False,
            "summary": "alert.detail-batch 需要先从 alert.fetch 返回中选择 alert_id，当前 run 尚无可用 ID",
            "data": {
                "tool": "alert.detail-batch",
                "run_id": run_id,
                "invalid_alert_ids": requested_alert_ids,
                "allowed_alert_ids_sample": [],
            },
            "warnings": ["detail_batch_requires_fetch_context"],
            "refs": {},
            "page": {"next_cursor": None, "has_more": False},
            "meta": {},
        }

    allowed_set = set(allowed_alert_ids)
    invalid_alert_ids = [alert_id for alert_id in requested_alert_ids if alert_id not in allowed_set]
    if not invalid_alert_ids:
        return None
    return {
        "ok": False,
        "summary": (
            "alert.detail-batch 仅允许使用本次巡检里 alert.fetch 返回的 alert_id，"
            f"发现 {len(invalid_alert_ids)} 条无效 ID"
        ),
        "data": {
            "tool": "alert.detail-batch",
            "run_id": run_id,
            "invalid_alert_ids": invalid_alert_ids,
            "allowed_alert_ids_sample": allowed_alert_ids[:20],
        },
        "warnings": ["detail_batch_alert_id_out_of_fetch_scope"],
        "refs": {},
        "page": {"next_cursor": None, "has_more": False},
        "meta": {},
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
        if tool_name == "alert.detail-batch":
            prevalidated = _validate_alert_detail_batch_ids(
                conn,
                payload=payload,
                source=source,
                run_id=run_id,
            )
            if prevalidated is not None:
                finalize_mcp_auto_run_after_tool(
                    conn,
                    source=source,
                    run_id=run_id,
                    tool_name=tool_name,
                    result=prevalidated,
                )
                insert_tool_call_log(
                    conn,
                    source=source,
                    tool_name=tool_name,
                    payload=payload,
                    result=prevalidated,
                    latency_ms=0,
                )
                conn.commit()
                return prevalidated

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
