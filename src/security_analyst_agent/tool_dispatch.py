import json
import sqlite3
import time
from typing import Any, Callable

from pydantic import ValidationError

from security_analyst_agent.config import (
    DEFAULT_MCP_ALERT_FETCH_AUTO_CLUSTER_THRESHOLD,
    DEFAULT_NEUTRAL_CASE_LINK_GUARD,
)
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


def _fetch_alert_signal_map(conn: sqlite3.Connection, alert_ids: list[str]) -> dict[str, dict[str, str]]:
    deduped = list(dict.fromkeys(str(item) for item in alert_ids if item))
    if not deduped:
        return {}
    rows = conn.execute(
        f"""
        select alert_id, severity, attack_stage
        from alerts
        where alert_id in ({', '.join('?' for _ in deduped)})
        """,
        deduped,
    ).fetchall()
    signal_map: dict[str, dict[str, str]] = {}
    for row in rows:
        signal_map[str(row["alert_id"])] = {
            "severity": str(row["severity"] or "").lower(),
            "attack_stage": str(row["attack_stage"] or "").lower(),
        }
    return signal_map


def _normalize_alert_fetch_payload_for_mcp(payload: dict, *, source: str) -> dict:
    if source != "mcp":
        return payload
    if not isinstance(payload, dict):
        return payload

    next_payload = dict(payload)
    raw_mode = next_payload.get("mode")
    mode = str(raw_mode).strip().lower() if isinstance(raw_mode, str) else ""

    if mode == "alerts" and "cursor" not in next_payload:
        next_payload["mode"] = "auto"
        mode = "auto"
    elif not mode:
        next_payload["mode"] = "auto"
        mode = "auto"

    if mode == "auto" and "auto_cluster_threshold" not in next_payload:
        next_payload["auto_cluster_threshold"] = max(1, DEFAULT_MCP_ALERT_FETCH_AUTO_CLUSTER_THRESHOLD)
    return next_payload


def _is_low_recon_noise(signal_item: dict[str, str] | None) -> bool:
    if not signal_item:
        return False
    return signal_item.get("severity") == "low" and signal_item.get("attack_stage") == "recon"


def _guard_case_link_alert_batch_payload(
    conn: sqlite3.Connection,
    *,
    payload: dict,
    source: str,
) -> tuple[dict, list[str]]:
    if source != "mcp" or not DEFAULT_NEUTRAL_CASE_LINK_GUARD:
        return payload, []
    if not isinstance(payload, dict):
        return payload, []
    items = payload.get("items")
    if not isinstance(items, list):
        return payload, []

    alert_ids = [
        str(item.get("alert_id") or "")
        for item in items
        if isinstance(item, dict) and str(item.get("alert_id") or "").strip()
    ]
    signal_map = _fetch_alert_signal_map(conn, alert_ids)
    kept_items: list[dict] = []
    skipped_alert_ids: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        alert_id = str(item.get("alert_id") or "").strip()
        if not alert_id:
            kept_items.append(item)
            continue
        if _is_low_recon_noise(signal_map.get(alert_id)):
            skipped_alert_ids.append(alert_id)
            continue
        kept_items.append(item)
    if not skipped_alert_ids:
        return payload, []
    next_payload = dict(payload)
    next_payload["items"] = kept_items
    return next_payload, list(dict.fromkeys(skipped_alert_ids))


def _guard_timeline_upsert_payload(
    conn: sqlite3.Connection,
    *,
    payload: dict,
    source: str,
) -> tuple[bool, list[str]]:
    if source != "mcp" or not DEFAULT_NEUTRAL_CASE_LINK_GUARD:
        return False, []
    if not isinstance(payload, dict):
        return False, []
    stage = str(payload.get("stage") or "").lower()
    if stage != "recon":
        return False, []
    related_alert_ids = payload.get("related_alert_ids")
    if not isinstance(related_alert_ids, list) or not related_alert_ids:
        return False, []
    deduped_alert_ids = list(dict.fromkeys(str(item) for item in related_alert_ids if item))
    signal_map = _fetch_alert_signal_map(conn, deduped_alert_ids)
    if not signal_map:
        return False, []
    if all(_is_low_recon_noise(signal_map.get(alert_id)) for alert_id in deduped_alert_ids):
        return True, deduped_alert_ids
    return False, []


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


def _batch_payload_guidance(tool_name: str) -> dict[str, Any] | None:
    if tool_name == "case.upsert-batch":
        return {
            "required_fields": ["case_id", "title", "status", "overall_severity", "current_stage"],
            "example_payload": {
                "items": [
                    {
                        "case_id": "case_demo_001",
                        "title": "示例案件",
                        "status": "open",
                        "overall_severity": "high",
                        "current_stage": "persistence",
                    }
                ]
            },
            "recommended_next_actions": [
                {
                    "tool": "case.search",
                    "reason": "先确认是否已有可复用案件，再决定新建/更新",
                },
                {
                    "tool": "case.list",
                    "reason": "缺少检索键时先列出现有案件，避免盲目创建",
                },
            ],
        }
    if tool_name == "case.link-alert-batch":
        return {
            "required_fields": ["case_id", "alert_id", "confidence", "reason"],
            "example_payload": {
                "items": [
                    {
                        "case_id": "case_demo_001",
                        "alert_id": "alt_demo_001",
                        "confidence": 0.85,
                        "reason": "same asset + stage continuity",
                    }
                ]
            },
            "recommended_next_actions": [
                {
                    "tool": "case.search",
                    "reason": "先定位最匹配案件，避免误关联",
                },
                {
                    "tool": "case.explain-link",
                    "reason": "先生成关联解释，再执行批量关联",
                },
            ],
        }
    if tool_name == "assessment.upsert-batch":
        return {
            "required_fields": [
                "entity_type",
                "entity_key",
                "risk_level",
                "assessment_confidence",
                "verdict",
                "reason_summary",
            ],
            "example_payload": {
                "items": [
                    {
                        "entity_type": "ip",
                        "entity_key": "198.51.100.23",
                        "risk_level": "high",
                        "assessment_confidence": 0.8,
                        "verdict": "attacker",
                        "reason_summary": "webshell exploitation chain continuity",
                    }
                ]
            },
            "recommended_next_actions": [
                {
                    "tool": "alert.detail-batch",
                    "reason": "补齐支持证据后再写评估",
                }
            ],
        }
    if tool_name == "actor.case-link-batch":
        return {
            "required_fields": ["case_actor_id", "target_type", "target_id", "link_confidence", "link_reason"],
            "example_payload": {
                "items": [
                    {
                        "case_actor_id": "act_demo_001",
                        "target_type": "alert",
                        "target_id": "alt_demo_001",
                        "link_confidence": 0.8,
                        "link_reason": "same actor behavior continuation",
                    }
                ]
            },
            "recommended_next_actions": [
                {
                    "tool": "actor.case-find-candidates",
                    "reason": "先找候选 actor，再执行链接",
                }
            ],
        }
    if tool_name == "actor.case-add-observation-batch":
        return {
            "required_fields": [
                "case_actor_id",
                "observation_type",
                "observation_key",
                "observation_value",
                "confidence",
            ],
            "example_payload": {
                "items": [
                    {
                        "case_actor_id": "act_demo_001",
                        "observation_type": "src_ip",
                        "observation_key": "198.51.100.23",
                        "observation_value": "198.51.100.23",
                        "confidence": 0.8,
                    }
                ]
            },
            "recommended_next_actions": [
                {
                    "tool": "actor.case-get",
                    "reason": "确认 actor 已存在后再补充观测",
                }
            ],
        }
    return None


def dispatch_tool(conn: sqlite3.Connection, tool_name: str, payload: dict, source: str = "unknown") -> dict:
    if tool_name not in TOOL_HANDLERS:
        raise ValueError(f"unsupported tool: {tool_name}")

    run_id, analysis_cutoff_at = resolve_run_context_for_dispatch(conn, source=source, tool_name=tool_name)
    token = bind_run_context(run_id, analysis_cutoff_at)
    try:
        skipped_noise_alert_ids: list[str] = []
        if tool_name == "alert.fetch":
            payload = _normalize_alert_fetch_payload_for_mcp(payload, source=source)
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
        if tool_name == "case.link-alert-batch":
            payload, skipped_noise_alert_ids = _guard_case_link_alert_batch_payload(
                conn,
                payload=payload,
                source=source,
            )
            if skipped_noise_alert_ids and not payload.get("items"):
                noop_result = {
                    "ok": True,
                    "summary": (
                        "neutral_guard skipped case linking for low-signal recon alerts "
                        f"({len(skipped_noise_alert_ids)} items)"
                    ),
                    "data": {"tool": tool_name, "skipped_alert_ids": skipped_noise_alert_ids},
                    "warnings": ["neutral_case_link_guard_skipped_noise_recon_alerts"],
                    "refs": {"alert_ids": skipped_noise_alert_ids},
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
                    latency_ms=0,
                )
                conn.commit()
                return noop_result
        if tool_name == "timeline.upsert":
            should_skip_timeline, skipped_alert_ids = _guard_timeline_upsert_payload(
                conn,
                payload=payload,
                source=source,
            )
            if should_skip_timeline:
                noop_result = {
                    "ok": True,
                    "summary": (
                        "neutral_guard skipped timeline node for recon-noise-only alerts "
                        f"({len(skipped_alert_ids)} alerts)"
                    ),
                    "data": {"tool": tool_name, "skipped_alert_ids": skipped_alert_ids},
                    "warnings": ["neutral_timeline_guard_skipped_recon_noise_node"],
                    "refs": {"alert_ids": skipped_alert_ids},
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
                    latency_ms=0,
                )
                conn.commit()
                return noop_result

        start = time.perf_counter()
        result: dict
        try:
            result = TOOL_HANDLERS[tool_name](conn, payload)
        except ValidationError as exc:
            latency_ms = int((time.perf_counter() - start) * 1000)
            guidance = _batch_payload_guidance(tool_name)
            warnings = ["payload_validation_error"]
            if guidance is not None:
                warnings.extend(["batch_items_required", "tool_schema_guidance"])
            validation_result = {
                "ok": False,
                "summary": _validation_error_summary(exc),
                "data": {
                    "tool": tool_name,
                    "validation_errors": exc.errors(),
                    "schema_guidance": guidance,
                },
                "warnings": warnings,
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
        if skipped_noise_alert_ids:
            result = dict(result)
            warnings = result.get("warnings")
            warnings_list = list(warnings) if isinstance(warnings, list) else []
            warnings_list.append("neutral_case_link_guard_skipped_noise_recon_alerts")
            result["warnings"] = list(dict.fromkeys(warnings_list))

            refs = result.get("refs")
            refs_map = dict(refs) if isinstance(refs, dict) else {}
            existing_alert_ids = refs_map.get("alert_ids")
            refs_alert_ids = list(existing_alert_ids) if isinstance(existing_alert_ids, list) else []
            refs_alert_ids.extend(skipped_noise_alert_ids)
            refs_map["alert_ids"] = list(dict.fromkeys(refs_alert_ids))
            result["refs"] = refs_map

            data = result.get("data")
            data_map = dict(data) if isinstance(data, dict) else {}
            data_map["skipped_alert_ids"] = skipped_noise_alert_ids
            result["data"] = data_map
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
