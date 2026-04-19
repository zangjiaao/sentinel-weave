from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from hashlib import sha1
import re
from typing import Any, Callable

from security_analyst_agent.config import DEFAULT_OPENAI_BASE_URL
from security_analyst_agent.mcp_server import CORE_TOOL_NAMES, TOOL_DESCRIPTIONS, TOOL_REQUEST_MODELS
from security_analyst_agent.repositories.audit import insert_agent_output_log
from security_analyst_agent.tool_dispatch import dispatch_tool

OpenAIClientFactory = Callable[[], Any]


@dataclass
class OpenAIPatrolResult:
    status: str
    detail: str
    response_id: str | None
    turns: int = 0
    tool_calls: int = 0
    read_tool_calls: int = 0
    write_tool_calls: int = 0
    usage_input_tokens: int = 0
    usage_output_tokens: int = 0
    usage_cached_input_tokens: int = 0
    fetch_resume_payload: dict[str, Any] | None = None


def _default_openai_client_factory() -> Any:
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError("openai package is required for trigger_mode=openai") from exc
    if DEFAULT_OPENAI_BASE_URL:
        return OpenAI(base_url=DEFAULT_OPENAI_BASE_URL)
    return OpenAI()


def _schema_for_tool(tool_name: str) -> dict[str, Any]:
    request_model = TOOL_REQUEST_MODELS.get(tool_name)
    if request_model is None:
        return {"type": "object", "properties": {}}
    return request_model.model_json_schema()


def _openai_tool_name(tool_name: str) -> str:
    return tool_name.replace(".", "_").replace("-", "_")


COMPACT_TOOL_NAMES = (
    "alert.fetch",
    "alert.suspect-ip-topk",
    "alert.ip-context",
    "alert.detail-batch",
    "alert.ack",
    "case.list",
    "case.search",
    "case.get",
    "case.timeline",
    "case.explain-link",
    "case.upsert-batch",
    "case.link-alert-batch",
    "case.update-risk",
    "assessment.upsert-batch",
    "timeline.upsert",
    "evidence.upsert",
    "actor.case-find-candidates",
    "actor.case-list",
    "actor.case-upsert",
    "actor.case-add-observation-batch",
    "actor.case-link-batch",
    "notify.send",
)


def _resolve_tool_names(tool_profile: str) -> tuple[str, ...]:
    normalized = (tool_profile or "").strip().lower()
    if normalized in {"", "compact", "core"}:
        return COMPACT_TOOL_NAMES
    if normalized in {"full", "all"}:
        return tuple(CORE_TOOL_NAMES)
    return COMPACT_TOOL_NAMES


def _build_openai_tools(tool_profile: str = "compact") -> tuple[list[dict[str, Any]], dict[str, str]]:
    specs: list[dict[str, Any]] = []
    name_map: dict[str, str] = {}
    for tool_name in _resolve_tool_names(tool_profile):
        openai_name = _openai_tool_name(tool_name)
        name_map[openai_name] = tool_name
        specs.append(
            {
                "type": "function",
                "name": openai_name,
                "description": f"{TOOL_DESCRIPTIONS.get(tool_name, '')} (backend tool: {tool_name})",
                "parameters": _schema_for_tool(tool_name),
            }
        )
    return specs, name_map


def _read_attr_or_key(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        return value.get(key, default)
    return getattr(value, key, default)


def _extract_response_id(response: Any) -> str | None:
    response_id = _read_attr_or_key(response, "id")
    if isinstance(response_id, str) and response_id.strip():
        return response_id.strip()
    return None


def _extract_output_text(response: Any) -> str:
    text = _read_attr_or_key(response, "output_text")
    if isinstance(text, str):
        return text
    return ""


def _extract_output_item_count(response: Any) -> int:
    output = _read_attr_or_key(response, "output", [])
    if isinstance(output, list):
        return len(output)
    return 0


def _extract_tool_calls(response: Any) -> list[dict[str, str]]:
    output = _read_attr_or_key(response, "output", [])
    if not isinstance(output, list):
        return []
    calls: list[dict[str, str]] = []
    for item in output:
        item_type = _read_attr_or_key(item, "type")
        if item_type != "function_call":
            continue
        tool_name = _read_attr_or_key(item, "name")
        call_id = _read_attr_or_key(item, "call_id") or _read_attr_or_key(item, "id")
        arguments = _read_attr_or_key(item, "arguments", "")
        if not isinstance(tool_name, str) or not tool_name.strip():
            continue
        if not isinstance(call_id, str) or not call_id.strip():
            continue
        if isinstance(arguments, dict):
            argument_text = json.dumps(arguments, ensure_ascii=False)
        elif isinstance(arguments, str):
            argument_text = arguments
        else:
            argument_text = "{}"
        calls.append({"name": tool_name, "call_id": call_id, "arguments": argument_text})
    return calls


def _invoke_response_create(client: Any, request: dict[str, Any]) -> Any:
    responses = _read_attr_or_key(client, "responses")
    if responses is None:
        raise RuntimeError("openai client missing responses API")
    create = _read_attr_or_key(responses, "create")
    if not callable(create):
        raise RuntimeError("openai client missing responses.create")
    return create(**request)


def _invoke_response_create_with_tool_choice_fallback(client: Any, request: dict[str, Any]) -> Any:
    try:
        return _invoke_response_create(client, request)
    except Exception:
        if "tool_choice" not in request:
            raise
        fallback_request = dict(request)
        fallback_request.pop("tool_choice", None)
        return _invoke_response_create(client, fallback_request)


def _to_int(value: Any, default: int = 0) -> int:
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


def _extract_usage_snapshot(response: Any) -> dict[str, int]:
    usage = _read_attr_or_key(response, "usage", None)
    input_tokens = _to_int(
        _read_attr_or_key(usage, "input_tokens", _read_attr_or_key(usage, "prompt_tokens", 0)),
        default=0,
    )
    output_tokens = _to_int(
        _read_attr_or_key(usage, "output_tokens", _read_attr_or_key(usage, "completion_tokens", 0)),
        default=0,
    )
    input_details = _read_attr_or_key(usage, "input_tokens_details", None)
    cached_input_tokens = _to_int(
        _read_attr_or_key(input_details, "cached_tokens", _read_attr_or_key(usage, "cached_input_tokens", 0)),
        default=0,
    )
    return {
        "input_tokens": max(0, input_tokens),
        "output_tokens": max(0, output_tokens),
        "cached_input_tokens": max(0, cached_input_tokens),
    }


_REPEATED_INVALID_BLOCK_WARNINGS = {
    "payload_validation_error",
    "detail_batch_requires_fetch_context",
    "detail_batch_alert_id_out_of_fetch_scope",
    "batch_items_required",
    "case_link_requires_existing_case",
    "patrol_requires_initial_alert_fetch",
}

_LOCAL_BATCH_ITEMS_REQUIRED_FIELDS: dict[str, list[str]] = {
    "case.upsert-batch": ["case_id", "title", "status", "overall_severity", "current_stage"],
    "case.link-alert-batch": ["case_id", "alert_id", "confidence", "reason"],
    "assessment.upsert-batch": [
        "entity_type",
        "entity_key",
        "risk_level",
        "assessment_confidence",
        "verdict",
        "reason_summary",
    ],
}

_READ_ONLY_TOOL_NAMES = {
    "alert.fetch",
    "alert.suspect-ip-topk",
    "alert.ip-context",
    "alert.detail-batch",
    "asset.search",
    "case.list",
    "case.search",
    "case.get",
    "case.timeline",
    "case.explain-link",
    "actor.case-find-candidates",
    "actor.case-list",
    "actor.case-get",
    "intel.lookup",
    "notify.preview",
    "report.draft",
}

_PERSISTENCE_WRITE_TOOL_NAMES = {
    "case.upsert-batch",
    "case.link-alert-batch",
    "case.update-risk",
    "assessment.upsert-batch",
    "timeline.upsert",
    "evidence.upsert",
    "actor.case-upsert",
    "actor.case-add-observation-batch",
    "actor.case-link-batch",
    "notify.send",
}

_DISCOVERY_REQUIRED_TOOLS = (
    "alert.fetch",
    "alert.suspect-ip-topk",
    "alert.ip-context",
    "alert.detail-batch",
)

_WRITE_TOOL_DISCOVERY_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "case.upsert-batch": (
        "alert.fetch",
        "alert.suspect-ip-topk",
        "alert.detail-batch",
    ),
}


def _tool_payload_signature(tool_name: str, payload: dict[str, Any]) -> str:
    try:
        canonical_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except TypeError:
        canonical_payload = str(payload)
    return f"{tool_name}::{canonical_payload}"


def _should_block_repeated_invalid_call(tool_result: dict[str, Any]) -> bool:
    if tool_result.get("ok") is True:
        return False
    warnings = tool_result.get("warnings")
    if not isinstance(warnings, list):
        return False
    warning_set = {str(item) for item in warnings}
    return len(warning_set & _REPEATED_INVALID_BLOCK_WARNINGS) > 0


def _duplicate_invalid_block_result(tool_name: str) -> dict[str, Any]:
    recommended_next_actions: list[dict[str, str]] = []
    if tool_name == "alert.detail-batch":
        recommended_next_actions = [
            {
                "tool": "alert.fetch",
                "reason": "先获取本轮可用 alert_id，再调用 alert.detail-batch",
            }
        ]
    elif tool_name in {"case.upsert-batch", "assessment.upsert-batch", "case.link-alert-batch"}:
        recommended_next_actions = [
            {
                "tool": tool_name,
                "reason": "修正 payload，确保 items 至少包含 1 条合法记录后再调用",
            }
        ]
    return {
        "ok": False,
        "summary": "重复无效调用已拦截：请先按上一次错误提示修正参数后再重试",
        "data": {
            "tool": tool_name,
            "blocked_reason": "duplicate_invalid_tool_call",
            "recommended_next_actions": recommended_next_actions,
        },
        "warnings": ["duplicate_invalid_tool_call_blocked", "follow_previous_validation_guidance"],
        "refs": {},
        "page": {"next_cursor": None, "has_more": False},
        "meta": {},
    }


def _tool_call_kind(tool_name: str) -> str:
    if tool_name in _READ_ONLY_TOOL_NAMES:
        return "read"
    return "write"


def _read_phase_missing_tool(completed_tools: set[str], *, write_tool_name: str) -> str | None:
    required_tools = _WRITE_TOOL_DISCOVERY_REQUIREMENTS.get(write_tool_name, _DISCOVERY_REQUIRED_TOOLS)
    for tool_name in required_tools:
        if tool_name not in completed_tools:
            return tool_name
    return None


def _tool_budget_exceeded_result(
    *,
    tool_name: str,
    scope: str,
    limit: int,
    used: int,
) -> dict[str, Any]:
    return {
        "ok": False,
        "summary": "巡检预算守门触发：本轮工具预算已达上限",
        "data": {
            "tool": tool_name,
            "blocked_reason": "tool_budget_exceeded",
            "scope": scope,
            "limit": limit,
            "used": used,
            "recommended_next_actions": [
                {
                    "tool": "alert.ack",
                    "reason": "若当前已有明确噪音结论，可批量 ack 后结束本轮",
                }
            ],
        },
        "warnings": ["tool_budget_exceeded", f"budget_scope:{scope}"],
        "refs": {},
        "page": {"next_cursor": None, "has_more": False},
        "meta": {"source": "openai_runner_budget_guard"},
    }


def _read_phase_guard_result(tool_name: str, *, missing_tool: str) -> dict[str, Any]:
    return {
        "ok": False,
        "summary": "巡检流程约束：当前仍在读阶段，请先完成关键取证再执行建案/写入工具",
        "data": {
            "tool": tool_name,
            "blocked_reason": "read_phase_not_ready",
            "required_sequence": list(_DISCOVERY_REQUIRED_TOOLS),
            "next_required_tool": missing_tool,
            "recommended_next_actions": [
                {
                    "tool": missing_tool,
                    "reason": "先补齐发现阶段证据，再进行 case/assessment/evidence 写入",
                }
            ],
        },
        "warnings": ["patrol_read_phase_not_ready"],
        "refs": {},
        "page": {"next_cursor": None, "has_more": False},
        "meta": {"source": "openai_runner_read_phase_guard"},
    }


def _prevalidate_tool_payload(tool_name: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    required_fields = _LOCAL_BATCH_ITEMS_REQUIRED_FIELDS.get(tool_name)
    if required_fields is None:
        return None
    items = payload.get("items")
    if isinstance(items, list) and len(items) > 0:
        return None
    return {
        "ok": False,
        "summary": "payload 校验失败：items List should have at least 1 item after validation, not 0",
        "data": {
            "tool": tool_name,
            "schema_guidance": {
                "required_fields": required_fields,
                "tip": "items 不能为空；单条写入也必须传 items=[{...}]",
            },
        },
        "warnings": ["payload_validation_error", "batch_items_required", "tool_schema_guidance"],
        "refs": {},
        "page": {"next_cursor": None, "has_more": False},
        "meta": {"source": "openai_runner_local_precheck"},
    }


def _prevalidate_case_link_alert_batch_case_exists(
    conn: sqlite3.Connection,
    payload: dict[str, Any],
) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    items = payload.get("items")
    if not isinstance(items, list):
        return None

    case_ids = list(
        dict.fromkeys(
            str(item.get("case_id") or "").strip()
            for item in items
            if isinstance(item, dict) and str(item.get("case_id") or "").strip()
        )
    )
    if not case_ids:
        return None

    existing_case_rows = conn.execute(
        f"""
        select case_id
        from cases
        where case_id in ({", ".join("?" for _ in case_ids)})
        """,
        tuple(case_ids),
    ).fetchall()
    existing_case_ids = {str(row["case_id"]) for row in existing_case_rows}
    missing_case_ids = [case_id for case_id in case_ids if case_id not in existing_case_ids]
    if not missing_case_ids:
        return None

    available_case_rows = conn.execute(
        """
        select case_id
        from cases
        where merge_state is null or merge_state != 'merged'
        order by case_id asc
        limit 20
        """
    ).fetchall()
    available_case_ids = [str(row["case_id"]) for row in available_case_rows]

    return {
        "ok": False,
        "summary": (
            "payload 校验失败：case.link-alert-batch 包含未创建案件，"
            f"missing_case_count={len(missing_case_ids)}"
        ),
        "data": {
            "tool": "case.link-alert-batch",
            "missing_case_ids": missing_case_ids,
            "available_case_ids_sample": available_case_ids,
            "recommended_next_actions": [
                {
                    "tool": "case.upsert-batch",
                    "reason": "先创建缺失案件后再执行告警关联",
                },
                {
                    "tool": "case.list",
                    "reason": "先查看当前可用案件，避免误用不存在的 case_id",
                },
                {
                    "tool": "case.search",
                    "reason": "按 src_ip/asset/stage 搜索候选案件后再关联",
                },
            ],
        },
        "warnings": (
            ["payload_validation_error", "case_link_requires_existing_case"]
            + [f"case_not_found:{case_id}" for case_id in missing_case_ids]
        ),
        "refs": {"case_ids": available_case_ids},
        "page": {"next_cursor": None, "has_more": False},
        "meta": {"source": "openai_runner_local_precheck"},
    }


def _initial_fetch_required_result(tool_name: str) -> dict[str, Any]:
    return {
        "ok": False,
        "summary": "巡检流程约束：必须先调用 alert.fetch 拉取当前待研判告警，再执行其它工具",
        "data": {
            "tool": tool_name,
            "required_first_tool": "alert.fetch",
            "recommended_next_actions": [
                {
                    "tool": "alert.fetch",
                    "reason": "先获取本轮待处理告警与聚类摘要，再进行 case/assessment/notify 操作",
                }
            ],
        },
        "warnings": ["patrol_requires_initial_alert_fetch"],
        "refs": {},
        "page": {"next_cursor": None, "has_more": False},
        "meta": {"source": "openai_runner_patrol_guardrail"},
    }


def _as_float(value: Any, default: float) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return default
    return default


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _first_non_empty(*values: Any) -> str:
    for value in values:
        text = _safe_text(value)
        if text:
            return text
    return ""


def _normalize_status(value: str, default: str = "active") -> str:
    lowered = value.lower()
    if lowered in {"active", "open", "tracking", "triaged", "closed", "merged"}:
        if lowered == "open":
            return "active"
        return lowered
    return default


def _normalize_stage(value: str, default: str = "recon") -> str:
    lowered = value.lower()
    allowed = {
        "recon",
        "exploit",
        "persistence",
        "command_execution",
        "lateral_prep",
        "reactivation",
    }
    if lowered in allowed:
        return lowered
    return default


def _normalize_risk_level(value: str, default: str = "medium") -> str:
    lowered = value.lower()
    if lowered in {"low", "medium", "high", "critical"}:
        return lowered
    if lowered in {"info", "informational"}:
        return "low"
    if lowered in {"severe", "urgent"}:
        return "high"
    return default


def _normalize_verdict(value: str, default: str = "unknown") -> str:
    lowered = value.lower()
    mapping = {
        "attacker": "attacker",
        "threat_actor": "attacker",
        "compromised_host": "compromised_host",
        "compromised": "compromised_host",
        "host_compromised": "compromised_host",
        "noise": "noise",
        "benign": "noise",
        "unknown": "unknown",
    }
    return mapping.get(lowered, default)


def _looks_like_ip(value: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value))


def _normalize_entity_type(raw_type: str, *, entity_key: str) -> str:
    lowered = raw_type.lower()
    if lowered in {"ip", "asset", "actor"}:
        return lowered
    alias = {
        "attacker": "ip",
        "source_ip": "ip",
        "src_ip": "ip",
        "destination_ip": "ip",
        "dst_ip": "ip",
        "host": "asset",
        "asset_id": "asset",
        "server": "asset",
        "case_actor": "actor",
        "actor_profile": "actor",
    }
    if lowered in alias:
        return alias[lowered]
    if entity_key.startswith("asset_"):
        return "asset"
    if entity_key.startswith("act_") or entity_key.startswith("case_actor_"):
        return "actor"
    if _looks_like_ip(entity_key):
        return "ip"
    return "ip"


def _auto_case_actor_id(case_id: str, label: str) -> str:
    seed = f"{case_id}:{label}".encode("utf-8")
    return f"act_{sha1(seed).hexdigest()[:16]}"


def _ensure_dict_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    items = payload.get("items")
    if not isinstance(items, list):
        return []
    normalized: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            normalized.append(dict(item))
    return normalized


def _normalize_case_upsert_batch_payload(payload: dict[str, Any]) -> dict[str, Any]:
    raw_items = _ensure_dict_items(payload)
    if not raw_items and any(
        key in payload for key in ("case_id", "id", "canonical_case_id", "title", "name", "summary")
    ):
        raw_items = [dict(payload)]
    items: list[dict[str, Any]] = []
    for item in raw_items:
        case_id = _first_non_empty(item.get("case_id"), item.get("id"), item.get("canonical_case_id"))
        if not case_id:
            continue
        title = _first_non_empty(item.get("title"), item.get("name"), item.get("summary"), f"Case {case_id}")
        normalized_item = {
            "case_id": case_id,
            "title": title,
            "status": _normalize_status(_first_non_empty(item.get("status"), "active"), default="active"),
            "overall_severity": _normalize_risk_level(
                _first_non_empty(item.get("overall_severity"), item.get("severity"), item.get("risk_level"), "medium"),
                default="medium",
            ),
            "current_stage": _normalize_stage(
                _first_non_empty(item.get("current_stage"), item.get("stage"), item.get("attack_stage"), "recon"),
                default="recon",
            ),
        }
        primary_actor_id = _first_non_empty(item.get("primary_actor_id"), item.get("case_actor_id"))
        if primary_actor_id:
            normalized_item["primary_actor_id"] = primary_actor_id
        items.append(normalized_item)
    return {"items": items}


def _normalize_case_link_alert_batch_payload(payload: dict[str, Any]) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for item in _ensure_dict_items(payload):
        case_id = _first_non_empty(item.get("case_id"), item.get("id"))
        alert_id = _first_non_empty(item.get("alert_id"), item.get("target_id"))
        if not case_id or not alert_id:
            continue
        confidence = _as_float(item.get("confidence", item.get("link_confidence", 0.8)), default=0.8)
        reason = _first_non_empty(item.get("reason"), item.get("link_reason"), item.get("summary"), "tool:auto_normalized")
        items.append(
            {
                "case_id": case_id,
                "alert_id": alert_id,
                "confidence": max(0.0, min(1.0, confidence)),
                "reason": reason,
            }
        )
    return {"items": items}


def _normalize_assessment_upsert_batch_payload(payload: dict[str, Any]) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for item in _ensure_dict_items(payload):
        entity_key = _first_non_empty(
            item.get("entity_key"),
            item.get("entity_id"),
            item.get("indicator"),
            item.get("src_ip"),
            item.get("asset_id"),
            item.get("case_actor_id"),
        )
        if not entity_key:
            continue
        entity_type = _normalize_entity_type(_first_non_empty(item.get("entity_type"), item.get("type")), entity_key=entity_key)
        verdict = _normalize_verdict(_first_non_empty(item.get("verdict"), item.get("assessment"), "unknown"), default="unknown")
        normalized_item = {
            "entity_type": entity_type,
            "entity_key": entity_key,
            "entity_label": _first_non_empty(item.get("entity_label"), item.get("label"), entity_key),
            "related_case_id": _first_non_empty(item.get("related_case_id"), item.get("case_id")) or None,
            "risk_level": _normalize_risk_level(
                _first_non_empty(item.get("risk_level"), item.get("severity"), "medium"),
                default="medium",
            ),
            "assessment_confidence": max(
                0.0,
                min(1.0, _as_float(item.get("assessment_confidence", item.get("confidence", 0.75)), default=0.75)),
            ),
            "verdict": verdict,
            "reason_summary": _first_non_empty(item.get("reason_summary"), item.get("reason"), item.get("summary"), "tool:auto_normalized"),
            "supporting_alert_ids": item.get("supporting_alert_ids", item.get("alert_ids", [])) or [],
            "supporting_evidence_ids": item.get("supporting_evidence_ids", item.get("evidence_ids", [])) or [],
            "first_seen_at": _first_non_empty(item.get("first_seen_at")) or None,
            "last_seen_at": _first_non_empty(item.get("last_seen_at")) or None,
        }
        items.append(normalized_item)
    return {"items": items}


def _normalize_actor_case_upsert_payload(payload: dict[str, Any]) -> dict[str, Any]:
    case_id = _first_non_empty(payload.get("case_id"), payload.get("related_case_id"))
    label = _first_non_empty(payload.get("label"), payload.get("name"), "case actor")
    case_actor_id = _first_non_empty(payload.get("case_actor_id"), payload.get("actor_id"))
    if not case_actor_id and case_id:
        case_actor_id = _auto_case_actor_id(case_id, label)
    return {
        "case_actor_id": case_actor_id,
        "case_id": case_id,
        "label": label,
        "status": _normalize_status(_first_non_empty(payload.get("status"), "active"), default="active"),
        "profile_confidence": max(
            0.0,
            min(1.0, _as_float(payload.get("profile_confidence", payload.get("confidence", 0.7)), default=0.7)),
        ),
        "risk_level": _normalize_risk_level(_first_non_empty(payload.get("risk_level"), payload.get("severity"), "medium"), default="medium"),
        "is_primary": bool(payload.get("is_primary", False)),
        "current_stage": _normalize_stage(
            _first_non_empty(payload.get("current_stage"), payload.get("stage"), payload.get("attack_stage"), "recon"),
            default="recon",
        ),
        "first_seen_at": _first_non_empty(payload.get("first_seen_at")) or None,
        "last_seen_at": _first_non_empty(payload.get("last_seen_at")) or None,
        "summary": _first_non_empty(payload.get("summary"), payload.get("reason"), label),
    }


def _normalize_actor_case_add_observation_batch_payload(payload: dict[str, Any]) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for item in _ensure_dict_items(payload):
        case_actor_id = _first_non_empty(item.get("case_actor_id"), item.get("actor_id"))
        observation_key = _first_non_empty(
            item.get("observation_key"),
            item.get("key"),
            item.get("observation_value"),
            item.get("value"),
            item.get("indicator"),
            item.get("src_ip"),
            item.get("asset_id"),
        )
        if not case_actor_id or not observation_key:
            continue
        observation_value = _first_non_empty(item.get("observation_value"), item.get("value"), observation_key)
        items.append(
            {
                "case_actor_id": case_actor_id,
                "observation_type": _first_non_empty(item.get("observation_type"), item.get("type"), "artifact"),
                "observation_key": observation_key,
                "observation_value": observation_value,
                "confidence": max(0.0, min(1.0, _as_float(item.get("confidence", 0.8), default=0.8))),
                "first_seen_at": _first_non_empty(item.get("first_seen_at")) or None,
                "last_seen_at": _first_non_empty(item.get("last_seen_at")) or None,
                "source_count": int(item.get("source_count", 1) or 1),
            }
        )
    return {"items": items}


def _normalize_actor_case_link_batch_payload(payload: dict[str, Any]) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    target_type_alias = {"timeline": "timeline_event", "timelineevent": "timeline_event"}
    for item in _ensure_dict_items(payload):
        case_actor_id = _first_non_empty(item.get("case_actor_id"), item.get("actor_id"))
        target_id = _first_non_empty(
            item.get("target_id"),
            item.get("id"),
            item.get("alert_id"),
            item.get("evidence_id"),
            item.get("timeline_event_id"),
        )
        raw_target_type = _first_non_empty(item.get("target_type"), "alert").lower()
        target_type = target_type_alias.get(raw_target_type, raw_target_type)
        if not case_actor_id or not target_id:
            continue
        items.append(
            {
                "case_actor_id": case_actor_id,
                "target_type": target_type,
                "target_id": target_id,
                "link_confidence": max(
                    0.0,
                    min(1.0, _as_float(item.get("link_confidence", item.get("confidence", 0.8)), default=0.8)),
                ),
                "link_reason": _first_non_empty(item.get("link_reason"), item.get("reason"), item.get("summary"), "tool:auto_normalized"),
            }
        )
    return {"items": items}


def _normalize_alert_fetch_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    if "status" not in normalized:
        normalized["status"] = ["new", "open"]
    if "limit" not in normalized:
        normalized["limit"] = 20
    mode = _first_non_empty(normalized.get("mode"), "auto").lower()
    if mode not in {"auto", "alerts", "clusters"}:
        mode = "auto"
    normalized["mode"] = mode
    if mode == "auto" and "auto_cluster_threshold" not in normalized:
        normalized["auto_cluster_threshold"] = 8
    return normalized


def _normalize_payload_for_tool(tool_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    if tool_name == "alert.fetch":
        return _normalize_alert_fetch_payload(payload)
    if tool_name == "case.upsert-batch":
        return _normalize_case_upsert_batch_payload(payload)
    if tool_name == "case.link-alert-batch":
        return _normalize_case_link_alert_batch_payload(payload)
    if tool_name == "assessment.upsert-batch":
        return _normalize_assessment_upsert_batch_payload(payload)
    if tool_name == "actor.case-upsert":
        return _normalize_actor_case_upsert_payload(payload)
    if tool_name == "actor.case-add-observation-batch":
        return _normalize_actor_case_add_observation_batch_payload(payload)
    if tool_name == "actor.case-link-batch":
        return _normalize_actor_case_link_batch_payload(payload)
    return payload


def run_openai_patrol(
    conn: sqlite3.Connection,
    *,
    model: str,
    instructions: str,
    query: str,
    previous_response_id: str | None,
    max_turns: int,
    max_tool_calls: int | None = None,
    max_read_tool_calls: int | None = None,
    max_write_tool_calls: int | None = None,
    enforce_read_phase_gate: bool = False,
    first_fetch_payload_override: dict[str, Any] | None = None,
    client_factory: OpenAIClientFactory | None = None,
    tool_profile: str = "compact",
) -> OpenAIPatrolResult:
    if max_turns <= 0:
        return OpenAIPatrolResult(status="failed", detail="openai_patrol_max_turns_must_be_positive", response_id=None)

    tools, openai_name_map = _build_openai_tools(tool_profile)
    client = (client_factory or _default_openai_client_factory)()

    next_input: Any = query
    resume_response_id = previous_response_id
    tool_call_count = 0
    last_response_id: str | None = previous_response_id
    response_text = ""
    include_instructions = True
    turn_count = 0
    usage_input_tokens = 0
    usage_output_tokens = 0
    usage_cached_input_tokens = 0
    read_tool_call_count = 0
    write_tool_call_count = 0
    invalid_tool_signatures: set[str] = set()
    has_seen_initial_alert_fetch = False
    completed_discovery_tools: set[str] = set()
    empty_provider_response_retries = 0
    enforce_initial_required_tool_choice = True
    fetch_override_payload = (
        _normalize_alert_fetch_payload(dict(first_fetch_payload_override))
        if isinstance(first_fetch_payload_override, dict)
        else None
    )
    next_fetch_resume_payload: dict[str, Any] | None = None

    for _ in range(max_turns):
        turn_count += 1
        request: dict[str, Any] = {
            "model": model,
            "input": next_input,
            "tools": tools,
        }
        if tool_call_count <= 0 and enforce_initial_required_tool_choice:
            request["tool_choice"] = "required"
        if include_instructions:
            request["instructions"] = instructions
        if isinstance(resume_response_id, str) and resume_response_id.strip():
            request["previous_response_id"] = resume_response_id
        response = _invoke_response_create_with_tool_choice_fallback(client, request)
        include_instructions = False
        usage_snapshot = _extract_usage_snapshot(response)
        usage_input_tokens += usage_snapshot["input_tokens"]
        usage_output_tokens += usage_snapshot["output_tokens"]
        usage_cached_input_tokens += usage_snapshot["cached_input_tokens"]
        response_id = _extract_response_id(response)
        if response_id:
            last_response_id = response_id
            resume_response_id = response_id

        response_text = _extract_output_text(response).strip()
        output_item_count = _extract_output_item_count(response)
        tool_calls = _extract_tool_calls(response)
        insert_agent_output_log(
            conn,
            source="openai",
            turn_index=turn_count,
            response_id=response_id,
            has_tool_calls=bool(tool_calls),
            output_text=response_text,
            usage_input_tokens=usage_snapshot["input_tokens"],
            usage_output_tokens=usage_snapshot["output_tokens"],
            usage_cached_input_tokens=usage_snapshot["cached_input_tokens"],
            meta={
                "output_item_count": output_item_count,
                "tool_call_names": [call["name"] for call in tool_calls],
            },
        )
        if not tool_calls:
            is_empty_provider_response = (
                not response_text
                and output_item_count == 0
                and usage_snapshot["input_tokens"] == 0
                and usage_snapshot["output_tokens"] == 0
                and usage_snapshot["cached_input_tokens"] == 0
            )
            if (
                tool_call_count <= 0
                and is_empty_provider_response
                and empty_provider_response_retries < 2
                and turn_count < max_turns
            ):
                enforce_initial_required_tool_choice = False
                empty_provider_response_retries += 1
                include_instructions = True
                resume_response_id = None
                next_input = query
                continue
            if tool_call_count <= 0:
                detail = (
                    "openai responses returned no backend tool calls for this patrol run "
                    f"(final_text={response_text or '[EMPTY]'}, empty_provider_responses={empty_provider_response_retries})"
                )
                return OpenAIPatrolResult(
                    status="failed",
                    detail=detail,
                    response_id=last_response_id,
                    turns=turn_count,
                    tool_calls=tool_call_count,
                    read_tool_calls=read_tool_call_count,
                    write_tool_calls=write_tool_call_count,
                    usage_input_tokens=usage_input_tokens,
                    usage_output_tokens=usage_output_tokens,
                    usage_cached_input_tokens=usage_cached_input_tokens,
                    fetch_resume_payload=next_fetch_resume_payload,
                )
            detail = (
                f"openai responses completed (tool_calls={tool_call_count}, final_text={response_text or '[EMPTY]'})"
            )
            return OpenAIPatrolResult(
                status="success",
                detail=detail,
                response_id=last_response_id,
                turns=turn_count,
                tool_calls=tool_call_count,
                read_tool_calls=read_tool_call_count,
                write_tool_calls=write_tool_call_count,
                usage_input_tokens=usage_input_tokens,
                usage_output_tokens=usage_output_tokens,
                usage_cached_input_tokens=usage_cached_input_tokens,
                fetch_resume_payload=next_fetch_resume_payload,
            )

        function_outputs: list[dict[str, str]] = []
        for call in tool_calls:
            backend_tool_name = openai_name_map.get(call["name"])
            if backend_tool_name is None:
                tool_result = {
                    "ok": False,
                    "summary": f"unsupported openai tool call: {call['name']}",
                    "data": {"tool_name": call["name"]},
                    "warnings": ["unsupported_openai_tool_name"],
                    "refs": {},
                    "page": {"next_cursor": None, "has_more": False},
                    "meta": {},
                }
            else:
                try:
                    payload = json.loads(call["arguments"]) if call["arguments"].strip() else {}
                except json.JSONDecodeError:
                    payload = {}
                payload = _normalize_payload_for_tool(backend_tool_name, payload)
                if (
                    backend_tool_name == "alert.fetch"
                    and not has_seen_initial_alert_fetch
                    and fetch_override_payload is not None
                ):
                    payload = dict(fetch_override_payload)
                payload_signature = _tool_payload_signature(backend_tool_name, payload)
                if payload_signature in invalid_tool_signatures:
                    tool_result = _duplicate_invalid_block_result(backend_tool_name)
                elif not has_seen_initial_alert_fetch and backend_tool_name != "alert.fetch":
                    tool_result = _initial_fetch_required_result(backend_tool_name)
                    if _should_block_repeated_invalid_call(tool_result):
                        invalid_tool_signatures.add(payload_signature)
                else:
                    call_kind = _tool_call_kind(backend_tool_name)
                    if max_tool_calls is not None and tool_call_count >= max_tool_calls:
                        tool_result = _tool_budget_exceeded_result(
                            tool_name=backend_tool_name,
                            scope="total",
                            limit=max_tool_calls,
                            used=tool_call_count,
                        )
                    elif (
                        call_kind == "read"
                        and max_read_tool_calls is not None
                        and read_tool_call_count >= max_read_tool_calls
                    ):
                        tool_result = _tool_budget_exceeded_result(
                            tool_name=backend_tool_name,
                            scope="read",
                            limit=max_read_tool_calls,
                            used=read_tool_call_count,
                        )
                    elif (
                        call_kind == "write"
                        and max_write_tool_calls is not None
                        and write_tool_call_count >= max_write_tool_calls
                    ):
                        tool_result = _tool_budget_exceeded_result(
                            tool_name=backend_tool_name,
                            scope="write",
                            limit=max_write_tool_calls,
                            used=write_tool_call_count,
                        )
                    elif (
                        enforce_read_phase_gate
                        and backend_tool_name in _PERSISTENCE_WRITE_TOOL_NAMES
                        and (
                            missing_tool := _read_phase_missing_tool(
                                completed_discovery_tools,
                                write_tool_name=backend_tool_name,
                            )
                        )
                        is not None
                    ):
                        tool_result = _read_phase_guard_result(backend_tool_name, missing_tool=missing_tool)
                    else:
                        precheck_result = _prevalidate_tool_payload(backend_tool_name, payload)
                        if precheck_result is None and backend_tool_name == "case.link-alert-batch":
                            precheck_result = _prevalidate_case_link_alert_batch_case_exists(conn, payload)
                        if precheck_result is not None:
                            tool_result = precheck_result
                            if _should_block_repeated_invalid_call(tool_result):
                                invalid_tool_signatures.add(payload_signature)
                        else:
                            tool_result = dispatch_tool(conn, backend_tool_name, payload, source="mcp")
                            tool_call_count += 1
                            if call_kind == "read":
                                read_tool_call_count += 1
                            else:
                                write_tool_call_count += 1
                            if backend_tool_name == "alert.fetch":
                                has_seen_initial_alert_fetch = True
                                page = tool_result.get("page") if isinstance(tool_result, dict) else None
                                page_has_more = bool(page.get("has_more")) if isinstance(page, dict) else False
                                page_next_cursor = page.get("next_cursor") if isinstance(page, dict) else None
                                if page_has_more and isinstance(page_next_cursor, str) and page_next_cursor.strip():
                                    next_fetch_resume_payload = dict(payload)
                                    next_fetch_resume_payload["cursor"] = page_next_cursor.strip()
                                else:
                                    next_fetch_resume_payload = None
                            if tool_result.get("ok") and backend_tool_name in _DISCOVERY_REQUIRED_TOOLS:
                                completed_discovery_tools.add(backend_tool_name)
                            if _should_block_repeated_invalid_call(tool_result):
                                invalid_tool_signatures.add(payload_signature)

            function_outputs.append(
                {
                    "type": "function_call_output",
                    "call_id": call["call_id"],
                    "output": json.dumps(tool_result, ensure_ascii=False),
                }
            )
        next_input = function_outputs

    detail = (
        f"openai responses exceeded max_turns={max_turns} "
        f"(tool_calls={tool_call_count}, last_text={response_text or '[EMPTY]'})"
    )
    return OpenAIPatrolResult(
        status="failed",
        detail=detail,
        response_id=last_response_id,
        turns=turn_count,
        tool_calls=tool_call_count,
        read_tool_calls=read_tool_call_count,
        write_tool_calls=write_tool_call_count,
        usage_input_tokens=usage_input_tokens,
        usage_output_tokens=usage_output_tokens,
        usage_cached_input_tokens=usage_cached_input_tokens,
        fetch_resume_payload=next_fetch_resume_payload,
    )
