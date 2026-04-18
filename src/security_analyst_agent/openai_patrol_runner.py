from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from hashlib import sha1
import re
from typing import Any, Callable

from security_analyst_agent.config import DEFAULT_OPENAI_BASE_URL
from security_analyst_agent.mcp_server import CORE_TOOL_NAMES, TOOL_DESCRIPTIONS, TOOL_REQUEST_MODELS
from security_analyst_agent.tool_dispatch import dispatch_tool

OpenAIClientFactory = Callable[[], Any]


@dataclass
class OpenAIPatrolResult:
    status: str
    detail: str
    response_id: str | None
    turns: int = 0
    tool_calls: int = 0
    usage_input_tokens: int = 0
    usage_output_tokens: int = 0
    usage_cached_input_tokens: int = 0


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
    items: list[dict[str, Any]] = []
    for item in _ensure_dict_items(payload):
        case_id = _first_non_empty(item.get("case_id"), item.get("id"), item.get("canonical_case_id"))
        title = _first_non_empty(item.get("title"), item.get("name"), item.get("summary"))
        if not case_id or not title:
            continue
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


def _normalize_payload_for_tool(tool_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
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

    for _ in range(max_turns):
        turn_count += 1
        request: dict[str, Any] = {
            "model": model,
            "input": next_input,
            "tools": tools,
        }
        if include_instructions:
            request["instructions"] = instructions
        if isinstance(resume_response_id, str) and resume_response_id.strip():
            request["previous_response_id"] = resume_response_id
        response = _invoke_response_create(client, request)
        include_instructions = False
        usage_snapshot = _extract_usage_snapshot(response)
        usage_input_tokens += usage_snapshot["input_tokens"]
        usage_output_tokens += usage_snapshot["output_tokens"]
        usage_cached_input_tokens += usage_snapshot["cached_input_tokens"]
        response_id = _extract_response_id(response)
        if response_id:
            last_response_id = response_id
            resume_response_id = response_id

        tool_calls = _extract_tool_calls(response)
        if not tool_calls:
            response_text = _extract_output_text(response).strip()
            if tool_call_count <= 0:
                detail = "openai responses returned no backend tool calls for this patrol run"
                return OpenAIPatrolResult(
                    status="failed",
                    detail=detail,
                    response_id=last_response_id,
                    turns=turn_count,
                    tool_calls=tool_call_count,
                    usage_input_tokens=usage_input_tokens,
                    usage_output_tokens=usage_output_tokens,
                    usage_cached_input_tokens=usage_cached_input_tokens,
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
                usage_input_tokens=usage_input_tokens,
                usage_output_tokens=usage_output_tokens,
                usage_cached_input_tokens=usage_cached_input_tokens,
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
                tool_result = dispatch_tool(conn, backend_tool_name, payload, source="mcp")
                tool_call_count += 1

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
        usage_input_tokens=usage_input_tokens,
        usage_output_tokens=usage_output_tokens,
        usage_cached_input_tokens=usage_cached_input_tokens,
    )
