from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from hashlib import sha1
import re
import time
from typing import Any, Callable

from security_analyst_agent.config import (
    DEFAULT_OPENAI_BASE_URL,
    DEFAULT_OPENAI_ENABLE_CHAT_FALLBACK,
    DEFAULT_OPENAI_REASONING_EFFORT,
    DEFAULT_OPENAI_USER_AGENT,
    DEFAULT_OPENAI_WIRE_API,
)
from security_analyst_agent.mcp_server import CORE_TOOL_NAMES, TOOL_DESCRIPTIONS, TOOL_REQUEST_MODELS
from security_analyst_agent.repositories.audit import insert_agent_output_log
from security_analyst_agent.stages import stage_rank
from security_analyst_agent.tool_dispatch import dispatch_tool

OpenAIClientFactory = Callable[[], Any]
_RETRYABLE_PROVIDER_STATUS_CODES = {429, 500, 502, 503, 504}
_MAX_PROVIDER_CREATE_RETRIES = 2
_PROVIDER_RETRY_BASE_DELAY_SECONDS = 0.8


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
    client_kwargs: dict[str, Any] = {}
    if DEFAULT_OPENAI_BASE_URL:
        client_kwargs["base_url"] = DEFAULT_OPENAI_BASE_URL
    if DEFAULT_OPENAI_USER_AGENT:
        client_kwargs["default_headers"] = {"User-Agent": DEFAULT_OPENAI_USER_AGENT}
    return OpenAI(**client_kwargs)


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


def _extract_output_items(response: Any) -> list[Any]:
    output = _read_attr_or_key(response, "output", [])
    if isinstance(output, list):
        return output
    if isinstance(output, tuple):
        return list(output)
    return []


def _extract_output_item_count(response: Any) -> int:
    return len(_extract_output_items(response))


def _truncate_text(value: Any, *, max_len: int = 240) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if len(text) <= max_len:
        return text
    return f"{text[:max_len]}…"


def _extract_output_item_types(response: Any, *, max_items: int = 12) -> list[str]:
    output = _extract_output_items(response)
    item_types: list[str] = []
    for item in output[:max_items]:
        item_type = _read_attr_or_key(item, "type")
        if isinstance(item_type, str) and item_type.strip():
            item_types.append(item_type.strip())
        else:
            item_types.append("<unknown>")
    return item_types


def _extract_response_diagnostics(response: Any) -> dict[str, Any]:
    diagnostics: dict[str, Any] = {}
    response_status = _truncate_text(_read_attr_or_key(response, "status"), max_len=64)
    if response_status:
        diagnostics["response_status"] = response_status

    output_raw = _read_attr_or_key(response, "output", None)
    if output_raw is not None:
        diagnostics["output_container_type"] = type(output_raw).__name__
    diagnostics["output_item_types"] = _extract_output_item_types(response)

    incomplete_details = _read_attr_or_key(response, "incomplete_details", None)
    incomplete_reason = _truncate_text(_read_attr_or_key(incomplete_details, "reason"), max_len=80)
    if incomplete_reason:
        diagnostics["incomplete_reason"] = incomplete_reason

    error_obj = _read_attr_or_key(response, "error", None)
    error_code = _truncate_text(_read_attr_or_key(error_obj, "code"), max_len=80)
    error_message = _truncate_text(_read_attr_or_key(error_obj, "message"), max_len=240)
    if error_code:
        diagnostics["provider_error_code"] = error_code
    if error_message:
        diagnostics["provider_error_message"] = error_message

    output = _extract_output_items(response)
    refusal_item_count = 0
    for item in output:
        item_type = _read_attr_or_key(item, "type")
        if item_type == "refusal":
            refusal_item_count += 1
            continue
        refusal_payload = _read_attr_or_key(item, "refusal", None)
        if refusal_payload not in (None, "", [], {}):
            refusal_item_count += 1
    if refusal_item_count > 0:
        diagnostics["refusal_item_count"] = refusal_item_count

    choices = _read_attr_or_key(response, "choices", None)
    if isinstance(choices, (list, tuple)):
        choices_list = list(choices)
        diagnostics["choices_count"] = len(choices_list)
        finish_reasons: list[str] = []
        choices_tool_call_count = 0
        for choice in choices_list[:5]:
            reason = _truncate_text(_read_attr_or_key(choice, "finish_reason"), max_len=48)
            if reason:
                finish_reasons.append(reason)
            message = _read_attr_or_key(choice, "message", None)
            tool_calls = _read_attr_or_key(message, "tool_calls", None)
            if isinstance(tool_calls, (list, tuple)):
                choices_tool_call_count += len(tool_calls)
        if finish_reasons:
            diagnostics["choices_finish_reasons"] = finish_reasons
        if choices_tool_call_count > 0:
            diagnostics["choices_tool_call_count"] = choices_tool_call_count
    return diagnostics


def _extract_tool_calls(response: Any) -> list[dict[str, str]]:
    output = _extract_output_items(response)
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


def _extract_error_status_code(exc: Exception) -> int | None:
    for attr in ("status_code", "http_status", "status"):
        value = _read_attr_or_key(exc, attr, None)
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
    response = _read_attr_or_key(exc, "response", None)
    if response is not None:
        value = _read_attr_or_key(response, "status_code", None)
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())

    text = str(exc)
    match = re.search(r"\b([45]\d{2})\b", text)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return None
    return None


def _is_retryable_provider_error(exc: Exception) -> bool:
    status_code = _extract_error_status_code(exc)
    if status_code in _RETRYABLE_PROVIDER_STATUS_CODES:
        return True

    lowered = str(exc).lower()
    retry_markers = (
        "bad gateway",
        "gateway timeout",
        "service temporarily unavailable",
        "upstream request failed",
        "connection error",
        "timed out",
        "timeout",
    )
    if any(marker in lowered for marker in retry_markers):
        return True

    if ("<!doctype html" in lowered or "<html" in lowered) and "cloudflare" in lowered:
        return True
    return False


def _provider_retry_delay_seconds(retry_index: int) -> float:
    return _PROVIDER_RETRY_BASE_DELAY_SECONDS * (2**max(0, retry_index))


def _invoke_response_create_with_retries(client: Any, request: dict[str, Any]) -> Any:
    last_exc: Exception | None = None
    for attempt in range(_MAX_PROVIDER_CREATE_RETRIES + 1):
        try:
            return _invoke_response_create(client, request)
        except Exception as exc:
            last_exc = exc
            if not _is_retryable_provider_error(exc):
                raise
            if attempt >= _MAX_PROVIDER_CREATE_RETRIES:
                break
            delay_seconds = _provider_retry_delay_seconds(attempt)
            if delay_seconds > 0:
                time.sleep(delay_seconds)
    if last_exc is None:
        raise RuntimeError("openai responses.create failed without exception details")
    raise RuntimeError(
        "openai responses.create transient failure exhausted retries "
        f"(retries={_MAX_PROVIDER_CREATE_RETRIES}, last_error={last_exc})"
    ) from last_exc


def _invoke_response_create_with_tool_choice_fallback(client: Any, request: dict[str, Any]) -> Any:
    try:
        return _invoke_response_create_with_retries(client, request)
    except Exception:
        if "tool_choice" not in request:
            raise
        fallback_request = dict(request)
        fallback_request.pop("tool_choice", None)
        return _invoke_response_create_with_retries(client, fallback_request)


def _invoke_chat_completion_create(client: Any, request: dict[str, Any]) -> Any:
    chat = _read_attr_or_key(client, "chat")
    if chat is None:
        raise RuntimeError("openai client missing chat API")
    completions = _read_attr_or_key(chat, "completions")
    if completions is None:
        raise RuntimeError("openai client missing chat.completions API")
    create = _read_attr_or_key(completions, "create")
    if not callable(create):
        raise RuntimeError("openai client missing chat.completions.create")
    return create(**request)


def _is_function_output_item(value: Any) -> bool:
    return _read_attr_or_key(value, "type") == "function_call_output"


def _is_function_output_input(input_payload: Any) -> bool:
    if not isinstance(input_payload, list) or not input_payload:
        return False
    return all(_is_function_output_item(item) for item in input_payload)


def _summarize_function_outputs_for_chat(input_payload: list[Any]) -> str:
    lines = [
        "Tool results from previous step:",
    ]
    for item in input_payload[:12]:
        call_id = _read_attr_or_key(item, "call_id") or "[unknown_call]"
        output = _read_attr_or_key(item, "output", "")
        output_text = output if isinstance(output, str) else json.dumps(output, ensure_ascii=False)
        normalized_output = output_text.strip().replace("\n", " ")
        if len(normalized_output) > 260:
            normalized_output = f"{normalized_output[:260]}…"
        lines.append(f"- {call_id}: {normalized_output}")
    lines.append("Based on these results, continue by calling backend tools when needed.")
    return "\n".join(lines)


def _responses_tool_to_chat_tool(tool_spec: dict[str, Any]) -> dict[str, Any]:
    if tool_spec.get("type") != "function":
        return dict(tool_spec)
    return {
        "type": "function",
        "function": {
            "name": tool_spec.get("name", ""),
            "description": tool_spec.get("description", ""),
            "parameters": tool_spec.get("parameters", {"type": "object", "properties": {}}),
        },
    }


def _extract_chat_message_content_text(message: Any) -> str:
    content = _read_attr_or_key(message, "content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
                continue
            text = _read_attr_or_key(block, "text")
            if isinstance(text, str):
                parts.append(text)
                continue
            nested_text = _read_attr_or_key(_read_attr_or_key(block, "text", None), "value", None)
            if isinstance(nested_text, str):
                parts.append(nested_text)
        return "\n".join(part for part in parts if part)
    return ""


def _normalize_chat_completion_response(response: Any) -> dict[str, Any]:
    choices = _read_attr_or_key(response, "choices", [])
    first_choice = choices[0] if isinstance(choices, list) and choices else None
    message = _read_attr_or_key(first_choice, "message", None)
    message_content = _extract_chat_message_content_text(message).strip()
    raw_tool_calls = _read_attr_or_key(message, "tool_calls", [])
    output_items: list[dict[str, Any]] = []
    if isinstance(raw_tool_calls, list):
        for tool_call in raw_tool_calls:
            function = _read_attr_or_key(tool_call, "function", None)
            name = _read_attr_or_key(function, "name", "")
            call_id = _read_attr_or_key(tool_call, "id") or _read_attr_or_key(tool_call, "call_id")
            arguments = _read_attr_or_key(function, "arguments", "{}")
            if not isinstance(name, str) or not name.strip():
                continue
            if not isinstance(call_id, str) or not call_id.strip():
                continue
            if isinstance(arguments, dict):
                arguments_text = json.dumps(arguments, ensure_ascii=False)
            elif isinstance(arguments, str):
                arguments_text = arguments
            else:
                arguments_text = "{}"
            output_items.append(
                {
                    "type": "function_call",
                    "name": name,
                    "call_id": call_id,
                    "arguments": arguments_text,
                }
            )
    if not output_items:
        output_items.append({"type": "message", "role": "assistant"})
    usage = _read_attr_or_key(response, "usage", None)
    input_tokens = _to_int(_read_attr_or_key(usage, "prompt_tokens", _read_attr_or_key(usage, "input_tokens", 0)), 0)
    output_tokens = _to_int(
        _read_attr_or_key(usage, "completion_tokens", _read_attr_or_key(usage, "output_tokens", 0)),
        0,
    )
    return {
        "id": _read_attr_or_key(response, "id"),
        "status": _read_attr_or_key(response, "status", "completed"),
        "output_text": message_content,
        "output": output_items,
        "usage": {
            "input_tokens": max(0, input_tokens),
            "output_tokens": max(0, output_tokens),
            "input_tokens_details": {"cached_tokens": 0},
        },
    }


def _is_structured_responses_payload(response: Any) -> bool:
    if isinstance(response, str):
        return False
    output = _read_attr_or_key(response, "output", None)
    if isinstance(output, list):
        return True
    if _read_attr_or_key(response, "status", None) is not None:
        return True
    if _read_attr_or_key(response, "id", None) is not None:
        return True
    return False


def _should_fallback_to_chat_from_exception(exc: Exception) -> bool:
    lowered = str(exc).lower()
    markers = (
        "no tool call found for function call output with call_id",
        "invalid url (post /responses)",
        "unsupported wire_api",
        "unsupported wire api",
        "responses api not supported",
    )
    return any(marker in lowered for marker in markers)


class _OpenAIWireAdapter:
    def __init__(
        self,
        *,
        client: Any,
        initial_wire_api: str,
        enable_chat_fallback: bool,
    ) -> None:
        normalized_wire = (initial_wire_api or "").strip().lower()
        self._client = client
        self._wire_api = (
            "chat_completions"
            if normalized_wire in {"chat", "chat_completions", "completions", "chat.completions"}
            else "responses"
        )
        self._enable_chat_fallback = bool(enable_chat_fallback)
        self._fallback_used = False
        self._chat_messages: list[dict[str, Any]] = []
        self._chat_call_name_by_id: dict[str, str] = {}
        self._chat_system_initialized = False

    @property
    def wire_api(self) -> str:
        return self._wire_api

    @property
    def fallback_used(self) -> bool:
        return self._fallback_used

    def create(self, request: dict[str, Any]) -> Any:
        if self._wire_api == "chat_completions":
            return self._create_chat_completion_response(request)
        try:
            response = _invoke_response_create_with_tool_choice_fallback(self._client, request)
            if _is_structured_responses_payload(response):
                return response
            if not self._enable_chat_fallback:
                return response
            self._fallback_used = True
            self._wire_api = "chat_completions"
            return self._create_chat_completion_response(request)
        except Exception as exc:
            if not self._enable_chat_fallback or not _should_fallback_to_chat_from_exception(exc):
                raise
            self._fallback_used = True
            self._wire_api = "chat_completions"
            return self._create_chat_completion_response(request)

    def _create_chat_completion_response(self, request: dict[str, Any]) -> dict[str, Any]:
        start_message_count = len(self._chat_messages)
        start_call_mapping = dict(self._chat_call_name_by_id)
        start_system_flag = self._chat_system_initialized
        try:
            instructions = request.get("instructions")
            if isinstance(instructions, str) and instructions.strip() and not self._chat_system_initialized:
                self._chat_messages.append({"role": "system", "content": instructions})
                self._chat_system_initialized = True

            input_payload = request.get("input")
            if isinstance(input_payload, str) and input_payload.strip():
                self._chat_messages.append({"role": "user", "content": input_payload})
            elif _is_function_output_input(input_payload):
                assert isinstance(input_payload, list)
                if any(message.get("tool_calls") for message in self._chat_messages if isinstance(message, dict)):
                    for item in input_payload:
                        call_id = str(_read_attr_or_key(item, "call_id") or "").strip()
                        if not call_id:
                            continue
                        output = _read_attr_or_key(item, "output", "")
                        output_text = output if isinstance(output, str) else json.dumps(output, ensure_ascii=False)
                        tool_message: dict[str, Any] = {
                            "role": "tool",
                            "tool_call_id": call_id,
                            "content": output_text,
                        }
                        tool_name = self._chat_call_name_by_id.get(call_id)
                        if tool_name:
                            tool_message["name"] = tool_name
                        self._chat_messages.append(tool_message)
                else:
                    self._chat_messages.append({"role": "user", "content": _summarize_function_outputs_for_chat(input_payload)})
            elif input_payload not in (None, ""):
                serialized_input = input_payload if isinstance(input_payload, str) else json.dumps(input_payload, ensure_ascii=False)
                self._chat_messages.append({"role": "user", "content": serialized_input})

            chat_tools = [_responses_tool_to_chat_tool(tool) for tool in request.get("tools", [])]
            chat_request: dict[str, Any] = {
                "model": request.get("model"),
                "messages": list(self._chat_messages),
            }
            if chat_tools:
                chat_request["tools"] = chat_tools
            if "tool_choice" in request:
                chat_request["tool_choice"] = request["tool_choice"]

            chat_response = _invoke_chat_completion_create(self._client, chat_request)
            normalized_response = _normalize_chat_completion_response(chat_response)
            output_items = normalized_response.get("output")
            if isinstance(output_items, list):
                tool_calls_for_history: list[dict[str, Any]] = []
                for item in output_items:
                    if _read_attr_or_key(item, "type") != "function_call":
                        continue
                    call_id = str(_read_attr_or_key(item, "call_id") or "").strip()
                    name = str(_read_attr_or_key(item, "name") or "").strip()
                    arguments = _read_attr_or_key(item, "arguments", "{}")
                    if isinstance(arguments, dict):
                        arguments_text = json.dumps(arguments, ensure_ascii=False)
                    elif isinstance(arguments, str):
                        arguments_text = arguments
                    else:
                        arguments_text = "{}"
                    if call_id and name:
                        self._chat_call_name_by_id[call_id] = name
                    if call_id and name:
                        tool_calls_for_history.append(
                            {
                                "id": call_id,
                                "type": "function",
                                "function": {"name": name, "arguments": arguments_text},
                            }
                        )
                assistant_content = normalized_response.get("output_text", "")
                assistant_message: dict[str, Any] = {"role": "assistant"}
                if tool_calls_for_history:
                    assistant_message["tool_calls"] = tool_calls_for_history
                    if assistant_content:
                        assistant_message["content"] = assistant_content
                else:
                    assistant_message["content"] = assistant_content or "[SILENT]"
                self._chat_messages.append(assistant_message)
            return normalized_response
        except Exception:
            del self._chat_messages[start_message_count:]
            self._chat_call_name_by_id = start_call_mapping
            self._chat_system_initialized = start_system_flag
            raise


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

_ACK_GUARD_HIGH_SIGNAL_STAGES = {
    "exploit",
    "persistence",
    "command_execution",
    "lateral_prep",
    "reactivation",
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
_MAX_CONSECUTIVE_BLOCKED_TOOL_TURNS = 5
_MAX_TEXT_ONLY_NO_TOOL_RETRIES = 1
_NO_TOOL_CALL_RECOVERY_QUERY = (
    "Your previous response did not call backend tools. "
    "For this patrol pass, call backend tools directly (start with alert.fetch) before any narrative output."
)


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


def _guard_alert_ack_payload(
    conn: sqlite3.Connection,
    payload: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    if not isinstance(payload, dict):
        return payload, []
    raw_alert_ids = payload.get("alert_ids")
    if not isinstance(raw_alert_ids, list):
        return payload, []
    requested_alert_ids = list(dict.fromkeys(str(item).strip() for item in raw_alert_ids if str(item).strip()))
    if not requested_alert_ids:
        return payload, []

    rows = conn.execute(
        f"""
        select
          alerts.alert_id,
          lower(alerts.severity) as severity,
          lower(alerts.attack_stage) as attack_stage,
          case when exists (
            select 1
            from case_alert_links
            where case_alert_links.alert_id = alerts.alert_id and case_alert_links.is_active = 1
          ) then 1 else 0 end as has_active_case_link
        from alerts
        where alerts.alert_id in ({", ".join("?" for _ in requested_alert_ids)})
        """,
        tuple(requested_alert_ids),
    ).fetchall()
    if not rows:
        return payload, []

    blocked_alerts: list[dict[str, str]] = []
    blocked_alert_id_set: set[str] = set()
    for row in rows:
        alert_id = str(row["alert_id"] or "").strip()
        if not alert_id:
            continue
        severity = str(row["severity"] or "").strip()
        attack_stage = str(row["attack_stage"] or "").strip()
        has_active_case_link = int(row["has_active_case_link"] or 0) > 0
        is_high_signal = severity in {"high", "critical"} or attack_stage in _ACK_GUARD_HIGH_SIGNAL_STAGES
        if not is_high_signal or has_active_case_link:
            continue
        blocked_alert_id_set.add(alert_id)
        blocked_alerts.append(
            {
                "alert_id": alert_id,
                "severity": severity or "unknown",
                "attack_stage": attack_stage or "unknown",
                "reason": "high_signal_unlinked_case",
            }
        )

    if not blocked_alerts:
        return payload, []

    kept_alert_ids = [alert_id for alert_id in requested_alert_ids if alert_id not in blocked_alert_id_set]
    next_payload = dict(payload)
    next_payload["alert_ids"] = kept_alert_ids
    return next_payload, blocked_alerts


def _alert_ack_guard_skip_result(
    blocked_alerts: list[dict[str, str]],
) -> dict[str, Any]:
    blocked_alert_ids = list(
        dict.fromkeys(str(item.get("alert_id") or "").strip() for item in blocked_alerts if item.get("alert_id"))
    )
    return {
        "ok": True,
        "summary": (
            "ack_guard skipped high-signal unlinked alerts; "
            f"blocked_count={len(blocked_alert_ids)}"
        ),
        "data": {
            "tool": "alert.ack",
            "blocked_alerts": blocked_alerts,
            "recommended_next_actions": [
                {
                    "tool": "alert.detail-batch",
                    "reason": "先补齐高信号告警详情，确认攻击证据链",
                },
                {
                    "tool": "case.search",
                    "reason": "先检索候选案件后再关联高信号告警",
                },
                {
                    "tool": "case.link-alert-batch",
                    "reason": "高信号告警应先入案，再执行 ack 出队",
                },
            ],
        },
        "warnings": ["ack_guard_skipped_unlinked_high_signal_alerts"],
        "refs": {"alert_ids": blocked_alert_ids},
        "page": {"next_cursor": None, "has_more": False},
        "meta": {"source": "openai_runner_ack_guard"},
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


def _normalize_alert_fetch_payload(payload: dict[str, Any], *, objective_mode: bool = False) -> dict[str, Any]:
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
    if objective_mode and "include_strategy_hints" not in normalized:
        normalized["include_strategy_hints"] = False
    return normalized


def _sanitize_first_fetch_payload_override(
    payload: dict[str, Any] | None,
    *,
    objective_mode: bool = False,
) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    normalized = _normalize_alert_fetch_payload(dict(payload), objective_mode=objective_mode)
    normalized.pop("cursor", None)
    return normalized


def _normalize_payload_for_tool(
    tool_name: str,
    payload: dict[str, Any],
    *,
    objective_mode: bool = False,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    if tool_name == "alert.fetch":
        return _normalize_alert_fetch_payload(payload, objective_mode=objective_mode)
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


def _has_non_empty_batch_items(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    items = payload.get("items")
    return isinstance(items, list) and len(items) > 0


def _safe_case_id_from_ip(src_ip: str) -> str:
    normalized = src_ip.strip().replace(".", "_").replace(":", "_")
    return f"case_auto_hotspot_{normalized[:48]}"


def _safe_actor_id_from_case(case_id: str) -> str:
    return f"actor_auto_{case_id}"[:64]


def _infer_stage_and_severity_from_alert_ids(conn: sqlite3.Connection, alert_ids: list[str]) -> tuple[str, str]:
    deduped_alert_ids = list(dict.fromkeys(str(item).strip() for item in alert_ids if str(item).strip()))
    if not deduped_alert_ids:
        return "exploit", "high"
    rows = conn.execute(
        f"""
        select lower(attack_stage) as attack_stage, lower(severity) as severity
        from alerts
        where alert_id in ({", ".join("?" for _ in deduped_alert_ids)})
        """,
        tuple(deduped_alert_ids),
    ).fetchall()
    if not rows:
        return "exploit", "high"

    max_stage = "recon"
    max_stage_rank = stage_rank(max_stage)
    max_severity = "low"
    severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    max_severity_rank = severity_rank[max_severity]
    for row in rows:
        candidate_stage = str(row["attack_stage"] or "").strip()
        candidate_severity = str(row["severity"] or "").strip()
        candidate_stage_rank = stage_rank(candidate_stage)
        if candidate_stage_rank > max_stage_rank:
            max_stage = candidate_stage or max_stage
            max_stage_rank = candidate_stage_rank
        candidate_severity_rank = severity_rank.get(candidate_severity, 1)
        if candidate_severity_rank > max_severity_rank:
            max_severity = candidate_severity if candidate_severity in severity_rank else max_severity
            max_severity_rank = candidate_severity_rank

    if max_stage_rank <= 0:
        max_stage = "exploit"
    if max_severity not in {"high", "critical"}:
        max_severity = "high"
    return max_stage, max_severity


def _build_case_upsert_autofill_from_suspects(
    conn: sqlite3.Connection,
    *,
    suspects: list[dict[str, Any]],
    max_cases: int = 2,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    if not suspects:
        return None, []

    sorted_suspects = sorted(
        (
            item
            for item in suspects
            if isinstance(item, dict) and str(item.get("src_ip") or "").strip()
        ),
        key=lambda item: (
            int(item.get("critical_count") or 0),
            int(item.get("high_severity_count") or 0),
            int(item.get("non_recon_stage_count") or 0),
            int(item.get("alert_count") or 0),
            str(item.get("src_ip") or ""),
        ),
        reverse=True,
    )
    case_items: list[dict[str, Any]] = []
    seed_link_items: list[dict[str, Any]] = []
    for suspect in sorted_suspects:
        if len(case_items) >= max_cases:
            break
        src_ip = str(suspect.get("src_ip") or "").strip()
        if not src_ip:
            continue
        high_count = int(suspect.get("high_severity_count") or 0)
        critical_count = int(suspect.get("critical_count") or 0)
        alert_count = int(suspect.get("alert_count") or 0)
        if high_count < 2 and critical_count < 1 and alert_count < 3:
            continue
        sample_alert_ids = suspect.get("sample_alert_ids")
        if not isinstance(sample_alert_ids, list):
            sample_alert_ids = []
        sample_alert_ids = [str(item).strip() for item in sample_alert_ids if str(item).strip()]
        current_stage, overall_severity = _infer_stage_and_severity_from_alert_ids(conn, sample_alert_ids)
        case_id = _safe_case_id_from_ip(src_ip)
        case_items.append(
            {
                "case_id": case_id,
                "title": f"Auto hotspot {src_ip}",
                "status": "open",
                "overall_severity": "critical" if overall_severity == "critical" else "high",
                "current_stage": current_stage,
                "primary_actor_id": _safe_actor_id_from_case(case_id),
            }
        )
        if sample_alert_ids:
            seed_link_items.append(
                {
                    "case_id": case_id,
                    "alert_id": sample_alert_ids[0],
                    "confidence": 0.86,
                    "reason": "auto:runner_case_upsert_seed_from_suspect",
                }
            )

    if not case_items:
        return None, []
    return {"items": case_items}, seed_link_items


def _auto_ack_low_recon_noise_alerts(
    conn: sqlite3.Connection,
    *,
    max_count: int = 60,
) -> int:
    rows = conn.execute(
        """
        select alert_id
        from alerts
        where status in ('new', 'open')
          and lower(severity) = 'low'
          and lower(attack_stage) = 'recon'
        order by occurred_at asc, alert_id asc
        limit ?
        """,
        (max(1, max_count),),
    ).fetchall()
    alert_ids = [str(row["alert_id"]) for row in rows if row["alert_id"]]
    if not alert_ids:
        return 0
    result = dispatch_tool(
        conn,
        "alert.ack",
        {"alert_ids": alert_ids, "status": "triaged"},
        source="mcp",
    )
    if not isinstance(result, dict) or not result.get("ok"):
        return 0
    return len(alert_ids)


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
    objective_mode: bool = False,
) -> OpenAIPatrolResult:
    if max_turns <= 0:
        return OpenAIPatrolResult(status="failed", detail="openai_patrol_max_turns_must_be_positive", response_id=None)

    tools, openai_name_map = _build_openai_tools(tool_profile)
    client = (client_factory or _default_openai_client_factory)()
    wire_adapter = _OpenAIWireAdapter(
        client=client,
        initial_wire_api=DEFAULT_OPENAI_WIRE_API,
        enable_chat_fallback=DEFAULT_OPENAI_ENABLE_CHAT_FALLBACK,
    )

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
    text_only_no_tool_retries = 0
    consecutive_blocked_tool_turns = 0
    has_successful_ack_call = False
    enforce_initial_required_tool_choice = True
    latest_suspect_candidates: list[dict[str, Any]] = []
    autofilled_case_upsert_once = False
    fetch_override_payload = (
        _sanitize_first_fetch_payload_override(first_fetch_payload_override, objective_mode=objective_mode)
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
        if DEFAULT_OPENAI_REASONING_EFFORT:
            request["reasoning"] = {"effort": DEFAULT_OPENAI_REASONING_EFFORT}
        if tool_call_count <= 0 and enforce_initial_required_tool_choice:
            request["tool_choice"] = "required"
        if include_instructions:
            request["instructions"] = instructions
        if isinstance(resume_response_id, str) and resume_response_id.strip():
            request["previous_response_id"] = resume_response_id
        response = wire_adapter.create(request)
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
        response_diagnostics = _extract_response_diagnostics(response)
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
                "wire_api": wire_adapter.wire_api,
                "wire_fallback_used": bool(wire_adapter.fallback_used),
                **response_diagnostics,
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
            if (
                tool_call_count <= 0
                and not is_empty_provider_response
                and response_text.strip()
                and response_text.strip() != "[SILENT]"
                and text_only_no_tool_retries < _MAX_TEXT_ONLY_NO_TOOL_RETRIES
                and turn_count < max_turns
            ):
                text_only_no_tool_retries += 1
                enforce_initial_required_tool_choice = True
                include_instructions = True
                resume_response_id = None
                next_input = _NO_TOOL_CALL_RECOVERY_QUERY
                continue
            if tool_call_count <= 0:
                response_status = response_diagnostics.get("response_status", "[UNKNOWN]")
                incomplete_reason = response_diagnostics.get("incomplete_reason", "[NONE]")
                provider_error_code = response_diagnostics.get("provider_error_code", "[NONE]")
                output_item_types = response_diagnostics.get("output_item_types", [])
                detail = (
                    "openai responses returned no backend tool calls for this patrol run "
                    f"(final_text={response_text or '[EMPTY]'}, "
                    f"wire_api={wire_adapter.wire_api}, "
                    f"wire_fallback_used={1 if wire_adapter.fallback_used else 0}, "
                    f"response_status={response_status}, "
                    f"incomplete_reason={incomplete_reason}, "
                    f"provider_error_code={provider_error_code}, "
                    f"output_items={output_item_count}, "
                    f"output_item_types={output_item_types}, "
                    f"empty_provider_responses={empty_provider_response_retries}, "
                    f"text_no_tool_retries={text_only_no_tool_retries})"
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
                "openai responses completed "
                f"(tool_calls={tool_call_count}, final_text={response_text or '[EMPTY]'}, "
                f"wire_api={wire_adapter.wire_api}, wire_fallback_used={1 if wire_adapter.fallback_used else 0})"
            )
            if not objective_mode and not has_successful_ack_call and (
                (max_tool_calls is None or tool_call_count < max_tool_calls)
                and (max_write_tool_calls is None or write_tool_call_count < max_write_tool_calls)
            ):
                auto_ack_count = _auto_ack_low_recon_noise_alerts(conn, max_count=60)
                if auto_ack_count > 0:
                    tool_call_count += 1
                    write_tool_call_count += 1
                    has_successful_ack_call = True
                    detail = f"{detail}; auto_noise_ack={auto_ack_count}"
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
        executed_backend_tool_calls_this_turn = 0
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
                payload = _normalize_payload_for_tool(
                    backend_tool_name,
                    payload,
                    objective_mode=objective_mode,
                )
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
                        blocked_ack_alerts: list[dict[str, str]] = []
                        auto_seed_links: list[dict[str, Any]] = []
                        if backend_tool_name == "alert.ack":
                            payload, blocked_ack_alerts = _guard_alert_ack_payload(conn, payload)
                            if blocked_ack_alerts and not payload.get("alert_ids"):
                                tool_result = _alert_ack_guard_skip_result(blocked_ack_alerts)
                                if _should_block_repeated_invalid_call(tool_result):
                                    invalid_tool_signatures.add(payload_signature)
                                function_outputs.append(
                                    {
                                        "type": "function_call_output",
                                        "call_id": call["call_id"],
                                        "output": json.dumps(tool_result, ensure_ascii=False),
                                    }
                                )
                                continue
                        if (
                            backend_tool_name == "case.upsert-batch"
                            and not _has_non_empty_batch_items(payload)
                            and not autofilled_case_upsert_once
                            and not objective_mode
                        ):
                            autofill_payload, auto_seed_links = _build_case_upsert_autofill_from_suspects(
                                conn,
                                suspects=latest_suspect_candidates,
                                max_cases=2,
                            )
                            if autofill_payload is not None:
                                payload = autofill_payload
                                autofilled_case_upsert_once = True
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
                            executed_backend_tool_calls_this_turn += 1
                            if call_kind == "read":
                                read_tool_call_count += 1
                            else:
                                write_tool_call_count += 1
                            if backend_tool_name == "alert.suspect-ip-topk" and tool_result.get("ok"):
                                suspects = tool_result.get("data", {}).get("suspects")
                                if isinstance(suspects, list):
                                    latest_suspect_candidates = [item for item in suspects if isinstance(item, dict)]
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
                            if backend_tool_name == "alert.ack" and tool_result.get("ok"):
                                has_successful_ack_call = True
                            if (
                                backend_tool_name == "case.upsert-batch"
                                and auto_seed_links
                                and max_tool_calls is not None
                                and tool_call_count >= max_tool_calls
                            ):
                                tool_result = dict(tool_result)
                                warnings = tool_result.get("warnings")
                                warning_list = list(warnings) if isinstance(warnings, list) else []
                                warning_list.append("auto_seed_link_skipped_due_tool_budget")
                                tool_result["warnings"] = list(dict.fromkeys(warning_list))
                            elif (
                                backend_tool_name == "case.upsert-batch"
                                and auto_seed_links
                                and max_write_tool_calls is not None
                                and write_tool_call_count >= max_write_tool_calls
                            ):
                                tool_result = dict(tool_result)
                                warnings = tool_result.get("warnings")
                                warning_list = list(warnings) if isinstance(warnings, list) else []
                                warning_list.append("auto_seed_link_skipped_due_write_budget")
                                tool_result["warnings"] = list(dict.fromkeys(warning_list))
                            elif backend_tool_name == "case.upsert-batch" and auto_seed_links:
                                seed_result = dispatch_tool(
                                    conn,
                                    "case.link-alert-batch",
                                    {"items": auto_seed_links},
                                    source="mcp",
                                )
                                tool_call_count += 1
                                write_tool_call_count += 1
                                tool_result = dict(tool_result)
                                warnings = tool_result.get("warnings")
                                warning_list = list(warnings) if isinstance(warnings, list) else []
                                warning_list.append("auto_seed_case_links_applied")
                                tool_result["warnings"] = list(dict.fromkeys(warning_list))

                                refs = tool_result.get("refs")
                                refs_map = dict(refs) if isinstance(refs, dict) else {}
                                existing_alert_ids = refs_map.get("alert_ids")
                                alert_ids = list(existing_alert_ids) if isinstance(existing_alert_ids, list) else []
                                alert_ids.extend(str(item.get("alert_id") or "").strip() for item in auto_seed_links)
                                refs_map["alert_ids"] = list(dict.fromkeys(item for item in alert_ids if item))
                                existing_case_ids = refs_map.get("case_ids")
                                case_ids = list(existing_case_ids) if isinstance(existing_case_ids, list) else []
                                case_ids.extend(str(item.get("case_id") or "").strip() for item in auto_seed_links)
                                refs_map["case_ids"] = list(dict.fromkeys(item for item in case_ids if item))
                                if seed_result.get("refs") and isinstance(seed_result.get("refs"), dict):
                                    seed_case_ids = seed_result["refs"].get("case_ids")
                                    if isinstance(seed_case_ids, list):
                                        refs_map["case_ids"] = list(
                                            dict.fromkeys(refs_map["case_ids"] + [str(item) for item in seed_case_ids if item])
                                        )
                                tool_result["refs"] = refs_map

                                data = tool_result.get("data")
                                data_map = dict(data) if isinstance(data, dict) else {}
                                data_map["auto_seed_links"] = auto_seed_links
                                data_map["auto_seed_link_result"] = {
                                    "ok": bool(seed_result.get("ok")),
                                    "summary": seed_result.get("summary"),
                                    "warnings": seed_result.get("warnings", []),
                                }
                                tool_result["data"] = data_map
                            if backend_tool_name == "alert.ack" and blocked_ack_alerts:
                                tool_result = dict(tool_result)
                                warnings = tool_result.get("warnings")
                                warnings_list = list(warnings) if isinstance(warnings, list) else []
                                warnings_list.append("ack_guard_skipped_unlinked_high_signal_alerts")
                                tool_result["warnings"] = list(dict.fromkeys(warnings_list))

                                refs = tool_result.get("refs")
                                refs_map = dict(refs) if isinstance(refs, dict) else {}
                                existing_alert_ids = refs_map.get("alert_ids")
                                refs_alert_ids = list(existing_alert_ids) if isinstance(existing_alert_ids, list) else []
                                refs_alert_ids.extend(
                                    str(item.get("alert_id") or "").strip()
                                    for item in blocked_ack_alerts
                                    if item.get("alert_id")
                                )
                                refs_map["alert_ids"] = list(dict.fromkeys(item for item in refs_alert_ids if item))
                                tool_result["refs"] = refs_map

                                data = tool_result.get("data")
                                data_map = dict(data) if isinstance(data, dict) else {}
                                data_map["blocked_alerts"] = blocked_ack_alerts
                                tool_result["data"] = data_map

            function_outputs.append(
                {
                    "type": "function_call_output",
                    "call_id": call["call_id"],
                    "output": json.dumps(tool_result, ensure_ascii=False),
                }
            )
        if tool_calls and executed_backend_tool_calls_this_turn <= 0:
            consecutive_blocked_tool_turns += 1
        else:
            consecutive_blocked_tool_turns = 0
        if consecutive_blocked_tool_turns >= _MAX_CONSECUTIVE_BLOCKED_TOOL_TURNS and tool_call_count > 0:
            detail = (
                "openai responses stopped_after_blocked_tool_loop="
                f"{consecutive_blocked_tool_turns} (tool_calls={tool_call_count}, "
                f"wire_api={wire_adapter.wire_api}, wire_fallback_used={1 if wire_adapter.fallback_used else 0})"
            )
            if not objective_mode and not has_successful_ack_call and (
                (max_tool_calls is None or tool_call_count < max_tool_calls)
                and (max_write_tool_calls is None or write_tool_call_count < max_write_tool_calls)
            ):
                auto_ack_count = _auto_ack_low_recon_noise_alerts(conn, max_count=60)
                if auto_ack_count > 0:
                    tool_call_count += 1
                    write_tool_call_count += 1
                    has_successful_ack_call = True
                    detail = f"{detail}; auto_noise_ack={auto_ack_count}"
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
        next_input = function_outputs

    detail = (
        f"openai responses exceeded max_turns={max_turns} "
        f"(tool_calls={tool_call_count}, last_text={response_text or '[EMPTY]'}, "
        f"wire_api={wire_adapter.wire_api}, wire_fallback_used={1 if wire_adapter.fallback_used else 0})"
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
