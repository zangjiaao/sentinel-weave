from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
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


def _build_openai_tools() -> tuple[list[dict[str, Any]], dict[str, str]]:
    specs: list[dict[str, Any]] = []
    name_map: dict[str, str] = {}
    for tool_name in CORE_TOOL_NAMES:
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


def run_openai_patrol(
    conn: sqlite3.Connection,
    *,
    model: str,
    instructions: str,
    query: str,
    previous_response_id: str | None,
    max_turns: int,
    client_factory: OpenAIClientFactory | None = None,
) -> OpenAIPatrolResult:
    if max_turns <= 0:
        return OpenAIPatrolResult(status="failed", detail="openai_patrol_max_turns_must_be_positive", response_id=None)

    tools, openai_name_map = _build_openai_tools()
    client = (client_factory or _default_openai_client_factory)()

    next_input: Any = query
    resume_response_id = previous_response_id
    tool_call_count = 0
    first_backend_tool_name: str | None = None
    last_response_id: str | None = previous_response_id
    response_text = ""

    for _ in range(max_turns):
        request: dict[str, Any] = {
            "model": model,
            "input": next_input,
            "tools": tools,
            "instructions": instructions,
        }
        if isinstance(resume_response_id, str) and resume_response_id.strip():
            request["previous_response_id"] = resume_response_id
        response = _invoke_response_create(client, request)
        response_id = _extract_response_id(response)
        if response_id:
            last_response_id = response_id
            resume_response_id = response_id

        tool_calls = _extract_tool_calls(response)
        if not tool_calls:
            response_text = _extract_output_text(response).strip()
            if tool_call_count <= 0:
                detail = "openai responses returned no backend tool calls for this patrol run"
                return OpenAIPatrolResult(status="failed", detail=detail, response_id=last_response_id)
            if first_backend_tool_name != "alert.fetch":
                detail = (
                    "openai responses violated patrol contract: first backend tool call must be alert.fetch "
                    f"(got={first_backend_tool_name or '[NONE]'})"
                )
                return OpenAIPatrolResult(status="failed", detail=detail, response_id=last_response_id)
            detail = (
                f"openai responses completed (tool_calls={tool_call_count}, final_text={response_text or '[EMPTY]'})"
            )
            return OpenAIPatrolResult(status="success", detail=detail, response_id=last_response_id)

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
                tool_result = dispatch_tool(conn, backend_tool_name, payload, source="mcp")
                tool_call_count += 1
                if first_backend_tool_name is None:
                    first_backend_tool_name = backend_tool_name

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
    return OpenAIPatrolResult(status="failed", detail=detail, response_id=last_response_id)
