import argparse
import inspect
import json
import os
from pathlib import Path
from typing import Any, Callable

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

from security_analyst_agent.db import connect_db
from security_analyst_agent.schemas.actor_tools import (
    ActorCaseAddObservationBatchRequest,
    ActorCaseAddObservationRequest,
    ActorCaseFindCandidatesRequest,
    ActorCaseGetRequest,
    ActorCaseLinkBatchRequest,
    ActorCaseLinkRequest,
    ActorCaseListRequest,
    ActorCaseUpsertRequest,
)
from security_analyst_agent.schemas.alert_tools import (
    AlertAckRequest,
    AlertDetailBatchRequest,
    AlertDetailRequest,
    AlertFetchRequest,
)
from security_analyst_agent.schemas.assessment_tools import AssessmentUpsertBatchRequest, AssessmentUpsertRequest
from security_analyst_agent.schemas.asset_tools import AssetSearchRequest
from security_analyst_agent.schemas.case_tools import (
    CaseExplainLinkRequest,
    CaseGetRequest,
    CaseLinkAlertBatchRequest,
    CaseLinkAlertRequest,
    CaseTimelineRequest,
    CaseUpsertBatchRequest,
    CaseUpdateRiskRequest,
    CaseUpsertRequest,
)
from security_analyst_agent.schemas.common import ToolResponse
from security_analyst_agent.schemas.derived_tools import EvidenceUpsertRequest, TimelineUpsertRequest
from security_analyst_agent.schemas.intel_tools import IntelLookupRequest
from security_analyst_agent.schemas.output_tools import NotifyPreviewRequest, NotifySendRequest, ReportDraftRequest
from security_analyst_agent.tool_dispatch import dispatch_tool

CORE_TOOL_NAMES = (
    "alert.fetch",
    "alert.detail",
    "alert.detail-batch",
    "alert.ack",
    "asset.search",
    "actor.case-list",
    "actor.case-get",
    "actor.case-find-candidates",
    "actor.case-upsert",
    "actor.case-add-observation",
    "actor.case-add-observation-batch",
    "actor.case-link",
    "actor.case-link-batch",
    "case.get",
    "case.timeline",
    "case.explain-link",
    "case.upsert",
    "case.upsert-batch",
    "case.link-alert",
    "case.link-alert-batch",
    "case.update-risk",
    "evidence.upsert",
    "timeline.upsert",
    "assessment.upsert",
    "assessment.upsert-batch",
    "intel.lookup",
    "notify.send",
    "notify.preview",
    "report.draft",
)

TOOL_DESCRIPTIONS = {
    "alert.fetch": "拉取待研判告警摘要队列。",
    "alert.detail": "读取单条告警详情与关键证据摘要。",
    "alert.detail-batch": "批量读取多条告警详情与关键证据摘要。",
    "alert.ack": "将已处理告警标记为 triaged/closed，避免重复出队。",
    "asset.search": "按指标搜索资产并返回资产上下文。",
    "actor.case-list": "列出某个案件下的案内攻击者画像。",
    "actor.case-get": "读取案内攻击者画像详情。",
    "actor.case-find-candidates": "为告警查找候选案内画像，避免把每个新 IP 误判为新攻击者。",
    "actor.case-upsert": "创建或更新案内攻击者画像。",
    "actor.case-add-observation": "为案内攻击者画像追加 IP、资产、URI、C2 等观测线索。",
    "actor.case-add-observation-batch": "批量追加案内攻击者画像观测线索。",
    "actor.case-link": "将案内画像关联到告警、证据或时间线节点。",
    "actor.case-link-batch": "批量将案内画像关联到告警、证据或时间线节点。",
    "case.get": "读取案件头部摘要与当前风险结论。",
    "case.timeline": "读取案件时间线与攻击阶段演进。",
    "case.explain-link": "解释事件与案件之间的关联依据。",
    "case.upsert": "创建或更新案件主记录。",
    "case.upsert-batch": "批量创建或更新案件主记录。",
    "case.link-alert": "将告警关联到指定案件并记录关联理由。",
    "case.link-alert-batch": "批量将告警关联到指定案件并记录关联理由。",
    "case.update-risk": "更新案件风险等级、阶段与状态。",
    "evidence.upsert": "写入或更新案件证据记录。",
    "timeline.upsert": "写入或更新时间线节点，沉淀攻击过程。",
    "assessment.upsert": "写入实体级风险评估（如攻击IP、失陷主机）。",
    "assessment.upsert-batch": "批量写入实体级风险评估（如攻击IP、失陷主机）。",
    "intel.lookup": "查询缓存化威胁情报用于补证。",
    "notify.send": "触发模拟通知发送并写入通知出站记录。",
    "notify.preview": "生成通知预览草稿，不进行实际发送。",
    "report.draft": "生成案件分析报告草稿。",
}

PROMPT_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "alert.ack": AlertAckRequest,
    "alert.detail-batch": AlertDetailBatchRequest,
    "case.link-alert-batch": CaseLinkAlertBatchRequest,
    "case.upsert-batch": CaseUpsertBatchRequest,
    "assessment.upsert-batch": AssessmentUpsertBatchRequest,
    "actor.case-add-observation-batch": ActorCaseAddObservationBatchRequest,
    "actor.case-link-batch": ActorCaseLinkBatchRequest,
    "actor.case-list": ActorCaseListRequest,
    "actor.case-get": ActorCaseGetRequest,
    "actor.case-find-candidates": ActorCaseFindCandidatesRequest,
    "actor.case-upsert": ActorCaseUpsertRequest,
    "actor.case-add-observation": ActorCaseAddObservationRequest,
    "actor.case-link": ActorCaseLinkRequest,
    "case.explain-link": CaseExplainLinkRequest,
    "intel.lookup": IntelLookupRequest,
    "case.upsert": CaseUpsertRequest,
    "case.link-alert": CaseLinkAlertRequest,
    "case.update-risk": CaseUpdateRiskRequest,
    "evidence.upsert": EvidenceUpsertRequest,
    "timeline.upsert": TimelineUpsertRequest,
    "assessment.upsert": AssessmentUpsertRequest,
    "notify.send": NotifySendRequest,
    "notify.preview": NotifyPreviewRequest,
    "report.draft": ReportDraftRequest,
}

TOOL_REQUEST_MODELS: dict[str, type[BaseModel]] = {
    "alert.fetch": AlertFetchRequest,
    "alert.detail": AlertDetailRequest,
    "alert.detail-batch": AlertDetailBatchRequest,
    "alert.ack": AlertAckRequest,
    "asset.search": AssetSearchRequest,
    "actor.case-list": ActorCaseListRequest,
    "actor.case-get": ActorCaseGetRequest,
    "actor.case-find-candidates": ActorCaseFindCandidatesRequest,
    "actor.case-upsert": ActorCaseUpsertRequest,
    "actor.case-add-observation": ActorCaseAddObservationRequest,
    "actor.case-add-observation-batch": ActorCaseAddObservationBatchRequest,
    "actor.case-link": ActorCaseLinkRequest,
    "actor.case-link-batch": ActorCaseLinkBatchRequest,
    "case.get": CaseGetRequest,
    "case.timeline": CaseTimelineRequest,
    "case.explain-link": CaseExplainLinkRequest,
    "case.upsert": CaseUpsertRequest,
    "case.upsert-batch": CaseUpsertBatchRequest,
    "case.link-alert": CaseLinkAlertRequest,
    "case.link-alert-batch": CaseLinkAlertBatchRequest,
    "case.update-risk": CaseUpdateRiskRequest,
    "evidence.upsert": EvidenceUpsertRequest,
    "timeline.upsert": TimelineUpsertRequest,
    "assessment.upsert": AssessmentUpsertRequest,
    "assessment.upsert-batch": AssessmentUpsertBatchRequest,
    "intel.lookup": IntelLookupRequest,
    "notify.send": NotifySendRequest,
    "notify.preview": NotifyPreviewRequest,
    "report.draft": ReportDraftRequest,
}

PROMPT_EXTRA_GUIDANCE: dict[str, list[str]] = {
    "alert.ack": ["`status` 仅支持 `triaged` 或 `closed`。"],
    "case.explain-link": ["当前仅支持 `target_type=alert`。"],
    "case.update-risk": ["默认阻止阶段回退；仅在确有需要时传入 `force_downgrade=true`。"],
}


def _select_json_schema_branch(spec: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(spec, dict):
        return {}
    if "anyOf" in spec:
        any_of = spec.get("anyOf")
        if isinstance(any_of, list):
            for branch in any_of:
                if isinstance(branch, dict) and branch.get("type") != "null":
                    return _select_json_schema_branch(branch)
    return spec


def _example_value_from_json_schema(field_name: str, spec: dict[str, Any]) -> Any:
    resolved = _select_json_schema_branch(spec)
    enum_values = resolved.get("enum")
    if isinstance(enum_values, list) and enum_values:
        return enum_values[0]

    field_type = resolved.get("type")
    if field_type == "boolean":
        return False
    if field_type == "integer":
        return 1
    if field_type == "number":
        return 0.8
    if field_type == "array":
        items = resolved.get("items")
        if isinstance(items, dict):
            return [_example_value_from_json_schema(f"{field_name}_item", items)]
        return [f"<{field_name}_item>"]
    return f"<{field_name}>"


def _build_prompt_guidance(
    tool_name: str,
    request_model: type[BaseModel],
    extra_lines: list[str] | None = None,
) -> str:
    schema = request_model.model_json_schema()
    properties = schema.get("properties", {})
    required_set = set(schema.get("required", []))

    required_keys = [key for key in properties if key in required_set]
    optional_keys = [key for key in properties if key not in required_set]
    example_payload = {
        key: _example_value_from_json_schema(key, properties[key]) for key in required_keys if key in properties
    }

    lines = [
        "以下内容仅在 `secagent-patrol` skill 不可用时作为兜底说明。",
        f"严格使用 `{tool_name}` 的后端请求 schema 字段；不要自造字段或旧别名。",
    ]

    if required_keys:
        lines.append("必填字段：" + "、".join(f"`{key}`" for key in required_keys) + "。")
    if optional_keys:
        lines.append("可选字段：" + "、".join(f"`{key}`" for key in optional_keys) + "。")
    if example_payload:
        lines.append("示例（仅含必填字段）：")
        lines.append(json.dumps(example_payload, ensure_ascii=False, separators=(",", ":")))

    if extra_lines:
        lines.extend(extra_lines)

    return "\n".join(lines)


PROMPT_GUIDANCE = {
    tool_name: _build_prompt_guidance(
        tool_name,
        request_model,
        extra_lines=PROMPT_EXTRA_GUIDANCE.get(tool_name),
    )
    for tool_name, request_model in PROMPT_SCHEMA_MODELS.items()
}


def resolve_db_path(db_path: Path | None = None) -> Path:
    if db_path is not None:
        return db_path
    env_path = os.getenv("SPIKE_DB_PATH")
    if env_path:
        return Path(env_path)
    return Path("./spike.db")


def invoke_tool(tool_name: str, payload: dict[str, Any] | None, db_path: Path | None = None) -> dict[str, Any]:
    if tool_name not in CORE_TOOL_NAMES:
        error = ToolResponse(
            ok=False,
            summary=f"unsupported tool: {tool_name}",
            data={"tool": tool_name},
            warnings=["unsupported_tool"],
        )
        return error.model_dump(mode="json", by_alias=True)

    body = payload or {}
    conn = connect_db(resolve_db_path(db_path))
    try:
        return dispatch_tool(conn, tool_name, body, source="mcp")
    except ValueError as exc:
        error = ToolResponse(
            ok=False,
            summary=str(exc),
            data={"tool": tool_name},
            warnings=["dispatch_error"],
        )
        return error.model_dump(mode="json", by_alias=True)
    finally:
        conn.close()


def get_tool_callable(tool_name: str, db_path: Path | None = None) -> Callable[..., dict[str, Any]]:
    request_model = TOOL_REQUEST_MODELS.get(tool_name)

    def _tool(payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = payload
        if isinstance(payload, BaseModel):
            body = payload.model_dump(mode="json", by_alias=True, exclude_none=True)
        return invoke_tool(tool_name, body, db_path=db_path)

    safe_name = tool_name.replace(".", "_").replace("-", "_")
    _tool.__name__ = f"tool_{safe_name}"
    _tool.__doc__ = TOOL_DESCRIPTIONS.get(tool_name, "")

    if request_model is not None:
        _tool.__signature__ = inspect.Signature(
            parameters=[
                inspect.Parameter(
                    "payload",
                    kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    default=None,
                    annotation=request_model | None,
                )
            ],
            return_annotation=dict[str, Any],
        )

    return _tool


def create_mcp_server(
    db_path: Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8000,
    mount_path: str = "/",
    sse_path: str = "/sse",
    streamable_http_path: str = "/mcp",
) -> FastMCP:
    server = FastMCP(
        name="security-analyst-agent",
        instructions="Security analyst MCP bridge that forwards to local spike CLI backend contracts.",
        host=host,
        port=port,
        mount_path=mount_path,
        sse_path=sse_path,
        streamable_http_path=streamable_http_path,
    )
    for tool_name in CORE_TOOL_NAMES:
        handler = get_tool_callable(tool_name, db_path=db_path)
        server.add_tool(
            handler,
            name=tool_name,
            description=TOOL_DESCRIPTIONS[tool_name],
            structured_output=True,
        )

    for prompt_name, prompt_text in PROMPT_GUIDANCE.items():
        @server.prompt(name=prompt_name, description=f"{prompt_name} usage guidance")
        def _prompt(text: str = prompt_text) -> str:
            return text

    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Run security analyst MCP server")
    parser.add_argument("--db-path", type=Path, default=None)
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--mount-path", default="/")
    parser.add_argument("--sse-path", default="/sse")
    parser.add_argument("--streamable-http-path", default="/mcp")
    args = parser.parse_args()

    server = create_mcp_server(
        db_path=args.db_path,
        host=args.host,
        port=args.port,
        mount_path=args.mount_path,
        sse_path=args.sse_path,
        streamable_http_path=args.streamable_http_path,
    )
    mount_path = args.mount_path if args.transport == "sse" else None
    server.run(transport=args.transport, mount_path=mount_path)


if __name__ == "__main__":
    main()
