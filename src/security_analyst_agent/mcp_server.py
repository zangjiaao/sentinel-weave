import argparse
import os
from pathlib import Path
from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

from security_analyst_agent.db import connect_db
from security_analyst_agent.schemas.common import ToolResponse
from security_analyst_agent.tool_dispatch import dispatch_tool

CORE_TOOL_NAMES = (
    "alert.fetch",
    "alert.detail",
    "alert.ack",
    "asset.search",
    "case.get",
    "case.timeline",
    "case.explain-link",
    "case.upsert",
    "case.link-alert",
    "case.update-risk",
    "evidence.upsert",
    "timeline.upsert",
    "assessment.upsert",
    "intel.lookup",
    "notify.send",
    "notify.preview",
    "report.draft",
)

TOOL_DESCRIPTIONS = {
    "alert.fetch": "拉取待研判告警摘要队列。",
    "alert.detail": "读取单条告警详情与关键证据摘要。",
    "alert.ack": "将已处理告警标记为 triaged/closed，避免重复出队。",
    "asset.search": "按指标搜索资产并返回资产上下文。",
    "case.get": "读取案件头部摘要与当前风险结论。",
    "case.timeline": "读取案件时间线与攻击阶段演进。",
    "case.explain-link": "解释事件与案件之间的关联依据。",
    "case.upsert": "创建或更新案件主记录。",
    "case.link-alert": "将告警关联到指定案件并记录关联理由。",
    "case.update-risk": "更新案件风险等级、阶段与状态。",
    "evidence.upsert": "写入或更新案件证据记录。",
    "timeline.upsert": "写入或更新时间线节点，沉淀攻击过程。",
    "assessment.upsert": "写入实体级风险评估（如攻击IP、失陷主机）。",
    "intel.lookup": "查询缓存化威胁情报用于补证。",
    "notify.send": "触发模拟通知发送并写入通知出站记录。",
    "notify.preview": "生成通知预览草稿，不进行实际发送。",
    "report.draft": "生成案件分析报告草稿。",
}

PROMPT_GUIDANCE = {
    "alert.ack": "\n".join(
        [
            "以下内容仅在 `secagent-patrol` skill 不可用时作为兜底说明。",
            '{"alert_ids":["<alert_id_1>","<alert_id_2>"],"status":"triaged"}',
            "状态仅支持 `triaged` 或 `closed`。",
        ]
    ),
    "case.explain-link": "\n".join(
        [
            "以下内容仅在 `secagent-patrol` skill 不可用时作为兜底说明。",
            '{"case_id": "<case_id>", "target_type": "alert", "target_id": "<alert_id>"}',
            "仅支持 `target_type=alert`。",
        ]
    ),
    "intel.lookup": "\n".join(
        [
            "以下内容仅在 `secagent-patrol` skill 不可用时作为兜底说明。",
            '{"indicator": "<ip_or_indicator>", "indicator_type": "ip"}',
        ]
    ),
    "case.upsert": "\n".join(
        [
            "以下内容仅在 `secagent-patrol` skill 不可用时作为兜底说明。",
            '{"case_id":"<case_id>","title":"<title>","status":"open","overall_severity":"medium","current_stage":"recon","primary_actor_id":"<actor_or_null>"}',
        ]
    ),
    "case.link-alert": "\n".join(
        [
            "以下内容仅在 `secagent-patrol` skill 不可用时作为兜底说明。",
            '{"case_id":"<case_id>","alert_id":"<alert_id>","confidence":0.8,"reason":"<why_linked>"}',
        ]
    ),
    "case.update-risk": "\n".join(
        [
            "以下内容仅在 `secagent-patrol` skill 不可用时作为兜底说明。",
            '{"case_id":"<case_id>","overall_severity":"high","current_stage":"persistence","status":"investigating","force_downgrade":false}',
            "默认阻止阶段回退；仅在确有需要时传入 force_downgrade=true。",
        ]
    ),
    "evidence.upsert": "\n".join(
        [
            "以下内容仅在 `secagent-patrol` skill 不可用时作为兜底说明。",
            '{"evidence_id":"<evidence_id>","case_id":"<case_id>","occurred_at":"2026-04-15T10:00:00+08:00","evidence_type":"webshell","summary":"<evidence_summary>"}',
        ]
    ),
    "timeline.upsert": "\n".join(
        [
            "以下内容仅在 `secagent-patrol` skill 不可用时作为兜底说明。",
            '{"timeline_event_id":"<timeline_event_id>","case_id":"<case_id>","occurred_at":"2026-04-15T10:01:00+08:00","stage":"persistence","title":"<timeline_title>","related_alert_ids":["<alert_id>"],"related_evidence_ids":["<evidence_id>"]}',
        ]
    ),
    "assessment.upsert": "\n".join(
        [
            "以下内容仅在 `secagent-patrol` skill 不可用时作为兜底说明。",
            '{"entity_type":"ip","entity_key":"198.51.100.23","entity_label":"198.51.100.23","related_case_id":"case_demo_001","risk_level":"high","assessment_confidence":0.93,"verdict":"attacker","reason_summary":"多阶段攻击链核心来源","supporting_alert_ids":["alt_r2_webshell"],"supporting_evidence_ids":["evi_webshell_01"]}',
        ]
    ),
    "notify.send": "\n".join(
        [
            "以下内容仅在 `secagent-patrol` skill 不可用时作为兜底说明。",
            '{"case_id":"<case_id>","channel":"email","template":"high_severity"}',
        ]
    ),
    "notify.preview": "\n".join(
        [
            "以下内容仅在 `secagent-patrol` skill 不可用时作为兜底说明。",
            '{"case_id": "<case_id>", "channel": "email", "template": "high_severity"}',
        ]
    ),
    "report.draft": "\n".join(
        [
            "以下内容仅在 `secagent-patrol` skill 不可用时作为兜底说明。",
            '{"case_id": "<case_id>", "template": "standard", "tone": "analytical"}',
        ]
    ),
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
    def _tool(payload: dict[str, Any] | None = None) -> dict[str, Any]:
        return invoke_tool(tool_name, payload, db_path=db_path)

    safe_name = tool_name.replace(".", "_").replace("-", "_")
    _tool.__name__ = f"tool_{safe_name}"
    _tool.__doc__ = TOOL_DESCRIPTIONS.get(tool_name, "")
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
