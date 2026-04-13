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
    "asset.search",
    "case.get",
    "case.timeline",
    "case.explain-link",
    "intel.lookup",
    "notify.preview",
    "report.draft",
)

TOOL_DESCRIPTIONS = {
    "alert.fetch": "拉取待研判告警摘要队列。",
    "alert.detail": "读取单条告警详情与关键证据摘要。",
    "asset.search": "按指标搜索资产并返回资产上下文。",
    "case.get": "读取案件头部摘要与当前风险结论。",
    "case.timeline": "读取案件时间线与攻击阶段演进。",
    "case.explain-link": "解释事件与案件之间的关联依据。",
    "intel.lookup": "查询缓存化威胁情报用于补证。",
    "notify.preview": "生成通知预览草稿，不进行实际发送。",
    "report.draft": "生成案件分析报告草稿。",
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
        return dispatch_tool(conn, tool_name, body)
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


def create_mcp_server(db_path: Path | None = None) -> FastMCP:
    server = FastMCP(
        name="security-analyst-agent",
        instructions="Security analyst MCP bridge that forwards to local spike CLI backend contracts.",
    )
    for tool_name in CORE_TOOL_NAMES:
        handler = get_tool_callable(tool_name, db_path=db_path)
        server.add_tool(
            handler,
            name=tool_name,
            description=TOOL_DESCRIPTIONS[tool_name],
            structured_output=True,
        )
    return server


def main() -> None:
    create_mcp_server().run(transport="stdio")


if __name__ == "__main__":
    main()
