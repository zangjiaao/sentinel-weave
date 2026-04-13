import sqlite3
from typing import Callable

from security_analyst_agent.tools.alert_tools import alert_detail, alert_fetch
from security_analyst_agent.tools.asset_tools import asset_search
from security_analyst_agent.tools.case_tools import case_explain_link, case_get, case_timeline
from security_analyst_agent.tools.intel_tools import intel_lookup
from security_analyst_agent.tools.output_tools import notify_preview, report_draft

ToolHandler = Callable[[sqlite3.Connection, dict], dict]

TOOL_HANDLERS: dict[str, ToolHandler] = {
    "alert.fetch": alert_fetch,
    "alert.detail": alert_detail,
    "asset.search": asset_search,
    "case.get": case_get,
    "case.timeline": case_timeline,
    "case.explain-link": case_explain_link,
    "intel.lookup": intel_lookup,
    "notify.preview": notify_preview,
    "report.draft": report_draft,
}


def dispatch_tool(conn: sqlite3.Connection, tool_name: str, payload: dict) -> dict:
    if tool_name not in TOOL_HANDLERS:
        raise ValueError(f"unsupported tool: {tool_name}")
    return TOOL_HANDLERS[tool_name](conn, payload)

