import asyncio

from security_analyst_agent.bootstrap import bootstrap_spike_database


def test_mcp_tool_names_match_core_contract() -> None:
    from security_analyst_agent.mcp_server import CORE_TOOL_NAMES

    assert CORE_TOOL_NAMES == (
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


def test_invoke_tool_forwards_to_existing_backend(tmp_path) -> None:
    from security_analyst_agent.mcp_server import invoke_tool

    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)

    body = invoke_tool("alert.fetch", {"status": ["new", "open"], "limit": 2}, db_path=db_path)
    assert body["ok"] is True
    assert "alerts" in body["data"]
    assert isinstance(body["warnings"], list)


def test_mcp_tools_return_dict(tmp_path) -> None:
    from security_analyst_agent.mcp_server import get_tool_callable

    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)

    tool = get_tool_callable("case.get", db_path=db_path)
    body = tool(payload={"case_id": "case_demo_001"})

    assert body["ok"] is True
    assert body["data"]["case"]["case_id"] == "case_demo_001"


def test_mcp_server_exposes_guidance_prompts() -> None:
    from security_analyst_agent.mcp_server import create_mcp_server

    server = create_mcp_server()

    prompts = asyncio.run(server.list_prompts())
    names = {item.name for item in prompts}

    assert "case.explain-link" in names
    assert "intel.lookup" in names


def test_mcp_prompt_case_explain_link_contains_usage_guidance() -> None:
    from security_analyst_agent.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = asyncio.run(server.get_prompt("case.explain-link"))
    text = "\n".join(
        message.content.text
        for message in result.messages
        if getattr(message.content, "text", None)
    )

    assert '"target_type": "alert"' in text
    assert '"target_id": "<alert_id>"' in text
    assert "仅在 `secagent-patrol` skill 不可用时作为兜底说明" in text


def test_mcp_prompt_intel_lookup_contains_usage_guidance() -> None:
    from security_analyst_agent.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = asyncio.run(server.get_prompt("intel.lookup"))
    text = "\n".join(
        message.content.text
        for message in result.messages
        if getattr(message.content, "text", None)
    )

    assert '"indicator": "<ip_or_indicator>"' in text
    assert '"indicator_type": "ip"' in text
    assert "仅在 `secagent-patrol` skill 不可用时作为兜底说明" in text
