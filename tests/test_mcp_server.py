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
