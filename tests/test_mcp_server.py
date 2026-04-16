import asyncio

from security_analyst_agent.bootstrap import bootstrap_spike_database, materialize_spike_runtime_demo


def test_mcp_tool_names_match_core_contract() -> None:
    from security_analyst_agent.mcp_server import CORE_TOOL_NAMES

    assert CORE_TOOL_NAMES == (
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
    materialize_spike_runtime_demo(db_path)

    tool = get_tool_callable("case.get", db_path=db_path)
    body = tool(payload={"case_id": "case_demo_001"})

    assert body["ok"] is True
    assert body["data"]["case"]["case_id"] == "case_demo_001"


def test_mcp_server_exposes_guidance_prompts() -> None:
    from security_analyst_agent.mcp_server import create_mcp_server

    server = create_mcp_server()

    prompts = asyncio.run(server.list_prompts())
    names = {item.name for item in prompts}

    assert "alert.ack" in names
    assert "case.explain-link" in names
    assert "evidence.upsert" in names
    assert "timeline.upsert" in names
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

    assert "严格使用 `case.explain-link` 的后端请求 schema 字段" in text
    assert "必填字段：`case_id`、`target_type`、`target_id`" in text
    assert "当前仅支持 `target_type=alert`" in text
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

    assert "严格使用 `intel.lookup` 的后端请求 schema 字段" in text
    assert "必填字段：`indicator`、`indicator_type`" in text
    assert "仅在 `secagent-patrol` skill 不可用时作为兜底说明" in text


def test_mcp_prompt_alert_ack_contains_usage_guidance() -> None:
    from security_analyst_agent.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = asyncio.run(server.get_prompt("alert.ack"))
    text = "\n".join(
        message.content.text
        for message in result.messages
        if getattr(message.content, "text", None)
    )

    assert "必填字段：`alert_ids`" in text
    assert "可选字段：`status`" in text
    assert "`status` 仅支持 `triaged` 或 `closed`" in text
    assert "仅在 `secagent-patrol` skill 不可用时作为兜底说明" in text


def test_mcp_prompt_assessment_upsert_contains_usage_guidance() -> None:
    from security_analyst_agent.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = asyncio.run(server.get_prompt("assessment.upsert"))
    text = "\n".join(
        message.content.text
        for message in result.messages
        if getattr(message.content, "text", None)
    )

    assert "严格使用 `assessment.upsert` 的后端请求 schema 字段" in text
    assert "必填字段：" in text
    assert "`entity_type`" in text
    assert "`verdict`" in text
    assert "仅在 `secagent-patrol` skill 不可用时作为兜底说明" in text


def test_mcp_prompt_evidence_upsert_contains_usage_guidance() -> None:
    from security_analyst_agent.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = asyncio.run(server.get_prompt("evidence.upsert"))
    text = "\n".join(
        message.content.text
        for message in result.messages
        if getattr(message.content, "text", None)
    )

    assert "严格使用 `evidence.upsert` 的后端请求 schema 字段" in text
    assert "必填字段：`evidence_id`、`case_id`、`evidence_type`、`summary`" in text
    assert "仅在 `secagent-patrol` skill 不可用时作为兜底说明" in text


def test_mcp_prompt_timeline_upsert_contains_usage_guidance() -> None:
    from security_analyst_agent.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = asyncio.run(server.get_prompt("timeline.upsert"))
    text = "\n".join(
        message.content.text
        for message in result.messages
        if getattr(message.content, "text", None)
    )

    assert "严格使用 `timeline.upsert` 的后端请求 schema 字段" in text
    assert "必填字段：`timeline_event_id`、`case_id`、`occurred_at`、`stage`、`title`" in text
    assert "仅在 `secagent-patrol` skill 不可用时作为兜底说明" in text


def test_mcp_prompt_actor_case_upsert_contains_schema_contract() -> None:
    from security_analyst_agent.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = asyncio.run(server.get_prompt("actor.case-upsert"))
    text = "\n".join(
        message.content.text
        for message in result.messages
        if getattr(message.content, "text", None)
    )

    assert "严格使用 `actor.case-upsert` 的后端请求 schema 字段" in text
    assert "必填字段：" in text
    assert "`case_actor_id`" in text
    assert "`profile_confidence`" in text
    assert "`summary`" in text


def test_mcp_prompt_actor_case_link_contains_schema_contract() -> None:
    from security_analyst_agent.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = asyncio.run(server.get_prompt("actor.case-link"))
    text = "\n".join(
        message.content.text
        for message in result.messages
        if getattr(message.content, "text", None)
    )

    assert "严格使用 `actor.case-link` 的后端请求 schema 字段" in text
    assert "`case_actor_id`" in text
    assert "`target_type`" in text
    assert "`link_confidence`" in text
    assert "`link_reason`" in text


def test_mcp_server_registers_actor_tools() -> None:
    from security_analyst_agent.mcp_server import CORE_TOOL_NAMES, TOOL_DESCRIPTIONS

    assert "actor.case-list" in CORE_TOOL_NAMES
    assert "actor.case-get" in CORE_TOOL_NAMES
    assert "actor.case-find-candidates" in CORE_TOOL_NAMES
    assert "actor.case-upsert" in CORE_TOOL_NAMES
    assert "actor.case-add-observation" in CORE_TOOL_NAMES
    assert "actor.case-add-observation-batch" in CORE_TOOL_NAMES
    assert "actor.case-link" in CORE_TOOL_NAMES
    assert "actor.case-link-batch" in CORE_TOOL_NAMES
    assert "actor.case-link" in TOOL_DESCRIPTIONS


def test_mcp_actor_tool_input_schema_is_typed() -> None:
    from security_analyst_agent.mcp_server import create_mcp_server

    server = create_mcp_server()
    tools = asyncio.run(server.list_tools())
    by_name = {item.name: item for item in tools}

    actor_upsert = by_name["actor.case-upsert"]
    schema = getattr(actor_upsert, "inputSchema", None) or getattr(actor_upsert, "input_schema", None)
    assert schema is not None

    payload_any_of = schema["properties"]["payload"]["anyOf"]
    ref_item = next(item for item in payload_any_of if "$ref" in item)
    ref_name = ref_item["$ref"].split("/")[-1]
    payload_model_schema = schema["$defs"][ref_name]

    assert payload_model_schema["title"] == "ActorCaseUpsertRequest"
    assert "case_actor_id" in payload_model_schema["required"]
    assert "profile_confidence" in payload_model_schema["required"]
    assert "summary" in payload_model_schema["required"]
