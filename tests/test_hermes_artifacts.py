import json
from pathlib import Path


CORE_TOOL_NAMES = [
    "alert.fetch",
    "alert.detail",
    "asset.search",
    "case.get",
    "case.timeline",
    "case.explain-link",
    "intel.lookup",
    "notify.preview",
    "report.draft",
]

REQUIRED_TOOL_FIELDS = {
    "name",
    "description",
    "when_to_use",
    "command_template",
    "read_only",
    "timeout_sec",
    "cost_level",
    "idempotent",
}


def test_tool_registry_contains_nine_core_tools() -> None:
    data = json.loads(Path("hermes/tool-registry.json").read_text(encoding="utf-8"))
    assert data["runtime"] == "hermes"

    tools = data["tools"]
    names = [item["name"] for item in tools]
    assert names == CORE_TOOL_NAMES
    assert len(names) == 9

    for item in tools:
        assert REQUIRED_TOOL_FIELDS.issubset(item.keys())
        assert item["read_only"] is True
        assert isinstance(item["timeout_sec"], int)
        assert item["timeout_sec"] > 0
        assert item["cost_level"] in {"low", "medium", "high"}
        assert isinstance(item["idempotent"], bool)

        command_template = item["command_template"]
        assert f"security_analyst_agent.cli {item['name']}" in command_template
        assert "--db-path ${SPIKE_DB_PATH}" in command_template
        assert "--payload" in command_template
        assert "${JSON_PAYLOAD}" in command_template


def test_patrol_loop_starts_from_alert_fetch() -> None:
    data = json.loads(Path("hermes/patrol-loop.json").read_text(encoding="utf-8"))

    assert data["schedule"] == "every_5m"
    assert data["entry_tool"] == "alert.fetch"
    assert data["default_filters"] == {"status": ["new", "open"], "limit": 20}
    assert data["max_alerts_per_run"] == 10
    assert set(data["stop_conditions"]) >= {
        "no_more_alerts",
        "time_budget_exceeded",
        "high_risk_case_found",
    }
    assert data["write_memory_on_finish"] is True


def test_main_analyst_prompt_contains_guardrails() -> None:
    text = Path("hermes/agents/main-analyst.md").read_text(encoding="utf-8")

    assert "默认先调用 `alert.fetch`" in text
    assert "只在证据不足时调用 `intel.lookup`" in text
    assert "只生成 `notify.preview`，不直接发送通知" in text
    assert "不要直接处理海量原始日志" in text


def test_runtime_runbook_contains_smoke_loop_steps() -> None:
    text = Path("docs/runbooks/hermes-runtime-bootstrap.md").read_text(encoding="utf-8")

    assert "hermes/tool-registry.json" in text
    assert "hermes/agents/main-analyst.md" in text
    assert "hermes/patrol-loop.json" in text
    assert "Confirm `alert.fetch` is called first" in text
