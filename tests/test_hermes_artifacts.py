import json
from pathlib import Path


CORE_TOOL_NAMES = [
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
    "assessment.upsert",
    "intel.lookup",
    "notify.send",
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


READ_ONLY_TOOLS = {
    "alert.fetch",
    "alert.detail",
    "asset.search",
    "case.get",
    "case.timeline",
    "case.explain-link",
    "intel.lookup",
    "notify.preview",
    "report.draft",
}


def test_tool_registry_contains_expected_tools() -> None:
    data = json.loads(Path("hermes/tool-registry.json").read_text(encoding="utf-8"))
    assert data["runtime"] == "hermes"

    tools = data["tools"]
    names = [item["name"] for item in tools]
    assert names == CORE_TOOL_NAMES
    assert len(names) == 15

    for item in tools:
        assert REQUIRED_TOOL_FIELDS.issubset(item.keys())
        assert item["read_only"] is (item["name"] in READ_ONLY_TOOLS)
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
    assert "对已处理告警调用 `alert.ack` 出队" in text
    assert "只在证据不足时调用 `intel.lookup`" in text
    assert "达到升级阈值时调用 `notify.send`" in text
    assert "不要直接处理海量原始日志" in text
    assert "所有时间默认使用 `Asia/Shanghai` 输出" in text
    assert "时间展示优先写 `(Asia/Shanghai)`，不要简写为 `CST`" in text
    assert "`Tool Calls`" in text
    assert "`Memory Summary`" in text
    assert "`Remaining Uncertainty`" in text
    assert "避免使用绝对措辞" in text
    assert "`notify.send` 默认使用 `channel=email` 与 `template=high_severity`" in text
    assert "仅在用户明确要求输出报告时调用 `report.draft`" in text


def test_runtime_runbook_contains_smoke_loop_steps() -> None:
    text = Path("docs/runbooks/hermes-runtime-bootstrap.md").read_text(encoding="utf-8")

    assert "Runner Adapter" in text
    assert "不是业务核心或唯一状态源" in text
    assert "本机运行态产物" in text
    assert "hermes/tool-registry.json" in text
    assert "hermes/agents/main-analyst.md" in text
    assert "hermes/SOUL.template.md" in text
    assert "make mcp-server" in text
    assert "make sync-hermes-mcp-url" in text
    assert "/Users/zangjiaao/.hermes/SOUL.md" in text
    assert "secagent-patrol" in text
    assert "hermes/patrol-loop.json" in text
    assert "Confirm `alert.fetch` is called first" in text
    assert "Confirm output includes `Tool Calls`" in text
    assert "Confirm output includes `Memory Summary`" in text
    assert "Confirm all report timestamps use `Asia/Shanghai`" in text


def test_poc_spec_keeps_hermes_runtime_neutral() -> None:
    text = Path("docs/superpowers/specs/2026-04-12-security-analyst-agent-poc-design.md").read_text(
        encoding="utf-8"
    )

    assert "核心能力必须保持 `runtime-neutral`" in text
    assert "可替换的 `Runner Adapter`" in text
    assert "`Hermes memory` 只允许保存巡检摘要" in text
    assert "`OpenAI SDK Runner`" in text
    assert "不能只依赖 `Hermes session`" in text


def test_hermes_soul_prefers_secagent_skill() -> None:
    text = Path("/Users/zangjiaao/.hermes/SOUL.md").read_text(encoding="utf-8")

    assert "secagent-patrol" in text
    assert "优先加载 `secagent-patrol`" in text
    assert "MCP prompt 仅作为兜底说明" in text


def test_repo_soul_template_contains_runtime_guardrails() -> None:
    text = Path("hermes/SOUL.template.md").read_text(encoding="utf-8")

    assert "secagent-patrol" in text
    assert "[SILENT]" in text
    assert "notify.send" in text
    assert "report.draft" in text
    assert "Asia/Shanghai" in text


def test_patrol_prompt_contains_output_contract() -> None:
    text = Path("hermes/patrol-prompt.md").read_text(encoding="utf-8")

    assert "First call `alert.fetch`" in text
    assert "call `alert.ack` to set status to `triaged`" in text
    assert "Only call `intel.lookup` when evidence is insufficient" in text
    assert "Use `assessment.upsert` to persist entity-level conclusions" in text
    assert "Never use evidence beyond the current run `analysis_cutoff_at`" in text
    assert "Call `notify.send` only when case risk reaches escalation threshold" in text
    assert "When calling `notify.send`, default to `channel=email` and `template=high_severity`" in text
    assert "Only call `report.draft` when user explicitly requests a report" in text
    assert "All timestamps must be rendered in `Asia/Shanghai`" in text
    assert "Prefer `(Asia/Shanghai)` instead of ambiguous abbreviations like `CST`" in text
    assert "If there is no material update, return exactly `[SILENT]`" in text
    assert "## Patrol Action Summary" in text
    assert "## Memory Summary" in text
    assert "Avoid unjustified absolute claims" in text


def test_memory_spike_runbook_contains_round_commands() -> None:
    text = Path("docs/runbooks/hermes-memory-spike.md").read_text(encoding="utf-8")

    assert "security_analyst_agent.memory_spike bootstrap" in text
    assert "round_01_recon" in text
    assert "round_06_reactivation" in text
    assert "Memory Summary" in text
    assert "次要干扰案件" in text
    assert "主案件" in text
    assert "不要把 Hermes memory 当事实源" in text
