import json
from pathlib import Path


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
    assert "`evidence.upsert`" in text
    assert "`timeline.upsert`" in text
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
    assert "不要猜测或拼接不存在的 `case_id`" in text


def test_runtime_runbook_contains_smoke_loop_steps() -> None:
    text = Path("docs/runbooks/hermes-runtime-bootstrap.md").read_text(encoding="utf-8")

    assert "Runner Adapter" in text
    assert "不是业务核心或唯一状态源" in text
    assert "本机运行态产物" in text
    assert "Verify MCP Tool Discovery" in text
    assert "hermes/agents/main-analyst.md" in text
    assert "hermes/SOUL.template.md" in text
    assert "hermes/SOUL.patrol.template.md" in text
    assert "make mcp-server" in text
    assert "make sync-hermes-patrol" in text
    assert "make sync-hermes-mcp-url" in text
    assert "hermes mcp test secagent" in text
    assert "/Users/zangjiaao/.hermes/SOUL.md" in text
    assert "/Users/zangjiaao/.hermes-patrol" in text
    assert "hermes chat --continue" in text
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
    assert "related_case_id" in text
    assert "assessment_confidence" in text
    assert "supporting_alert_ids" in text
    assert "supporting_evidence_ids" in text
    assert "case.link-alert-batch" in text
    assert "evidence.upsert" in text
    assert "timeline.upsert" in text
    assert "confidence" in text
    assert "case_assessments" in text or "案件级评估" in text


def test_patrol_soul_template_is_lightweight_and_skill_first() -> None:
    text = Path("hermes/SOUL.patrol.template.md").read_text(encoding="utf-8")

    assert "secagent-patrol" in text
    assert "alert.fetch" in text
    assert "intel.lookup" in text
    assert "notify.send" in text
    assert "report.draft" in text
    assert "[SILENT]" in text
    assert "Asia/Shanghai" in text


def test_patrol_prompt_contains_output_contract() -> None:
    text = Path("hermes/patrol-prompt.md").read_text(encoding="utf-8")

    assert "First call `alert.fetch`" in text
    assert "call `alert.detail-batch` with at least one representative alert before creating a new case" in text
    assert "Never fabricate a `case_id` for `case.get`" in text
    assert "call `alert.ack` to set status to `triaged`" in text
    assert "Only call `intel.lookup` when evidence is insufficient" in text
    assert "Use exact `case.upsert-batch` schema keys" in text
    assert "Use `assessment.upsert-batch` to persist entity-level conclusions" in text
    assert "Use `evidence.upsert` to persist derived evidence records" in text
    assert "Use `timeline.upsert` to persist attack-chain timeline nodes" in text
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
