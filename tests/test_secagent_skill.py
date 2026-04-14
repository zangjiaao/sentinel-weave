from pathlib import Path


def test_secagent_skill_has_finalized_frontmatter() -> None:
    text = Path("skills/secagent-patrol/SKILL.md").read_text(encoding="utf-8")

    assert "name: secagent-patrol" in text
    assert "description: Use when" in text
    assert "[TODO:" not in text


def test_secagent_skill_contains_mcp_workflow_guidance() -> None:
    text = Path("skills/secagent-patrol/SKILL.md").read_text(encoding="utf-8")

    assert "`alert.fetch`" in text
    assert "`alert.ack`" in text
    assert "`case.get`" in text
    assert "`case.timeline`" in text
    assert "`case.explain-link`" in text
    assert "`case.upsert`" in text
    assert "`case.link-alert`" in text
    assert "`case.update-risk`" in text
    assert "`assessment.upsert`" in text
    assert "`intel.lookup`" in text
    assert "`notify.send`" in text
    assert "`report.draft`" in text
    assert "不要对同一个 `alert_id` 重复调用 `case.explain-link`" in text
    assert "不要对同一个 `indicator` 重复调用 `intel.lookup`" in text
    assert "优先复用 MCP prompt" in text
    assert "analysis_cutoff_at" in text


def test_secagent_skill_contains_output_contract() -> None:
    text = Path("skills/secagent-patrol/SKILL.md").read_text(encoding="utf-8")

    assert "`Patrol Action Summary`" in text
    assert "`Escalation`" in text
    assert "`Memory Summary`" in text
    assert "`Asia/Shanghai`" in text


def test_secagent_skill_openai_yaml_mentions_skill() -> None:
    text = Path("skills/secagent-patrol/agents/openai.yaml").read_text(encoding="utf-8")

    assert 'display_name: "SecAgent Patrol"' in text
    assert 'default_prompt: "Use $secagent-patrol' in text
