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
    assert "`evidence.upsert`" in text
    assert "`timeline.upsert`" in text
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


def test_secagent_skill_contains_assessment_upsert_contract() -> None:
    text = Path("skills/secagent-patrol/SKILL.md").read_text(encoding="utf-8")

    assert "`assessment.upsert`" in text
    assert "`attacker` / `compromised_host` / `noise`" in text
    assert "参数字段一律以对应 MCP prompt 的 schema contract 为准" in text


def test_secagent_skill_contains_case_link_alert_contract() -> None:
    text = Path("skills/secagent-patrol/SKILL.md").read_text(encoding="utf-8")

    assert "`case.link-alert`" in text
    assert "参数字段一律以对应 MCP prompt 的 schema contract 为准" in text


def test_secagent_skill_contains_exact_case_upsert_contract() -> None:
    text = Path("skills/secagent-patrol/SKILL.md").read_text(encoding="utf-8")

    assert "`case.upsert`" in text
    assert "参数字段一律以对应 MCP prompt 的 schema contract 为准" in text


def test_secagent_skill_requires_case_update_risk_for_case_level_assessment() -> None:
    text = Path("skills/secagent-patrol/SKILL.md").read_text(encoding="utf-8")

    assert "`case.update-risk`" in text
    assert "案件级评估" in text
    assert "即使案件头字段已经同步" in text


def test_secagent_skill_teaches_case_actor_workflow() -> None:
    text = Path("skills/secagent-patrol/SKILL.md").read_text(encoding="utf-8")

    assert "actor.case-list" in text
    assert "actor.case-find-candidates" in text
    assert "actor.case-upsert" in text
    assert "不要因为源 IP 变化就创建新的案内画像" in text


def test_secagent_skill_marks_only_alert_asset_intel_as_preloaded_facts() -> None:
    text = Path("skills/secagent-patrol/SKILL.md").read_text(encoding="utf-8")

    assert "`alerts` / `assets` / `intel_cache`" in text
    assert "`cases` / `case_alert_links` / `timeline_events` / `evidence`" in text


def test_secagent_skill_openai_yaml_mentions_skill() -> None:
    text = Path("skills/secagent-patrol/agents/openai.yaml").read_text(encoding="utf-8")

    assert 'display_name: "SecAgent Patrol"' in text
    assert 'default_prompt: "Use $secagent-patrol' in text
