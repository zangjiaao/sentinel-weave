def build_notify_preview(case: dict, channel: str) -> dict:
    return {
        "preview_id": f"preview_{case['case_id']}",
        "channel": channel,
        "title": f"[{case['overall_severity'].upper()}] {case['title']}",
        "body": "攻击者已从侦察进入命令执行阶段，请立即核查受害资产。",
        "overall_severity": case["overall_severity"],
        "why_now": "24 小时内出现 webshell 后续控制行为，风险明显升级",
        "recommended_recipients": ["soc_oncall", "asset_owner"],
        "dedupe_key": case["case_id"],
    }


def build_report(case: dict, timeline: list[dict], tone: str) -> dict:
    timeline_lines = [f"- {item['occurred_at']} {item['stage']} {item['title']}" for item in timeline]
    draft_markdown = "\n".join(
        [
            f"# {case['title']}",
            "## Summary",
            "该案件表现为典型的多阶段 Web 入侵。",
            f"语气: {tone}",
            "## Timeline",
            *timeline_lines,
        ]
    )
    return {
        "report_id": f"report_{case['case_id']}",
        "title": case["title"],
        "summary": "该案件表现为典型的多阶段 Web 入侵。",
        "outline": ["summary", "timeline", "targets", "actor_profile", "evidence", "recommendations"],
        "draft_markdown": draft_markdown,
    }

