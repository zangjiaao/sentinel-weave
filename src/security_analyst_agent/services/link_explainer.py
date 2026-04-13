def explain_alert_link(alert: dict) -> dict:
    return {
        "is_linked": True,
        "confidence": 0.87,
        "reason_summary": "同一目标资产上的多阶段活动形成连续攻击路径",
        "positive_factors": [
            {"factor_type": "same_target_asset", "weight": 0.35, "summary": "命中同一生产 API 资产"},
            {"factor_type": "same_attack_path", "weight": 0.30, "summary": "webshell 写入后出现命令执行"},
            {"factor_type": "case_continuity", "weight": 0.22, "summary": f"告警仍归属同一案件 {alert['case_id']}"},
        ],
        "negative_factors": [],
        "uncertainties": ["攻击源 IP 已发生变化，但仍指向同一落点"],
        "supporting_evidence_ids": ["evi_webshell_01", "evi_shell_conn_01"],
    }

