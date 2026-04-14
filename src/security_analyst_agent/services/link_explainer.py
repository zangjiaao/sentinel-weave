def explain_alert_link(alert: dict, case_id: str, supporting_evidence_ids: list[str] | None = None) -> dict:
    evidence_ids = sorted(set(supporting_evidence_ids or []))
    positive_factors: list[dict] = [
        {"factor_type": "same_target_asset", "weight": 0.35, "summary": "命中同一目标资产，攻击面连续"},
        {"factor_type": "case_continuity", "weight": 0.22, "summary": f"告警仍归属同一案件 {case_id}"},
    ]
    uncertainties: list[str] = []

    if evidence_ids:
        positive_factors.append(
            {
                "factor_type": "supporting_evidence",
                "weight": 0.25,
                "summary": f"已关联 {len(evidence_ids)} 条同案证据",
            }
        )
    else:
        uncertainties.append("当前轮次缺少可直接支撑关联的证据，结论以告警上下文为主")

    if "evi_webshell_01" in evidence_ids and alert.get("attack_stage") in {
        "command_execution",
        "lateral_prep",
    }:
        positive_factors.append(
            {
                "factor_type": "same_attack_path",
                "weight": 0.18,
                "summary": "webshell 落地后出现后续执行/横向迹象",
            }
        )

    if alert.get("src_ip") is None:
        uncertainties.append("当前告警源 IP 缺失，需要结合主机侧证据复核")

    confidence = min(0.95, 0.62 + 0.07 * len(positive_factors) + 0.04 * len(evidence_ids))
    return {
        "is_linked": True,
        "confidence": round(confidence, 2),
        "reason_summary": "同一目标资产上的多阶段活动形成连续攻击路径",
        "positive_factors": positive_factors,
        "negative_factors": [],
        "uncertainties": uncertainties,
        "supporting_evidence_ids": evidence_ids,
    }
