from __future__ import annotations

STAGE_ORDER = {
    "recon": 1,
    "exploit": 2,
    "persistence": 3,
    "command_execution": 4,
    "lateral_prep": 5,
}


def _recommended_action(score: float, alert: dict) -> str:
    if score >= 0.80:
        return "link_existing_case_actor"
    if score >= 0.45:
        return "candidate_actor_relation"
    if alert.get("severity") == "low" or alert.get("attack_stage") == "recon":
        return "classify_as_noise"
    return "create_new_case_actor"


def score_case_actor_candidate(context: dict) -> dict:
    alert = context["target_alert"]
    profile = context["profile"]
    observations = context["observations"]
    positive_factors: list[dict] = []
    negative_factors: list[dict] = []

    observed_values = {item["observation_value"] for item in observations}
    observed_assets = {
        item["observation_value"]
        for item in observations
        if item["observation_type"] in {"asset_id", "compromised_asset"}
    }

    artifact_continuity_score = 0.0
    if any(item["observation_type"] in {"webshell_path", "uri", "c2", "file_hash"} for item in observations):
        artifact_continuity_score = 0.45
        positive_factors.append(
            {"factor_type": "artifact_context_present", "summary": "已有攻击产物上下文可用于关联"}
        )

    behavior_continuity_score = 0.2
    profile_stage_rank = STAGE_ORDER.get(profile.get("current_stage"), 0)
    alert_stage_rank = STAGE_ORDER.get(alert.get("attack_stage"), 0)
    if alert_stage_rank >= profile_stage_rank and alert_stage_rank > 0:
        behavior_continuity_score = 0.85 if alert_stage_rank > profile_stage_rank else 0.65
        positive_factors.append(
            {"factor_type": "behavior_continuity", "summary": "告警阶段与案内画像行为连续"}
        )
    elif alert.get("severity") in {"high", "critical"} and alert.get("attack_stage") == "command_execution":
        behavior_continuity_score = 0.75
        positive_factors.append(
            {"factor_type": "reactivation_behavior", "summary": "高风险回连/命令执行行为可视为画像延续"}
        )

    asset_overlap_score = 0.0
    if alert.get("asset_id") and alert["asset_id"] in observed_assets:
        asset_overlap_score = 1.0
        positive_factors.append({"factor_type": "same_actor_asset", "summary": "命中画像已观察资产"})
    elif alert.get("asset_id"):
        asset_overlap_score = 0.8
        positive_factors.append({"factor_type": "same_case_asset", "summary": "告警仍处于同一案件资产面"})

    infra_similarity_score = 0.0
    if alert.get("src_ip") and alert["src_ip"] in observed_values:
        infra_similarity_score = 1.0
        positive_factors.append({"factor_type": "same_source_ip", "summary": "源 IP 已存在于画像观测中"})
    elif alert.get("src_ip"):
        infra_similarity_score = 0.2
        negative_factors.append({"factor_type": "source_ip_changed", "summary": "源 IP 变化，不能单独判定为新画像"})

    temporal_continuity_score = 0.65
    if profile.get("last_seen_at"):
        positive_factors.append({"factor_type": "existing_actor_context", "summary": "画像已有历史活动上下文"})

    relation_score = round(
        artifact_continuity_score * 0.35
        + behavior_continuity_score * 0.25
        + asset_overlap_score * 0.20
        + infra_similarity_score * 0.10
        + temporal_continuity_score * 0.10,
        4,
    )
    return {
        "case_actor_id": profile["case_actor_id"],
        "case_id": profile["case_id"],
        "label": profile["label"],
        "relation_score": relation_score,
        "artifact_continuity_score": artifact_continuity_score,
        "behavior_continuity_score": behavior_continuity_score,
        "asset_overlap_score": asset_overlap_score,
        "infra_similarity_score": infra_similarity_score,
        "temporal_continuity_score": temporal_continuity_score,
        "positive_factors": positive_factors,
        "negative_factors": negative_factors,
        "recommended_action": _recommended_action(relation_score, alert),
    }
