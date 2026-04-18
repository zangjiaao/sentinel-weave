from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from security_analyst_agent.stages import normalize_stage, stage_rank

_SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_RECON_TO_ATTACK_BRIDGE_BONUS_WEIGHT = 0.24
_SAME_ASSET_STAGE_PROGRESS_BONUS_WEIGHT = 0.36


@dataclass
class CaseRelationScore:
    total: float
    factors: list[dict[str, Any]]
    supporting_alert_ids: list[str]
    supporting_evidence_ids: list[str]


def _normalize_set(value: Any) -> set[str]:
    if isinstance(value, set):
        return {str(item) for item in value if item}
    if isinstance(value, (list, tuple)):
        return {str(item) for item in value if item}
    if isinstance(value, str) and value:
        return {value}
    return set()


def _stage_continuity_score(left_stage: str | None, right_stage: str | None) -> float:
    left_rank = stage_rank(left_stage)
    right_rank = stage_rank(right_stage)
    if left_rank == 0 or right_rank == 0:
        return 0.5
    distance = abs(left_rank - right_rank)
    if distance == 0:
        return 0.85
    if distance == 1:
        return 1.0
    if distance == 2:
        return 0.6
    return 0.0


def _temporal_continuity_score(left: dict[str, Any], right: dict[str, Any]) -> float:
    left_time = left.get("last_event_at") or left.get("updated_at")
    right_time = right.get("last_event_at") or right.get("updated_at")
    if not left_time or not right_time:
        return 0.7

    try:
        left_dt = datetime.fromisoformat(str(left_time))
        right_dt = datetime.fromisoformat(str(right_time))
    except ValueError:
        return 0.5

    hours = abs((right_dt - left_dt).total_seconds()) / 3600
    if hours <= 24:
        return 1.0
    if hours <= 72:
        return 0.8
    if hours <= 7 * 24:
        return 0.55
    return 0.25


def _recon_to_attack_bridge_score(
    *,
    left: dict[str, Any],
    right: dict[str, Any],
    shared_assets: set[str],
    shared_src_ips: set[str],
    temporal_score: float,
) -> float:
    if not shared_assets or not shared_src_ips:
        return 0.0
    if temporal_score < 0.8:
        return 0.0

    left_stage = normalize_stage(left.get("current_stage"))
    right_stage = normalize_stage(right.get("current_stage"))
    left_rank = stage_rank(left_stage)
    right_rank = stage_rank(right_stage)
    if min(left_rank, right_rank) != stage_rank("recon"):
        return 0.0
    if max(left_rank, right_rank) < stage_rank("persistence"):
        return 0.0

    left_severity = _SEVERITY_ORDER.get(str(left.get("overall_severity") or "").lower(), 0)
    right_severity = _SEVERITY_ORDER.get(str(right.get("overall_severity") or "").lower(), 0)
    if max(left_severity, right_severity) < _SEVERITY_ORDER["high"]:
        return 0.0
    return 1.0


def _same_asset_stage_progress_score(
    *,
    left: dict[str, Any],
    right: dict[str, Any],
    left_assets: set[str],
    right_assets: set[str],
    shared_assets: set[str],
    temporal_score: float,
) -> float:
    if not shared_assets:
        return 0.0
    if left_assets == right_assets:
        return 0.0
    if temporal_score < 0.8:
        return 0.0

    left_stage = normalize_stage(left.get("current_stage"))
    right_stage = normalize_stage(right.get("current_stage"))
    left_rank = stage_rank(left_stage)
    right_rank = stage_rank(right_stage)
    if min(left_rank, right_rank) < stage_rank("persistence"):
        return 0.0
    if max(left_rank, right_rank) < stage_rank("command_execution"):
        return 0.0
    if left_rank == right_rank:
        return 0.0
    if abs(left_rank - right_rank) > 2:
        return 0.0

    left_severity = _SEVERITY_ORDER.get(str(left.get("overall_severity") or "").lower(), 0)
    right_severity = _SEVERITY_ORDER.get(str(right.get("overall_severity") or "").lower(), 0)
    if max(left_severity, right_severity) < _SEVERITY_ORDER["high"]:
        return 0.0
    if min(left_severity, right_severity) < _SEVERITY_ORDER["medium"]:
        return 0.0
    return 1.0


def score_case_relation(left: dict[str, Any], right: dict[str, Any]) -> CaseRelationScore:
    left_assets = _normalize_set(left.get("asset_ids"))
    right_assets = _normalize_set(right.get("asset_ids"))
    asset_overlap = left_assets & right_assets
    asset_union = left_assets | right_assets
    asset_overlap_score = (len(asset_overlap) / len(asset_union)) if asset_union else 0.0

    left_ips = _normalize_set(left.get("src_ips"))
    right_ips = _normalize_set(right.get("src_ips"))
    ip_overlap = left_ips & right_ips
    ip_union = left_ips | right_ips
    ioc_overlap_score = (len(ip_overlap) / len(ip_union)) if ip_union else 0.0

    stage_score = _stage_continuity_score(left.get("current_stage"), right.get("current_stage"))
    temporal_score = _temporal_continuity_score(left, right)
    recon_bridge_score = _recon_to_attack_bridge_score(
        left=left,
        right=right,
        shared_assets=asset_overlap,
        shared_src_ips=ip_overlap,
        temporal_score=temporal_score,
    )
    same_asset_stage_progress_score = _same_asset_stage_progress_score(
        left=left,
        right=right,
        left_assets=left_assets,
        right_assets=right_assets,
        shared_assets=asset_overlap,
        temporal_score=temporal_score,
    )

    weights = {
        "asset_overlap": 0.42,
        "stage_continuity": 0.32,
        "ioc_overlap": 0.14,
        "temporal_continuity": 0.12,
    }

    factors = [
        {
            "factor_type": "asset_overlap",
            "weight": weights["asset_overlap"],
            "score": round(asset_overlap_score, 4),
            "summary": f"shared_assets={len(asset_overlap)}",
        },
        {
            "factor_type": "stage_continuity",
            "weight": weights["stage_continuity"],
            "score": round(stage_score, 4),
            "summary": f"stages={left.get('current_stage')}->{right.get('current_stage')}",
        },
        {
            "factor_type": "ioc_overlap",
            "weight": weights["ioc_overlap"],
            "score": round(ioc_overlap_score, 4),
            "summary": f"shared_src_ips={len(ip_overlap)}",
        },
        {
            "factor_type": "temporal_continuity",
            "weight": weights["temporal_continuity"],
            "score": round(temporal_score, 4),
            "summary": "event recency continuity",
        },
        {
            "factor_type": "recon_to_attack_bridge",
            "weight": _RECON_TO_ATTACK_BRIDGE_BONUS_WEIGHT,
            "score": round(recon_bridge_score, 4),
            "summary": "recon continuation into high-signal attack chain",
        },
        {
            "factor_type": "same_asset_stage_progress",
            "weight": _SAME_ASSET_STAGE_PROGRESS_BONUS_WEIGHT,
            "score": round(same_asset_stage_progress_score, 4),
            "summary": "same asset high-signal stage progression despite source rotation",
        },
    ]

    total = round(sum(item["weight"] * item["score"] for item in factors), 4)
    supporting_alert_ids = sorted(
        _normalize_set(left.get("alert_ids")) & _normalize_set(right.get("alert_ids"))
    )
    supporting_evidence_ids = sorted(
        _normalize_set(left.get("evidence_ids")) & _normalize_set(right.get("evidence_ids"))
    )
    return CaseRelationScore(
        total=total,
        factors=factors,
        supporting_alert_ids=supporting_alert_ids,
        supporting_evidence_ids=supporting_evidence_ids,
    )
