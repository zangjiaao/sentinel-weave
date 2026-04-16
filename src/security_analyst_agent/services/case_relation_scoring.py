from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

_STAGE_ORDER = {
    "recon": 1,
    "exploit": 2,
    "persistence": 3,
    "command_execution": 4,
    "lateral_prep": 5,
}


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
    left_rank = _STAGE_ORDER.get(left_stage or "")
    right_rank = _STAGE_ORDER.get(right_stage or "")
    if left_rank is None or right_rank is None:
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
