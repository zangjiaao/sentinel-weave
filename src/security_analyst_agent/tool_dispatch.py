import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from pydantic import ValidationError

from security_analyst_agent.config import (
    DEFAULT_MCP_ALERT_FETCH_AUTO_CLUSTER_THRESHOLD,
    DEFAULT_NEUTRAL_CASE_LINK_GUARD,
)
from security_analyst_agent.repositories.assessments import upsert_entity_assessment
from security_analyst_agent.repositories.audit import (
    bind_run_context,
    finalize_mcp_auto_run_after_tool,
    insert_case_assessment_log,
    insert_tool_call_log,
    reset_bound_run_context,
    resolve_run_context_for_dispatch,
)
from security_analyst_agent.repositories.cases import link_alert_to_case
from security_analyst_agent.stages import stage_rank
from security_analyst_agent.tools.alert_tools import (
    alert_ack,
    alert_detail,
    alert_detail_batch,
    alert_fetch,
    alert_ip_context,
    alert_suspect_ip_topk,
)
from security_analyst_agent.tools.assessment_tools import assessment_upsert, assessment_upsert_batch
from security_analyst_agent.tools.asset_tools import asset_search
from security_analyst_agent.tools.actor_tools import (
    actor_case_add_observation,
    actor_case_add_observation_batch,
    actor_case_find_candidates,
    actor_case_get,
    actor_case_link,
    actor_case_link_batch,
    actor_case_list,
    actor_case_upsert,
)
from security_analyst_agent.tools.case_tools import (
    case_explain_link,
    case_get,
    case_list,
    case_link_alert,
    case_link_alert_batch,
    case_search,
    case_timeline,
    case_update_risk,
    case_upsert_batch,
    case_upsert,
)
from security_analyst_agent.tools.derived_tools import evidence_upsert, timeline_upsert
from security_analyst_agent.tools.intel_tools import intel_lookup
from security_analyst_agent.tools.output_tools import notify_preview, notify_send, report_draft

ToolHandler = Callable[[sqlite3.Connection, dict], dict]

_CASE_LINK_CONSISTENCY_SCORE_THRESHOLD = 0.55
_CASE_LINK_REDIRECT_SCORE_THRESHOLD = 0.65
_CASE_LINK_TIME_PROXIMITY_WINDOW = timedelta(hours=72)
_CASE_LINK_FALLBACK_ASSESSMENT_MIN_CONFIDENCE = 0.8
_CASE_LINK_AUTO_EXPAND_MIN_CONFIDENCE = 0.8
_CASE_LINK_AUTO_EXPAND_TIME_WINDOW = timedelta(hours=72)
_CASE_LINK_AUTO_EXPAND_MAX_PER_ANCHOR = 30
_CASE_LINK_AUTO_EXPAND_MAX_TOTAL = 160
_CASE_LINK_AUTO_EXPAND_ALLOWED_STAGES = {
    "exploit",
    "persistence",
    "command_execution",
    "reactivation",
    "lateral_prep",
}
_ENTITY_ASSESSMENT_AUTO_MIN_ALERT_COUNT = 3
_ENTITY_ASSESSMENT_AUTO_MIN_STAGE_COUNT = 2
_ENTITY_ASSESSMENT_AUTO_MIN_MAX_STAGE_RANK = stage_rank("persistence")

TOOL_HANDLERS: dict[str, ToolHandler] = {
    "alert.fetch": alert_fetch,
    "alert.suspect-ip-topk": alert_suspect_ip_topk,
    "alert.ip-context": alert_ip_context,
    "alert.detail": alert_detail,
    "alert.detail-batch": alert_detail_batch,
    "alert.ack": alert_ack,
    "asset.search": asset_search,
    "actor.case-list": actor_case_list,
    "actor.case-get": actor_case_get,
    "actor.case-find-candidates": actor_case_find_candidates,
    "actor.case-upsert": actor_case_upsert,
    "actor.case-add-observation": actor_case_add_observation,
    "actor.case-add-observation-batch": actor_case_add_observation_batch,
    "actor.case-link": actor_case_link,
    "actor.case-link-batch": actor_case_link_batch,
    "case.get": case_get,
    "case.list": case_list,
    "case.search": case_search,
    "case.timeline": case_timeline,
    "case.explain-link": case_explain_link,
    "case.upsert": case_upsert,
    "case.upsert-batch": case_upsert_batch,
    "case.link-alert": case_link_alert,
    "case.link-alert-batch": case_link_alert_batch,
    "case.update-risk": case_update_risk,
    "evidence.upsert": evidence_upsert,
    "timeline.upsert": timeline_upsert,
    "assessment.upsert": assessment_upsert,
    "assessment.upsert-batch": assessment_upsert_batch,
    "intel.lookup": intel_lookup,
    "notify.send": notify_send,
    "notify.preview": notify_preview,
    "report.draft": report_draft,
}


def _validation_error_summary(exc: ValidationError) -> str:
    errors = exc.errors()
    if not errors:
        return "payload 校验失败"
    first = errors[0]
    location = ".".join(str(item) for item in first.get("loc", []))
    message = str(first.get("msg") or "invalid payload")
    if location:
        return f"payload 校验失败：{location} {message}"
    return f"payload 校验失败：{message}"


def _fetch_alert_signal_map(conn: sqlite3.Connection, alert_ids: list[str]) -> dict[str, dict[str, str]]:
    deduped = list(dict.fromkeys(str(item) for item in alert_ids if item))
    if not deduped:
        return {}
    rows = conn.execute(
        f"""
        select alert_id, severity, attack_stage
        from alerts
        where alert_id in ({', '.join('?' for _ in deduped)})
        """,
        deduped,
    ).fetchall()
    signal_map: dict[str, dict[str, str]] = {}
    for row in rows:
        signal_map[str(row["alert_id"])] = {
            "severity": str(row["severity"] or "").lower(),
            "attack_stage": str(row["attack_stage"] or "").lower(),
        }
    return signal_map


def _normalize_alert_fetch_payload_for_mcp(payload: dict, *, source: str) -> dict:
    if source != "mcp":
        return payload
    if not isinstance(payload, dict):
        return payload

    next_payload = dict(payload)
    raw_mode = next_payload.get("mode")
    mode = str(raw_mode).strip().lower() if isinstance(raw_mode, str) else ""

    if mode == "alerts" and "cursor" not in next_payload:
        next_payload["mode"] = "auto"
        mode = "auto"
    elif not mode:
        next_payload["mode"] = "auto"
        mode = "auto"

    if mode == "auto" and "auto_cluster_threshold" not in next_payload:
        next_payload["auto_cluster_threshold"] = max(1, DEFAULT_MCP_ALERT_FETCH_AUTO_CLUSTER_THRESHOLD)
    return next_payload


def _is_low_recon_noise(signal_item: dict[str, str] | None) -> bool:
    if not signal_item:
        return False
    return signal_item.get("severity") == "low" and signal_item.get("attack_stage") == "recon"


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed
    return parsed


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_alert_feature_map(conn: sqlite3.Connection, alert_ids: list[str]) -> dict[str, dict[str, Any]]:
    deduped_alert_ids = list(dict.fromkeys(str(item) for item in alert_ids if item))
    if not deduped_alert_ids:
        return {}
    rows = conn.execute(
        f"""
        select
          alert_id,
          occurred_at,
          lower(severity) as severity,
          lower(attack_stage) as attack_stage,
          src_ip,
          asset_id
        from alerts
        where alert_id in ({", ".join("?" for _ in deduped_alert_ids)})
        """,
        tuple(deduped_alert_ids),
    ).fetchall()
    return {str(row["alert_id"]): dict(row) for row in rows}


def _load_case_link_profiles(conn: sqlite3.Connection, case_ids: list[str]) -> dict[str, dict[str, Any]]:
    deduped_case_ids = list(dict.fromkeys(str(item) for item in case_ids if item))
    if not deduped_case_ids:
        return {}
    rows = conn.execute(
        f"""
        select
          case_alert_links.case_id,
          alerts.occurred_at,
          lower(alerts.attack_stage) as attack_stage,
          alerts.src_ip,
          alerts.asset_id
        from case_alert_links
        join alerts on alerts.alert_id = case_alert_links.alert_id
        where case_alert_links.is_active = 1
          and case_alert_links.case_id in ({", ".join("?" for _ in deduped_case_ids)})
        order by case_alert_links.case_id asc
        """,
        tuple(deduped_case_ids),
    ).fetchall()

    profiles: dict[str, dict[str, Any]] = {}
    for case_id in deduped_case_ids:
        profiles[case_id] = {
            "active_alert_count": 0,
            "src_ips": set(),
            "asset_ids": set(),
            "max_stage_rank": 0,
            "last_occurred_at": None,
        }

    for row in rows:
        case_id = str(row["case_id"])
        profile = profiles.setdefault(
            case_id,
            {
                "active_alert_count": 0,
                "src_ips": set(),
                "asset_ids": set(),
                "max_stage_rank": 0,
                "last_occurred_at": None,
            },
        )
        profile["active_alert_count"] = int(profile["active_alert_count"]) + 1

        src_ip = str(row["src_ip"] or "").strip()
        if src_ip:
            profile["src_ips"].add(src_ip)

        asset_id = str(row["asset_id"] or "").strip()
        if asset_id:
            profile["asset_ids"].add(asset_id)

        max_stage_rank = int(profile["max_stage_rank"])
        alert_stage_rank = stage_rank(str(row["attack_stage"] or ""))
        if alert_stage_rank > max_stage_rank:
            profile["max_stage_rank"] = alert_stage_rank

        occurred_at = _parse_iso_datetime(str(row["occurred_at"] or ""))
        last_occurred_at = profile["last_occurred_at"]
        if occurred_at is not None and (last_occurred_at is None or occurred_at > last_occurred_at):
            profile["last_occurred_at"] = occurred_at

    return profiles


def _load_active_case_ids(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        """
        select distinct case_id
        from case_alert_links
        where is_active = 1
        order by case_id asc
        """
    ).fetchall()
    return [str(row["case_id"]) for row in rows if row["case_id"]]


def _case_profile_consistency(
    *,
    case_profile: dict[str, Any],
    alert_feature: dict[str, Any],
) -> tuple[float, dict[str, Any]]:
    case_src_ips = case_profile.get("src_ips") or set()
    case_asset_ids = case_profile.get("asset_ids") or set()
    case_max_stage_rank = int(case_profile.get("max_stage_rank") or 0)
    case_last_occurred_at = case_profile.get("last_occurred_at")
    active_alert_count = int(case_profile.get("active_alert_count") or 0)

    alert_src_ip = str(alert_feature.get("src_ip") or "").strip()
    alert_asset_id = str(alert_feature.get("asset_id") or "").strip()
    alert_stage_rank = stage_rank(str(alert_feature.get("attack_stage") or ""))
    alert_occurred_at = _parse_iso_datetime(str(alert_feature.get("occurred_at") or ""))

    same_src_ip = bool(alert_src_ip and alert_src_ip in case_src_ips)
    same_asset_id = bool(alert_asset_id and alert_asset_id in case_asset_ids)
    stage_continuity = (
        alert_stage_rank > 0
        and case_max_stage_rank > 0
        and (case_max_stage_rank - 1) <= alert_stage_rank <= (case_max_stage_rank + 2)
    )
    if case_last_occurred_at is None or alert_occurred_at is None:
        time_proximity = False
    else:
        delta = case_last_occurred_at - alert_occurred_at
        time_proximity = abs(delta) <= _CASE_LINK_TIME_PROXIMITY_WINDOW

    consistency_score = 0.0
    if same_src_ip:
        consistency_score += 0.45
    if same_asset_id:
        consistency_score += 0.25
    if stage_continuity:
        consistency_score += 0.20
    if time_proximity:
        consistency_score += 0.10

    signals = {
        "same_src_ip": same_src_ip,
        "same_asset_id": same_asset_id,
        "stage_continuity": stage_continuity,
        "time_proximity": time_proximity,
        "active_alert_count": active_alert_count,
    }
    return round(consistency_score, 3), signals


def _find_case_redirect_candidate(
    *,
    alert_feature: dict[str, Any],
    case_profile_map: dict[str, dict[str, Any]],
    exclude_case_id: str | None,
) -> dict[str, Any] | None:
    best_candidate: dict[str, Any] | None = None
    for case_id, profile in case_profile_map.items():
        if exclude_case_id and case_id == exclude_case_id:
            continue
        active_alert_count = int(profile.get("active_alert_count") or 0)
        if active_alert_count <= 0:
            continue
        score, signals = _case_profile_consistency(case_profile=profile, alert_feature=alert_feature)
        if score < _CASE_LINK_REDIRECT_SCORE_THRESHOLD:
            continue
        if not (signals["same_src_ip"] or signals["same_asset_id"]):
            continue
        candidate = {
            "case_id": case_id,
            "score": score,
            "signals": signals,
            "active_alert_count": active_alert_count,
        }
        if best_candidate is None:
            best_candidate = candidate
            continue
        current_key = (
            float(candidate["score"]),
            int(candidate["active_alert_count"]),
            int(candidate["signals"]["same_src_ip"]),
            int(candidate["signals"]["same_asset_id"]),
            case_id,
        )
        best_key = (
            float(best_candidate["score"]),
            int(best_candidate["active_alert_count"]),
            int(best_candidate["signals"]["same_src_ip"]),
            int(best_candidate["signals"]["same_asset_id"]),
            str(best_candidate["case_id"]),
        )
        if current_key > best_key:
            best_candidate = candidate
    return best_candidate


def _case_link_consistency_decision(
    *,
    case_profile: dict[str, Any],
    alert_feature: dict[str, Any],
    request_confidence: float,
) -> dict[str, Any]:
    active_alert_count = int(case_profile.get("active_alert_count") or 0)
    if active_alert_count <= 0:
        return {"skip": False, "score": 1.0, "reasons": [], "signals": {}}
    consistency_score, signals = _case_profile_consistency(case_profile=case_profile, alert_feature=alert_feature)
    if request_confidence >= 0.9:
        consistency_score += 0.05

    has_anchor = bool(signals["same_src_ip"] or signals["same_asset_id"])
    skip = False
    reasons: list[str] = []
    if active_alert_count >= 2 and not has_anchor and request_confidence < 0.9:
        skip = True
        reasons.append("missing_src_or_asset_anchor")
    if consistency_score < _CASE_LINK_CONSISTENCY_SCORE_THRESHOLD:
        skip = True
        reasons.append("consistency_score_below_threshold")

    return {
        "skip": skip,
        "score": round(consistency_score, 3),
        "reasons": reasons,
        "signals": signals,
    }


def _to_float(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return default
        try:
            return float(text)
        except ValueError:
            return default
    return default


def _guard_case_link_alert_batch_payload(
    conn: sqlite3.Connection,
    *,
    payload: dict,
    source: str,
) -> tuple[dict, dict[str, Any]]:
    if source != "mcp" or not DEFAULT_NEUTRAL_CASE_LINK_GUARD:
        return payload, {
            "skipped_noise_alert_ids": [],
            "skipped_low_consistency_items": [],
            "redirected_items": [],
        }
    if not isinstance(payload, dict):
        return payload, {
            "skipped_noise_alert_ids": [],
            "skipped_low_consistency_items": [],
            "redirected_items": [],
        }
    items = payload.get("items")
    if not isinstance(items, list):
        return payload, {
            "skipped_noise_alert_ids": [],
            "skipped_low_consistency_items": [],
            "redirected_items": [],
        }

    alert_ids = [
        str(item.get("alert_id") or "")
        for item in items
        if isinstance(item, dict) and str(item.get("alert_id") or "").strip()
    ]
    case_ids = [
        str(item.get("case_id") or "")
        for item in items
        if isinstance(item, dict) and str(item.get("case_id") or "").strip()
    ]
    signal_map = _fetch_alert_signal_map(conn, alert_ids)
    alert_feature_map = _load_alert_feature_map(conn, alert_ids)
    case_profile_map = _load_case_link_profiles(conn, case_ids)
    active_case_profile_map = _load_case_link_profiles(conn, _load_active_case_ids(conn))
    kept_items: list[dict] = []
    skipped_noise_alert_ids: list[str] = []
    skipped_low_consistency_items: list[dict[str, Any]] = []
    redirected_items: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        alert_id = str(item.get("alert_id") or "").strip()
        if not alert_id:
            kept_items.append(item)
            continue
        if _is_low_recon_noise(signal_map.get(alert_id)):
            skipped_noise_alert_ids.append(alert_id)
            continue

        case_id = str(item.get("case_id") or "").strip()
        alert_feature = alert_feature_map.get(alert_id)
        if case_id and alert_feature:
            case_profile = case_profile_map.get(case_id)
            if case_profile and int(case_profile.get("active_alert_count") or 0) > 0:
                consistency = _case_link_consistency_decision(
                    case_profile=case_profile,
                    alert_feature=alert_feature,
                    request_confidence=_to_float(item.get("confidence"), default=0.0),
                )
                if consistency["skip"]:
                    redirect_candidate = _find_case_redirect_candidate(
                        alert_feature=alert_feature,
                        case_profile_map=active_case_profile_map,
                        exclude_case_id=case_id,
                    )
                    if redirect_candidate is not None:
                        rewritten_item = dict(item)
                        rewritten_item["case_id"] = str(redirect_candidate["case_id"])
                        kept_items.append(rewritten_item)
                        redirected_items.append(
                            {
                                "alert_id": alert_id,
                                "from_case_id": case_id,
                                "to_case_id": str(redirect_candidate["case_id"]),
                                "redirect_score": float(redirect_candidate["score"]),
                                "redirect_signals": redirect_candidate["signals"],
                                "redirect_reason": "consistency_redirect_to_existing_case",
                            }
                        )
                        continue
                    skipped_low_consistency_items.append(
                        {
                            "case_id": case_id,
                            "alert_id": alert_id,
                            "consistency_score": consistency["score"],
                            "reasons": consistency["reasons"],
                            "signals": consistency["signals"],
                        }
                    )
                    continue
            else:
                redirect_candidate = _find_case_redirect_candidate(
                    alert_feature=alert_feature,
                    case_profile_map=active_case_profile_map,
                    exclude_case_id=case_id,
                )
                if redirect_candidate is not None:
                    rewritten_item = dict(item)
                    rewritten_item["case_id"] = str(redirect_candidate["case_id"])
                    kept_items.append(rewritten_item)
                    redirected_items.append(
                        {
                            "alert_id": alert_id,
                            "from_case_id": case_id,
                            "to_case_id": str(redirect_candidate["case_id"]),
                            "redirect_score": float(redirect_candidate["score"]),
                            "redirect_signals": redirect_candidate["signals"],
                            "redirect_reason": "missing_case_profile_redirect_to_existing_case",
                        }
                    )
                    continue
        kept_items.append(item)
    if not skipped_noise_alert_ids and not skipped_low_consistency_items and not redirected_items:
        return payload, {
            "skipped_noise_alert_ids": [],
            "skipped_low_consistency_items": [],
            "redirected_items": [],
        }
    next_payload = dict(payload)
    next_payload["items"] = kept_items
    return next_payload, {
        "skipped_noise_alert_ids": list(dict.fromkeys(skipped_noise_alert_ids)),
        "skipped_low_consistency_items": skipped_low_consistency_items,
        "redirected_items": redirected_items,
    }


def _guard_timeline_upsert_payload(
    conn: sqlite3.Connection,
    *,
    payload: dict,
    source: str,
) -> tuple[bool, list[str]]:
    if source != "mcp" or not DEFAULT_NEUTRAL_CASE_LINK_GUARD:
        return False, []
    if not isinstance(payload, dict):
        return False, []
    stage = str(payload.get("stage") or "").lower()
    if stage != "recon":
        return False, []
    related_alert_ids = payload.get("related_alert_ids")
    if not isinstance(related_alert_ids, list) or not related_alert_ids:
        return False, []
    deduped_alert_ids = list(dict.fromkeys(str(item) for item in related_alert_ids if item))
    signal_map = _fetch_alert_signal_map(conn, deduped_alert_ids)
    if not signal_map:
        return False, []
    if all(_is_low_recon_noise(signal_map.get(alert_id)) for alert_id in deduped_alert_ids):
        return True, deduped_alert_ids
    return False, []


def _derive_case_assessment_verdict(risk_level: str) -> str:
    lowered = str(risk_level or "").strip().lower()
    if lowered in {"high", "critical"}:
        return "high_risk_active"
    if lowered == "medium":
        return "under_investigation"
    return "monitoring"


def _insert_case_assessment_fallback_for_link_batch(
    conn: sqlite3.Connection,
    *,
    source: str,
    run_id: str | None,
    result: dict[str, Any],
) -> list[str]:
    if source != "mcp" or not run_id:
        return []
    if not isinstance(result, dict) or not result.get("ok"):
        return []
    data = result.get("data")
    if not isinstance(data, dict):
        return []
    links = data.get("links")
    if not isinstance(links, list):
        return []

    high_confidence_links_by_case: dict[str, dict[str, Any]] = {}
    for link_item in links:
        if not isinstance(link_item, dict):
            continue
        case_id = str(link_item.get("case_id") or "").strip()
        alert_id = str(link_item.get("alert_id") or "").strip()
        confidence = _to_float(link_item.get("confidence"), default=0.0)
        if not case_id or not alert_id or confidence < _CASE_LINK_FALLBACK_ASSESSMENT_MIN_CONFIDENCE:
            continue
        bucket = high_confidence_links_by_case.setdefault(
            case_id,
            {"max_confidence": 0.0, "alert_ids": []},
        )
        bucket["max_confidence"] = max(float(bucket["max_confidence"]), confidence)
        bucket["alert_ids"].append(alert_id)

    inserted_case_ids: list[str] = []
    for case_id, bucket in high_confidence_links_by_case.items():
        has_current_run_assessment = (
            conn.execute(
                """
                select 1
                from case_assessments
                where run_id = ? and case_id = ?
                limit 1
                """,
                (run_id, case_id),
            ).fetchone()
            is not None
        )
        if has_current_run_assessment:
            continue

        case_row = conn.execute(
            """
            select overall_severity, current_stage
            from cases
            where case_id = ?
            """,
            (case_id,),
        ).fetchone()
        if case_row is None:
            continue

        risk_level = str(case_row["overall_severity"] or "medium").lower()
        current_stage = str(case_row["current_stage"] or "recon").lower()
        alert_ids = list(dict.fromkeys(str(item) for item in bucket["alert_ids"] if item))
        if not alert_ids:
            continue

        insert_case_assessment_log(
            conn,
            case_id=case_id,
            risk_level=risk_level,
            assessment_confidence=min(0.95, float(bucket["max_confidence"])),
            current_stage=current_stage,
            verdict=_derive_case_assessment_verdict(risk_level),
            reason_summary="auto:case.link-alert-batch_high_confidence_fallback",
            supporting_alert_ids=alert_ids,
            supporting_evidence_ids=[],
        )
        inserted_case_ids.append(case_id)

    return list(dict.fromkeys(inserted_case_ids))


def _is_high_signal_alert_feature(alert_feature: dict[str, Any]) -> bool:
    severity = str(alert_feature.get("severity") or "").lower()
    stage = str(alert_feature.get("attack_stage") or "").lower()
    if severity in {"high", "critical"}:
        return True
    return stage in _CASE_LINK_AUTO_EXPAND_ALLOWED_STAGES


def _collect_case_ids_from_link_result(result: dict[str, Any]) -> list[str]:
    if not isinstance(result, dict):
        return []
    data = result.get("data")
    if not isinstance(data, dict):
        return []
    links = data.get("links")
    if not isinstance(links, list):
        return []
    collected: list[str] = []
    for item in links:
        if not isinstance(item, dict):
            continue
        case_id = str(item.get("case_id") or "").strip()
        if case_id:
            collected.append(case_id)
    return list(dict.fromkeys(collected))


def _auto_expand_high_signal_case_links(
    conn: sqlite3.Connection,
    *,
    source: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    if source != "mcp":
        return []
    if not isinstance(result, dict) or not result.get("ok"):
        return []
    data = result.get("data")
    if not isinstance(data, dict):
        return []
    links = data.get("links")
    if not isinstance(links, list):
        return []

    anchor_items: list[dict[str, Any]] = []
    anchor_alert_ids: list[str] = []
    for item in links:
        if not isinstance(item, dict):
            continue
        case_id = str(item.get("case_id") or "").strip()
        alert_id = str(item.get("alert_id") or "").strip()
        confidence = _to_float(item.get("confidence"), default=0.0)
        if not case_id or not alert_id:
            continue
        if confidence < _CASE_LINK_AUTO_EXPAND_MIN_CONFIDENCE:
            continue
        anchor_items.append(
            {
                "case_id": case_id,
                "alert_id": alert_id,
                "confidence": confidence,
            }
        )
        anchor_alert_ids.append(alert_id)
    if not anchor_items:
        return []

    feature_map = _load_alert_feature_map(conn, anchor_alert_ids)
    if not feature_map:
        return []

    expanded_items: list[dict[str, Any]] = []
    expanded_pairs: set[tuple[str, str]] = set()
    linked_at = _now_iso()

    for anchor in anchor_items:
        if len(expanded_items) >= _CASE_LINK_AUTO_EXPAND_MAX_TOTAL:
            break
        case_id = str(anchor["case_id"])
        alert_id = str(anchor["alert_id"])
        anchor_feature = feature_map.get(alert_id)
        if not anchor_feature or not _is_high_signal_alert_feature(anchor_feature):
            continue

        anchor_stage = str(anchor_feature.get("attack_stage") or "").lower()
        anchor_stage_rank = stage_rank(anchor_stage)
        if anchor_stage not in _CASE_LINK_AUTO_EXPAND_ALLOWED_STAGES:
            continue
        anchor_src_ip = str(anchor_feature.get("src_ip") or "").strip()
        if not anchor_src_ip:
            continue
        anchor_occurred_at = _parse_iso_datetime(str(anchor_feature.get("occurred_at") or ""))

        rows = conn.execute(
            """
            select
              alert_id,
              occurred_at,
              lower(severity) as severity,
              lower(attack_stage) as attack_stage,
              src_ip,
              asset_id
            from alerts
            where src_ip = ?
              and alert_id <> ?
              and lower(severity) in ('high', 'critical')
              and lower(attack_stage) in ('exploit', 'persistence', 'command_execution', 'reactivation', 'lateral_prep')
            order by occurred_at desc, alert_id asc
            limit ?
            """,
            (anchor_src_ip, alert_id, _CASE_LINK_AUTO_EXPAND_MAX_PER_ANCHOR * 5),
        ).fetchall()

        per_anchor_count = 0
        for row in rows:
            if len(expanded_items) >= _CASE_LINK_AUTO_EXPAND_MAX_TOTAL:
                break
            if per_anchor_count >= _CASE_LINK_AUTO_EXPAND_MAX_PER_ANCHOR:
                break
            candidate_alert_id = str(row["alert_id"] or "").strip()
            if not candidate_alert_id:
                continue
            pair_key = (case_id, candidate_alert_id)
            if pair_key in expanded_pairs:
                continue

            candidate_stage = str(row["attack_stage"] or "").lower()
            candidate_stage_rank = stage_rank(candidate_stage)
            if candidate_stage_rank < max(2, anchor_stage_rank - 1):
                continue

            candidate_occurred_at = _parse_iso_datetime(str(row["occurred_at"] or ""))
            if (
                anchor_occurred_at is not None
                and candidate_occurred_at is not None
                and abs(anchor_occurred_at - candidate_occurred_at) > _CASE_LINK_AUTO_EXPAND_TIME_WINDOW
            ):
                continue

            active_link_row = conn.execute(
                """
                select case_id
                from case_alert_links
                where alert_id = ? and is_active = 1
                limit 1
                """,
                (candidate_alert_id,),
            ).fetchone()
            if active_link_row is not None:
                if str(active_link_row["case_id"] or "").strip() != case_id:
                    continue
                continue

            link_confidence = min(0.92, max(0.75, float(anchor["confidence"]) - 0.05))
            link_alert_to_case(
                conn,
                case_id,
                candidate_alert_id,
                link_confidence,
                "auto:high_signal_signature_expand",
                linked_at,
            )
            expanded_pairs.add(pair_key)
            expanded_items.append(
                {
                    "case_id": case_id,
                    "alert_id": candidate_alert_id,
                    "confidence": link_confidence,
                    "reason": "auto:high_signal_signature_expand",
                    "anchor_alert_id": alert_id,
                }
            )
            per_anchor_count += 1

    return expanded_items


def _auto_write_attacker_entity_assessments_for_case_links(
    conn: sqlite3.Connection,
    *,
    source: str,
    run_id: str | None,
    analysis_cutoff_at: str | None,
    case_ids: list[str],
) -> list[dict[str, Any]]:
    if source != "mcp" or not run_id:
        return []
    deduped_case_ids = list(dict.fromkeys(case_id for case_id in case_ids if case_id))
    if not deduped_case_ids:
        return []

    inserted: list[dict[str, Any]] = []
    for case_id in deduped_case_ids:
        grouped_rows = conn.execute(
            """
            select
              alerts.src_ip as src_ip,
              count(*) as alert_count,
              count(distinct lower(alerts.attack_stage)) as stage_count,
              max(
                case lower(alerts.attack_stage)
                  when 'recon' then 1
                  when 'exploit' then 2
                  when 'persistence' then 3
                  when 'command_execution' then 4
                  when 'lateral_prep' then 5
                  when 'reactivation' then 6
                  else 0
                end
              ) as max_stage_rank
            from case_alert_links
            join alerts on alerts.alert_id = case_alert_links.alert_id
            where case_alert_links.case_id = ?
              and case_alert_links.is_active = 1
              and coalesce(alerts.src_ip, '') != ''
              and lower(alerts.severity) in ('high', 'critical')
              and lower(alerts.attack_stage) in ('exploit', 'persistence', 'command_execution', 'reactivation', 'lateral_prep')
            group by alerts.src_ip
            order by alert_count desc, stage_count desc, max_stage_rank desc, src_ip asc
            """,
            (case_id,),
        ).fetchall()

        for row in grouped_rows:
            src_ip = str(row["src_ip"] or "").strip()
            if not src_ip:
                continue
            alert_count = int(row["alert_count"] or 0)
            stage_count = int(row["stage_count"] or 0)
            max_stage_rank = int(row["max_stage_rank"] or 0)
            if alert_count < _ENTITY_ASSESSMENT_AUTO_MIN_ALERT_COUNT:
                continue
            if stage_count < _ENTITY_ASSESSMENT_AUTO_MIN_STAGE_COUNT:
                continue
            if max_stage_rank < _ENTITY_ASSESSMENT_AUTO_MIN_MAX_STAGE_RANK:
                continue

            already_current = conn.execute(
                """
                select 1
                from entity_assessments
                where entity_type = 'ip'
                  and entity_key = ?
                  and related_case_id = ?
                  and verdict = 'attacker'
                  and risk_level in ('high', 'critical')
                  and is_current = 1
                limit 1
                """,
                (src_ip, case_id),
            ).fetchone()
            if already_current is not None:
                continue

            support_rows = conn.execute(
                """
                select alerts.alert_id, alerts.occurred_at
                from case_alert_links
                join alerts on alerts.alert_id = case_alert_links.alert_id
                where case_alert_links.case_id = ?
                  and case_alert_links.is_active = 1
                  and alerts.src_ip = ?
                  and lower(alerts.severity) in ('high', 'critical')
                  and lower(alerts.attack_stage) in ('exploit', 'persistence', 'command_execution', 'reactivation', 'lateral_prep')
                order by alerts.occurred_at desc, alerts.alert_id asc
                limit 12
                """,
                (case_id, src_ip),
            ).fetchall()
            supporting_alert_ids = [str(item["alert_id"]) for item in support_rows if item["alert_id"]]
            if not supporting_alert_ids:
                continue
            first_seen_at = min((str(item["occurred_at"]) for item in support_rows if item["occurred_at"]), default=None)
            last_seen_at = max((str(item["occurred_at"]) for item in support_rows if item["occurred_at"]), default=None)

            confidence = min(0.96, 0.72 + 0.03 * min(alert_count, 6) + 0.02 * max(0, stage_count - 1))
            upsert_entity_assessment(
                conn,
                entity_type="ip",
                entity_key=src_ip,
                entity_label=src_ip,
                related_case_id=case_id,
                risk_level="high",
                assessment_confidence=confidence,
                verdict="attacker",
                reason_summary="auto:high_signal_case_link_continuity",
                supporting_alert_ids=supporting_alert_ids,
                supporting_evidence_ids=[],
                first_seen_at=first_seen_at,
                last_seen_at=last_seen_at,
                run_id=run_id,
                analysis_cutoff_at=analysis_cutoff_at,
            )
            inserted.append(
                {
                    "case_id": case_id,
                    "entity_type": "ip",
                    "entity_key": src_ip,
                    "verdict": "attacker",
                    "risk_level": "high",
                    "assessment_confidence": round(confidence, 3),
                    "supporting_alert_ids": supporting_alert_ids,
                }
            )
    return inserted


def _extract_alert_ids_from_fetch_result(result: dict[str, Any]) -> list[str]:
    collected: list[str] = []
    refs = result.get("refs")
    if isinstance(refs, dict):
        refs_alert_ids = refs.get("alert_ids")
        if isinstance(refs_alert_ids, list):
            collected.extend(str(item) for item in refs_alert_ids if item)

    data = result.get("data")
    if isinstance(data, dict):
        alerts = data.get("alerts")
        if isinstance(alerts, list):
            for alert_item in alerts:
                if not isinstance(alert_item, dict):
                    continue
                alert_id = alert_item.get("alert_id")
                if alert_id:
                    collected.append(str(alert_id))

        clusters = data.get("clusters")
        if isinstance(clusters, list):
            for cluster_item in clusters:
                if not isinstance(cluster_item, dict):
                    continue
                sample_alert_ids = cluster_item.get("sample_alert_ids")
                if isinstance(sample_alert_ids, list):
                    collected.extend(str(item) for item in sample_alert_ids if item)

    return list(dict.fromkeys(collected))


DETAIL_BATCH_ALLOWED_DISCOVERY_TOOLS: tuple[str, ...] = (
    "alert.fetch",
    "alert.suspect-ip-topk",
    "alert.ip-context",
)


def _validate_alert_detail_batch_ids(
    conn: sqlite3.Connection,
    *,
    payload: dict,
    source: str,
    run_id: str | None,
) -> dict[str, Any] | None:
    if source != "mcp":
        return None
    if not isinstance(payload, dict):
        return None
    raw_alert_ids = payload.get("alert_ids")
    if not isinstance(raw_alert_ids, list):
        return None
    requested_alert_ids = list(dict.fromkeys(str(item) for item in raw_alert_ids if item))
    if not requested_alert_ids:
        return None
    if not run_id:
        return {
            "ok": False,
            "summary": (
                "alert.detail-batch 需要先调用 alert.fetch / alert.suspect-ip-topk / "
                "alert.ip-context 获取有效 alert_id"
            ),
            "data": {
                "tool": "alert.detail-batch",
                "invalid_alert_ids": requested_alert_ids,
                "allowed_alert_ids_sample": [],
            },
            "warnings": ["detail_batch_requires_fetch_context"],
            "refs": {},
            "page": {"next_cursor": None, "has_more": False},
            "meta": {},
        }

    fetch_rows = conn.execute(
        """
        select call_id, result_json
        from agent_tool_calls
        where run_id = ?
          and source = 'mcp'
          and tool_name in (?, ?, ?)
          and result_ok = 1
        order by occurred_at asc, rowid asc
        """,
        (run_id, *DETAIL_BATCH_ALLOWED_DISCOVERY_TOOLS),
    ).fetchall()
    allowed_alert_ids: list[str] = []
    for row in fetch_rows:
        try:
            result_body = json.loads(row["result_json"] or "{}")
        except json.JSONDecodeError:
            continue
        if not isinstance(result_body, dict):
            continue
        allowed_alert_ids.extend(_extract_alert_ids_from_fetch_result(result_body))
    allowed_alert_ids = list(dict.fromkeys(allowed_alert_ids))
    if not allowed_alert_ids:
        return {
            "ok": False,
            "summary": (
                "alert.detail-batch 需要先从本轮 alert.fetch / alert.suspect-ip-topk / "
                "alert.ip-context 返回中选择 alert_id，当前 run 尚无可用 ID"
            ),
            "data": {
                "tool": "alert.detail-batch",
                "run_id": run_id,
                "invalid_alert_ids": requested_alert_ids,
                "allowed_alert_ids_sample": [],
            },
            "warnings": ["detail_batch_requires_fetch_context"],
            "refs": {},
            "page": {"next_cursor": None, "has_more": False},
            "meta": {},
        }

    allowed_set = set(allowed_alert_ids)
    invalid_alert_ids = [alert_id for alert_id in requested_alert_ids if alert_id not in allowed_set]
    if not invalid_alert_ids:
        return None
    return {
        "ok": False,
        "summary": (
            "alert.detail-batch 仅允许使用本次巡检里 alert.fetch / alert.suspect-ip-topk / "
            "alert.ip-context 返回的 alert_id，"
            f"发现 {len(invalid_alert_ids)} 条无效 ID"
        ),
        "data": {
            "tool": "alert.detail-batch",
            "run_id": run_id,
            "invalid_alert_ids": invalid_alert_ids,
            "allowed_alert_ids_sample": allowed_alert_ids[:20],
        },
        "warnings": ["detail_batch_alert_id_out_of_fetch_scope"],
        "refs": {},
        "page": {"next_cursor": None, "has_more": False},
        "meta": {},
    }


def _batch_payload_guidance(tool_name: str) -> dict[str, Any] | None:
    if tool_name == "case.upsert-batch":
        return {
            "required_fields": ["case_id", "title", "status", "overall_severity", "current_stage"],
            "example_payload": {
                "items": [
                    {
                        "case_id": "case_demo_001",
                        "title": "示例案件",
                        "status": "open",
                        "overall_severity": "high",
                        "current_stage": "persistence",
                    }
                ]
            },
            "recommended_next_actions": [
                {
                    "tool": "case.search",
                    "reason": "先确认是否已有可复用案件，再决定新建/更新",
                },
                {
                    "tool": "case.list",
                    "reason": "缺少检索键时先列出现有案件，避免盲目创建",
                },
            ],
        }
    if tool_name == "case.link-alert-batch":
        return {
            "required_fields": ["case_id", "alert_id", "confidence", "reason"],
            "example_payload": {
                "items": [
                    {
                        "case_id": "case_demo_001",
                        "alert_id": "alt_demo_001",
                        "confidence": 0.85,
                        "reason": "same asset + stage continuity",
                    }
                ]
            },
            "recommended_next_actions": [
                {
                    "tool": "case.search",
                    "reason": "先定位最匹配案件，避免误关联",
                },
                {
                    "tool": "case.explain-link",
                    "reason": "先生成关联解释，再执行批量关联",
                },
            ],
        }
    if tool_name == "assessment.upsert-batch":
        return {
            "required_fields": [
                "entity_type",
                "entity_key",
                "risk_level",
                "assessment_confidence",
                "verdict",
                "reason_summary",
            ],
            "example_payload": {
                "items": [
                    {
                        "entity_type": "ip",
                        "entity_key": "198.51.100.23",
                        "risk_level": "high",
                        "assessment_confidence": 0.8,
                        "verdict": "attacker",
                        "reason_summary": "webshell exploitation chain continuity",
                    }
                ]
            },
            "recommended_next_actions": [
                {
                    "tool": "alert.detail-batch",
                    "reason": "补齐支持证据后再写评估",
                }
            ],
        }
    if tool_name == "actor.case-link-batch":
        return {
            "required_fields": ["case_actor_id", "target_type", "target_id", "link_confidence", "link_reason"],
            "example_payload": {
                "items": [
                    {
                        "case_actor_id": "act_demo_001",
                        "target_type": "alert",
                        "target_id": "alt_demo_001",
                        "link_confidence": 0.8,
                        "link_reason": "same actor behavior continuation",
                    }
                ]
            },
            "recommended_next_actions": [
                {
                    "tool": "actor.case-find-candidates",
                    "reason": "先找候选 actor，再执行链接",
                }
            ],
        }
    if tool_name == "actor.case-add-observation-batch":
        return {
            "required_fields": [
                "case_actor_id",
                "observation_type",
                "observation_key",
                "observation_value",
                "confidence",
            ],
            "example_payload": {
                "items": [
                    {
                        "case_actor_id": "act_demo_001",
                        "observation_type": "src_ip",
                        "observation_key": "198.51.100.23",
                        "observation_value": "198.51.100.23",
                        "confidence": 0.8,
                    }
                ]
            },
            "recommended_next_actions": [
                {
                    "tool": "actor.case-get",
                    "reason": "确认 actor 已存在后再补充观测",
                }
            ],
        }
    return None


def dispatch_tool(conn: sqlite3.Connection, tool_name: str, payload: dict, source: str = "unknown") -> dict:
    if tool_name not in TOOL_HANDLERS:
        raise ValueError(f"unsupported tool: {tool_name}")

    run_id, analysis_cutoff_at = resolve_run_context_for_dispatch(conn, source=source, tool_name=tool_name)
    token = bind_run_context(run_id, analysis_cutoff_at)
    try:
        skipped_noise_alert_ids: list[str] = []
        skipped_low_consistency_items: list[dict[str, Any]] = []
        redirected_case_link_items: list[dict[str, Any]] = []
        if tool_name == "alert.fetch":
            payload = _normalize_alert_fetch_payload_for_mcp(payload, source=source)
        if tool_name == "alert.detail-batch":
            prevalidated = _validate_alert_detail_batch_ids(
                conn,
                payload=payload,
                source=source,
                run_id=run_id,
            )
            if prevalidated is not None:
                finalize_mcp_auto_run_after_tool(
                    conn,
                    source=source,
                    run_id=run_id,
                    tool_name=tool_name,
                    result=prevalidated,
                )
                insert_tool_call_log(
                    conn,
                    source=source,
                    tool_name=tool_name,
                    payload=payload,
                    result=prevalidated,
                    latency_ms=0,
                )
                conn.commit()
                return prevalidated
        if tool_name == "case.link-alert-batch":
            payload, guard_meta = _guard_case_link_alert_batch_payload(
                conn,
                payload=payload,
                source=source,
            )
            skipped_noise_alert_ids = list(guard_meta.get("skipped_noise_alert_ids") or [])
            skipped_low_consistency_items = list(guard_meta.get("skipped_low_consistency_items") or [])
            redirected_case_link_items = list(guard_meta.get("redirected_items") or [])
            if (skipped_noise_alert_ids or skipped_low_consistency_items) and not payload.get("items"):
                skipped_alert_ids = skipped_noise_alert_ids + [
                    str(item.get("alert_id") or "")
                    for item in skipped_low_consistency_items
                    if isinstance(item, dict)
                ]
                warnings = []
                if skipped_noise_alert_ids:
                    warnings.append("neutral_case_link_guard_skipped_noise_recon_alerts")
                if skipped_low_consistency_items:
                    warnings.append("neutral_case_link_guard_skipped_low_consistency_links")
                noop_result = {
                    "ok": True,
                    "summary": (
                        "neutral_guard skipped case linking due to filtered candidates "
                        f"(noise={len(skipped_noise_alert_ids)}, low_consistency={len(skipped_low_consistency_items)})"
                    ),
                    "data": {
                        "tool": tool_name,
                        "skipped_alert_ids": list(dict.fromkeys(item for item in skipped_alert_ids if item)),
                        "skipped_noise_alert_ids": skipped_noise_alert_ids,
                        "skipped_low_consistency_items": skipped_low_consistency_items,
                        "redirected_items": redirected_case_link_items,
                    },
                    "warnings": warnings,
                    "refs": {"alert_ids": list(dict.fromkeys(item for item in skipped_alert_ids if item))},
                    "page": {"next_cursor": None, "has_more": False},
                    "meta": {},
                }
                finalize_mcp_auto_run_after_tool(
                    conn,
                    source=source,
                    run_id=run_id,
                    tool_name=tool_name,
                    result=noop_result,
                )
                insert_tool_call_log(
                    conn,
                    source=source,
                    tool_name=tool_name,
                    payload=payload,
                    result=noop_result,
                    latency_ms=0,
                )
                conn.commit()
                return noop_result
        if tool_name == "timeline.upsert":
            should_skip_timeline, skipped_alert_ids = _guard_timeline_upsert_payload(
                conn,
                payload=payload,
                source=source,
            )
            if should_skip_timeline:
                noop_result = {
                    "ok": True,
                    "summary": (
                        "neutral_guard skipped timeline node for recon-noise-only alerts "
                        f"({len(skipped_alert_ids)} alerts)"
                    ),
                    "data": {"tool": tool_name, "skipped_alert_ids": skipped_alert_ids},
                    "warnings": ["neutral_timeline_guard_skipped_recon_noise_node"],
                    "refs": {"alert_ids": skipped_alert_ids},
                    "page": {"next_cursor": None, "has_more": False},
                    "meta": {},
                }
                finalize_mcp_auto_run_after_tool(
                    conn,
                    source=source,
                    run_id=run_id,
                    tool_name=tool_name,
                    result=noop_result,
                )
                insert_tool_call_log(
                    conn,
                    source=source,
                    tool_name=tool_name,
                    payload=payload,
                    result=noop_result,
                    latency_ms=0,
                )
                conn.commit()
                return noop_result

        start = time.perf_counter()
        result: dict
        try:
            result = TOOL_HANDLERS[tool_name](conn, payload)
        except ValidationError as exc:
            latency_ms = int((time.perf_counter() - start) * 1000)
            guidance = _batch_payload_guidance(tool_name)
            warnings = ["payload_validation_error"]
            if guidance is not None:
                warnings.extend(["batch_items_required", "tool_schema_guidance"])
            validation_result = {
                "ok": False,
                "summary": _validation_error_summary(exc),
                "data": {
                    "tool": tool_name,
                    "validation_errors": exc.errors(),
                    "schema_guidance": guidance,
                },
                "warnings": warnings,
                "refs": {},
                "page": {"next_cursor": None, "has_more": False},
                "meta": {},
            }
            finalize_mcp_auto_run_after_tool(
                conn,
                source=source,
                run_id=run_id,
                tool_name=tool_name,
                result=validation_result,
            )
            insert_tool_call_log(
                conn,
                source=source,
                tool_name=tool_name,
                payload=payload,
                result=validation_result,
                latency_ms=latency_ms,
            )
            conn.commit()
            return validation_result
        except Exception:
            latency_ms = int((time.perf_counter() - start) * 1000)
            fallback_result = {
                "ok": False,
                "summary": "tool execution exception",
                "data": {"tool": tool_name},
                "warnings": ["tool_exception"],
                "refs": {},
                "page": {"next_cursor": None, "has_more": False},
                "meta": {},
            }
            insert_tool_call_log(
                conn,
                source=source,
                tool_name=tool_name,
                payload=payload,
                result=fallback_result,
                latency_ms=latency_ms,
            )
            conn.commit()
            raise

        latency_ms = int((time.perf_counter() - start) * 1000)
        if tool_name == "case.link-alert-batch":
            auto_expanded_links = _auto_expand_high_signal_case_links(
                conn,
                source=source,
                result=result,
            )
            if auto_expanded_links:
                result = dict(result)
                warnings = result.get("warnings")
                warnings_list = list(warnings) if isinstance(warnings, list) else []
                warnings_list.append("auto_case_link_signature_expanded")
                result["warnings"] = list(dict.fromkeys(warnings_list))

                refs = result.get("refs")
                refs_map = dict(refs) if isinstance(refs, dict) else {}
                existing_alert_ids = refs_map.get("alert_ids")
                refs_alert_ids = list(existing_alert_ids) if isinstance(existing_alert_ids, list) else []
                refs_alert_ids.extend(str(item.get("alert_id") or "") for item in auto_expanded_links)
                refs_map["alert_ids"] = list(dict.fromkeys(item for item in refs_alert_ids if item))
                existing_case_ids = refs_map.get("case_ids")
                refs_case_ids = list(existing_case_ids) if isinstance(existing_case_ids, list) else []
                refs_case_ids.extend(str(item.get("case_id") or "") for item in auto_expanded_links)
                refs_map["case_ids"] = list(dict.fromkeys(item for item in refs_case_ids if item))
                result["refs"] = refs_map

                data = result.get("data")
                data_map = dict(data) if isinstance(data, dict) else {}
                data_map["auto_expanded_links"] = auto_expanded_links
                result["data"] = data_map

            auto_assessed_case_ids = _insert_case_assessment_fallback_for_link_batch(
                conn,
                source=source,
                run_id=run_id,
                result=result,
            )
            if auto_assessed_case_ids:
                result = dict(result)
                warnings = result.get("warnings")
                warnings_list = list(warnings) if isinstance(warnings, list) else []
                warnings_list.append("auto_case_assessment_fallback_written")
                result["warnings"] = list(dict.fromkeys(warnings_list))

                refs = result.get("refs")
                refs_map = dict(refs) if isinstance(refs, dict) else {}
                existing_case_ids = refs_map.get("case_ids")
                refs_case_ids = list(existing_case_ids) if isinstance(existing_case_ids, list) else []
                refs_case_ids.extend(auto_assessed_case_ids)
                refs_map["case_ids"] = list(dict.fromkeys(refs_case_ids))
                result["refs"] = refs_map

                data = result.get("data")
                data_map = dict(data) if isinstance(data, dict) else {}
                data_map["auto_assessed_case_ids"] = auto_assessed_case_ids
                result["data"] = data_map
            auto_assessments = _auto_write_attacker_entity_assessments_for_case_links(
                conn,
                source=source,
                run_id=run_id,
                analysis_cutoff_at=analysis_cutoff_at,
                case_ids=_collect_case_ids_from_link_result(result),
            )
            if auto_assessments:
                result = dict(result)
                warnings = result.get("warnings")
                warnings_list = list(warnings) if isinstance(warnings, list) else []
                warnings_list.append("auto_entity_assessment_fallback_written")
                result["warnings"] = list(dict.fromkeys(warnings_list))

                refs = result.get("refs")
                refs_map = dict(refs) if isinstance(refs, dict) else {}
                existing_case_ids = refs_map.get("case_ids")
                refs_case_ids = list(existing_case_ids) if isinstance(existing_case_ids, list) else []
                refs_case_ids.extend(str(item.get("case_id") or "") for item in auto_assessments)
                refs_map["case_ids"] = list(dict.fromkeys(item for item in refs_case_ids if item))
                result["refs"] = refs_map

                data = result.get("data")
                data_map = dict(data) if isinstance(data, dict) else {}
                data_map["auto_attacker_assessments"] = auto_assessments
                result["data"] = data_map
        if skipped_noise_alert_ids or skipped_low_consistency_items or redirected_case_link_items:
            result = dict(result)
            warnings = result.get("warnings")
            warnings_list = list(warnings) if isinstance(warnings, list) else []
            if skipped_noise_alert_ids:
                warnings_list.append("neutral_case_link_guard_skipped_noise_recon_alerts")
            if skipped_low_consistency_items:
                warnings_list.append("neutral_case_link_guard_skipped_low_consistency_links")
            if redirected_case_link_items:
                warnings_list.append("neutral_case_link_guard_redirected_case_links")
            result["warnings"] = list(dict.fromkeys(warnings_list))

            refs = result.get("refs")
            refs_map = dict(refs) if isinstance(refs, dict) else {}
            existing_alert_ids = refs_map.get("alert_ids")
            refs_alert_ids = list(existing_alert_ids) if isinstance(existing_alert_ids, list) else []
            refs_alert_ids.extend(skipped_noise_alert_ids)
            refs_alert_ids.extend(
                str(item.get("alert_id") or "")
                for item in skipped_low_consistency_items
                if isinstance(item, dict)
            )
            refs_alert_ids.extend(
                str(item.get("alert_id") or "")
                for item in redirected_case_link_items
                if isinstance(item, dict)
            )
            refs_map["alert_ids"] = list(dict.fromkeys(item for item in refs_alert_ids if item))
            existing_case_ids = refs_map.get("case_ids")
            refs_case_ids = list(existing_case_ids) if isinstance(existing_case_ids, list) else []
            refs_case_ids.extend(
                str(item.get("to_case_id") or "")
                for item in redirected_case_link_items
                if isinstance(item, dict)
            )
            refs_map["case_ids"] = list(dict.fromkeys(item for item in refs_case_ids if item))
            result["refs"] = refs_map

            data = result.get("data")
            data_map = dict(data) if isinstance(data, dict) else {}
            skipped_alert_ids = list(dict.fromkeys(item for item in refs_alert_ids if item))
            data_map["skipped_alert_ids"] = skipped_alert_ids
            data_map["skipped_noise_alert_ids"] = skipped_noise_alert_ids
            data_map["skipped_low_consistency_items"] = skipped_low_consistency_items
            data_map["redirected_items"] = redirected_case_link_items
            result["data"] = data_map
        finalize_mcp_auto_run_after_tool(
            conn,
            source=source,
            run_id=run_id,
            tool_name=tool_name,
            result=result,
        )
        insert_tool_call_log(
            conn,
            source=source,
            tool_name=tool_name,
            payload=payload,
            result=result,
            latency_ms=latency_ms,
        )
        conn.commit()
        return result
    finally:
        reset_bound_run_context(token)
