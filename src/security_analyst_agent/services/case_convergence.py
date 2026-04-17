from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from itertools import combinations
from typing import Any
from uuid import uuid4

from security_analyst_agent.repositories.actors import (
    add_case_actor_link,
    add_case_actor_observation,
    upsert_case_actor_profile,
)
from security_analyst_agent.repositories.assessments import upsert_entity_assessment
from security_analyst_agent.repositories.case_relations import (
    list_confirmed_case_relations,
    upsert_case_relation_candidate,
)
from security_analyst_agent.repositories.cases import reselect_cluster_canonical_case
from security_analyst_agent.services.case_relation_scoring import score_case_relation

_MIN_LINK_CONFIDENCE_FOR_RELATION = 0.6
_ALLOWED_ALERT_SEVERITIES_FOR_RELATION = {"medium", "high", "critical"}
_CLUSTER_BRIDGE_PROMOTION_SCORE = 0.82
_FAST_TRACK_MERGE_SCORE = 0.78
_FAST_TRACK_MIN_STAGE_RANK = 3
_FAST_TRACK_MIN_SEVERITY_RANK = 3
_SUPERSEDED_RELATION_SCORE_MARGIN = 0.08
_STAGE_ORDER = {
    "recon": 1,
    "exploit": 2,
    "persistence": 3,
    "command_execution": 4,
    "lateral_prep": 5,
}
_SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_HIGH_SIGNAL_ACTOR_STAGES = {"exploit", "persistence", "command_execution", "lateral_prep"}
_HIGH_SIGNAL_ACTOR_SEVERITIES = {"high", "critical"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _select_latest_high_signal_stage_for_case(conn: sqlite3.Connection, *, case_id: str) -> str | None:
    allowed_severities = tuple(sorted(_ALLOWED_ALERT_SEVERITIES_FOR_RELATION))
    placeholders = ", ".join("?" for _ in allowed_severities)
    stage_rank_sql = """
    case lower(alerts.attack_stage)
      when 'recon' then 1
      when 'exploit' then 2
      when 'persistence' then 3
      when 'command_execution' then 4
      when 'lateral_prep' then 5
      else 0
    end
    """
    row = conn.execute(
        f"""
        select alerts.attack_stage
        from case_alert_links
        join alerts on alerts.alert_id = case_alert_links.alert_id
        where case_alert_links.case_id = ?
          and case_alert_links.is_active = 1
          and case_alert_links.confidence >= ?
          and lower(alerts.severity) in ({placeholders})
        order by {stage_rank_sql} desc, alerts.occurred_at desc, case_alert_links.linked_at desc, case_alert_links.rowid desc
        limit 1
        """,
        (case_id, _MIN_LINK_CONFIDENCE_FOR_RELATION, *allowed_severities),
    ).fetchone()
    if row is not None and row["attack_stage"]:
        return str(row["attack_stage"])

    fallback_row = conn.execute(
        f"""
        select alerts.attack_stage
        from case_alert_links
        join alerts on alerts.alert_id = case_alert_links.alert_id
        where case_alert_links.case_id = ?
          and case_alert_links.is_active = 1
          and lower(alerts.severity) in ({placeholders})
        order by {stage_rank_sql} desc, alerts.occurred_at desc, case_alert_links.linked_at desc, case_alert_links.rowid desc
        limit 1
        """,
        (case_id, *allowed_severities),
    ).fetchone()
    if fallback_row is not None and fallback_row["attack_stage"]:
        return str(fallback_row["attack_stage"])
    return None


def _default_case_actor_id(conn: sqlite3.Connection, *, case_id: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9]+", "_", case_id).strip("_").lower()[:36] or "case"
    candidate = f"actor_auto_{normalized}"
    exists = conn.execute(
        """
        select 1
        from case_actor_profiles
        where case_actor_id = ?
        limit 1
        """,
        (candidate,),
    ).fetchone()
    if exists is None:
        return candidate
    return f"{candidate}_{uuid4().hex[:6]}"


def _risk_level_from_case_severity(case_severity: str) -> str:
    severity = str(case_severity or "").lower()
    if severity in {"critical", "high"}:
        return "high"
    if severity == "medium":
        return "medium"
    return "low"


def _pick_case_actor_for_high_signal_coverage(
    conn: sqlite3.Connection,
    *,
    case_id: str,
    case_primary_actor_id: str | None,
    case_stage: str,
    case_severity: str,
    high_signal_alert_rows: list[sqlite3.Row],
) -> tuple[str, int]:
    actor_rows = conn.execute(
        """
        select case_actor_id, status, profile_confidence, is_primary, current_stage, updated_at
        from case_actor_profiles
        where case_id = ?
        """,
        (case_id,),
    ).fetchall()

    actor_by_id = {row["case_actor_id"]: row for row in actor_rows}
    if case_primary_actor_id and case_primary_actor_id in actor_by_id:
        return case_primary_actor_id, 0

    if actor_rows:
        def _actor_score(item: sqlite3.Row) -> tuple[int, float, int, int, str, str]:
            status = str(item["status"] or "").lower()
            status_rank = 2 if status == "active" else (1 if status in {"suspected", "watch"} else 0)
            return (
                status_rank,
                float(item["profile_confidence"] or 0.0),
                _STAGE_ORDER.get(str(item["current_stage"] or "").lower(), 0),
                int(item["is_primary"] or 0),
                str(item["updated_at"] or ""),
                str(item["case_actor_id"] or ""),
            )

        return max(actor_rows, key=_actor_score)["case_actor_id"], 0

    src_ips = sorted({str(row["src_ip"]) for row in high_signal_alert_rows if row["src_ip"]})
    first_seen_at = min((str(row["occurred_at"]) for row in high_signal_alert_rows), default=None)
    last_seen_at = max((str(row["occurred_at"]) for row in high_signal_alert_rows), default=None)
    actor_id = _default_case_actor_id(conn, case_id=case_id)
    if len(src_ips) == 1:
        actor_label = f"{src_ips[0]} (组织级攻击者)"
    elif len(src_ips) >= 2:
        actor_label = f"组织级攻击者（{len(src_ips)} 源IP）"
    else:
        actor_label = "组织级攻击者"
    confidence = min(0.9, 0.65 + 0.05 * len(high_signal_alert_rows))
    actor = upsert_case_actor_profile(
        conn,
        {
            "case_actor_id": actor_id,
            "case_id": case_id,
            "label": actor_label,
            "status": "active",
            "profile_confidence": confidence,
            "risk_level": _risk_level_from_case_severity(case_severity),
            "is_primary": False,
            "current_stage": case_stage,
            "first_seen_at": first_seen_at,
            "last_seen_at": last_seen_at,
            "summary": "auto_backfill_high_signal_coverage",
        },
    )
    return str(actor["case_actor_id"]), 1


def _backfill_high_signal_alert_actor_coverage(conn: sqlite3.Connection) -> dict[str, int]:
    case_rows = conn.execute(
        """
        select case_id, current_stage, overall_severity, primary_actor_id
        from cases
        where coalesce(merge_state, 'standalone') <> 'merged'
        """
    ).fetchall()
    if not case_rows:
        return {
            "backfilled_case_actor_count": 0,
            "backfilled_actor_link_count": 0,
            "backfilled_actor_observation_count": 0,
        }

    severities = tuple(sorted(_HIGH_SIGNAL_ACTOR_SEVERITIES))
    severity_placeholders = ", ".join("?" for _ in severities)
    stages = tuple(sorted(_HIGH_SIGNAL_ACTOR_STAGES))
    stage_placeholders = ", ".join("?" for _ in stages)
    now = _now_iso()

    created_actor_count = 0
    created_link_count = 0
    created_observation_count = 0

    for case_row in case_rows:
        case_id = case_row["case_id"]
        alert_rows = conn.execute(
            f"""
            select
              alerts.alert_id,
              alerts.src_ip,
              alerts.occurred_at,
              alerts.attack_stage,
              alerts.severity,
              case_alert_links.confidence as link_confidence
            from case_alert_links
            join alerts on alerts.alert_id = case_alert_links.alert_id
            where case_alert_links.case_id = ?
              and case_alert_links.is_active = 1
              and case_alert_links.confidence >= ?
              and lower(alerts.severity) in ({severity_placeholders})
              and lower(alerts.attack_stage) in ({stage_placeholders})
            order by alerts.occurred_at asc, case_alert_links.linked_at asc, case_alert_links.rowid asc
            """,
            (case_id, _MIN_LINK_CONFIDENCE_FOR_RELATION, *severities, *stages),
        ).fetchall()
        if not alert_rows:
            continue

        case_actor_id, actor_created = _pick_case_actor_for_high_signal_coverage(
            conn,
            case_id=case_id,
            case_primary_actor_id=case_row["primary_actor_id"],
            case_stage=case_row["current_stage"],
            case_severity=case_row["overall_severity"],
            high_signal_alert_rows=alert_rows,
        )
        created_actor_count += actor_created

        conn.execute(
            """
            update case_actor_profiles
            set current_stage = ?, updated_at = ?
            where case_actor_id = ?
            """,
            (case_row["current_stage"], now, case_actor_id),
        )

        for alert_row in alert_rows:
            alert_id = alert_row["alert_id"]
            has_alert_mapping = conn.execute(
                """
                select 1
                from case_actor_links
                join case_actor_profiles on case_actor_profiles.case_actor_id = case_actor_links.case_actor_id
                where case_actor_profiles.case_id = ?
                  and case_actor_links.target_type = 'alert'
                  and case_actor_links.target_id = ?
                limit 1
                """,
                (case_id, alert_id),
            ).fetchone()
            if has_alert_mapping is None:
                add_case_actor_link(
                    conn,
                    {
                        "case_actor_id": case_actor_id,
                        "target_type": "alert",
                        "target_id": alert_id,
                        "link_confidence": max(float(alert_row["link_confidence"] or 0.0), 0.6),
                        "link_reason": "auto_backfill_high_signal_alert",
                        "linked_at": alert_row["occurred_at"],
                    },
                )
                created_link_count += 1

            src_ip = str(alert_row["src_ip"] or "").strip()
            if not src_ip:
                continue
            observation_exists = conn.execute(
                """
                select 1
                from case_actor_observations
                where case_actor_id = ?
                  and observation_type = 'src_ip'
                  and observation_key = ?
                limit 1
                """,
                (case_actor_id, src_ip),
            ).fetchone()
            if observation_exists is not None:
                continue
            add_case_actor_observation(
                conn,
                {
                    "case_actor_id": case_actor_id,
                    "observation_type": "src_ip",
                    "observation_key": src_ip,
                    "observation_value": src_ip,
                    "confidence": max(float(alert_row["link_confidence"] or 0.0), 0.6),
                    "first_seen_at": alert_row["occurred_at"],
                    "last_seen_at": alert_row["occurred_at"],
                    "source_count": 1,
                },
            )
            created_observation_count += 1

    return {
        "backfilled_case_actor_count": created_actor_count,
        "backfilled_actor_link_count": created_link_count,
        "backfilled_actor_observation_count": created_observation_count,
    }


def _backfill_high_signal_compromised_host_assessments(
    conn: sqlite3.Connection,
    *,
    run_id: str,
) -> int:
    case_rows = conn.execute(
        """
        select case_id, current_stage, overall_severity
        from cases
        where coalesce(merge_state, 'standalone') <> 'merged'
        """
    ).fetchall()
    if not case_rows:
        return 0

    severities = tuple(sorted(_HIGH_SIGNAL_ACTOR_SEVERITIES))
    severity_placeholders = ", ".join("?" for _ in severities)
    stages = tuple(sorted(_HIGH_SIGNAL_ACTOR_STAGES))
    stage_placeholders = ", ".join("?" for _ in stages)
    created_count = 0

    for case_row in case_rows:
        case_id = str(case_row["case_id"])
        alert_rows = conn.execute(
            f"""
            select
              alerts.alert_id,
              alerts.asset_id,
              alerts.occurred_at,
              case_alert_links.confidence as link_confidence
            from case_alert_links
            join alerts on alerts.alert_id = case_alert_links.alert_id
            where case_alert_links.case_id = ?
              and case_alert_links.is_active = 1
              and case_alert_links.confidence >= ?
              and lower(alerts.severity) in ({severity_placeholders})
              and lower(alerts.attack_stage) in ({stage_placeholders})
            order by alerts.occurred_at asc, case_alert_links.linked_at asc, case_alert_links.rowid asc
            """,
            (case_id, _MIN_LINK_CONFIDENCE_FOR_RELATION, *severities, *stages),
        ).fetchall()
        if not alert_rows:
            continue

        asset_rows: dict[str, list[sqlite3.Row]] = {}
        for alert_row in alert_rows:
            asset_id = str(alert_row["asset_id"] or "").strip()
            if not asset_id:
                continue
            asset_rows.setdefault(asset_id, []).append(alert_row)
        if not asset_rows:
            continue

        for asset_id, rows in asset_rows.items():
            existing = conn.execute(
                """
                select 1
                from entity_assessments
                where entity_type = 'asset'
                  and entity_key = ?
                  and related_case_id = ?
                  and verdict = 'compromised_host'
                  and is_current = 1
                limit 1
                """,
                (asset_id, case_id),
            ).fetchone()
            if existing is not None:
                continue

            supporting_alert_ids = list(dict.fromkeys(str(item["alert_id"]) for item in rows if item["alert_id"]))
            first_seen_at = min((str(item["occurred_at"]) for item in rows if item["occurred_at"]), default=None)
            last_seen_at = max((str(item["occurred_at"]) for item in rows if item["occurred_at"]), default=None)
            confidence = max((float(item["link_confidence"] or 0.0) for item in rows), default=0.8)
            upsert_entity_assessment(
                conn,
                entity_type="asset",
                entity_key=asset_id,
                entity_label=asset_id,
                related_case_id=case_id,
                risk_level=_risk_level_from_case_severity(str(case_row["overall_severity"] or "")),
                assessment_confidence=max(0.8, min(confidence, 0.98)),
                verdict="compromised_host",
                reason_summary="auto_backfill_compromised_host_high_signal",
                supporting_alert_ids=supporting_alert_ids,
                supporting_evidence_ids=[],
                first_seen_at=first_seen_at,
                last_seen_at=last_seen_at,
                run_id=run_id,
                analysis_cutoff_at=None,
            )
            created_count += 1

    return created_count


def _load_case_contexts(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        select
          case_id,
          current_stage,
          overall_severity,
          coalesce(canonical_case_id, case_id) as canonical_case_id,
          merge_state,
          status
        from cases
        where status in ('open', 'active', 'investigating', 'observing')
           or merge_state = 'merged'
        """
    ).fetchall()
    contexts: list[dict[str, Any]] = []
    for row in rows:
        case_id = row["case_id"]
        active_alert_rows = conn.execute(
            """
            select
              alerts.alert_id,
              alerts.asset_id,
              alerts.src_ip,
              alerts.occurred_at,
              alerts.severity,
              case_alert_links.confidence as link_confidence
            from case_alert_links
            join alerts on alerts.alert_id = case_alert_links.alert_id
            where case_alert_links.case_id = ? and case_alert_links.is_active = 1
            """,
            (case_id,),
        ).fetchall()
        alert_rows = list(active_alert_rows)
        if not alert_rows and str(row["merge_state"] or "").lower() == "merged":
            alert_rows = conn.execute(
                """
                select
                  alerts.alert_id,
                  alerts.asset_id,
                  alerts.src_ip,
                  alerts.occurred_at,
                  alerts.severity,
                  case_alert_links.confidence as link_confidence
                from case_alert_links
                join alerts on alerts.alert_id = case_alert_links.alert_id
                where case_alert_links.case_id = ?
                order by coalesce(case_alert_links.unlinked_at, case_alert_links.linked_at) desc,
                         case_alert_links.rowid desc
                limit 8
                """,
                (case_id,),
            ).fetchall()
        if not alert_rows:
            continue
        high_signal_alert_rows = [
            item
            for item in alert_rows
            if float(item["link_confidence"]) >= _MIN_LINK_CONFIDENCE_FOR_RELATION
            and str(item["severity"]).lower() in _ALLOWED_ALERT_SEVERITIES_FOR_RELATION
        ]
        if not high_signal_alert_rows:
            high_signal_alert_rows = [
                item for item in alert_rows if str(item["severity"]).lower() in _ALLOWED_ALERT_SEVERITIES_FOR_RELATION
            ]
        scored_alert_rows = high_signal_alert_rows or list(alert_rows)
        evidence_rows = conn.execute(
            """
            select evidence_id, occurred_at
            from evidence
            where case_id = ?
            """,
            (case_id,),
        ).fetchall()
        if (
            not high_signal_alert_rows
            and str(row["current_stage"]).lower() == "recon"
            and str(row["merge_state"] or "").lower() != "merged"
            and all(_SEVERITY_ORDER.get(str(item["severity"]).lower(), 0) <= 1 for item in alert_rows)
            and not evidence_rows
        ):
            continue
        timeline_last_row = conn.execute(
            """
            select max(occurred_at) as last_event_at
            from timeline_events
            where case_id = ?
            """,
            (case_id,),
        ).fetchone()
        last_alert_at = max((item["occurred_at"] for item in scored_alert_rows), default="")
        last_event_at = timeline_last_row["last_event_at"] or last_alert_at
        contexts.append(
            {
                "case_id": case_id,
                "canonical_case_id": row["canonical_case_id"],
                "current_stage": row["current_stage"],
                "asset_ids": {item["asset_id"] for item in scored_alert_rows if item["asset_id"]},
                "src_ips": {item["src_ip"] for item in scored_alert_rows if item["src_ip"]},
                "alert_ids": {item["alert_id"] for item in scored_alert_rows},
                "evidence_ids": {item["evidence_id"] for item in evidence_rows},
                "overall_severity": row["overall_severity"],
                "max_alert_severity_rank": max(
                    (_SEVERITY_ORDER.get(str(item["severity"]).lower(), 0) for item in scored_alert_rows),
                    default=0,
                ),
                "last_event_at": last_event_at,
            }
        )
    return contexts


def _case_pair_key(case_a: str, case_b: str) -> tuple[str, str]:
    return (case_a, case_b) if case_a <= case_b else (case_b, case_a)


def _load_relation_candidates(conn: sqlite3.Connection) -> dict[tuple[str, str], dict[str, Any]]:
    rows = conn.execute(
        """
        select
          left_case_id,
          right_case_id,
          score,
          streak_count,
          status,
          supporting_alert_ids_json,
          supporting_evidence_ids_json
        from case_relations
        where status in ('candidate', 'confirmed')
        """
    ).fetchall()
    relation_map: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        relation = dict(row)
        relation["supporting_alert_ids"] = json.loads(relation.pop("supporting_alert_ids_json"))
        relation["supporting_evidence_ids"] = json.loads(relation.pop("supporting_evidence_ids_json"))
        relation_map[(relation["left_case_id"], relation["right_case_id"])] = relation
    return relation_map


def _build_confirmed_clusters(confirmed_relations: list[dict[str, Any]]) -> list[list[str]]:
    adjacency: dict[str, set[str]] = {}
    for relation in confirmed_relations:
        left_case_id = relation["left_case_id"]
        right_case_id = relation["right_case_id"]
        adjacency.setdefault(left_case_id, set()).add(right_case_id)
        adjacency.setdefault(right_case_id, set()).add(left_case_id)

    visited: set[str] = set()
    clusters: list[list[str]] = []
    for node in sorted(adjacency.keys()):
        if node in visited:
            continue
        stack = [node]
        component: list[str] = []
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            component.append(current)
            for neighbor in sorted(adjacency.get(current, set())):
                if neighbor not in visited:
                    stack.append(neighbor)
        if len(component) >= 2:
            clusters.append(sorted(component))
    return clusters


def _promote_cluster_bridge_relations(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    case_context_by_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    promoted: list[dict[str, Any]] = []
    while True:
        relation_map = _load_relation_candidates(conn)
        confirmed_relations = list_confirmed_case_relations(conn)
        clusters = _build_confirmed_clusters(confirmed_relations)
        promoted_in_pass = 0

        for cluster in clusters:
            cluster_set = set(cluster)
            cluster_max_stage_rank = max(
                _STAGE_ORDER.get(case_context_by_id.get(case_id, {}).get("current_stage", ""), 0)
                for case_id in cluster
            )
            if cluster_max_stage_rank < _STAGE_ORDER["persistence"]:
                continue

            for outside_case_id, outside_context in case_context_by_id.items():
                if outside_case_id in cluster_set:
                    continue
                outside_stage_rank = _STAGE_ORDER.get(outside_context.get("current_stage", ""), 0)
                if outside_stage_rank < _STAGE_ORDER["persistence"]:
                    continue

                best_relation: dict[str, Any] | None = None
                best_member_case_id: str | None = None
                for member_case_id in cluster:
                    pair_key = _case_pair_key(member_case_id, outside_case_id)
                    relation = relation_map.get(pair_key)
                    if relation is None or relation["status"] == "confirmed":
                        continue
                    if float(relation["score"]) < _CLUSTER_BRIDGE_PROMOTION_SCORE:
                        continue
                    if best_relation is None or float(relation["score"]) > float(best_relation["score"]):
                        best_relation = relation
                        best_member_case_id = member_case_id

                if best_relation is None or best_member_case_id is None:
                    continue

                promoted_relation = upsert_case_relation_candidate(
                    conn,
                    run_id,
                    best_member_case_id,
                    outside_case_id,
                    float(best_relation["score"]),
                    "cluster_bridge_promotion",
                    list(best_relation["supporting_alert_ids"]),
                    list(best_relation["supporting_evidence_ids"]),
                    required_streak=1,
                )
                if promoted_relation["status"] == "confirmed":
                    promoted.append(promoted_relation)
                    promoted_in_pass += 1

        if promoted_in_pass == 0:
            return promoted


def _should_fast_track_relation(
    left_context: dict[str, Any],
    right_context: dict[str, Any],
    *,
    score: Any,
) -> bool:
    factor_map = {item["factor_type"]: float(item["score"]) for item in score.factors}
    left_stage_rank = _STAGE_ORDER.get(str(left_context.get("current_stage", "")).lower(), 0)
    right_stage_rank = _STAGE_ORDER.get(str(right_context.get("current_stage", "")).lower(), 0)
    left_severity_rank = int(left_context.get("max_alert_severity_rank") or 0)
    right_severity_rank = int(right_context.get("max_alert_severity_rank") or 0)
    return (
        float(score.total) >= _FAST_TRACK_MERGE_SCORE
        and factor_map.get("asset_overlap", 0.0) >= 1.0
        and factor_map.get("stage_continuity", 0.0) >= 0.85
        and factor_map.get("temporal_continuity", 0.0) >= 0.8
        and min(left_stage_rank, right_stage_rank) >= _FAST_TRACK_MIN_STAGE_RANK
        and min(left_severity_rank, right_severity_rank) >= _FAST_TRACK_MIN_SEVERITY_RANK
    )


def _normalize_cluster_case_links_and_artifacts(
    conn: sqlite3.Connection,
    *,
    canonical_case_id: str,
    case_ids: list[str],
) -> dict[str, int]:
    child_case_ids = [case_id for case_id in case_ids if case_id != canonical_case_id]
    if not child_case_ids:
        return {"retargeted_links_count": 0, "evidence_migrated_count": 0, "timeline_migrated_count": 0}

    now = _now_iso()
    placeholders = ", ".join("?" for _ in child_case_ids)
    link_rows = conn.execute(
        f"""
        select
          case_alert_links.case_id,
          case_alert_links.alert_id,
          case_alert_links.linked_at,
          case_alert_links.confidence,
          case_alert_links.reason,
          alerts.severity as alert_severity,
          alerts.attack_stage as alert_stage
        from case_alert_links
        join alerts on alerts.alert_id = case_alert_links.alert_id
        where is_active = 1
          and case_id in ({placeholders})
        order by linked_at asc, case_alert_links.rowid asc
        """,
        tuple(child_case_ids),
    ).fetchall()
    clustered_case_ids = set(case_ids)
    in_scope_placeholders = ", ".join("?" for _ in clustered_case_ids)
    in_scope_case_ids = tuple(sorted(clustered_case_ids))
    retargeted_links_count = 0
    filtered_low_signal_links_count = 0

    for row in link_rows:
        if (
            float(row["confidence"]) < _MIN_LINK_CONFIDENCE_FOR_RELATION
            and str(row["alert_severity"] or "").lower() == "low"
            and str(row["alert_stage"] or "").lower() in {"recon", "reconnaissance"}
        ):
            conn.execute(
                f"""
                update case_alert_links
                set is_active = 0, unlinked_at = ?
                where alert_id = ?
                  and is_active = 1
                  and case_id in ({in_scope_placeholders})
                """,
                (now, row["alert_id"], *in_scope_case_ids),
            )
            filtered_low_signal_links_count += 1
            continue
        conn.execute(
            """
            update case_alert_links
            set is_active = 0, unlinked_at = ?
            where alert_id = ? and is_active = 1 and case_id <> ?
            """,
            (now, row["alert_id"], canonical_case_id),
        )
        conn.execute(
            """
            insert into case_alert_links (
              case_id, alert_id, linked_at, confidence, reason, is_active, unlinked_at
            ) values (?, ?, ?, ?, ?, 1, null)
            on conflict(case_id, alert_id) do update set
              linked_at = excluded.linked_at,
              confidence = excluded.confidence,
              reason = excluded.reason,
              is_active = 1,
              unlinked_at = null
            """,
            (
                canonical_case_id,
                row["alert_id"],
                row["linked_at"],
                row["confidence"],
                f"{row['reason']}; auto_retarget_to_canonical",
            ),
        )
        retargeted_links_count += 1

    evidence_migrated_count = conn.execute(
        f"""
        update evidence
        set case_id = ?
        where case_id in ({placeholders})
        """,
        (canonical_case_id, *tuple(child_case_ids)),
    ).rowcount
    timeline_migrated_count = conn.execute(
        f"""
        update timeline_events
        set case_id = ?
        where case_id in ({placeholders})
        """,
        (canonical_case_id, *tuple(child_case_ids)),
    ).rowcount

    actor_migrated_count = conn.execute(
        f"""
        update case_actor_profiles
        set case_id = ?, is_primary = 0, updated_at = ?
        where case_id in ({placeholders})
        """,
        (canonical_case_id, now, *tuple(child_case_ids)),
    ).rowcount

    conn.execute(
        """
        delete from case_digests
        where case_id = ?
        """,
        (canonical_case_id,),
    )
    conn.execute(
        f"""
        delete from case_digests
        where case_id in ({placeholders})
        """,
        tuple(child_case_ids),
    )
    return {
        "retargeted_links_count": retargeted_links_count,
        "evidence_migrated_count": int(evidence_migrated_count or 0),
        "timeline_migrated_count": int(timeline_migrated_count or 0),
        "filtered_low_signal_links_count": filtered_low_signal_links_count,
        "actor_migrated_count": int(actor_migrated_count or 0),
    }


def _apply_cluster_merge(conn: sqlite3.Connection, *, run_id: str, case_ids: list[str]) -> dict[str, Any]:
    canonical_case_id = reselect_cluster_canonical_case(conn, case_ids, run_id=run_id)
    now = _now_iso()
    previous_rows = {
        row["case_id"]: dict(row)
        for row in conn.execute(
            """
            select case_id, status, canonical_case_id, merged_into_case_id, merge_state
            from cases
            where case_id in ({})
            """.format(", ".join("?" for _ in case_ids)),
            tuple(case_ids),
        ).fetchall()
    }

    changed_case_ids: list[str] = []
    for case_id in case_ids:
        before = previous_rows.get(case_id)
        if case_id == canonical_case_id:
            canonical_target = case_id
            merged_into_target = None
            merge_state_target = "standalone"
            if before is not None and str(before.get("status", "")).lower() != "closed":
                status_target = before["status"]
            else:
                status_target = "open"
        else:
            canonical_target = canonical_case_id
            merged_into_target = canonical_case_id
            merge_state_target = "merged"
            status_target = "closed"
        if (
            before is not None
            and before.get("status") == status_target
            and before.get("canonical_case_id") == canonical_target
            and before.get("merged_into_case_id") == merged_into_target
            and before.get("merge_state") == merge_state_target
        ):
            continue
        conn.execute(
            """
            update cases
            set status = ?, canonical_case_id = ?, merged_into_case_id = ?, merge_state = ?, merge_updated_at = ?
            where case_id = ?
            """,
            (status_target, canonical_target, merged_into_target, merge_state_target, now, case_id),
        )
        changed_case_ids.append(case_id)

    normalize_stats = _normalize_cluster_case_links_and_artifacts(
        conn,
        canonical_case_id=canonical_case_id,
        case_ids=case_ids,
    )
    if not changed_case_ids:
        return {"event_created": False, "canonical_case_id": canonical_case_id, "affected_case_ids": case_ids}

    old_canonical_case_id = None
    for case_id in case_ids:
        previous = previous_rows.get(case_id)
        if not previous:
            continue
        candidate = previous.get("canonical_case_id") or case_id
        if candidate in case_ids:
            old_canonical_case_id = candidate
            break

    conn.execute(
        """
        insert into case_merge_events (
          event_id,
          occurred_at,
          run_id,
          cluster_id,
          old_canonical_case_id,
          new_canonical_case_id,
          affected_case_ids_json,
          reason,
          detail_json
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            f"merge_{uuid4().hex[:12]}",
            now,
            run_id,
            "|".join(case_ids),
            old_canonical_case_id,
            canonical_case_id,
            json.dumps(case_ids, ensure_ascii=False),
            "auto_case_convergence",
            json.dumps({"changed_case_ids": changed_case_ids, **normalize_stats}, ensure_ascii=False),
        ),
    )
    return {"event_created": True, "canonical_case_id": canonical_case_id, "affected_case_ids": case_ids}


def _relation_counterparty(relation: dict[str, Any], case_id: str) -> str:
    if relation["left_case_id"] == case_id:
        return relation["right_case_id"]
    return relation["left_case_id"]


def _demote_superseded_confirmed_relations(conn: sqlite3.Connection, *, run_id: str) -> int:
    rows = conn.execute(
        """
        select relation_id, left_case_id, right_case_id, score, last_run_id, last_reason, last_seen_at
        from case_relations
        where status = 'confirmed'
        """
    ).fetchall()
    by_case_id: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        relation = dict(row)
        by_case_id.setdefault(relation["left_case_id"], []).append(relation)
        by_case_id.setdefault(relation["right_case_id"], []).append(relation)

    demotions: dict[str, str] = {}
    for case_id, relations in by_case_id.items():
        if len(relations) < 2:
            continue
        fresh_relations = [item for item in relations if item["last_run_id"] == run_id]
        if not fresh_relations:
            continue
        best_relation = max(
            fresh_relations,
            key=lambda item: (
                float(item["score"]),
                str(item.get("last_seen_at") or ""),
                str(item["relation_id"]),
            ),
        )
        best_score = float(best_relation["score"])
        best_counterparty = _relation_counterparty(best_relation, case_id)

        for relation in relations:
            if relation["relation_id"] == best_relation["relation_id"]:
                continue
            if relation["last_run_id"] == run_id:
                continue
            if float(relation["score"]) + _SUPERSEDED_RELATION_SCORE_MARGIN >= best_score:
                continue
            demotions.setdefault(
                relation["relation_id"],
                f"{relation['last_reason']}; superseded_by_newer_relation={best_counterparty}",
            )

    if not demotions:
        return 0
    now = _now_iso()
    updated = 0
    for relation_id, reason in demotions.items():
        result = conn.execute(
            """
            update case_relations
            set status = 'candidate',
                streak_count = 0,
                last_run_id = ?,
                last_reason = ?,
                last_seen_at = ?
            where relation_id = ? and status = 'confirmed'
            """,
            (run_id, reason, now, relation_id),
        )
        updated += int(result.rowcount or 0)
    return updated


def _reconcile_detached_cases(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    clustered_case_ids: set[str],
) -> list[str]:
    rows = conn.execute(
        """
        select case_id, status, canonical_case_id, merged_into_case_id, merge_state
        from cases
        where merge_state = 'merged'
           or (canonical_case_id is not null and canonical_case_id <> case_id)
        """
    ).fetchall()
    if not rows:
        return []

    detached_case_ids: list[str] = []
    now = _now_iso()
    for row in rows:
        case_id = row["case_id"]
        if case_id in clustered_case_ids:
            continue

        status_target = row["status"]
        if str(row["merge_state"] or "").lower() == "merged" and str(row["status"] or "").lower() == "closed":
            status_target = "open"
        conn.execute(
            """
            update cases
            set status = ?,
                canonical_case_id = ?,
                merged_into_case_id = null,
                merge_state = 'standalone',
                merge_updated_at = ?
            where case_id = ?
            """,
            (status_target, case_id, now, case_id),
        )
        detached_case_ids.append(case_id)
        conn.execute(
            """
            insert into case_merge_events (
              event_id,
              occurred_at,
              run_id,
              cluster_id,
              old_canonical_case_id,
              new_canonical_case_id,
              affected_case_ids_json,
              reason,
              detail_json
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"merge_{uuid4().hex[:12]}",
                now,
                run_id,
                case_id,
                row["canonical_case_id"],
                case_id,
                json.dumps([case_id], ensure_ascii=False),
                "auto_case_convergence_detach",
                json.dumps({"detached_case_id": case_id}, ensure_ascii=False),
            ),
        )

    return detached_case_ids


def _json_list(raw: Any) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(item) for item in raw if item is not None and str(item)]
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if isinstance(parsed, list):
            return [str(item) for item in parsed if item is not None and str(item)]
    return []


def _rollup_canonical_entity_assessment_state(conn: sqlite3.Connection, *, run_id: str) -> int:
    case_rows = conn.execute(
        """
        select case_id, coalesce(canonical_case_id, case_id) as canonical_case_id
        from cases
        """
    ).fetchall()
    if not case_rows:
        return 0

    members_by_canonical: dict[str, list[str]] = {}
    for row in case_rows:
        members_by_canonical.setdefault(str(row["canonical_case_id"]), []).append(str(row["case_id"]))

    now = _now_iso()
    updates = 0
    for canonical_case_id, member_case_ids in members_by_canonical.items():
        scoped_case_ids = list(dict.fromkeys(member_case_ids + [canonical_case_id]))
        if not scoped_case_ids:
            continue
        placeholders = ", ".join("?" for _ in scoped_case_ids)
        rows = conn.execute(
            f"""
            select
              assessment_id,
              occurred_at,
              run_id,
              entity_type,
              entity_key,
              entity_label,
              related_case_id,
              risk_level,
              assessment_confidence,
              verdict,
              reason_summary,
              supporting_alert_ids_json,
              supporting_evidence_ids_json,
              first_seen_at,
              last_seen_at,
              analysis_cutoff_at,
              is_current
            from entity_assessments
            where is_current = 1
              and related_case_id in ({placeholders})
            """,
            tuple(scoped_case_ids),
        ).fetchall()
        if not rows:
            continue

        grouped: dict[tuple[str, str], list[sqlite3.Row]] = {}
        for row in rows:
            grouped.setdefault((str(row["entity_type"]), str(row["entity_key"])), []).append(row)

        for entity_key, candidates in grouped.items():
            if len(candidates) == 1 and str(candidates[0]["related_case_id"] or "") == canonical_case_id:
                continue

            winner = max(
                candidates,
                key=lambda item: (
                    _SEVERITY_ORDER.get(str(item["risk_level"] or "").lower(), 0),
                    float(item["assessment_confidence"] or 0.0),
                    str(item["occurred_at"] or ""),
                    str(item["assessment_id"] or ""),
                ),
            )
            winner_case_id = str(winner["related_case_id"] or "")
            if len(candidates) == 1 and winner_case_id == canonical_case_id:
                continue

            first_seen_candidates = [str(item["first_seen_at"]) for item in candidates if item["first_seen_at"]]
            last_seen_candidates = [str(item["last_seen_at"]) for item in candidates if item["last_seen_at"]]
            first_seen_at = min(first_seen_candidates) if first_seen_candidates else winner["first_seen_at"]
            last_seen_at = max(last_seen_candidates) if last_seen_candidates else winner["last_seen_at"]

            alert_ids: list[str] = []
            evidence_ids: list[str] = []
            for item in candidates:
                alert_ids.extend(_json_list(item["supporting_alert_ids_json"]))
                evidence_ids.extend(_json_list(item["supporting_evidence_ids_json"]))
            merged_alert_ids = list(dict.fromkeys(alert_ids))
            merged_evidence_ids = list(dict.fromkeys(evidence_ids))

            demoted_ids = [str(item["assessment_id"]) for item in candidates]
            demote_placeholders = ", ".join("?" for _ in demoted_ids)
            conn.execute(
                f"""
                update entity_assessments
                set is_current = 0
                where assessment_id in ({demote_placeholders})
                """,
                tuple(demoted_ids),
            )
            assessment_id = f"eass_{uuid4().hex[:12]}"
            conn.execute(
                """
                insert into entity_assessments (
                  assessment_id,
                  occurred_at,
                  run_id,
                  entity_type,
                  entity_key,
                  entity_label,
                  related_case_id,
                  risk_level,
                  assessment_confidence,
                  verdict,
                  reason_summary,
                  supporting_alert_ids_json,
                  supporting_evidence_ids_json,
                  first_seen_at,
                  last_seen_at,
                  analysis_cutoff_at,
                  is_current
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    assessment_id,
                    now,
                    run_id,
                    winner["entity_type"],
                    winner["entity_key"],
                    winner["entity_label"] or winner["entity_key"],
                    canonical_case_id,
                    winner["risk_level"],
                    winner["assessment_confidence"],
                    winner["verdict"],
                    "auto_case_convergence_entity_rollup",
                    json.dumps(merged_alert_ids, ensure_ascii=False),
                    json.dumps(merged_evidence_ids, ensure_ascii=False),
                    first_seen_at,
                    last_seen_at,
                    winner["analysis_cutoff_at"],
                ),
            )
            updates += 1

    return updates


def _rollup_canonical_case_state(conn: sqlite3.Connection) -> int:
    rows = conn.execute(
        """
        select case_id, canonical_case_id, merge_state, status, current_stage, overall_severity
        from cases
        """
    ).fetchall()
    if not rows:
        return 0

    case_row_by_id: dict[str, dict[str, Any]] = {}
    members_by_canonical: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        item = dict(row)
        case_id = item["case_id"]
        canonical_case_id = item["canonical_case_id"] or case_id
        case_row_by_id[case_id] = item
        members_by_canonical.setdefault(canonical_case_id, []).append(item)

    updates = 0
    for canonical_case_id, members in members_by_canonical.items():
        canonical_row = case_row_by_id.get(canonical_case_id)
        if canonical_row is None:
            continue
        if str(canonical_row.get("merge_state") or "").lower() == "merged":
            continue

        observed_stage = _select_latest_high_signal_stage_for_case(conn, case_id=canonical_case_id)
        observed_stage_rank = _STAGE_ORDER.get(str(observed_stage or "").lower(), 0)
        if observed_stage and observed_stage_rank > 0:
            target_stage = observed_stage
            target_stage_rank = observed_stage_rank
        else:
            target_stage = canonical_row["current_stage"]
            target_stage_rank = _STAGE_ORDER.get(str(target_stage or "").lower(), 0)
        target_severity = canonical_row["overall_severity"]
        target_severity_rank = _SEVERITY_ORDER.get(str(target_severity or "").lower(), 0)
        has_active_member = False
        for member in members:
            member_stage = member["current_stage"]
            member_stage_rank = _STAGE_ORDER.get(str(member_stage or "").lower(), 0)
            if observed_stage is None and member_stage_rank > target_stage_rank:
                target_stage = member_stage
                target_stage_rank = member_stage_rank
            member_severity = member["overall_severity"]
            member_severity_rank = _SEVERITY_ORDER.get(str(member_severity or "").lower(), 0)
            if member_severity_rank > target_severity_rank:
                target_severity = member_severity
                target_severity_rank = member_severity_rank
            if str(member["status"] or "").lower() in {"open", "active", "investigating", "observing"}:
                has_active_member = True

        status_target = canonical_row["status"]
        if has_active_member and str(status_target or "").lower() == "closed":
            status_target = "open"

        if (
            canonical_row["current_stage"] == target_stage
            and canonical_row["overall_severity"] == target_severity
            and canonical_row["status"] == status_target
        ):
            continue
        conn.execute(
            """
            update cases
            set current_stage = ?, overall_severity = ?, status = ?
            where case_id = ?
            """,
            (target_stage, target_severity, status_target, canonical_case_id),
        )
        updates += 1
    return updates


def _rollup_canonical_primary_actor_state(conn: sqlite3.Connection) -> int:
    rows = conn.execute(
        """
        select case_id, primary_actor_id
        from cases
        where coalesce(merge_state, 'standalone') <> 'merged'
        """
    ).fetchall()
    if not rows:
        return 0

    updates = 0
    now = _now_iso()
    for row in rows:
        case_id = row["case_id"]
        actor_rows = conn.execute(
            """
            select case_actor_id, status, profile_confidence, is_primary, current_stage, updated_at
            from case_actor_profiles
            where case_id = ?
            """,
            (case_id,),
        ).fetchall()
        if not actor_rows:
            continue

        def _actor_score(item: sqlite3.Row) -> tuple[int, float, int, int, str, str]:
            status = str(item["status"] or "").lower()
            status_rank = 2 if status == "active" else (1 if status in {"suspected", "watch"} else 0)
            return (
                status_rank,
                float(item["profile_confidence"] or 0.0),
                _STAGE_ORDER.get(str(item["current_stage"] or "").lower(), 0),
                int(item["is_primary"] or 0),
                str(item["updated_at"] or ""),
                str(item["case_actor_id"] or ""),
            )

        winner = max(actor_rows, key=_actor_score)["case_actor_id"]
        current_primary_ids = {item["case_actor_id"] for item in actor_rows if int(item["is_primary"] or 0) == 1}
        if current_primary_ids != {winner}:
            conn.execute(
                """
                update case_actor_profiles
                set is_primary = case when case_actor_id = ? then 1 else 0 end,
                    updated_at = ?
                where case_id = ?
                """,
                (winner, now, case_id),
            )
            updates += 1
        if row["primary_actor_id"] != winner:
            conn.execute(
                """
                update cases
                set primary_actor_id = ?
                where case_id = ?
                """,
                (winner, case_id),
            )
            updates += 1
    return updates


def run_case_convergence_for_run(conn: sqlite3.Connection, run_id: str) -> dict[str, Any]:
    contexts = _load_case_contexts(conn)
    case_context_by_id = {context["case_id"]: context for context in contexts}
    relation_updates: list[dict[str, Any]] = []
    for left_context, right_context in combinations(contexts, 2):
        if left_context["canonical_case_id"] == right_context["canonical_case_id"]:
            continue
        score = score_case_relation(left_context, right_context)
        reason = "; ".join(
            f"{item['factor_type']}={item['score']:.2f}"
            for item in score.factors
            if item["score"] >= 0.5
        ) or "weak_case_relation"
        fast_track = _should_fast_track_relation(left_context, right_context, score=score)
        if fast_track:
            reason = f"{reason}; fast_track_same_asset_chain"
        relation = upsert_case_relation_candidate(
            conn,
            run_id,
            left_context["case_id"],
            right_context["case_id"],
            score.total,
            reason,
            score.supporting_alert_ids,
            score.supporting_evidence_ids,
            required_streak=1 if fast_track else 3,
        )
        relation_updates.append(relation)

    promoted_relations = _promote_cluster_bridge_relations(
        conn,
        run_id=run_id,
        case_context_by_id=case_context_by_id,
    )
    superseded_relations_count = _demote_superseded_confirmed_relations(conn, run_id=run_id)
    confirmed_relations = list_confirmed_case_relations(conn)
    clusters = _build_confirmed_clusters(confirmed_relations)
    merge_events: list[dict[str, Any]] = []
    clustered_case_ids: set[str] = set()
    for cluster in clusters:
        clustered_case_ids.update(cluster)
        applied = _apply_cluster_merge(conn, run_id=run_id, case_ids=cluster)
        if applied["event_created"]:
            merge_events.append(applied)
    detached_case_ids = _reconcile_detached_cases(
        conn,
        run_id=run_id,
        clustered_case_ids=clustered_case_ids,
    )
    rolled_up_entity_assessments_count = _rollup_canonical_entity_assessment_state(conn, run_id=run_id)
    rolled_up_cases_count = _rollup_canonical_case_state(conn)
    actor_backfill_stats = _backfill_high_signal_alert_actor_coverage(conn)
    backfilled_compromised_host_count = _backfill_high_signal_compromised_host_assessments(conn, run_id=run_id)
    rolled_up_case_actors_count = _rollup_canonical_primary_actor_state(conn)
    confirmed_relations_after = list_confirmed_case_relations(conn)

    return {
        "run_id": run_id,
        "scored_relation_pairs": len(relation_updates),
        "promoted_relations_count": len(promoted_relations),
        "superseded_relations_count": superseded_relations_count,
        "confirmed_relations_count": len(confirmed_relations_after),
        "merge_events_count": len(merge_events),
        "detached_cases_count": len(detached_case_ids),
        "rolled_up_entity_assessments_count": rolled_up_entity_assessments_count,
        "rolled_up_cases_count": rolled_up_cases_count,
        "rolled_up_case_actors_count": rolled_up_case_actors_count,
        "backfilled_compromised_host_assessments_count": backfilled_compromised_host_count,
        **actor_backfill_stats,
    }
