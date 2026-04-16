from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from itertools import combinations
from typing import Any
from uuid import uuid4

from security_analyst_agent.repositories.case_relations import (
    list_confirmed_case_relations,
    upsert_case_relation_candidate,
)
from security_analyst_agent.repositories.cases import reselect_cluster_canonical_case
from security_analyst_agent.services.case_relation_scoring import score_case_relation

_MIN_LINK_CONFIDENCE_FOR_RELATION = 0.6
_ALLOWED_ALERT_SEVERITIES_FOR_RELATION = {"medium", "high", "critical"}
_CLUSTER_BRIDGE_PROMOTION_SCORE = 0.82
_STAGE_ORDER = {
    "recon": 1,
    "exploit": 2,
    "persistence": 3,
    "command_execution": 4,
    "lateral_prep": 5,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_case_contexts(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        select case_id, current_stage, coalesce(canonical_case_id, case_id) as canonical_case_id, merge_state, status
        from cases
        where status in ('open', 'investigating', 'observing')
        """
    ).fetchall()
    contexts: list[dict[str, Any]] = []
    for row in rows:
        case_id = row["case_id"]
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
            where case_alert_links.case_id = ? and case_alert_links.is_active = 1
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


def _apply_cluster_merge(conn: sqlite3.Connection, *, run_id: str, case_ids: list[str]) -> dict[str, Any]:
    canonical_case_id = reselect_cluster_canonical_case(conn, case_ids, run_id=run_id)
    now = _now_iso()
    previous_rows = {
        row["case_id"]: dict(row)
        for row in conn.execute(
            """
            select case_id, canonical_case_id, merged_into_case_id, merge_state
            from cases
            where case_id in ({})
            """.format(", ".join("?" for _ in case_ids)),
            tuple(case_ids),
        ).fetchall()
    }

    changed_case_ids: list[str] = []
    for case_id in case_ids:
        if case_id == canonical_case_id:
            canonical_target = case_id
            merged_into_target = None
            merge_state_target = "standalone"
        else:
            canonical_target = canonical_case_id
            merged_into_target = canonical_case_id
            merge_state_target = "merged"
        before = previous_rows.get(case_id)
        if (
            before is not None
            and before.get("canonical_case_id") == canonical_target
            and before.get("merged_into_case_id") == merged_into_target
            and before.get("merge_state") == merge_state_target
        ):
            continue
        conn.execute(
            """
            update cases
            set canonical_case_id = ?, merged_into_case_id = ?, merge_state = ?, merge_updated_at = ?
            where case_id = ?
            """,
            (canonical_target, merged_into_target, merge_state_target, now, case_id),
        )
        changed_case_ids.append(case_id)

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
            json.dumps({"changed_case_ids": changed_case_ids}, ensure_ascii=False),
        ),
    )
    return {"event_created": True, "canonical_case_id": canonical_case_id, "affected_case_ids": case_ids}


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
        relation = upsert_case_relation_candidate(
            conn,
            run_id,
            left_context["case_id"],
            right_context["case_id"],
            score.total,
            reason,
            score.supporting_alert_ids,
            score.supporting_evidence_ids,
        )
        relation_updates.append(relation)

    promoted_relations = _promote_cluster_bridge_relations(
        conn,
        run_id=run_id,
        case_context_by_id=case_context_by_id,
    )
    confirmed_relations = list_confirmed_case_relations(conn)
    clusters = _build_confirmed_clusters(confirmed_relations)
    merge_events: list[dict[str, Any]] = []
    for cluster in clusters:
        applied = _apply_cluster_merge(conn, run_id=run_id, case_ids=cluster)
        if applied["event_created"]:
            merge_events.append(applied)

    return {
        "run_id": run_id,
        "scored_relation_pairs": len(relation_updates),
        "promoted_relations_count": len(promoted_relations),
        "confirmed_relations_count": len(confirmed_relations),
        "merge_events_count": len(merge_events),
    }
