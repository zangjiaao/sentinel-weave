from __future__ import annotations

from datetime import datetime, timezone
import sqlite3
from typing import Any
from uuid import uuid4


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_observations(conn: sqlite3.Connection, case_actor_id: str) -> list[dict]:
    rows = conn.execute(
        """
        select observation_id, case_actor_id, observation_type, observation_key, observation_value,
               confidence, first_seen_at, last_seen_at, source_count, created_at, updated_at
        from case_actor_observations
        where case_actor_id = ?
        order by observation_type asc, observation_key asc
        """,
        (case_actor_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def _load_links(conn: sqlite3.Connection, case_actor_id: str) -> list[dict]:
    rows = conn.execute(
        """
        select link_id, case_actor_id, target_type, target_id, link_confidence, link_reason, linked_at
        from case_actor_links
        where case_actor_id = ?
        order by linked_at asc
        """,
        (case_actor_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def upsert_case_actor_profile(conn: sqlite3.Connection, profile: dict[str, Any]) -> dict:
    now = _now_iso()
    if profile.get("is_primary"):
        conn.execute(
            """
            update case_actor_profiles
            set is_primary = 0, updated_at = ?
            where case_id = ? and case_actor_id != ?
            """,
            (now, profile["case_id"], profile["case_actor_id"]),
        )
    conn.execute(
        """
        insert into case_actor_profiles (
          case_actor_id, case_id, label, status, profile_confidence, risk_level,
          is_primary, current_stage, first_seen_at, last_seen_at, summary, created_at, updated_at
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        on conflict(case_actor_id) do update set
          case_id=excluded.case_id,
          label=excluded.label,
          status=excluded.status,
          profile_confidence=excluded.profile_confidence,
          risk_level=excluded.risk_level,
          is_primary=excluded.is_primary,
          current_stage=excluded.current_stage,
          first_seen_at=excluded.first_seen_at,
          last_seen_at=excluded.last_seen_at,
          summary=excluded.summary,
          updated_at=excluded.updated_at
        """,
        (
            profile["case_actor_id"],
            profile["case_id"],
            profile["label"],
            profile["status"],
            profile["profile_confidence"],
            profile["risk_level"],
            1 if profile.get("is_primary") else 0,
            profile["current_stage"],
            profile.get("first_seen_at"),
            profile.get("last_seen_at"),
            profile["summary"],
            now,
            now,
        ),
    )
    saved = load_case_actor_profile(conn, profile["case_actor_id"])
    if saved is None:
        raise RuntimeError("case actor profile upsert failed")
    return saved


def add_case_actor_observation(conn: sqlite3.Connection, observation: dict[str, Any]) -> dict:
    now = _now_iso()
    observation_id = observation.get("observation_id") or f"caobs_{uuid4().hex[:12]}"
    conn.execute(
        """
        insert into case_actor_observations (
          observation_id, case_actor_id, observation_type, observation_key, observation_value,
          confidence, first_seen_at, last_seen_at, source_count, created_at, updated_at
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        on conflict(case_actor_id, observation_type, observation_key) do update set
          observation_value=excluded.observation_value,
          confidence=max(case_actor_observations.confidence, excluded.confidence),
          first_seen_at=coalesce(case_actor_observations.first_seen_at, excluded.first_seen_at),
          last_seen_at=coalesce(excluded.last_seen_at, case_actor_observations.last_seen_at),
          source_count=case_actor_observations.source_count + excluded.source_count,
          updated_at=excluded.updated_at
        """,
        (
            observation_id,
            observation["case_actor_id"],
            observation["observation_type"],
            observation["observation_key"],
            observation["observation_value"],
            observation["confidence"],
            observation.get("first_seen_at"),
            observation.get("last_seen_at"),
            observation.get("source_count", 1),
            now,
            now,
        ),
    )
    row = conn.execute(
        """
        select observation_id, case_actor_id, observation_type, observation_key, observation_value,
               confidence, first_seen_at, last_seen_at, source_count, created_at, updated_at
        from case_actor_observations
        where case_actor_id = ? and observation_type = ? and observation_key = ?
        """,
        (observation["case_actor_id"], observation["observation_type"], observation["observation_key"]),
    ).fetchone()
    return dict(row)


def add_case_actor_link(conn: sqlite3.Connection, link: dict[str, Any]) -> dict:
    link_id = link.get("link_id") or f"calink_{uuid4().hex[:12]}"
    linked_at = link.get("linked_at") or _now_iso()
    conn.execute(
        """
        insert into case_actor_links (
          link_id, case_actor_id, target_type, target_id, link_confidence, link_reason, linked_at
        ) values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            link_id,
            link["case_actor_id"],
            link["target_type"],
            link["target_id"],
            link["link_confidence"],
            link["link_reason"],
            linked_at,
        ),
    )
    return {
        "link_id": link_id,
        "case_actor_id": link["case_actor_id"],
        "target_type": link["target_type"],
        "target_id": link["target_id"],
        "link_confidence": link["link_confidence"],
        "link_reason": link["link_reason"],
        "linked_at": linked_at,
    }


def load_case_actor_profile(conn: sqlite3.Connection, case_actor_id: str) -> dict | None:
    row = conn.execute(
        """
        select case_actor_id, case_id, label, status, profile_confidence, risk_level,
               is_primary, current_stage, first_seen_at, last_seen_at, summary, created_at, updated_at
        from case_actor_profiles
        where case_actor_id = ?
        """,
        (case_actor_id,),
    ).fetchone()
    if row is None:
        return None
    profile = dict(row)
    profile["is_primary"] = bool(profile["is_primary"])
    profile["observations"] = _load_observations(conn, case_actor_id)
    profile["links"] = _load_links(conn, case_actor_id)
    return profile


def list_case_actor_profiles(conn: sqlite3.Connection, case_id: str) -> list[dict]:
    rows = conn.execute(
        """
        select case_actor_id
        from case_actor_profiles
        where case_id = ?
        order by is_primary desc, updated_at desc
        """,
        (case_id,),
    ).fetchall()
    return [
        profile
        for row in rows
        if (profile := load_case_actor_profile(conn, row["case_actor_id"])) is not None
    ]


def load_case_actor_candidate_contexts(
    conn: sqlite3.Connection,
    *,
    case_id: str,
    alert_id: str,
) -> list[dict]:
    alert = conn.execute(
        """
        select alert_id, occurred_at, title, severity, attack_stage, src_ip, dst_ip, asset_id
        from alerts
        where alert_id = ?
        """,
        (alert_id,),
    ).fetchone()
    if alert is None:
        return []
    profiles = list_case_actor_profiles(conn, case_id)
    contexts: list[dict] = []
    for profile in profiles:
        contexts.append(
            {
                "case_id": case_id,
                "target_alert": dict(alert),
                "profile": profile,
                "observations": profile["observations"],
                "links": profile["links"],
            }
        )
    return contexts
