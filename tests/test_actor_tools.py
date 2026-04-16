from security_analyst_agent.db import create_schema
from security_analyst_agent.repositories.actors import (
    add_case_actor_link,
    add_case_actor_observation,
    list_case_actor_profiles,
    load_case_actor_candidate_contexts,
    load_case_actor_profile,
    upsert_case_actor_profile,
)
from security_analyst_agent.services.case_actor_scoring import score_case_actor_candidate
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


def test_actor_profile_tables_exist(db_conn) -> None:
    create_schema(db_conn)

    tables = {
        row["name"]
        for row in db_conn.execute("select name from sqlite_master where type = 'table'").fetchall()
    }

    assert "case_actor_profiles" in tables
    assert "case_actor_observations" in tables
    assert "case_actor_links" in tables
    assert "attacker_profiles" in tables
    assert "case_actor_profile_links" in tables


def test_case_actor_profiles_table_shape(db_conn) -> None:
    create_schema(db_conn)

    columns = {
        row["name"]
        for row in db_conn.execute("pragma table_info(case_actor_profiles)").fetchall()
    }

    assert {
        "case_actor_id",
        "case_id",
        "label",
        "status",
        "profile_confidence",
        "risk_level",
        "is_primary",
        "current_stage",
        "first_seen_at",
        "last_seen_at",
        "summary",
        "created_at",
        "updated_at",
    }.issubset(columns)


def test_case_actor_repository_round_trips_profile_observation_and_link(db_conn) -> None:
    profile = upsert_case_actor_profile(
        db_conn,
        {
            "case_actor_id": "cactor_demo_001",
            "case_id": "case_demo_001",
            "label": "case demo actor",
            "status": "active",
            "profile_confidence": 0.86,
            "risk_level": "high",
            "is_primary": True,
            "current_stage": "command_execution",
            "first_seen_at": "2026-04-10T09:10:00+08:00",
            "last_seen_at": "2026-04-12T11:03:00+08:00",
            "summary": "multi-ip actor in demo case",
        },
    )
    observation = add_case_actor_observation(
        db_conn,
        {
            "case_actor_id": "cactor_demo_001",
            "observation_type": "src_ip",
            "observation_key": "198.51.100.77",
            "observation_value": "198.51.100.77",
            "confidence": 0.9,
            "first_seen_at": "2026-04-12T11:03:00+08:00",
            "last_seen_at": "2026-04-12T11:03:00+08:00",
            "source_count": 1,
        },
    )
    link = add_case_actor_link(
        db_conn,
        {
            "case_actor_id": "cactor_demo_001",
            "target_type": "alert",
            "target_id": "alt_day3_shell_01",
            "link_confidence": 0.9,
            "link_reason": "new IP connected existing webshell",
        },
    )
    db_conn.commit()

    loaded = load_case_actor_profile(db_conn, "cactor_demo_001")
    listed = list_case_actor_profiles(db_conn, "case_demo_001")

    assert profile["case_actor_id"] == "cactor_demo_001"
    assert observation["observation_type"] == "src_ip"
    assert link["target_id"] == "alt_day3_shell_01"
    assert loaded is not None
    assert loaded["observations"][0]["observation_key"] == "198.51.100.77"
    assert listed[0]["case_actor_id"] == "cactor_demo_001"


def test_case_actor_candidate_links_new_ip_to_existing_webshell_actor(db_conn) -> None:
    upsert_case_actor_profile(
        db_conn,
        {
            "case_actor_id": "cactor_demo_002",
            "case_id": "case_demo_001",
            "label": "webshell operator",
            "status": "active",
            "profile_confidence": 0.9,
            "risk_level": "high",
            "is_primary": True,
            "current_stage": "persistence",
            "first_seen_at": "2026-04-11T14:20:00+08:00",
            "last_seen_at": "2026-04-11T14:20:00+08:00",
            "summary": "actor that established webshell persistence",
        },
    )
    add_case_actor_observation(
        db_conn,
        {
            "case_actor_id": "cactor_demo_002",
            "observation_type": "src_ip",
            "observation_key": "198.51.100.23",
            "observation_value": "198.51.100.23",
            "confidence": 0.93,
            "first_seen_at": "2026-04-11T14:20:00+08:00",
            "last_seen_at": "2026-04-11T14:20:00+08:00",
            "source_count": 1,
        },
    )

    contexts = load_case_actor_candidate_contexts(
        db_conn,
        case_id="case_demo_001",
        alert_id="alt_day3_shell_01",
    )
    candidate = score_case_actor_candidate(contexts[0])

    assert candidate["case_actor_id"] == "cactor_demo_002"
    assert candidate["recommended_action"] in {"link_existing_case_actor", "candidate_actor_relation"}
    assert candidate["relation_score"] >= 0.45
    assert any(item["factor_type"] == "behavior_continuity" for item in candidate["positive_factors"])


def test_actor_case_tools_create_profile_and_list_it(db_conn) -> None:
    result = actor_case_upsert(
        db_conn,
        {
            "case_actor_id": "cactor_tool_001",
            "case_id": "case_demo_001",
            "label": "primary tool actor",
            "status": "active",
            "profile_confidence": 0.9,
            "risk_level": "high",
            "is_primary": True,
            "current_stage": "persistence",
            "first_seen_at": "2026-04-11T14:20:00+08:00",
            "last_seen_at": "2026-04-11T14:20:00+08:00",
            "summary": "tool-created actor",
        },
    )
    observation = actor_case_add_observation(
        db_conn,
        {
            "case_actor_id": "cactor_tool_001",
            "observation_type": "src_ip",
            "observation_key": "198.51.100.23",
            "observation_value": "198.51.100.23",
            "confidence": 0.93,
            "first_seen_at": "2026-04-11T14:20:00+08:00",
            "last_seen_at": "2026-04-11T14:20:00+08:00",
            "source_count": 1,
        },
    )
    link = actor_case_link(
        db_conn,
        {
            "case_actor_id": "cactor_tool_001",
            "target_type": "alert",
            "target_id": "alt_day2_webshell_01",
            "link_confidence": 0.9,
            "link_reason": "webshell write belongs to actor",
        },
    )
    listed = actor_case_list(db_conn, {"case_id": "case_demo_001"})
    loaded = actor_case_get(db_conn, {"case_actor_id": "cactor_tool_001"})

    assert result["ok"] is True
    assert observation["ok"] is True
    assert link["ok"] is True
    assert listed["data"]["actors"][0]["case_actor_id"] == "cactor_tool_001"
    assert loaded["data"]["actor"]["observations"][0]["observation_key"] == "198.51.100.23"


def test_actor_case_find_candidates_returns_scored_actor(db_conn) -> None:
    actor_case_upsert(
        db_conn,
        {
            "case_actor_id": "cactor_tool_002",
            "case_id": "case_demo_001",
            "label": "candidate actor",
            "status": "active",
            "profile_confidence": 0.9,
            "risk_level": "high",
            "is_primary": True,
            "current_stage": "persistence",
            "first_seen_at": "2026-04-11T14:20:00+08:00",
            "last_seen_at": "2026-04-11T14:20:00+08:00",
            "summary": "candidate actor",
        },
    )
    result = actor_case_find_candidates(
        db_conn,
        {"case_id": "case_demo_001", "alert_id": "alt_day3_shell_01", "limit": 3},
    )

    assert result["ok"] is True
    assert result["data"]["candidates"][0]["case_actor_id"] == "cactor_tool_002"


def test_actor_case_find_candidates_infers_case_from_alert_when_case_id_empty(db_conn) -> None:
    actor_case_upsert(
        db_conn,
        {
            "case_actor_id": "cactor_tool_002_fallback",
            "case_id": "case_demo_001",
            "label": "candidate actor fallback",
            "status": "active",
            "profile_confidence": 0.9,
            "risk_level": "high",
            "is_primary": True,
            "current_stage": "persistence",
            "first_seen_at": "2026-04-11T14:20:00+08:00",
            "last_seen_at": "2026-04-11T14:20:00+08:00",
            "summary": "candidate actor fallback",
        },
    )
    result = actor_case_find_candidates(
        db_conn,
        {"case_id": "", "alert_id": "alt_day3_shell_01", "limit": 3},
    )

    assert result["ok"] is True
    assert "case_id_inferred_from_alert" in result["warnings"]
    assert result["refs"]["case_ids"] == ["case_demo_001"]


def test_actor_case_batch_tools_write_multiple_items(db_conn) -> None:
    actor_case_upsert(
        db_conn,
        {
            "case_actor_id": "cactor_batch_001",
            "case_id": "case_demo_001",
            "label": "batch actor",
            "status": "active",
            "profile_confidence": 0.9,
            "risk_level": "high",
            "is_primary": True,
            "current_stage": "command_execution",
            "first_seen_at": "2026-04-11T14:20:00+08:00",
            "last_seen_at": "2026-04-11T14:20:00+08:00",
            "summary": "batch actor profile",
        },
    )
    obs_result = actor_case_add_observation_batch(
        db_conn,
        {
            "items": [
                {
                    "case_actor_id": "cactor_batch_001",
                    "observation_type": "src_ip",
                    "observation_key": "198.51.100.23",
                    "observation_value": "198.51.100.23",
                    "confidence": 0.93,
                },
                {
                    "case_actor_id": "cactor_batch_001",
                    "observation_type": "asset_id",
                    "observation_key": "asset_api_prod",
                    "observation_value": "asset_api_prod",
                    "confidence": 0.8,
                },
            ]
        },
    )
    link_result = actor_case_link_batch(
        db_conn,
        {
            "items": [
                {
                    "case_actor_id": "cactor_batch_001",
                    "target_type": "alert",
                    "target_id": "alt_day2_webshell_01",
                    "link_confidence": 0.9,
                    "link_reason": "batch-link-1",
                },
                {
                    "case_actor_id": "cactor_batch_001",
                    "target_type": "alert",
                    "target_id": "alt_day3_shell_01",
                    "link_confidence": 0.88,
                    "link_reason": "batch-link-2",
                },
            ]
        },
    )

    assert obs_result["ok"] is True
    assert len(obs_result["data"]["observations"]) == 2
    assert obs_result["data"]["failures"] == []
    assert link_result["ok"] is True
    assert len(link_result["data"]["links"]) == 2
    assert link_result["data"]["failures"] == []
