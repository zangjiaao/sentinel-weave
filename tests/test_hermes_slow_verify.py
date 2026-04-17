from pathlib import Path
import subprocess
import sys

import pytest

from security_analyst_agent import hermes_slow_verify
from security_analyst_agent.db import connect_db, create_schema
from security_analyst_agent.hermes_slow_verify import (
    DEFAULT_FINALIZE_QUERY,
    HermesSlowVerificationError,
    _is_missing_header_error,
    _is_retryable_round_db_error,
    _run_chat_with_continue_fallback,
    _verify_final_db_state,
    _verify_chat_output,
    build_chat_command,
    load_integration_manifest,
    prepare_isolated_hermes_home,
    resolve_round_specs,
)


def test_load_integration_manifest_returns_expected_scenario() -> None:
    manifest = load_integration_manifest("hermes-slow-integration")

    assert manifest["scenario"] == "hermes-slow-integration"
    assert [item["round_id"] for item in manifest["rounds"]] == [
        "round_01_recon",
        "round_02_exploit",
        "round_03_new_ip",
        "round_04_lateral_prep",
        "round_05_silent_period",
        "round_06_reactivation",
    ]
    assert manifest["round_defaults"]["required_tool_names"][0] == "alert.fetch"
    assert manifest["round_defaults"]["max_tool_calls"] == 18


def test_resolve_round_specs_merges_defaults_and_round_overrides() -> None:
    manifest = {
        "round_defaults": {
            "query": "Run one patrol pass",
            "max_turns": 12,
            "required_tool_names": ["alert.fetch"],
            "required_any_tool_names": [["case.get", "case.timeline"]],
            "required_output_headers": ["## Patrol Action Summary"],
            "min_tool_calls": 2,
        },
        "rounds": [
            {"round_id": "round_01_recon"},
            {
                "round_id": "round_02_exploit",
                "max_turns": 18,
                "required_tool_names": ["alert.fetch", "alert.ack"],
            },
        ],
    }

    round_specs = resolve_round_specs(manifest)

    assert round_specs[0]["round_id"] == "round_01_recon"
    assert round_specs[0]["query"] == "Run one patrol pass"
    assert round_specs[0]["max_turns"] == 12
    assert round_specs[0]["required_tool_names"] == ["alert.fetch"]
    assert round_specs[1]["round_id"] == "round_02_exploit"
    assert round_specs[1]["max_turns"] == 18
    assert round_specs[1]["required_tool_names"] == ["alert.fetch", "alert.ack"]


def test_round_05_silent_period_keeps_default_output_contract() -> None:
    manifest = load_integration_manifest("hermes-slow-integration")

    round_specs = resolve_round_specs(manifest)
    round_05 = next(item for item in round_specs if item["round_id"] == "round_05_silent_period")

    assert round_05["required_output_headers"] == [
        "## Patrol Action Summary",
        "## Remaining Uncertainty",
        "## Memory Summary",
    ]
    assert "required_exact_output" not in round_05
    assert round_05["max_turns"] == 18


def test_verify_chat_output_accepts_exact_silent_marker(tmp_path: Path) -> None:
    round_spec = {
        "round_id": "round_05_silent_period",
        "required_output_headers": [
            "## Patrol Action Summary",
            "## Remaining Uncertainty",
            "## Memory Summary",
        ],
    }
    _verify_chat_output(chat_stdout="[SILENT]", round_spec=round_spec, artifact_dir=tmp_path)


def test_verify_chat_output_still_requires_headers_for_non_silent_output(tmp_path: Path) -> None:
    round_spec = {
        "round_id": "round_05_silent_period",
        "required_output_headers": [
            "## Patrol Action Summary",
            "## Remaining Uncertainty",
            "## Memory Summary",
        ],
    }
    with pytest.raises(HermesSlowVerificationError, match="missing output header"):
        _verify_chat_output(chat_stdout="No updates", round_spec=round_spec, artifact_dir=tmp_path)


def test_verify_chat_output_accepts_silent_marker_with_wrapper_text(tmp_path: Path) -> None:
    round_spec = {
        "round_id": "round_01_recon",
        "required_output_headers": [
            "## Patrol Action Summary",
            "## Remaining Uncertainty",
            "## Memory Summary",
        ],
    }
    wrapped_output = "╭─ ⚕ Hermes ─╮\n[SILENT]\n\nsession_id: test_001"
    _verify_chat_output(chat_stdout=wrapped_output, round_spec=round_spec, artifact_dir=tmp_path)


def test_load_integration_manifest_requires_zero_failed_tools_and_compromised_host() -> None:
    manifest = load_integration_manifest("hermes-slow-integration")

    final_assertions = manifest["final_assertions"]
    assert final_assertions["max_failed_tool_calls"] == 0
    assert final_assertions["min_case_assessments"] >= 1
    assert "case.upsert-batch" in final_assertions["required_tool_names"]
    assert {
        "entity_type": "asset",
        "entity_key": "asset_api_prod",
        "risk_level_at_least": "high",
        "verdict": "compromised_host",
    } in final_assertions["required_current_entities"]


def test_load_integration_manifest_uses_weak_guidance_without_forced_playbook() -> None:
    manifest = load_integration_manifest("hermes-slow-integration")

    assert manifest["skills"] == []
    query = manifest["round_defaults"]["query"]
    assert "attack chain" in query.lower() or "攻击链" in query
    assert "evidence" in query.lower() or "证据" in query
    assert "information is incomplete" in query.lower() or "信息不足" in query
    assert "exact case.upsert-batch schema keys" not in query
    assert "alert.detail-batch" not in query


def test_verify_final_db_state_fails_when_failed_tool_calls_exist(tmp_path: Path) -> None:
    db_path = tmp_path / "slow.db"
    conn = connect_db(db_path)
    create_schema(conn)
    conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at, finished_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "run_test_001",
            "mcp_auto",
            "success",
            "done",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:01:00+08:00",
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_ok_001",
            "2026-04-14T10:00:10+08:00",
            "run_test_001",
            "mcp",
            "alert.fetch",
            "{}",
            1,
            "ok",
            "{}",
            10,
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_fail_001",
            "2026-04-14T10:00:20+08:00",
            "run_test_001",
            "mcp",
            "assessment.upsert",
            "{}",
            0,
            "tool execution exception",
            "{}",
            12,
        ),
    )
    conn.commit()

    manifest = {
        "final_assertions": {
            "min_patrol_runs": 1,
            "min_tool_calls": 1,
            "required_tool_names": ["alert.fetch"],
            "required_any_tool_names": [],
            "min_entity_assessments": 0,
            "min_alert_decisions": 0,
            "max_failed_tool_calls": 0,
            "required_current_entities": [],
        }
    }
    with pytest.raises(HermesSlowVerificationError, match="failed tool calls"):
        _verify_final_db_state(conn, manifest=manifest, round_count=1)
    conn.close()


def test_verify_final_db_state_fails_when_tool_calls_exceed_max(tmp_path: Path) -> None:
    db_path = tmp_path / "slow_max_calls.db"
    conn = connect_db(db_path)
    create_schema(conn)
    conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at, finished_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "run_test_max_calls_001",
            "mcp_auto",
            "success",
            "done",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:01:00+08:00",
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_ok_max_001",
            "2026-04-14T10:00:10+08:00",
            "run_test_max_calls_001",
            "mcp",
            "alert.fetch",
            "{}",
            1,
            "ok",
            "{}",
            10,
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_ok_max_002",
            "2026-04-14T10:00:20+08:00",
            "run_test_max_calls_001",
            "mcp",
            "alert.ack",
            "{}",
            1,
            "ok",
            "{}",
            12,
        ),
    )
    conn.commit()

    manifest = {
        "final_assertions": {
            "min_patrol_runs": 1,
            "min_tool_calls": 1,
            "max_tool_calls": 1,
            "required_tool_names": ["alert.fetch"],
            "required_any_tool_names": [],
            "min_entity_assessments": 0,
            "min_alert_decisions": 0,
            "max_failed_tool_calls": 0,
            "required_current_entities": [],
        }
    }
    with pytest.raises(HermesSlowVerificationError, match="expected at most 1 tool calls"):
        _verify_final_db_state(conn, manifest=manifest, round_count=1)
    conn.close()


def test_verify_final_db_state_ignores_case_get_not_found_failures(tmp_path: Path) -> None:
    db_path = tmp_path / "slow.db"
    conn = connect_db(db_path)
    create_schema(conn)
    conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at, finished_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "run_test_001b",
            "mcp_auto",
            "success",
            "done",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:01:00+08:00",
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_ok_001b",
            "2026-04-14T10:00:10+08:00",
            "run_test_001b",
            "mcp",
            "alert.fetch",
            "{}",
            1,
            "ok",
            "{}",
            10,
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_fail_001b",
            "2026-04-14T10:00:20+08:00",
            "run_test_001b",
            "mcp",
            "case.get",
            "{\"case_id\":\"case_missing_001\"}",
            0,
            "未找到案件 case_missing_001",
            "{\"ok\":false,\"warnings\":[\"case_not_found:case_missing_001\"]}",
            12,
        ),
    )
    conn.commit()

    manifest = {
        "final_assertions": {
            "min_patrol_runs": 1,
            "min_tool_calls": 1,
            "required_tool_names": ["alert.fetch"],
            "required_any_tool_names": [],
            "min_entity_assessments": 0,
            "min_alert_decisions": 0,
            "max_failed_tool_calls": 0,
            "required_current_entities": [],
        }
    }
    summary = _verify_final_db_state(conn, manifest=manifest, round_count=1)
    assert summary["failed_tool_calls_count"] == 0
    conn.close()


def test_verify_final_db_state_ignores_actor_candidate_not_found_failures(tmp_path: Path) -> None:
    db_path = tmp_path / "slow.db"
    conn = connect_db(db_path)
    create_schema(conn)
    conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at, finished_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "run_test_001c",
            "mcp_auto",
            "success",
            "done",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:01:00+08:00",
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_ok_001c",
            "2026-04-14T10:00:10+08:00",
            "run_test_001c",
            "mcp",
            "alert.fetch",
            "{}",
            1,
            "ok",
            "{}",
            10,
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_fail_001c",
            "2026-04-14T10:00:20+08:00",
            "run_test_001c",
            "mcp",
            "actor.case-find-candidates",
            "{\"case_id\":\"\",\"alert_id\":\"alt_missing\"}",
            0,
            "未找到案件 ",
            "{\"ok\":false,\"warnings\":[\"case_not_found:\"]}",
            12,
        ),
    )
    conn.commit()

    manifest = {
        "final_assertions": {
            "min_patrol_runs": 1,
            "min_tool_calls": 1,
            "required_tool_names": ["alert.fetch"],
            "required_any_tool_names": [],
            "min_entity_assessments": 0,
            "min_alert_decisions": 0,
            "max_failed_tool_calls": 0,
            "required_current_entities": [],
        }
    }
    summary = _verify_final_db_state(conn, manifest=manifest, round_count=1)
    assert summary["failed_tool_calls_count"] == 0
    conn.close()


def test_verify_final_db_state_ignores_failed_tool_call_if_same_run_later_succeeds(tmp_path: Path) -> None:
    db_path = tmp_path / "slow.db"
    conn = connect_db(db_path)
    create_schema(conn)
    conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at, finished_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "run_test_retry_001",
            "mcp_auto",
            "success",
            "done",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:01:00+08:00",
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_ok_retry_fetch",
            "2026-04-14T10:00:10+08:00",
            "run_test_retry_001",
            "mcp",
            "alert.fetch",
            "{}",
            1,
            "ok",
            "{}",
            10,
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_fail_retry_001",
            "2026-04-14T10:00:20+08:00",
            "run_test_retry_001",
            "mcp",
            "actor.case-upsert",
            "{}",
            0,
            "tool execution exception",
            "{}",
            12,
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_ok_retry_001",
            "2026-04-14T10:00:30+08:00",
            "run_test_retry_001",
            "mcp",
            "actor.case-upsert",
            "{\"payload\":{\"case_actor_id\":\"actor_demo\"}}",
            1,
            "ok",
            "{}",
            14,
        ),
    )
    conn.commit()

    manifest = {
        "final_assertions": {
            "min_patrol_runs": 1,
            "min_tool_calls": 1,
            "required_tool_names": ["alert.fetch"],
            "required_any_tool_names": [],
            "min_entity_assessments": 0,
            "min_alert_decisions": 0,
            "max_failed_tool_calls": 0,
            "required_current_entities": [],
        }
    }
    summary = _verify_final_db_state(conn, manifest=manifest, round_count=1)
    assert summary["failed_tool_calls_count"] == 0
    conn.close()


def test_verify_final_db_state_fails_when_required_entity_missing(tmp_path: Path) -> None:
    db_path = tmp_path / "slow.db"
    conn = connect_db(db_path)
    create_schema(conn)
    conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at, finished_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "run_test_002",
            "mcp_auto",
            "success",
            "done",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:01:00+08:00",
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_ok_002",
            "2026-04-14T10:00:10+08:00",
            "run_test_002",
            "mcp",
            "alert.fetch",
            "{}",
            1,
            "ok",
            "{}",
            10,
        ),
    )
    conn.commit()

    manifest = {
        "final_assertions": {
            "min_patrol_runs": 1,
            "min_tool_calls": 1,
            "required_tool_names": ["alert.fetch"],
            "required_any_tool_names": [],
            "min_entity_assessments": 0,
            "min_alert_decisions": 0,
            "max_failed_tool_calls": 0,
            "required_current_entities": [
                {
                    "entity_type": "asset",
                    "entity_key": "203.0.113.10",
                    "risk_level": "high",
                    "verdict": "compromised_host",
                }
            ],
        }
    }
    with pytest.raises(HermesSlowVerificationError, match="required current entity"):
        _verify_final_db_state(conn, manifest=manifest, round_count=1)
    conn.close()


def test_verify_final_db_state_matches_required_entity_without_related_case_id(tmp_path: Path) -> None:
    db_path = tmp_path / "slow.db"
    conn = connect_db(db_path)
    create_schema(conn)
    conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at, finished_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "run_test_003",
            "mcp_auto",
            "success",
            "done",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:01:00+08:00",
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_ok_003",
            "2026-04-14T10:00:10+08:00",
            "run_test_003",
            "mcp",
            "alert.fetch",
            "{}",
            1,
            "ok",
            "{}",
            10,
        ),
    )
    conn.execute(
        """
        insert into entity_assessments (
          assessment_id, occurred_at, run_id, entity_type, entity_key, entity_label,
          related_case_id, risk_level, assessment_confidence, verdict, reason_summary,
          supporting_alert_ids_json, supporting_evidence_ids_json, first_seen_at, last_seen_at,
          analysis_cutoff_at, is_current
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "eass_test_003",
            "2026-04-14T10:00:20+08:00",
            "run_test_003",
            "asset",
            "asset_api_prod",
            "asset_api_prod",
            "case_demo_001",
            "high",
            0.95,
            "compromised_host",
            "webshell evidence",
            "[]",
            "[]",
            None,
            None,
            "2026-04-14T10:00:00+08:00",
            1,
        ),
    )
    conn.commit()

    manifest = {
        "final_assertions": {
            "min_patrol_runs": 1,
            "min_tool_calls": 1,
            "required_tool_names": ["alert.fetch"],
            "required_any_tool_names": [],
            "min_entity_assessments": 1,
            "min_alert_decisions": 0,
            "max_failed_tool_calls": 0,
            "required_current_entities": [
                {
                    "entity_type": "asset",
                    "entity_key": "asset_api_prod",
                    "risk_level": "high",
                    "verdict": "compromised_host",
                }
            ],
        }
    }
    summary = _verify_final_db_state(conn, manifest=manifest, round_count=1)
    assert summary["entity_assessments_count"] == 1
    conn.close()


def test_verify_final_db_state_matches_required_entity_with_minimum_risk_level(tmp_path: Path) -> None:
    db_path = tmp_path / "slow.db"
    conn = connect_db(db_path)
    create_schema(conn)
    conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at, finished_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "run_test_003b",
            "mcp_auto",
            "success",
            "done",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:01:00+08:00",
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_ok_003b",
            "2026-04-14T10:00:10+08:00",
            "run_test_003b",
            "mcp",
            "alert.fetch",
            "{}",
            1,
            "ok",
            "{}",
            10,
        ),
    )
    conn.execute(
        """
        insert into entity_assessments (
          assessment_id, occurred_at, run_id, entity_type, entity_key, entity_label,
          related_case_id, risk_level, assessment_confidence, verdict, reason_summary,
          supporting_alert_ids_json, supporting_evidence_ids_json, first_seen_at, last_seen_at,
          analysis_cutoff_at, is_current
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "eass_test_003b",
            "2026-04-14T10:00:20+08:00",
            "run_test_003b",
            "asset",
            "asset_api_prod",
            "asset_api_prod",
            "case_demo_001",
            "critical",
            0.95,
            "compromised_host",
            "critical compromise evidence",
            "[]",
            "[]",
            None,
            None,
            "2026-04-14T10:00:00+08:00",
            1,
        ),
    )
    conn.commit()

    manifest = {
        "final_assertions": {
            "min_patrol_runs": 1,
            "min_tool_calls": 1,
            "required_tool_names": ["alert.fetch"],
            "required_any_tool_names": [],
            "min_entity_assessments": 1,
            "min_alert_decisions": 0,
            "max_failed_tool_calls": 0,
            "required_current_entities": [
                {
                    "entity_type": "asset",
                    "entity_key": "asset_api_prod",
                    "risk_level_at_least": "high",
                    "verdict": "compromised_host",
                }
            ],
        }
    }
    summary = _verify_final_db_state(conn, manifest=manifest, round_count=1)
    assert summary["entity_assessments_count"] == 1
    conn.close()


def test_verify_final_db_state_checks_case_convergence(tmp_path: Path) -> None:
    db_path = tmp_path / "slow.db"
    conn = connect_db(db_path)
    create_schema(conn)
    conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at, finished_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "run_conv_verify_001",
            "mcp_auto",
            "success",
            "done",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:01:00+08:00",
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_conv_verify_001",
            "2026-04-14T10:00:10+08:00",
            "run_conv_verify_001",
            "mcp",
            "alert.fetch",
            "{}",
            1,
            "ok",
            "{}",
            10,
        ),
    )
    conn.execute(
        """
        insert into cases (
          case_id, title, status, overall_severity, current_stage, primary_actor_id,
          canonical_case_id, merged_into_case_id, merge_state, merge_updated_at
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "case_conv_main",
            "main",
            "open",
            "high",
            "persistence",
            "actor_conv",
            "case_conv_main",
            None,
            "standalone",
            "2026-04-14T10:00:30+08:00",
        ),
    )
    conn.execute(
        """
        insert into cases (
          case_id, title, status, overall_severity, current_stage, primary_actor_id,
          canonical_case_id, merged_into_case_id, merge_state, merge_updated_at
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "case_conv_child",
            "child",
            "open",
            "medium",
            "command_execution",
            "actor_conv_child",
            "case_conv_main",
            "case_conv_main",
            "merged",
            "2026-04-14T10:00:30+08:00",
        ),
    )
    conn.commit()

    manifest = {
        "final_assertions": {
            "min_patrol_runs": 1,
            "min_tool_calls": 1,
            "required_tool_names": ["alert.fetch"],
            "required_any_tool_names": [],
            "min_entity_assessments": 0,
            "min_alert_decisions": 0,
            "max_failed_tool_calls": 0,
            "required_current_entities": [],
            "min_converged_case_clusters": 1,
        }
    }
    summary = _verify_final_db_state(conn, manifest=manifest, round_count=1)
    assert summary["converged_case_clusters_count"] >= 1
    conn.close()


def test_verify_final_db_state_accepts_single_chain_case_without_cluster(tmp_path: Path) -> None:
    db_path = tmp_path / "slow.db"
    conn = connect_db(db_path)
    create_schema(conn)
    conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at, finished_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "run_chain_verify_001",
            "mcp_auto",
            "success",
            "done",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:01:00+08:00",
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_chain_verify_001",
            "2026-04-14T10:00:10+08:00",
            "run_chain_verify_001",
            "mcp",
            "alert.fetch",
            "{}",
            1,
            "ok",
            "{}",
            10,
        ),
    )
    conn.execute(
        """
        insert into cases (
          case_id, title, status, overall_severity, current_stage, primary_actor_id,
          canonical_case_id, merged_into_case_id, merge_state, merge_updated_at
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "case_chain_main",
            "chain main",
            "active",
            "critical",
            "lateral_prep",
            "actor_chain_001",
            "case_chain_main",
            None,
            "standalone",
            "2026-04-14T10:00:30+08:00",
        ),
    )
    for alert_id, occurred_at, stage in [
        ("alt_chain_verify_001", "2026-04-14T09:55:00+08:00", "persistence"),
        ("alt_chain_verify_002", "2026-04-14T09:56:00+08:00", "command_execution"),
        ("alt_chain_verify_003", "2026-04-14T09:57:00+08:00", "lateral_prep"),
    ]:
        conn.execute(
            """
            insert into alerts (alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                occurred_at,
                "chain verify",
                "triaged",
                "high",
                stage,
                "198.51.100.23",
                "203.0.113.10",
                "asset_api_prod",
            ),
        )
        conn.execute(
            """
            insert into case_alert_links (case_id, alert_id, linked_at, confidence, reason, is_active)
            values (?, ?, ?, ?, ?, 1)
            """,
            (
                "case_chain_main",
                alert_id,
                occurred_at,
                0.9,
                "single chain continuity",
            ),
        )
    conn.commit()

    manifest = {
        "final_assertions": {
            "min_patrol_runs": 1,
            "min_tool_calls": 1,
            "required_tool_names": ["alert.fetch"],
            "required_any_tool_names": [],
            "min_entity_assessments": 0,
            "min_alert_decisions": 0,
            "max_failed_tool_calls": 0,
            "required_current_entities": [],
            "min_converged_case_clusters": 1,
            "allow_single_chain_case_fallback": True,
            "min_single_chain_cases": 1,
            "single_chain_min_distinct_stages": 3,
            "single_chain_min_alerts": 3,
        }
    }
    summary = _verify_final_db_state(conn, manifest=manifest, round_count=1)
    assert summary["converged_case_clusters_count"] == 0
    assert summary["single_chain_case_candidates_count"] == 1
    conn.close()


def test_verify_final_db_state_fails_when_case_assessments_missing(tmp_path: Path) -> None:
    db_path = tmp_path / "slow.db"
    conn = connect_db(db_path)
    create_schema(conn)
    conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at, finished_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "run_test_004",
            "mcp_auto",
            "success",
            "done",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:01:00+08:00",
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_ok_004",
            "2026-04-14T10:00:10+08:00",
            "run_test_004",
            "mcp",
            "alert.fetch",
            "{}",
            1,
            "ok",
            "{}",
            10,
        ),
    )
    conn.commit()

    manifest = {
        "final_assertions": {
            "min_patrol_runs": 1,
            "min_tool_calls": 1,
            "required_tool_names": ["alert.fetch"],
            "required_any_tool_names": [],
            "max_failed_tool_calls": 0,
            "min_entity_assessments": 0,
            "min_alert_decisions": 0,
            "min_case_assessments": 1,
            "required_current_entities": [],
        }
    }
    with pytest.raises(HermesSlowVerificationError, match="case assessments"):
        _verify_final_db_state(conn, manifest=manifest, round_count=1)
    conn.close()


def test_verify_final_db_state_fails_when_primary_case_actor_missing_for_single_chain(tmp_path: Path) -> None:
    db_path = tmp_path / "slow.db"
    conn = connect_db(db_path)
    create_schema(conn)
    conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at, finished_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "run_actor_verify_001",
            "mcp_auto",
            "success",
            "done",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:01:00+08:00",
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_actor_verify_001",
            "2026-04-14T10:00:10+08:00",
            "run_actor_verify_001",
            "mcp",
            "alert.fetch",
            "{}",
            1,
            "ok",
            "{}",
            10,
        ),
    )
    conn.execute(
        """
        insert into cases (case_id, title, status, overall_severity, current_stage, primary_actor_id)
        values (?, ?, ?, ?, ?, ?)
        """,
        ("case_actor_verify_001", "case", "open", "high", "persistence", "198.51.100.23"),
    )
    conn.execute(
        """
        insert into alerts (alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "alt_case_actor_verify_001",
            "2026-04-14T09:55:00+08:00",
            "verify single chain alert",
            "triaged",
            "high",
            "persistence",
            "198.51.100.23",
            "203.0.113.10",
            "asset_api_prod",
        ),
    )
    conn.execute(
        """
        insert into case_alert_links (case_id, alert_id, linked_at, confidence, reason, is_active)
        values (?, ?, ?, ?, ?, 1)
        """,
        (
            "case_actor_verify_001",
            "alt_case_actor_verify_001",
            "2026-04-14T09:55:00+08:00",
            0.9,
            "single chain seed",
        ),
    )
    conn.commit()

    manifest = {
        "final_assertions": {
            "required_single_chain_alert_ids": ["alt_case_actor_verify_001"],
            "require_primary_case_actor_for_single_chain": True,
        }
    }
    with pytest.raises(HermesSlowVerificationError, match="primary case actor missing"):
        _verify_final_db_state(conn, manifest=manifest, round_count=1)
    conn.close()


def test_verify_final_db_state_fails_when_high_signal_alert_missing_actor_coverage(tmp_path: Path) -> None:
    db_path = tmp_path / "slow.db"
    conn = connect_db(db_path)
    create_schema(conn)
    conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at, finished_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "run_actor_cov_001",
            "mcp_auto",
            "success",
            "done",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:01:00+08:00",
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_actor_cov_001",
            "2026-04-14T10:00:10+08:00",
            "run_actor_cov_001",
            "mcp",
            "alert.fetch",
            "{}",
            1,
            "ok",
            "{}",
            10,
        ),
    )
    conn.execute(
        """
        insert into cases (case_id, title, status, overall_severity, current_stage, primary_actor_id)
        values (?, ?, ?, ?, ?, ?)
        """,
        ("case_actor_cov_001", "case", "open", "high", "command_execution", None),
    )
    conn.execute(
        """
        insert into alerts (alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "alt_actor_cov_001",
            "2026-04-14T09:55:00+08:00",
            "verify actor coverage",
            "triaged",
            "high",
            "command_execution",
            "198.51.100.91",
            "203.0.113.10",
            "asset_api_prod",
        ),
    )
    conn.execute(
        """
        insert into case_alert_links (case_id, alert_id, linked_at, confidence, reason, is_active)
        values (?, ?, ?, ?, ?, 1)
        """,
        (
            "case_actor_cov_001",
            "alt_actor_cov_001",
            "2026-04-14T09:55:00+08:00",
            0.9,
            "coverage seed",
        ),
    )
    conn.commit()

    manifest = {
        "final_assertions": {
            "required_tool_names": ["alert.fetch"],
            "required_any_tool_names": [],
            "require_actor_coverage_for_high_signal_alerts": True,
        }
    }
    with pytest.raises(HermesSlowVerificationError, match="missing actor coverage"):
        _verify_final_db_state(conn, manifest=manifest, round_count=1)
    conn.close()


def test_verify_final_db_state_fails_when_primary_actor_missing_for_high_signal_cases(tmp_path: Path) -> None:
    db_path = tmp_path / "slow.db"
    conn = connect_db(db_path)
    create_schema(conn)
    conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at, finished_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "run_actor_primary_001",
            "mcp_auto",
            "success",
            "done",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:01:00+08:00",
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_actor_primary_001",
            "2026-04-14T10:00:10+08:00",
            "run_actor_primary_001",
            "mcp",
            "alert.fetch",
            "{}",
            1,
            "ok",
            "{}",
            10,
        ),
    )
    conn.execute(
        """
        insert into cases (case_id, title, status, overall_severity, current_stage, primary_actor_id)
        values (?, ?, ?, ?, ?, ?)
        """,
        ("case_actor_primary_001", "case", "open", "high", "command_execution", None),
    )
    conn.execute(
        """
        insert into alerts (alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "alt_actor_primary_001",
            "2026-04-14T09:55:00+08:00",
            "verify primary actor",
            "triaged",
            "high",
            "command_execution",
            "198.51.100.91",
            "203.0.113.10",
            "asset_api_prod",
        ),
    )
    conn.execute(
        """
        insert into case_alert_links (case_id, alert_id, linked_at, confidence, reason, is_active)
        values (?, ?, ?, ?, ?, 1)
        """,
        (
            "case_actor_primary_001",
            "alt_actor_primary_001",
            "2026-04-14T09:55:00+08:00",
            0.9,
            "primary seed",
        ),
    )
    conn.execute(
        """
        insert into case_actor_profiles (
          case_actor_id, case_id, label, status, profile_confidence, risk_level,
          is_primary, current_stage, first_seen_at, last_seen_at, summary, created_at, updated_at
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "actor_case_primary_001",
            "case_actor_primary_001",
            "org actor",
            "active",
            0.8,
            "high",
            0,
            "command_execution",
            "2026-04-14T09:55:00+08:00",
            "2026-04-14T09:55:00+08:00",
            "seed",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:00:00+08:00",
        ),
    )
    conn.execute(
        """
        insert into case_actor_links (
          link_id, case_actor_id, target_type, target_id, link_confidence, link_reason, linked_at
        ) values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "calink_primary_001",
            "actor_case_primary_001",
            "alert",
            "alt_actor_primary_001",
            0.9,
            "seed",
            "2026-04-14T09:55:00+08:00",
        ),
    )
    conn.commit()

    manifest = {
        "final_assertions": {
            "required_tool_names": ["alert.fetch"],
            "required_any_tool_names": [],
            "require_actor_coverage_for_high_signal_alerts": True,
            "require_primary_case_actor_for_high_signal_cases": True,
        }
    }
    with pytest.raises(HermesSlowVerificationError, match="primary case actor missing for high-signal cases"):
        _verify_final_db_state(conn, manifest=manifest, round_count=1)
    conn.close()


def test_verify_final_db_state_accepts_single_actor_covering_multiple_high_signal_alerts(tmp_path: Path) -> None:
    db_path = tmp_path / "slow.db"
    conn = connect_db(db_path)
    create_schema(conn)
    conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at, finished_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "run_actor_ok_001",
            "mcp_auto",
            "success",
            "done",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:01:00+08:00",
        ),
    )
    conn.execute(
        """
        insert into agent_tool_calls (
          call_id, occurred_at, run_id, source, tool_name, payload_json,
          result_ok, result_summary, result_json, latency_ms
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "call_actor_ok_001",
            "2026-04-14T10:00:10+08:00",
            "run_actor_ok_001",
            "mcp",
            "alert.fetch",
            "{}",
            1,
            "ok",
            "{}",
            10,
        ),
    )
    conn.execute(
        """
        insert into cases (case_id, title, status, overall_severity, current_stage, primary_actor_id)
        values (?, ?, ?, ?, ?, ?)
        """,
        ("case_actor_ok_001", "case", "open", "high", "command_execution", "actor_case_ok_001"),
    )
    conn.execute(
        """
        insert into case_actor_profiles (
          case_actor_id, case_id, label, status, profile_confidence, risk_level,
          is_primary, current_stage, first_seen_at, last_seen_at, summary, created_at, updated_at
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "actor_case_ok_001",
            "case_actor_ok_001",
            "org actor",
            "active",
            0.85,
            "high",
            1,
            "command_execution",
            "2026-04-14T09:55:00+08:00",
            "2026-04-14T10:00:00+08:00",
            "seed",
            "2026-04-14T10:00:00+08:00",
            "2026-04-14T10:00:00+08:00",
        ),
    )
    for alert_id, src_ip, occurred_at in [
        ("alt_actor_ok_001", "198.51.100.77", "2026-04-14T09:55:00+08:00"),
        ("alt_actor_ok_002", "198.51.100.91", "2026-04-14T10:00:00+08:00"),
    ]:
        conn.execute(
            """
            insert into alerts (alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                occurred_at,
                "verify actor coverage",
                "triaged",
                "high",
                "command_execution",
                src_ip,
                "203.0.113.10",
                "asset_api_prod",
            ),
        )
        conn.execute(
            """
            insert into case_alert_links (case_id, alert_id, linked_at, confidence, reason, is_active)
            values (?, ?, ?, ?, ?, 1)
            """,
            (
                "case_actor_ok_001",
                alert_id,
                occurred_at,
                0.9,
                "seed",
            ),
        )
        conn.execute(
            """
            insert into case_actor_links (
              link_id, case_actor_id, target_type, target_id, link_confidence, link_reason, linked_at
            ) values (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"calink_{alert_id}",
                "actor_case_ok_001",
                "alert",
                alert_id,
                0.9,
                "seed",
                occurred_at,
            ),
        )
    conn.commit()

    manifest = {
        "final_assertions": {
            "required_tool_names": ["alert.fetch"],
            "required_any_tool_names": [],
            "require_actor_coverage_for_high_signal_alerts": True,
            "require_primary_case_actor_for_high_signal_cases": True,
        }
    }
    summary = _verify_final_db_state(conn, manifest=manifest, round_count=1)
    assert summary["failed_tool_calls_count"] == 0
    conn.close()


def test_build_chat_command_includes_query_and_skill() -> None:
    command = build_chat_command(
        query="Run one patrol pass",
        max_turns=12,
        model="openai/gpt-5",
        skills=["secagent-patrol"],
    )

    assert command[:3] == ["hermes", "chat", "-q"]
    assert "Run one patrol pass" in command
    assert "--max-turns" in command
    assert "12" in command
    assert "-m" in command
    assert "openai/gpt-5" in command
    assert "-s" in command
    assert "secagent-patrol" in command


def test_build_chat_command_supports_continue_latest() -> None:
    command = build_chat_command(
        query=DEFAULT_FINALIZE_QUERY,
        max_turns=2,
        continue_latest=True,
    )

    assert "--continue" in command
    assert "--max-turns" in command
    assert "2" in command
    assert "-q" in command


def test_run_chat_with_continue_fallback_prefers_continue_on_success(monkeypatch) -> None:
    commands: list[list[str]] = []

    def fake_run_command(command, *, env, cwd, timeout_sec):  # noqa: ANN001
        del env, cwd, timeout_sec
        commands.append(command)
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="ok", stderr="")

    result = _run_chat_with_continue_fallback(
        run_command=fake_run_command,
        query="run patrol",
        max_turns=12,
        model=None,
        provider=None,
        skills=["secagent-patrol"],
        env={},
        cwd=Path("."),
        timeout_sec=30,
    )
    assert result.returncode == 0
    assert len(commands) == 1
    assert "--continue" in commands[0]


def test_run_chat_with_continue_fallback_uses_fresh_session_when_continue_fails() -> None:
    commands: list[list[str]] = []

    def fake_run_command(command, *, env, cwd, timeout_sec):  # noqa: ANN001
        del env, cwd, timeout_sec
        commands.append(command)
        if len(commands) == 1:
            return subprocess.CompletedProcess(args=command, returncode=1, stdout="", stderr="no session")
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="ok", stderr="")

    result = _run_chat_with_continue_fallback(
        run_command=fake_run_command,
        query="run patrol",
        max_turns=12,
        model=None,
        provider=None,
        skills=["secagent-patrol"],
        env={},
        cwd=Path("."),
        timeout_sec=30,
    )
    assert result.returncode == 0
    assert len(commands) == 2
    assert "--continue" in commands[0]
    assert "--continue" not in commands[1]


def test_prepare_isolated_hermes_home_copies_required_files(tmp_path: Path) -> None:
    source_home = tmp_path / "source"
    source_home.mkdir()
    (source_home / "config.yaml").write_text("model:\n  default: demo\n", encoding="utf-8")
    (source_home / ".env").write_text("DUMMY=1\n", encoding="utf-8")
    (source_home / "auth.json").write_text("{}", encoding="utf-8")
    (source_home / "SOUL.md").write_text("# soul\n", encoding="utf-8")

    dest_home = tmp_path / "dest"
    repo_skill_dir = Path("skills/secagent-patrol")

    prepare_isolated_hermes_home(source_home=source_home, dest_home=dest_home, repo_skill_dir=repo_skill_dir)

    assert (dest_home / "config.yaml").exists()
    assert (dest_home / ".env").exists()
    assert (dest_home / "auth.json").exists()
    assert (dest_home / "SOUL.md").exists()
    assert (dest_home / "skills" / "secagent-patrol" / "SKILL.md").exists()


def test_prepare_isolated_hermes_home_uses_repo_soul_template(tmp_path: Path) -> None:
    source_home = tmp_path / "source"
    source_home.mkdir()
    (source_home / "config.yaml").write_text("model:\n  default: demo\n", encoding="utf-8")
    (source_home / "SOUL.md").write_text("# stale soul\n", encoding="utf-8")

    dest_home = tmp_path / "dest"
    repo_skill_dir = Path("skills/secagent-patrol")

    prepare_isolated_hermes_home(source_home=source_home, dest_home=dest_home, repo_skill_dir=repo_skill_dir)

    expected_template = Path("hermes/SOUL.patrol.template.md")
    if not expected_template.exists():
        expected_template = Path("hermes/SOUL.template.md")
    assert (dest_home / "SOUL.md").read_text(encoding="utf-8") == expected_template.read_text(encoding="utf-8")


def test_is_missing_header_error_matches_chat_output_header_failures(tmp_path: Path) -> None:
    round_spec = {"round_id": "round_demo", "required_output_headers": ["## Patrol Action Summary"]}

    with pytest.raises(HermesSlowVerificationError) as captured:
        _verify_chat_output(chat_stdout="No headers", round_spec=round_spec, artifact_dir=tmp_path)
    assert _is_missing_header_error(captured.value, round_id="round_demo") is True


def test_is_retryable_round_db_error_matches_empty_round_failures() -> None:
    err = HermesSlowVerificationError("round_db_assertions:round_04_lateral_prep", "no patrol_runs created by Hermes flow")
    assert _is_retryable_round_db_error(err) is True


def test_is_retryable_round_db_error_rejects_non_round_failures() -> None:
    err = HermesSlowVerificationError("final_db_assertions", "expected at least 1 converged case clusters")
    assert _is_retryable_round_db_error(err) is False


def test_main_prints_progress_to_stderr_and_summary_to_stdout(monkeypatch, capsys, tmp_path: Path) -> None:
    db_path = tmp_path / "slow.db"

    def fake_run_slow_integration(*, scenario, db_path, model, provider, keep_artifacts, progress):
        progress(1, 3, "准备隔离 Hermes Home")
        progress(2, 3, "启动 MCP server")
        progress(3, 3, "运行真实 Hermes patrol")
        return {"scenario": scenario, "db_path": str(db_path), "tool_calls_count": 5}

    monkeypatch.setattr(hermes_slow_verify, "run_slow_integration", fake_run_slow_integration)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "security_analyst_agent.hermes_slow_verify",
            "--scenario",
            "hermes-slow-integration",
            "--db-path",
            str(db_path),
        ],
    )

    hermes_slow_verify.main()

    captured = capsys.readouterr()
    assert "[1/3] 准备隔离 Hermes Home" in captured.err
    assert "[2/3] 启动 MCP server" in captured.err
    assert "[3/3] 运行真实 Hermes patrol" in captured.err
    assert "PASS: hermes slow integration verify hermes-slow-integration" in captured.out
    assert '"tool_calls_count": 5' in captured.out
