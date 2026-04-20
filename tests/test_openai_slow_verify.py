from __future__ import annotations

from pathlib import Path

from security_analyst_agent.bootstrap import bootstrap_spike_database
from security_analyst_agent.db import connect_db
from security_analyst_agent.hermes_slow_verify import load_integration_manifest, resolve_round_specs
from security_analyst_agent.openai_slow_verify import (
    _build_verification_manifest_for_openai,
    _verify_with_mcp_auto_alias,
    run_openai_slow_integration,
)


def test_verify_with_mcp_auto_alias_restores_trigger_source(tmp_path: Path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at, finished_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "run_alias_001",
            "ingest_event",
            "success",
            "seed",
            "2026-04-18T00:00:00+00:00",
            "2026-04-18T00:00:00+00:00",
            "2026-04-18T00:01:00+00:00",
        ),
    )
    conn.commit()

    aliased_sources: list[str] = []

    def _inspect_alias() -> dict:
        rows = conn.execute(
            """
            select distinct trigger_source
            from patrol_runs
            order by trigger_source asc
            """
        ).fetchall()
        aliased_sources.extend(str(row["trigger_source"]) for row in rows)
        return {"ok": True}

    _verify_with_mcp_auto_alias(conn, _inspect_alias)
    restored_source = conn.execute(
        """
        select trigger_source
        from patrol_runs
        where run_id = ?
        """,
        ("run_alias_001",),
    ).fetchone()["trigger_source"]
    conn.close()

    assert aliased_sources == ["mcp_auto"]
    assert restored_source == "ingest_event"


def test_run_openai_slow_integration_invokes_trigger_with_openai_mode(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "openai-slow.db"
    recorded_trigger_calls: list[dict] = []

    manifest = {"scenario": "demo", "round_defaults": {}, "rounds": [{"round_id": "round_01"}], "final_assertions": {}}

    monkeypatch.setattr("security_analyst_agent.openai_slow_verify.load_integration_manifest", lambda _s: manifest)
    monkeypatch.setattr("security_analyst_agent.openai_slow_verify.resolve_fixture_dir", lambda _m: tmp_path)
    monkeypatch.setattr(
        "security_analyst_agent.openai_slow_verify.resolve_round_specs",
        lambda _m: [{"round_id": "round_01", "max_turns": 7, "min_tool_calls": 0}],
    )
    monkeypatch.setattr(
        "security_analyst_agent.openai_slow_verify.load_memory_spike_rounds",
        lambda _fixture_dir: [
            {
                "round_id": "round_01",
                "alerts": [
                    {
                        "alert_id": "alt_day1_scan_01",
                        "case_id": None,
                        "occurred_at": "2026-04-10T09:10:00+08:00",
                        "title": "seed alert for test",
                        "status": "new",
                        "severity": "medium",
                        "attack_stage": "recon",
                        "src_ip": "198.51.100.23",
                        "dst_ip": "203.0.113.10",
                        "asset_id": "asset_api_prod",
                    }
                ],
            }
        ],
    )
    monkeypatch.setattr(
        "security_analyst_agent.openai_slow_verify._bootstrap_db",
        lambda target_db_path, fixture_dir: bootstrap_spike_database(target_db_path),
    )
    monkeypatch.setattr(
        "security_analyst_agent.openai_slow_verify.apply_memory_spike_round",
        lambda *_args, **_kwargs: {"applied": True},
    )
    monkeypatch.setattr(
        "security_analyst_agent.openai_slow_verify._verify_round_db_state",
        lambda *_args, **_kwargs: {"round_id": "round_01", "tool_calls_count": 1, "tool_names": ["alert.fetch"]},
    )
    monkeypatch.setattr(
        "security_analyst_agent.openai_slow_verify._verify_final_db_state",
        lambda *_args, **_kwargs: {"tool_calls_count": 1, "tool_names": ["alert.fetch"], "patrol_runs": []},
    )

    def _fake_trigger(*args, **kwargs):
        recorded_trigger_calls.append({"args": args, "kwargs": kwargs})
        return {"triggered": True, "processed_events": 1, "status": "success", "run_id": "run_openai_001", "job_id": "job"}

    summary = run_openai_slow_integration(
        scenario="demo",
        db_path=db_path,
        model="gpt-5-mini",
        trigger_runner=_fake_trigger,
    )

    assert summary["trigger_mode"] == "openai"
    assert summary["openai_model"] == "gpt-5-mini"
    assert len(recorded_trigger_calls) == 1
    trigger_kwargs = recorded_trigger_calls[0]["kwargs"]
    assert trigger_kwargs["trigger_mode"] == "openai"
    assert trigger_kwargs["patrol_max_turns"] == 7
    assert trigger_kwargs["openai_model"] == "gpt-5-mini"


def test_load_realistic_manifest_and_round_specs() -> None:
    manifest = load_integration_manifest("hermes-slow-integration-realistic")
    assert manifest["fixture_dir"] == "fixtures/spike_memory_realistic"
    specs = resolve_round_specs(manifest)
    assert len(specs) == 5
    assert specs[0]["round_id"] == "round_01_realistic"


def test_build_verification_manifest_for_openai_relaxes_ack_and_strategy_assertions_in_objective_mode() -> None:
    manifest = {
        "scenario": "demo",
        "round_defaults": {},
        "rounds": [{"round_id": "round_01"}],
        "final_assertions": {
            "required_tool_names": ["alert.fetch", "alert.ack"],
            "required_any_tool_names": [["assessment.upsert-batch", "case.link-alert-batch"]],
            "min_entity_assessments": 1,
            "min_case_assessments": 1,
            "min_fetch_calls_with_processing_guardrails": 1,
            "min_fetch_calls_with_recommended_next_actions": 1,
            "min_fetch_calls_with_ack_recommendations": 1,
            "min_five_layer_cluster_fetch_calls": 1,
        },
    }
    updated = _build_verification_manifest_for_openai(
        manifest,
        objective_mode=True,
        expected_processed_ingest_events=12,
    )
    final_assertions = updated["final_assertions"]

    assert final_assertions["required_tool_names"] == ["alert.fetch"]
    assert final_assertions["required_any_tool_names"] == []
    assert final_assertions["min_fetch_calls_with_processing_guardrails"] == 0
    assert final_assertions["min_fetch_calls_with_recommended_next_actions"] == 0
    assert final_assertions["min_fetch_calls_with_ack_recommendations"] == 0
    assert final_assertions["min_five_layer_cluster_fetch_calls"] == 0
    assert final_assertions["min_entity_assessments"] == 0
    assert final_assertions["min_case_assessments"] == 0
    assert final_assertions["min_processed_ingest_events"] == 12
    assert final_assertions["min_processed_ingest_events_with_run_id"] == 12
