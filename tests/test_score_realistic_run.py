import json
from pathlib import Path

from security_analyst_agent.db import connect_db, create_schema
from security_analyst_agent.tools.score_realistic_run import render_score_markdown, score_realistic_run


def _write_answer_key(path: Path) -> None:
    answer_key = {
        "schema_version": 1,
        "chains": [
            {
                "chain_id": "chain_a",
                "primary_src_ip": "198.51.100.23",
                "src_ip_pool": ["198.51.100.23"],
                "assets": ["asset_api_prod"],
                "stage_by_round": {
                    "round_01_realistic": "exploit",
                    "round_02_realistic": "persistence",
                },
            },
            {
                "chain_id": "chain_b",
                "primary_src_ip": "203.0.113.88",
                "src_ip_pool": ["203.0.113.88"],
                "assets": ["asset_pay_gateway"],
                "stage_by_round": {
                    "round_01_realistic": "exploit",
                    "round_02_realistic": "command_execution",
                },
            },
        ],
        "expected_entities": {
            "primary_attack_ips": ["198.51.100.23", "203.0.113.88"],
            "all_attack_src_ips": ["198.51.100.23", "203.0.113.88"],
            "noise_src_ip_pool": ["192.0.2.23"],
        },
        "alert_truth": {
            "a1": {
                "round_id": "round_01_realistic",
                "chain_id": "chain_a",
                "attack_stage": "exploit",
                "severity": "high",
                "src_ip": "198.51.100.23",
                "asset_id": "asset_api_prod",
                "is_attack": True,
                "is_high_signal": True,
            },
            "a2": {
                "round_id": "round_02_realistic",
                "chain_id": "chain_a",
                "attack_stage": "persistence",
                "severity": "high",
                "src_ip": "198.51.100.23",
                "asset_id": "asset_api_prod",
                "is_attack": True,
                "is_high_signal": True,
            },
            "b1": {
                "round_id": "round_01_realistic",
                "chain_id": "chain_b",
                "attack_stage": "exploit",
                "severity": "high",
                "src_ip": "203.0.113.88",
                "asset_id": "asset_pay_gateway",
                "is_attack": True,
                "is_high_signal": True,
            },
            "b2": {
                "round_id": "round_02_realistic",
                "chain_id": "chain_b",
                "attack_stage": "command_execution",
                "severity": "critical",
                "src_ip": "203.0.113.88",
                "asset_id": "asset_pay_gateway",
                "is_attack": True,
                "is_high_signal": True,
            },
            "n1": {
                "round_id": "round_01_realistic",
                "chain_id": "noise",
                "attack_stage": "unknown",
                "severity": "low",
                "src_ip": "192.0.2.23",
                "asset_id": "asset_static_www",
                "is_attack": False,
                "is_high_signal": False,
            },
            "n2": {
                "round_id": "round_02_realistic",
                "chain_id": "noise",
                "attack_stage": "unknown",
                "severity": "low",
                "src_ip": "192.0.2.23",
                "asset_id": "asset_static_www",
                "is_attack": False,
                "is_high_signal": False,
            },
        },
    }
    path.write_text(json.dumps(answer_key, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _seed_db_for_scoring(db_path: Path) -> None:
    conn = connect_db(db_path)
    create_schema(conn)

    conn.executemany(
        """
        insert into alerts (alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            ("a1", "2026-04-13T09:00:00+08:00", "A1", "open", "high", "exploit", "198.51.100.23", "203.0.113.10", "asset_api_prod"),
            ("a2", "2026-04-14T09:00:00+08:00", "A2", "open", "high", "persistence", "198.51.100.23", "203.0.113.10", "asset_api_prod"),
            ("b1", "2026-04-13T09:01:00+08:00", "B1", "open", "high", "exploit", "203.0.113.88", "203.0.113.22", "asset_pay_gateway"),
            ("b2", "2026-04-14T09:01:00+08:00", "B2", "open", "critical", "command_execution", "203.0.113.88", "203.0.113.22", "asset_pay_gateway"),
            ("n1", "2026-04-13T09:02:00+08:00", "N1", "open", "low", "unknown", "192.0.2.23", "203.0.113.12", "asset_static_www"),
            ("n2", "2026-04-14T09:02:00+08:00", "N2", "open", "low", "unknown", "192.0.2.23", "203.0.113.12", "asset_static_www"),
        ],
    )
    conn.executemany(
        """
        insert into cases (
          case_id, title, status, overall_severity, current_stage, primary_actor_id,
          canonical_case_id, merged_into_case_id, merge_state, merge_updated_at
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            ("case_a", "case a", "open", "high", "persistence", None, None, None, "standalone", None),
            ("case_b", "case b", "open", "high", "command_execution", None, None, None, "standalone", None),
        ],
    )
    conn.executemany(
        """
        insert into case_alert_links (case_id, alert_id, linked_at, confidence, reason, is_active, unlinked_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            ("case_a", "a1", "2026-04-13T09:10:00+08:00", 0.9, "same chain", 1, None),
            ("case_a", "a2", "2026-04-14T09:10:00+08:00", 0.9, "same chain", 1, None),
            ("case_a", "b1", "2026-04-13T09:11:00+08:00", 0.7, "wrong merge", 1, None),
            ("case_a", "n1", "2026-04-13T09:12:00+08:00", 0.6, "noise leak", 1, None),
            ("case_b", "b2", "2026-04-14T09:11:00+08:00", 0.9, "same chain", 1, None),
        ],
    )
    conn.executemany(
        """
        insert into entity_assessments (
          assessment_id, occurred_at, run_id, entity_type, entity_key, entity_label, related_case_id,
          risk_level, assessment_confidence, verdict, reason_summary, supporting_alert_ids_json,
          supporting_evidence_ids_json, first_seen_at, last_seen_at, analysis_cutoff_at, is_current
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                "asm_1",
                "2026-04-15T00:00:00+00:00",
                "run_x",
                "ip",
                "198.51.100.23",
                "198.51.100.23",
                "case_a",
                "high",
                0.9,
                "attacker",
                "confirmed",
                "[]",
                "[]",
                None,
                None,
                None,
                1,
            ),
            (
                "asm_2",
                "2026-04-15T00:00:00+00:00",
                "run_x",
                "ip",
                "203.0.113.88",
                "203.0.113.88",
                "case_b",
                "high",
                0.88,
                "attacker",
                "confirmed",
                "[]",
                "[]",
                None,
                None,
                None,
                1,
            ),
        ],
    )
    conn.execute(
        """
        insert into patrol_run_costs (
          run_id, trigger_source, trigger_mode, model, status, started_at, finished_at, duration_ms,
          turns, tool_calls, usage_input_tokens, usage_output_tokens, usage_cached_input_tokens,
          usage_total_tokens, recorded_at
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "run_x",
            "ingest_event",
            "openai",
            "qwen3.5-flash",
            "success",
            "2026-04-15T00:00:00+00:00",
            "2026-04-15T00:02:00+00:00",
            120000,
            8,
            12,
            1000,
            120,
            0,
            1120,
            "2026-04-15T00:02:01+00:00",
        ),
    )
    conn.commit()
    conn.close()


def test_score_realistic_run_computes_key_metrics(tmp_path) -> None:
    db_path = tmp_path / "score.db"
    answer_key_path = tmp_path / "answer_key.json"
    _seed_db_for_scoring(db_path)
    _write_answer_key(answer_key_path)

    summary = score_realistic_run(db_path=db_path, answer_key_path=answer_key_path)
    assert summary["counts"]["answer_key_alert_count"] == 6
    assert summary["chains"]["chain_a"]["recall"] == 1.0
    assert summary["chains"]["chain_b"]["recall"] == 0.5
    assert summary["metrics"]["cross_chain_mix_rate"] == 0.25
    assert summary["metrics"]["noise_leak_to_attack_case_rate"] == 0.5
    assert summary["metrics"]["primary_ip_attacker_recall"] == 1.0
    assert summary["metrics"]["auto_link_ratio"] == 0.0
    assert summary["metrics"]["manual_link_ratio"] == 1.0
    assert summary["counts"]["active_link_contribution"]["manual_active_link_count"] == 5
    assert summary["cost"]["usage_total_tokens_total"] == 1120
    assert summary["score"]["pass"] is False
    markdown = render_score_markdown(summary)
    assert "Realistic Scenario Score" in markdown
    assert "cross_chain_mix_rate" in "\n".join(summary["score"]["fail_reasons"])
