import re

from security_analyst_agent.tools.generate_alert_fixture import (
    generate_rounds,
    generate_rounds_with_answer_key,
    write_rounds,
)


def test_generate_rounds_is_deterministic_with_same_seed() -> None:
    rounds_a = generate_rounds(round_count=5, alerts_per_round=1000, chain_count=2, seed=20260419)
    rounds_b = generate_rounds(round_count=5, alerts_per_round=1000, chain_count=2, seed=20260419)
    assert rounds_a == rounds_b


def test_generate_rounds_shape_distribution_and_stage_fallback() -> None:
    rounds = generate_rounds(round_count=5, alerts_per_round=1000, chain_count=2, seed=7)
    assert len(rounds) == 5
    assert [item["round_id"] for item in rounds] == [
        "round_01_realistic",
        "round_02_realistic",
        "round_03_realistic",
        "round_04_realistic",
        "round_05_realistic",
    ]
    assert all(len(item["alerts"]) == 1000 for item in rounds)
    assert rounds[0]["previous_round_id"] is None
    assert rounds[1]["previous_round_id"] == "round_01_realistic"

    all_alerts = [alert for item in rounds for alert in item["alerts"]]
    assert len(all_alerts) == 5000

    attack_signal = [a for a in all_alerts if a["severity"] in {"high", "critical"}]
    assert len(attack_signal) >= 80

    assert all(a.get("attack_stage") for a in all_alerts)
    unknown_stage_rows = [a for a in all_alerts if a["attack_stage"] == "unknown"]
    assert unknown_stage_rows
    assert all(a["raw_attack_stage"] is None or isinstance(a["raw_attack_stage"], str) for a in all_alerts)
    assert any(a["raw_attack_stage"] is None for a in unknown_stage_rows)

    bad_ids = [a["alert_id"] for a in all_alerts if re.search(r"(chain|round|r\d+)", a["alert_id"], re.I)]
    assert bad_ids == []


def test_write_rounds_generates_rounds_json(tmp_path) -> None:
    output_path = write_rounds(
        output_dir=tmp_path / "spike_memory_realistic",
        round_count=2,
        alerts_per_round=50,
        chain_count=2,
        seed=42,
    )
    assert output_path.name == "rounds.json"
    assert output_path.exists() is True
    assert (output_path.parent / "answer_key.json").exists() is True


def test_generate_rounds_with_answer_key_contains_ground_truth() -> None:
    rounds, answer_key = generate_rounds_with_answer_key(
        round_count=2,
        alerts_per_round=80,
        chain_count=2,
        seed=20260419,
    )
    assert len(rounds) == 2
    assert answer_key["schema_version"] == 1
    assert answer_key["chain_count"] == 2
    assert len(answer_key["chains"]) == 2
    assert answer_key["expected_entities"]["primary_attack_ips"] == ["198.51.100.23", "203.0.113.88"]

    all_alert_ids = {alert["alert_id"] for round_item in rounds for alert in round_item["alerts"]}
    assert set(answer_key["alert_truth"]) == all_alert_ids
    chain_values = {item["chain_id"] for item in answer_key["alert_truth"].values()}
    assert chain_values == {"chain_a", "chain_b", "noise"}
