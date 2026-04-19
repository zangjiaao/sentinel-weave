from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import sqlite3
from typing import Any

from security_analyst_agent.db import connect_db
from security_analyst_agent.stages import stage_rank

DEFAULT_PASS_THRESHOLDS = {
    "min_chain_high_signal_recall": 0.70,
    "max_cross_chain_mix_rate": 0.15,
    "max_noise_leak_to_attack_case_rate": 0.25,
    "min_chain_stage_coverage": 0.80,
    "min_primary_ip_attacker_recall": 1.0,
}


def _safe_div(numerator: int | float, denominator: int | float) -> float:
    if denominator == 0:
        return 0.0
    return float(numerator) / float(denominator)


def _load_answer_key(answer_key_path: Path) -> dict[str, Any]:
    answer_key = json.loads(answer_key_path.read_text(encoding="utf-8"))
    required_keys = {"chains", "alert_truth", "expected_entities"}
    missing_keys = sorted(required_keys.difference(answer_key))
    if missing_keys:
        raise ValueError(f"answer_key missing keys: {missing_keys}")
    return answer_key


def _load_active_alert_case_links(conn: sqlite3.Connection) -> dict[str, str]:
    rows = conn.execute(
        """
        select
          case_alert_links.case_id,
          case_alert_links.alert_id,
          case_alert_links.confidence,
          case_alert_links.linked_at
        from case_alert_links
        where case_alert_links.is_active = 1
        order by
          case_alert_links.alert_id asc,
          case_alert_links.confidence desc,
          case_alert_links.linked_at desc,
          case_alert_links.case_id asc
        """
    ).fetchall()
    best_link_by_alert: dict[str, str] = {}
    for row in rows:
        alert_id = str(row["alert_id"])
        if alert_id not in best_link_by_alert:
            best_link_by_alert[alert_id] = str(row["case_id"])
    return best_link_by_alert


def _load_current_ip_assessments(conn: sqlite3.Connection) -> dict[str, dict[str, str]]:
    rows = conn.execute(
        """
        select entity_key, verdict, risk_level
        from entity_assessments
        where entity_type = 'ip'
          and is_current = 1
        order by entity_key asc, occurred_at desc
        """
    ).fetchall()
    assessments: dict[str, dict[str, str]] = {}
    for row in rows:
        entity_key = str(row["entity_key"])
        if entity_key not in assessments:
            assessments[entity_key] = {
                "verdict": str(row["verdict"]),
                "risk_level": str(row["risk_level"]),
            }
    return assessments


def _load_cost_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    rows = conn.execute(
        """
        select
          run_id,
          status,
          duration_ms,
          turns,
          tool_calls,
          usage_input_tokens,
          usage_output_tokens,
          usage_total_tokens
        from patrol_run_costs
        order by started_at asc
        """
    ).fetchall()
    runs = [dict(row) for row in rows]
    return {
        "run_count": len(runs),
        "duration_ms_total": sum(int(item["duration_ms"] or 0) for item in runs),
        "turns_total": sum(int(item["turns"] or 0) for item in runs),
        "tool_calls_total": sum(int(item["tool_calls"] or 0) for item in runs),
        "usage_input_tokens_total": sum(int(item["usage_input_tokens"] or 0) for item in runs),
        "usage_output_tokens_total": sum(int(item["usage_output_tokens"] or 0) for item in runs),
        "usage_total_tokens_total": sum(int(item["usage_total_tokens"] or 0) for item in runs),
        "runs": runs,
    }


def _load_active_link_contribution(conn: sqlite3.Connection) -> dict[str, int]:
    row = conn.execute(
        """
        select
          count(*) as total_active_link_count,
          sum(case when coalesce(reason, '') like 'auto:%' then 1 else 0 end) as auto_active_link_count
        from case_alert_links
        where is_active = 1
        """
    ).fetchone()
    total = int(row["total_active_link_count"] or 0) if row is not None else 0
    auto = int(row["auto_active_link_count"] or 0) if row is not None else 0
    manual = max(0, total - auto)
    return {
        "total_active_link_count": total,
        "auto_active_link_count": auto,
        "manual_active_link_count": manual,
    }


def _dominant_chain_for_case(
    *,
    case_alert_ids: list[str],
    truth_by_alert_id: dict[str, dict[str, Any]],
    attack_chain_ids: set[str],
) -> str | None:
    chain_scores: dict[str, int] = defaultdict(int)
    for alert_id in case_alert_ids:
        truth = truth_by_alert_id.get(alert_id)
        if not truth:
            continue
        chain_id = str(truth.get("chain_id"))
        if chain_id not in attack_chain_ids:
            continue
        score = 2 if bool(truth.get("is_high_signal")) else 1
        chain_scores[chain_id] += score

    if not chain_scores:
        return None

    sorted_items = sorted(chain_scores.items(), key=lambda item: (item[1], item[0]), reverse=True)
    if len(sorted_items) > 1 and sorted_items[0][1] == sorted_items[1][1]:
        return None
    return sorted_items[0][0]


def _compute_chain_metrics(
    *,
    chain_id: str,
    truth_by_alert_id: dict[str, dict[str, Any]],
    predicted_chain_by_alert_id: dict[str, str],
    expected_stages: set[str],
) -> dict[str, Any]:
    chain_truth_alert_ids = {
        alert_id for alert_id, truth in truth_by_alert_id.items() if str(truth.get("chain_id")) == chain_id
    }
    chain_truth_high_signal_alert_ids = {
        alert_id
        for alert_id, truth in truth_by_alert_id.items()
        if str(truth.get("chain_id")) == chain_id and bool(truth.get("is_high_signal"))
    }
    chain_predicted_alert_ids = {
        alert_id for alert_id, predicted_chain in predicted_chain_by_alert_id.items() if predicted_chain == chain_id
    }

    true_positive_alert_ids = chain_truth_alert_ids.intersection(chain_predicted_alert_ids)
    true_positive_high_signal_alert_ids = chain_truth_high_signal_alert_ids.intersection(chain_predicted_alert_ids)

    observed_correct_stages = {
        str(truth_by_alert_id[alert_id].get("attack_stage"))
        for alert_id in true_positive_alert_ids
        if truth_by_alert_id.get(alert_id)
    }
    stage_overlap = observed_correct_stages.intersection(expected_stages)

    expected_latest_rank = max((stage_rank(item) for item in expected_stages), default=0)
    observed_latest_rank = max((stage_rank(item) for item in observed_correct_stages), default=0)

    return {
        "truth_alert_count": len(chain_truth_alert_ids),
        "truth_high_signal_alert_count": len(chain_truth_high_signal_alert_ids),
        "predicted_alert_count": len(chain_predicted_alert_ids),
        "true_positive_alert_count": len(true_positive_alert_ids),
        "true_positive_high_signal_alert_count": len(true_positive_high_signal_alert_ids),
        "recall": _safe_div(len(true_positive_alert_ids), len(chain_truth_alert_ids)),
        "precision": _safe_div(len(true_positive_alert_ids), len(chain_predicted_alert_ids)),
        "high_signal_recall": _safe_div(
            len(true_positive_high_signal_alert_ids),
            len(chain_truth_high_signal_alert_ids),
        ),
        "expected_stages": sorted(expected_stages),
        "observed_correct_stages": sorted(observed_correct_stages),
        "stage_coverage": _safe_div(len(stage_overlap), len(expected_stages)),
        "expected_latest_stage_rank": expected_latest_rank,
        "observed_latest_stage_rank": observed_latest_rank,
        "stage_progress_ratio": _safe_div(observed_latest_rank, expected_latest_rank),
    }


def score_realistic_run(*, db_path: Path, answer_key_path: Path) -> dict[str, Any]:
    answer_key = _load_answer_key(answer_key_path)
    truth_by_alert_id: dict[str, dict[str, Any]] = answer_key["alert_truth"]
    chains = answer_key["chains"]
    attack_chain_ids = {str(item["chain_id"]) for item in chains}

    conn = connect_db(db_path)
    try:
        best_case_by_alert_id = _load_active_alert_case_links(conn)
        current_ip_assessments = _load_current_ip_assessments(conn)
        cost_summary = _load_cost_summary(conn)
        link_contribution = _load_active_link_contribution(conn)
    finally:
        conn.close()

    case_alert_ids: dict[str, list[str]] = defaultdict(list)
    for alert_id, case_id in best_case_by_alert_id.items():
        case_alert_ids[case_id].append(alert_id)

    dominant_chain_by_case_id: dict[str, str] = {}
    for case_id, alert_ids in case_alert_ids.items():
        dominant_chain = _dominant_chain_for_case(
            case_alert_ids=alert_ids,
            truth_by_alert_id=truth_by_alert_id,
            attack_chain_ids=attack_chain_ids,
        )
        if dominant_chain:
            dominant_chain_by_case_id[case_id] = dominant_chain

    predicted_chain_by_alert_id: dict[str, str] = {}
    for alert_id, case_id in best_case_by_alert_id.items():
        predicted_chain = dominant_chain_by_case_id.get(case_id)
        if predicted_chain:
            predicted_chain_by_alert_id[alert_id] = predicted_chain

    attack_truth_alert_ids = {
        alert_id for alert_id, truth in truth_by_alert_id.items() if str(truth.get("chain_id")) in attack_chain_ids
    }
    noise_truth_alert_ids = {
        alert_id for alert_id, truth in truth_by_alert_id.items() if str(truth.get("chain_id")) == "noise"
    }
    predicted_attack_alert_ids = set(predicted_chain_by_alert_id.keys())

    predicted_attack_alert_ids_with_truth = attack_truth_alert_ids.intersection(predicted_attack_alert_ids)
    cross_chain_wrong_count = 0
    for alert_id in predicted_attack_alert_ids_with_truth:
        expected_chain_id = str(truth_by_alert_id[alert_id]["chain_id"])
        predicted_chain_id = predicted_chain_by_alert_id[alert_id]
        if expected_chain_id != predicted_chain_id:
            cross_chain_wrong_count += 1

    noise_with_any_case_count = len(noise_truth_alert_ids.intersection(best_case_by_alert_id))
    noise_with_attack_case_count = len(noise_truth_alert_ids.intersection(predicted_attack_alert_ids))

    chain_metrics: dict[str, dict[str, Any]] = {}
    for chain in chains:
        chain_id = str(chain["chain_id"])
        expected_stages = set(chain.get("stage_by_round", {}).values())
        chain_metrics[chain_id] = _compute_chain_metrics(
            chain_id=chain_id,
            truth_by_alert_id=truth_by_alert_id,
            predicted_chain_by_alert_id=predicted_chain_by_alert_id,
            expected_stages=expected_stages,
        )

    primary_attack_ips = [str(item) for item in answer_key.get("expected_entities", {}).get("primary_attack_ips", [])]
    attacker_hit_ips = sorted(
        ip
        for ip in primary_attack_ips
        if current_ip_assessments.get(ip, {}).get("verdict") == "attacker"
    )
    primary_ip_attacker_recall = _safe_div(len(attacker_hit_ips), len(primary_attack_ips))
    auto_link_ratio = _safe_div(
        link_contribution["auto_active_link_count"],
        link_contribution["total_active_link_count"],
    )
    manual_link_ratio = _safe_div(
        link_contribution["manual_active_link_count"],
        link_contribution["total_active_link_count"],
    )

    mean_high_signal_recall = _safe_div(
        sum(item["high_signal_recall"] for item in chain_metrics.values()),
        len(chain_metrics),
    )
    mean_stage_coverage = _safe_div(
        sum(item["stage_coverage"] for item in chain_metrics.values()),
        len(chain_metrics),
    )
    noise_control_score = max(0.0, 1.0 - _safe_div(noise_with_attack_case_count, len(noise_truth_alert_ids)))
    cross_chain_control_score = max(
        0.0,
        1.0 - _safe_div(cross_chain_wrong_count, len(predicted_attack_alert_ids_with_truth)),
    )
    overall_score = (
        mean_high_signal_recall * 0.40
        + mean_stage_coverage * 0.20
        + noise_control_score * 0.20
        + cross_chain_control_score * 0.10
        + primary_ip_attacker_recall * 0.10
    )

    pass_thresholds = DEFAULT_PASS_THRESHOLDS.copy()
    pass_fail_reasons: list[str] = []
    for chain_id, metrics in chain_metrics.items():
        if metrics["high_signal_recall"] < pass_thresholds["min_chain_high_signal_recall"]:
            pass_fail_reasons.append(
                f"{chain_id}.high_signal_recall={metrics['high_signal_recall']:.3f} < "
                f"{pass_thresholds['min_chain_high_signal_recall']:.2f}"
            )
        if metrics["stage_coverage"] < pass_thresholds["min_chain_stage_coverage"]:
            pass_fail_reasons.append(
                f"{chain_id}.stage_coverage={metrics['stage_coverage']:.3f} < "
                f"{pass_thresholds['min_chain_stage_coverage']:.2f}"
            )

    cross_chain_mix_rate = _safe_div(cross_chain_wrong_count, len(predicted_attack_alert_ids_with_truth))
    if cross_chain_mix_rate > pass_thresholds["max_cross_chain_mix_rate"]:
        pass_fail_reasons.append(
            f"cross_chain_mix_rate={cross_chain_mix_rate:.3f} > "
            f"{pass_thresholds['max_cross_chain_mix_rate']:.2f}"
        )

    noise_leak_to_attack_case_rate = _safe_div(noise_with_attack_case_count, len(noise_truth_alert_ids))
    if noise_leak_to_attack_case_rate > pass_thresholds["max_noise_leak_to_attack_case_rate"]:
        pass_fail_reasons.append(
            f"noise_leak_to_attack_case_rate={noise_leak_to_attack_case_rate:.3f} > "
            f"{pass_thresholds['max_noise_leak_to_attack_case_rate']:.2f}"
        )

    if primary_ip_attacker_recall < pass_thresholds["min_primary_ip_attacker_recall"]:
        pass_fail_reasons.append(
            f"primary_ip_attacker_recall={primary_ip_attacker_recall:.3f} < "
            f"{pass_thresholds['min_primary_ip_attacker_recall']:.2f}"
        )

    result = {
        "schema_version": 1,
        "inputs": {
            "db_path": str(db_path),
            "answer_key_path": str(answer_key_path),
        },
        "counts": {
            "answer_key_alert_count": len(truth_by_alert_id),
            "attack_truth_alert_count": len(attack_truth_alert_ids),
            "noise_truth_alert_count": len(noise_truth_alert_ids),
            "active_linked_alert_count": len(best_case_by_alert_id),
            "cases_with_active_links": len(case_alert_ids),
            "cases_mapped_to_attack_chain": len(dominant_chain_by_case_id),
            "active_link_contribution": link_contribution,
        },
        "chains": chain_metrics,
        "metrics": {
            "cross_chain_mix_rate": cross_chain_mix_rate,
            "noise_leak_any_case_rate": _safe_div(noise_with_any_case_count, len(noise_truth_alert_ids)),
            "noise_leak_to_attack_case_rate": noise_leak_to_attack_case_rate,
            "primary_ip_attacker_recall": primary_ip_attacker_recall,
            "primary_ip_attacker_hits": attacker_hit_ips,
            "auto_link_ratio": auto_link_ratio,
            "manual_link_ratio": manual_link_ratio,
        },
        "cost": cost_summary,
        "score": {
            "overall": round(overall_score * 100.0, 2),
            "components": {
                "mean_chain_high_signal_recall": round(mean_high_signal_recall * 100.0, 2),
                "mean_chain_stage_coverage": round(mean_stage_coverage * 100.0, 2),
                "noise_control": round(noise_control_score * 100.0, 2),
                "cross_chain_control": round(cross_chain_control_score * 100.0, 2),
                "primary_ip_attacker_recall": round(primary_ip_attacker_recall * 100.0, 2),
            },
            "pass_thresholds": pass_thresholds,
            "pass": len(pass_fail_reasons) == 0,
            "fail_reasons": pass_fail_reasons,
        },
    }
    return result


def render_score_markdown(summary: dict[str, Any]) -> str:
    lines = ["# Realistic Scenario Score", ""]
    score = summary["score"]
    metrics = summary["metrics"]
    counts = summary["counts"]
    lines.extend(
        [
            f"- Overall: **{score['overall']}**",
            f"- Pass: **{'yes' if score['pass'] else 'no'}**",
            f"- Active linked alerts: `{counts['active_linked_alert_count']}`",
            f"- Cross-chain mix rate: `{metrics['cross_chain_mix_rate']:.3f}`",
            f"- Noise leak to attack cases: `{metrics['noise_leak_to_attack_case_rate']:.3f}`",
            f"- Primary attacker IP recall: `{metrics['primary_ip_attacker_recall']:.3f}`",
            f"- Auto link ratio: `{metrics['auto_link_ratio']:.3f}`",
            f"- Manual link ratio: `{metrics['manual_link_ratio']:.3f}`",
            "",
            "## Chain Metrics",
        ]
    )

    for chain_id, item in summary["chains"].items():
        lines.extend(
            [
                f"- `{chain_id}` recall={item['recall']:.3f}, high_signal_recall={item['high_signal_recall']:.3f}, "
                f"stage_coverage={item['stage_coverage']:.3f}, precision={item['precision']:.3f}",
            ]
        )

    lines.extend(["", "## Cost"])
    cost = summary["cost"]
    lines.extend(
        [
            f"- Runs: `{cost['run_count']}`",
            f"- Duration(ms): `{cost['duration_ms_total']}`",
            f"- Turns: `{cost['turns_total']}`",
            f"- Tool calls: `{cost['tool_calls_total']}`",
            f"- Tokens(total): `{cost['usage_total_tokens_total']}`",
        ]
    )

    if score["fail_reasons"]:
        lines.extend(["", "## Fail Reasons"])
        for reason in score["fail_reasons"]:
            lines.append(f"- {reason}")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Score realistic alert fixture runs against answer key")
    parser.add_argument("--db-path", type=Path, required=True)
    parser.add_argument("--answer-key", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, default=None)
    parser.add_argument("--output-md", type=Path, default=None)
    args = parser.parse_args()

    summary = score_realistic_run(db_path=args.db_path, answer_key_path=args.answer_key)

    if args.output_json:
        args.output_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.output_md:
        args.output_md.write_text(render_score_markdown(summary), encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
