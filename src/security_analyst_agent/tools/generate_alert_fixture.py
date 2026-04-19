from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import random
from typing import Any


UTC_PLUS_EIGHT = timezone(timedelta(hours=8))
STAGE_VALUES = {
    "recon",
    "exploit",
    "persistence",
    "command_execution",
    "lateral_prep",
    "reactivation",
    "unknown",
}
STAGE_ALIASES = {
    "reconnaissance": "recon",
    "discovery": "recon",
    "initial_access": "exploit",
    "initial_access_attempt": "exploit",
    "webshell_drop": "persistence",
    "command_exec": "command_execution",
    "command_execution": "command_execution",
    "post_exploitation": "lateral_prep",
    "lateral_movement": "lateral_prep",
    "beaconing": "reactivation",
}
STAGE_SEVERITY = {
    "recon": ("medium", "medium", "high"),
    "exploit": ("high", "high", "critical"),
    "persistence": ("high", "critical"),
    "command_execution": ("critical", "critical", "high"),
    "lateral_prep": ("high", "critical"),
    "reactivation": ("high", "critical"),
}
ATTACK_TITLES_BY_STAGE = {
    "recon": (
        "WAF: Suspicious URL Enumeration Pattern",
        "IDS: High-Rate Path Probing from External Source",
        "WAF: Sensitive Endpoint Discovery Behavior",
    ),
    "exploit": (
        "WAF: CVE-2024-4577 PHP-CGI Argument Injection Attempt",
        "WAF: OGNL Expression Injection Attempt Detected",
        "RASP: Server-Side Template Injection Payload Blocked",
    ),
    "persistence": (
        "EDR: Webshell-like Script Drop in Web Root",
        "HIDS: Unexpected Executable Written by Web Process",
        "FIM: Suspicious Persistence File Created on Internet-Facing Host",
    ),
    "command_execution": (
        "EDR: Shell Spawned by Web Service Process",
        "NDR: Outbound C2-like Beacon after Web Request",
        "HIDS: Encoded Command Execution from Application Worker",
    ),
    "lateral_prep": (
        "NDR: Internal Service Discovery from Compromised Web Node",
        "EDR: Credential Dumping Utility Behavior Observed",
        "NDR: East-West Authentication Probe Burst",
    ),
    "reactivation": (
        "NDR: Repeated Callback Pattern to Rare External Host",
        "EDR: Dormant Implant Reactivation Signature Matched",
        "WAF: Follow-on Post-Exploitation Request Sequence",
    ),
}
NOISE_TITLES = (
    "WAF: Generic Scanner Signature Match",
    "WAF: Repeated Directory Traversal Probe Blocked",
    "WAF: Automated Bot Rule Hit on Public Endpoint",
    "IDS: Low-Confidence Port Sweep Pattern",
    "NGFW: Low-Reputation IP Access Attempt",
    "WAF: Common Payload Fuzzing Pattern",
    "WAF: Health Check Request Misclassified by Legacy Rule",
    "IDS: Benign Crawler Triggered Recon Heuristic",
    "WAF: API Parameter Fuzzing Suspected",
    "NGFW: Automated Login Probe Pattern",
)
NOISE_RAW_STAGES = (None, None, None, "recon", "Reconnaissance", "discovery", "N/A")
NOISE_SEVERITY = ("low", "low", "low", "low", "medium")

ASSET_DST_IP = {
    "asset_api_prod": "203.0.113.10",
    "asset_admin_portal": "203.0.113.11",
    "asset_static_www": "203.0.113.12",
    "asset_billing_api": "203.0.113.20",
    "asset_finance_admin": "203.0.113.21",
    "asset_pay_gateway": "203.0.113.22",
}
NOISE_SRC_IP_POOL = (
    "192.0.2.11",
    "192.0.2.12",
    "192.0.2.13",
    "192.0.2.14",
    "192.0.2.21",
    "192.0.2.22",
    "192.0.2.23",
    "198.51.100.200",
    "198.51.100.201",
    "198.51.100.202",
    "203.0.113.201",
    "203.0.113.202",
    "203.0.113.203",
    "203.0.113.204",
)
DEFAULT_SEED = 20260419
ATTACK_ALERTS_PER_CHAIN_PER_ROUND = 15
HIGH_SIGNAL_STAGES = {"exploit", "persistence", "command_execution", "reactivation", "lateral_prep"}


@dataclass(frozen=True)
class AttackTemplate:
    chain: str
    assets: tuple[str, ...]
    src_ip_pool: tuple[str, ...]
    stage_by_round: dict[int, str]


ATTACK_TEMPLATES: tuple[AttackTemplate, ...] = (
    AttackTemplate(
        chain="chain_a",
        assets=("asset_api_prod", "asset_admin_portal", "asset_static_www"),
        src_ip_pool=("198.51.100.23", "198.51.100.24", "198.51.100.25"),
        stage_by_round={
            1: "recon",
            2: "exploit",
            3: "persistence",
            4: "command_execution",
            5: "lateral_prep",
        },
    ),
    AttackTemplate(
        chain="chain_b",
        assets=("asset_billing_api", "asset_finance_admin", "asset_pay_gateway"),
        src_ip_pool=("203.0.113.88", "203.0.113.89", "203.0.113.90"),
        stage_by_round={
            1: "recon",
            2: "exploit",
            3: "persistence",
            4: "reactivation",
            5: "command_execution",
        },
    ),
    AttackTemplate(
        chain="chain_c",
        assets=("asset_api_prod", "asset_billing_api"),
        src_ip_pool=("198.51.100.60", "198.51.100.61"),
        stage_by_round={
            1: "recon",
            2: "exploit",
            3: "command_execution",
            4: "lateral_prep",
            5: "reactivation",
        },
    ),
)


def _normalize_stage(raw_stage: str | None) -> tuple[str, str | None]:
    if raw_stage is None:
        return "unknown", None
    text = str(raw_stage).strip()
    if not text:
        return "unknown", None
    candidate = text.lower().replace(" ", "_").replace("-", "_")
    mapped = STAGE_ALIASES.get(candidate, candidate)
    if mapped in STAGE_VALUES:
        return mapped, text
    return "unknown", text


def _build_alert_id(rng: random.Random, index: int) -> str:
    return f"alt_{rng.getrandbits(48):012x}_{index:04d}"


def _sample_attack_raw_stage(stage: str, rng: random.Random) -> str | None:
    options = {
        "recon": ("recon", "Reconnaissance"),
        "exploit": ("exploit", "initial-access"),
        "persistence": ("persistence", "webshell_drop"),
        "command_execution": ("command_execution", "command-exec"),
        "lateral_prep": ("lateral_prep", "lateral-movement"),
        "reactivation": ("reactivation", "beaconing"),
    }[stage]
    return rng.choice(options)


def _sample_attack_src_ip(src_ip_pool: tuple[str, ...], rng: random.Random) -> str:
    if len(src_ip_pool) == 1:
        return src_ip_pool[0]
    if rng.random() < 0.78:
        return src_ip_pool[0]
    return rng.choice(src_ip_pool[1:])


def _build_alert_row(
    *,
    alert_id: str,
    occurred_at: datetime,
    title: str,
    severity: str,
    raw_attack_stage: str | None,
    src_ip: str,
    asset_id: str,
) -> dict[str, Any]:
    attack_stage, raw_stage = _normalize_stage(raw_attack_stage)
    return {
        "alert_id": alert_id,
        "occurred_at": occurred_at.isoformat(),
        "title": title,
        "status": "open",
        "severity": severity,
        "attack_stage": attack_stage,
        "raw_attack_stage": raw_stage,
        "src_ip": src_ip,
        "dst_ip": ASSET_DST_IP[asset_id],
        "asset_id": asset_id,
    }


def _round_start(round_index: int) -> datetime:
    return datetime(2026, 4, 13 + (round_index - 1), 9, 0, tzinfo=UTC_PLUS_EIGHT)


def _build_attack_alerts(
    *,
    round_index: int,
    template: AttackTemplate,
    rng: random.Random,
    next_alert_index: int,
) -> tuple[list[dict[str, Any]], int]:
    stage = template.stage_by_round[round_index]
    titles = ATTACK_TITLES_BY_STAGE[stage]
    severities = STAGE_SEVERITY[stage]
    start_at = _round_start(round_index)
    alerts: list[dict[str, Any]] = []
    alert_index = next_alert_index
    for _ in range(ATTACK_ALERTS_PER_CHAIN_PER_ROUND):
        occurred_at = start_at + timedelta(seconds=rng.randint(0, 30 * 60 - 1))
        asset_id = rng.choice(template.assets)
        alerts.append(
            _build_alert_row(
                alert_id=_build_alert_id(rng, alert_index),
                occurred_at=occurred_at,
                title=rng.choice(titles),
                severity=rng.choice(severities),
                raw_attack_stage=_sample_attack_raw_stage(stage, rng),
                src_ip=_sample_attack_src_ip(template.src_ip_pool, rng),
                asset_id=asset_id,
            )
        )
        alert_index += 1
    return alerts, alert_index


def _build_noise_alerts(
    *,
    round_index: int,
    count: int,
    rng: random.Random,
    next_alert_index: int,
) -> tuple[list[dict[str, Any]], int]:
    start_at = _round_start(round_index)
    assets = tuple(ASSET_DST_IP.keys())
    alerts: list[dict[str, Any]] = []
    alert_index = next_alert_index
    for _ in range(count):
        occurred_at = start_at + timedelta(seconds=rng.randint(0, 30 * 60 - 1))
        asset_id = rng.choice(assets)
        alerts.append(
            _build_alert_row(
                alert_id=_build_alert_id(rng, alert_index),
                occurred_at=occurred_at,
                title=rng.choice(NOISE_TITLES),
                severity=rng.choice(NOISE_SEVERITY),
                raw_attack_stage=rng.choice(NOISE_RAW_STAGES),
                src_ip=rng.choice(NOISE_SRC_IP_POOL),
                asset_id=asset_id,
            )
        )
        alert_index += 1
    return alerts, alert_index


def _build_answer_key(
    *,
    round_count: int,
    alerts_per_round: int,
    chain_count: int,
    seed: int,
    templates: tuple[AttackTemplate, ...],
    alert_truth_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    chains: list[dict[str, Any]] = []
    for template in templates:
        stage_by_round = {
            f"round_{round_index:02d}_realistic": template.stage_by_round[round_index]
            for round_index in range(1, round_count + 1)
            if round_index in template.stage_by_round
        }
        chains.append(
            {
                "chain_id": template.chain,
                "primary_src_ip": template.src_ip_pool[0],
                "src_ip_pool": list(template.src_ip_pool),
                "assets": list(template.assets),
                "stage_by_round": stage_by_round,
            }
        )

    sorted_alert_truth = {alert_id: alert_truth_by_id[alert_id] for alert_id in sorted(alert_truth_by_id)}
    attack_chain_ids = {template.chain for template in templates}
    attack_alert_count = sum(1 for item in sorted_alert_truth.values() if item["chain_id"] in attack_chain_ids)
    noise_alert_count = sum(1 for item in sorted_alert_truth.values() if item["chain_id"] == "noise")

    return {
        "schema_version": 1,
        "generator": "security_analyst_agent.tools.generate_alert_fixture",
        "seed": seed,
        "round_count": round_count,
        "alerts_per_round": alerts_per_round,
        "chain_count": chain_count,
        "attack_alerts_per_chain_per_round": ATTACK_ALERTS_PER_CHAIN_PER_ROUND,
        "high_signal_stages": sorted(HIGH_SIGNAL_STAGES),
        "chains": chains,
        "expected_entities": {
            "primary_attack_ips": [item["primary_src_ip"] for item in chains],
            "all_attack_src_ips": sorted({ip for item in chains for ip in item["src_ip_pool"]}),
            "noise_src_ip_pool": sorted(set(NOISE_SRC_IP_POOL)),
        },
        "totals": {
            "alert_count": len(sorted_alert_truth),
            "attack_alert_count": attack_alert_count,
            "noise_alert_count": noise_alert_count,
        },
        "alert_truth": sorted_alert_truth,
    }


def generate_rounds_with_answer_key(
    *,
    round_count: int,
    alerts_per_round: int,
    chain_count: int,
    seed: int = DEFAULT_SEED,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if round_count <= 0:
        raise ValueError("round_count must be > 0")
    if alerts_per_round <= 0:
        raise ValueError("alerts_per_round must be > 0")
    if chain_count <= 0 or chain_count > len(ATTACK_TEMPLATES):
        raise ValueError(f"chain_count must be in [1, {len(ATTACK_TEMPLATES)}]")

    attack_total = ATTACK_ALERTS_PER_CHAIN_PER_ROUND * chain_count
    if attack_total >= alerts_per_round:
        raise ValueError("alerts_per_round must exceed attack alerts per round")

    rng = random.Random(seed)
    templates = ATTACK_TEMPLATES[:chain_count]
    rounds: list[dict[str, Any]] = []
    alert_truth_by_id: dict[str, dict[str, Any]] = {}
    previous_round_id: str | None = None
    next_alert_index = 1

    for round_index in range(1, round_count + 1):
        round_id = f"round_{round_index:02d}_realistic"
        attack_alerts: list[dict[str, Any]] = []
        for template in templates:
            generated, next_alert_index = _build_attack_alerts(
                round_index=round_index,
                template=template,
                rng=rng,
                next_alert_index=next_alert_index,
            )
            attack_alerts.extend(generated)
            for alert in generated:
                alert_truth_by_id[alert["alert_id"]] = {
                    "round_id": round_id,
                    "chain_id": template.chain,
                    "attack_stage": alert["attack_stage"],
                    "severity": alert["severity"],
                    "src_ip": alert.get("src_ip"),
                    "asset_id": alert.get("asset_id"),
                    "is_attack": True,
                    "is_high_signal": (
                        alert["attack_stage"] in HIGH_SIGNAL_STAGES
                        and alert["severity"] in {"high", "critical"}
                    ),
                }

        noise_count = alerts_per_round - len(attack_alerts)
        noise_alerts, next_alert_index = _build_noise_alerts(
            round_index=round_index,
            count=noise_count,
            rng=rng,
            next_alert_index=next_alert_index,
        )
        for alert in noise_alerts:
            alert_truth_by_id[alert["alert_id"]] = {
                "round_id": round_id,
                "chain_id": "noise",
                "attack_stage": alert["attack_stage"],
                "severity": alert["severity"],
                "src_ip": alert.get("src_ip"),
                "asset_id": alert.get("asset_id"),
                "is_attack": False,
                "is_high_signal": False,
            }

        alerts = attack_alerts + noise_alerts
        alerts.sort(key=lambda item: (item["occurred_at"], item["alert_id"]))

        rounds.append(
            {
                "round_id": round_id,
                "previous_round_id": previous_round_id,
                "cases_upsert": [],
                "alerts": alerts,
                "timeline_events": [],
                "evidence": [],
                "intel_cache_upsert": [],
            }
        )
        previous_round_id = round_id
    answer_key = _build_answer_key(
        round_count=round_count,
        alerts_per_round=alerts_per_round,
        chain_count=chain_count,
        seed=seed,
        templates=templates,
        alert_truth_by_id=alert_truth_by_id,
    )
    return rounds, answer_key


def generate_rounds(
    *,
    round_count: int,
    alerts_per_round: int,
    chain_count: int,
    seed: int = DEFAULT_SEED,
) -> list[dict[str, Any]]:
    rounds, _ = generate_rounds_with_answer_key(
        round_count=round_count,
        alerts_per_round=alerts_per_round,
        chain_count=chain_count,
        seed=seed,
    )
    return rounds


def write_rounds(
    *,
    output_dir: Path,
    round_count: int,
    alerts_per_round: int,
    chain_count: int,
    seed: int,
) -> Path:
    rounds, answer_key = generate_rounds_with_answer_key(
        round_count=round_count,
        alerts_per_round=alerts_per_round,
        chain_count=chain_count,
        seed=seed,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "rounds.json"
    output_path.write_text(json.dumps(rounds, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    answer_key_path = output_dir / "answer_key.json"
    answer_key_path.write_text(json.dumps(answer_key, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate realistic memory-spike alert fixture rounds")
    parser.add_argument("--output-dir", type=Path, default=Path("fixtures/spike_memory_realistic"))
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--per-round", type=int, default=1000)
    parser.add_argument("--chains", type=int, default=2)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()

    output_path = write_rounds(
        output_dir=args.output_dir,
        round_count=args.rounds,
        alerts_per_round=args.per_round,
        chain_count=args.chains,
        seed=args.seed,
    )
    print(
        json.dumps(
            {
                "ok": True,
                "output_path": str(output_path),
                "answer_key_path": str(output_path.parent / "answer_key.json"),
                "rounds": args.rounds,
                "per_round": args.per_round,
                "chains": args.chains,
                "seed": args.seed,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
