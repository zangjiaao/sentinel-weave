from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from security_analyst_agent.config import PROJECT_ROOT
from security_analyst_agent.db import connect_db, create_schema
from security_analyst_agent.memory_spike import apply_memory_spike_round, bootstrap_memory_spike_database
from security_analyst_agent.tool_dispatch import dispatch_tool

MANIFEST_DIR = PROJECT_ROOT / "docs" / "runbooks" / "manifests"
DEFAULT_DB_PATH = PROJECT_ROOT / "runbook-verify.db"


@dataclass
class RunbookVerificationError(AssertionError):
    scenario: str
    round_id: str | None
    assertion: str
    detail: str

    def __str__(self) -> str:
        location = f" round={self.round_id}" if self.round_id else ""
        return f"scenario={self.scenario}{location} assertion={self.assertion}: {self.detail}"


def _read_manifest(scenario: str) -> dict[str, Any]:
    manifest_path = MANIFEST_DIR / f"{scenario}.json"
    if not manifest_path.exists():
        raise RunbookVerificationError(
            scenario=scenario,
            round_id=None,
            assertion="manifest_exists",
            detail=f"manifest not found: {manifest_path}",
        )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("scenario") != scenario:
        raise RunbookVerificationError(
            scenario=scenario,
            round_id=None,
            assertion="manifest_scenario",
            detail=f"manifest scenario mismatch: {manifest.get('scenario')}",
        )
    return manifest


def _reset_running_runs(conn, *, finished_at: str) -> None:
    conn.execute(
        """
        update patrol_runs
        set status = 'success', finished_at = coalesce(finished_at, ?)
        where status = 'running'
        """,
        (finished_at,),
    )


def _create_round_run(conn, *, round_spec: dict[str, Any]) -> None:
    _reset_running_runs(conn, finished_at=round_spec["started_at"])
    conn.execute(
        """
        insert into patrol_runs (
          run_id,
          trigger_source,
          status,
          summary,
          started_at,
          analysis_cutoff_at
        ) values (?, ?, ?, ?, ?, ?)
        """,
        (
            round_spec["run_id"],
            "runbook_verify",
            "running",
            f"runbook verify {round_spec['round_id']}",
            round_spec["started_at"],
            round_spec["analysis_cutoff_at"],
        ),
    )
    conn.commit()


def _finish_round_run(conn, *, round_spec: dict[str, Any]) -> None:
    conn.execute(
        """
        update patrol_runs
        set status = 'success', finished_at = ?
        where run_id = ?
        """,
        (round_spec["analysis_cutoff_at"], round_spec["run_id"]),
    )
    conn.commit()


def _assert_no_intersection(
    *,
    scenario: str,
    round_id: str,
    assertion: str,
    actual_ids: list[str],
    excluded_ids: list[str],
) -> None:
    leaked_ids = sorted(set(actual_ids).intersection(excluded_ids))
    if leaked_ids:
        raise RunbookVerificationError(
            scenario=scenario,
            round_id=round_id,
            assertion=assertion,
            detail=f"unexpected evidence ids: {leaked_ids}",
        )


def _run_check(conn, *, scenario: str, round_id: str, check: dict[str, Any], summary: dict[str, Any]) -> None:
    check_type = check["type"]
    if check_type == "alert_detail_excludes_evidence":
        result = dispatch_tool(conn, "alert.detail", {"alert_id": check["alert_id"]}, source="mcp")
        evidence_ids = result.get("refs", {}).get("evidence_ids", [])
        _assert_no_intersection(
            scenario=scenario,
            round_id=round_id,
            assertion=check_type,
            actual_ids=evidence_ids,
            excluded_ids=check["excluded_evidence_ids"],
        )
        summary[check["summary_key"]] = evidence_ids
        return

    if check_type == "explain_link_excludes_evidence":
        result = dispatch_tool(
            conn,
            "case.explain-link",
            {"case_id": check["case_id"], "target_type": "alert", "target_id": check["alert_id"]},
            source="mcp",
        )
        evidence_ids = result.get("data", {}).get("link_decision", {}).get("supporting_evidence_ids", [])
        _assert_no_intersection(
            scenario=scenario,
            round_id=round_id,
            assertion=check_type,
            actual_ids=evidence_ids,
            excluded_ids=check["excluded_evidence_ids"],
        )
        summary[check["summary_key"]] = evidence_ids
        return

    raise RunbookVerificationError(
        scenario=scenario,
        round_id=round_id,
        assertion="known_check_type",
        detail=f"unsupported check type: {check_type}",
    )


def _run_action(conn, *, scenario: str, round_id: str, action: dict[str, Any]) -> None:
    result = dispatch_tool(conn, action["tool"], action.get("payload", {}), source="mcp")
    if not result.get("ok"):
        raise RunbookVerificationError(
            scenario=scenario,
            round_id=round_id,
            assertion="tool_action_ok",
            detail=f"{action['tool']} failed: {result.get('summary')}",
        )


def _load_high_attacker_ips(conn) -> list[str]:
    rows = conn.execute(
        """
        select entity_key
        from entity_assessments
        where entity_type = 'ip'
          and is_current = 1
          and risk_level = 'high'
          and verdict = 'attacker'
        order by entity_key asc
        """
    ).fetchall()
    return [row["entity_key"] for row in rows]


def _load_noise_ips(conn) -> list[str]:
    rows = conn.execute(
        """
        select entity_key
        from entity_assessments
        where entity_type = 'ip'
          and is_current = 1
          and risk_level = 'low'
          and verdict = 'noise'
        order by entity_key asc
        """
    ).fetchall()
    return [row["entity_key"] for row in rows]


def _load_compromised_host(conn, entity_key: str) -> dict[str, str] | None:
    row = conn.execute(
        """
        select entity_key, risk_level, verdict
        from entity_assessments
        where entity_type = 'asset'
          and entity_key = ?
          and is_current = 1
        order by occurred_at desc
        limit 1
        """,
        (entity_key,),
    ).fetchone()
    return dict(row) if row else None


def _assert_final_state(conn, *, scenario: str, assertions: dict[str, Any], summary: dict[str, Any]) -> None:
    high_attacker_ips = _load_high_attacker_ips(conn)
    expected_high_attacker_ips = assertions["high_attacker_ips"]
    if high_attacker_ips != expected_high_attacker_ips:
        raise RunbookVerificationError(
            scenario=scenario,
            round_id=None,
            assertion="high_attacker_ips",
            detail=f"expected {expected_high_attacker_ips}, got {high_attacker_ips}",
        )
    summary["high_attacker_ips"] = high_attacker_ips

    noise_ips = _load_noise_ips(conn)
    expected_noise_ips = assertions["noise_ips"]
    if noise_ips != expected_noise_ips:
        raise RunbookVerificationError(
            scenario=scenario,
            round_id=None,
            assertion="noise_ips",
            detail=f"expected {expected_noise_ips}, got {noise_ips}",
        )
    summary["noise_ips"] = noise_ips

    not_high_attacker_ips = assertions["not_high_attacker_ips"]
    leaked_noise_ips = sorted(set(high_attacker_ips).intersection(not_high_attacker_ips))
    if leaked_noise_ips:
        raise RunbookVerificationError(
            scenario=scenario,
            round_id=None,
            assertion="not_high_attacker_ips",
            detail=f"noise IPs became high attackers: {leaked_noise_ips}",
        )

    compromised_assertion = assertions["compromised_host"]
    compromised_host = _load_compromised_host(conn, compromised_assertion["entity_key"])
    if compromised_host is None:
        raise RunbookVerificationError(
            scenario=scenario,
            round_id=None,
            assertion="compromised_host",
            detail=f"missing compromised host: {compromised_assertion['entity_key']}",
        )
    if compromised_host["verdict"] != compromised_assertion["verdict"]:
        raise RunbookVerificationError(
            scenario=scenario,
            round_id=None,
            assertion="compromised_host_verdict",
            detail=f"expected {compromised_assertion['verdict']}, got {compromised_host['verdict']}",
        )
    if compromised_host["risk_level"] not in compromised_assertion["allowed_risk_levels"]:
        raise RunbookVerificationError(
            scenario=scenario,
            round_id=None,
            assertion="compromised_host_risk",
            detail=f"unexpected risk level: {compromised_host['risk_level']}",
        )
    summary["compromised_host"] = compromised_host


def run_scenario(scenario: str, db_path: Path | None = None) -> dict[str, Any]:
    manifest = _read_manifest(scenario)
    target_db_path = db_path or DEFAULT_DB_PATH
    if target_db_path.exists():
        target_db_path.unlink()

    bootstrap_memory_spike_database(target_db_path)
    summary: dict[str, Any] = {
        "scenario": scenario,
        "db_path": str(target_db_path),
        "round_count": len(manifest["rounds"]),
        "round_runs": [],
    }

    for round_spec in manifest["rounds"]:
        round_id = round_spec["round_id"]
        apply_memory_spike_round(target_db_path, round_id)
        conn = connect_db(target_db_path)
        try:
            create_schema(conn)
            _create_round_run(conn, round_spec=round_spec)
            for check in round_spec.get("checks", []):
                _run_check(conn, scenario=scenario, round_id=round_id, check=check, summary=summary)
            for action in round_spec.get("actions", []):
                _run_action(conn, scenario=scenario, round_id=round_id, action=action)
            _finish_round_run(conn, round_spec=round_spec)
            summary["round_runs"].append(
                {
                    "round_id": round_id,
                    "run_id": round_spec["run_id"],
                    "analysis_cutoff_at": round_spec["analysis_cutoff_at"],
                }
            )
        finally:
            conn.close()

    conn = connect_db(target_db_path)
    try:
        create_schema(conn)
        _assert_final_state(conn, scenario=scenario, assertions=manifest["final_assertions"], summary=summary)
        summary["rounds_applied"] = conn.execute("select count(*) from verify_spike_round_runs").fetchone()[0]
        summary["link_decisions_count"] = conn.execute("select count(*) from link_decisions").fetchone()[0]
        summary["case_assessments_count"] = conn.execute("select count(*) from case_assessments").fetchone()[0]
        summary["entity_assessments_count"] = conn.execute("select count(*) from entity_assessments").fetchone()[0]
        return summary
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify executable runbook scenarios")
    parser.add_argument("--scenario", default="hermes-memory-spike")
    parser.add_argument("--db-path", type=Path, default=DEFAULT_DB_PATH)
    args = parser.parse_args()

    summary = run_scenario(args.scenario, db_path=args.db_path)
    print(f"PASS: runbook scenario {args.scenario}")
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
