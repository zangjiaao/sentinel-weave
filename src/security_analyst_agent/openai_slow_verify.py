from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Callable

from security_analyst_agent.config import DEFAULT_OPENAI_PATROL_MODEL, PROJECT_ROOT
from security_analyst_agent.db import connect_db
from security_analyst_agent.hermes_slow_verify import (
    HermesSlowVerificationError,
    _bootstrap_db,
    _emit_progress,
    _verify_final_db_state,
    _verify_round_db_state,
    load_integration_manifest,
    resolve_fixture_dir,
    resolve_round_specs,
)
from security_analyst_agent.memory_spike import apply_memory_spike_round
from security_analyst_agent.patrol_trigger import trigger_patrol_from_ingest

DEFAULT_DB_PATH = PROJECT_ROOT / "openai-slow-verify.db"
ProgressReporter = Callable[[int, int, str], None]
TriggerRunner = Callable[..., dict[str, Any]]


def _verify_with_mcp_auto_alias(conn, verify_fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    conn.execute("savepoint openai_slow_verify_alias")
    conn.execute(
        """
        update patrol_runs
        set trigger_source = 'mcp_auto'
        where trigger_source = 'ingest_event'
        """
    )
    try:
        return verify_fn()
    finally:
        conn.execute("rollback to openai_slow_verify_alias")
        conn.execute("release openai_slow_verify_alias")


def run_openai_slow_integration(
    *,
    scenario: str,
    db_path: Path | None = None,
    model: str | None = None,
    keep_artifacts: bool = False,
    progress: ProgressReporter | None = None,
    trigger_runner: TriggerRunner | None = None,
) -> dict[str, Any]:
    del keep_artifacts
    reporter = progress or (lambda _step, _total, _message: None)
    manifest = load_integration_manifest(scenario)
    fixture_dir = resolve_fixture_dir(manifest)
    round_specs = resolve_round_specs(manifest)
    total_steps = 2 + len(round_specs) * 2 + 1

    reporter(1, total_steps, "读取慢速集成 manifest")
    target_db_path = db_path or DEFAULT_DB_PATH
    if target_db_path.exists():
        target_db_path.unlink()

    reporter(2, total_steps, "初始化测试数据库")
    _bootstrap_db(target_db_path, fixture_dir=fixture_dir)

    trigger = trigger_runner or trigger_patrol_from_ingest
    selected_model = model or DEFAULT_OPENAI_PATROL_MODEL
    round_summaries: list[dict[str, Any]] = []

    step = 3
    for round_spec in round_specs:
        round_id = round_spec["round_id"]
        reporter(step, total_steps, f"应用 {round_id}")
        apply_memory_spike_round(target_db_path, round_id, fixture_dir=fixture_dir)
        step += 1

        reporter(step, total_steps, f"运行并校验 OpenAI patrol {round_id}")
        started_at_iso = datetime.now(timezone.utc).isoformat()
        trigger_result = trigger(
            target_db_path,
            trigger_mode="openai",
            patrol_max_turns=int(round_spec.get("max_turns", 18)),
            openai_model=selected_model,
        )
        if trigger_result.get("status") != "success":
            raise HermesSlowVerificationError(
                f"openai_trigger:{round_id}",
                f"trigger failed: {trigger_result}",
            )

        conn = connect_db(target_db_path)
        try:
            round_summary = _verify_with_mcp_auto_alias(
                conn,
                lambda: _verify_round_db_state(conn, round_spec=round_spec, started_at=started_at_iso),
            )
        finally:
            conn.close()
        round_summary["trigger_result"] = trigger_result
        round_summaries.append(round_summary)
        step += 1

    conn = connect_db(target_db_path)
    try:
        reporter(step, total_steps, "校验聚合数据库结果")
        db_summary = _verify_with_mcp_auto_alias(
            conn,
            lambda: _verify_final_db_state(conn, manifest=manifest, round_count=len(round_specs)),
        )
    finally:
        conn.close()

    return {
        "scenario": scenario,
        "db_path": str(target_db_path),
        "trigger_mode": "openai",
        "openai_model": selected_model,
        "round_summaries": round_summaries,
        **db_summary,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run OpenAI trigger-path slow integration verification")
    parser.add_argument("--scenario", default="hermes-slow-integration")
    parser.add_argument("--db-path", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--model", default=None)
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()

    try:
        summary = run_openai_slow_integration(
            scenario=args.scenario,
            db_path=args.db_path,
            model=args.model,
            keep_artifacts=args.keep_artifacts,
            progress=_emit_progress,
        )
    except HermesSlowVerificationError as exc:
        print(f"FAIL: openai slow integration verify\n{exc}")
        raise SystemExit(1) from exc

    print(f"PASS: openai slow integration verify {args.scenario}")
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
