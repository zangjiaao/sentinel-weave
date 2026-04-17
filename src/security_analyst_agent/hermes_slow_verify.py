from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable

from security_analyst_agent.config import PROJECT_ROOT
from security_analyst_agent.db import connect_db
from security_analyst_agent.memory_spike import apply_memory_spike_round, bootstrap_memory_spike_database

MANIFEST_DIR = PROJECT_ROOT / "docs" / "runbooks" / "manifests"
DEFAULT_DB_PATH = PROJECT_ROOT / "hermes-slow-verify.db"
DEFAULT_SOURCE_HERMES_HOME = Path.home() / ".hermes"
DEFAULT_MCP_HOST = "127.0.0.1"
DEFAULT_SOURCE_TAG = "tool"
DEFAULT_FINALIZE_QUERY = (
    "Do not call any tools. Based only on evidence already collected in this session, "
    "output final answer with exact Markdown headers: "
    "'## Patrol Action Summary', '## Remaining Uncertainty', '## Memory Summary'."
)
ProgressReporter = Callable[[int, int, str], None]


@dataclass
class HermesSlowVerificationError(RuntimeError):
    stage: str
    detail: str
    artifact_dir: str | None = None

    def __str__(self) -> str:
        suffix = f" artifacts={self.artifact_dir}" if self.artifact_dir else ""
        return f"stage={self.stage}: {self.detail}{suffix}"


def load_integration_manifest(scenario: str) -> dict[str, Any]:
    path = MANIFEST_DIR / f"{scenario}.json"
    if not path.exists():
        raise HermesSlowVerificationError("manifest", f"manifest not found: {path}")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("scenario") != scenario:
        raise HermesSlowVerificationError("manifest", f"scenario mismatch: {manifest.get('scenario')}")
    return manifest


def resolve_round_specs(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    round_defaults = deepcopy(manifest.get("round_defaults", {}))
    rounds = manifest.get("rounds", [])
    if not rounds:
        raise HermesSlowVerificationError("manifest", "rounds must not be empty")

    round_specs: list[dict[str, Any]] = []
    for index, round_item in enumerate(rounds, start=1):
        if "round_id" not in round_item:
            raise HermesSlowVerificationError("manifest", f"round {index} missing round_id")
        round_spec = deepcopy(round_defaults)
        round_spec.update(deepcopy(round_item))
        round_specs.append(round_spec)
    return round_specs


def build_chat_command(
    *,
    query: str,
    max_turns: int,
    model: str | None = None,
    provider: str | None = None,
    skills: list[str] | None = None,
    continue_latest: bool = False,
) -> list[str]:
    command = ["hermes", "chat", "-q", query, "-Q", "--max-turns", str(max_turns), "--source", DEFAULT_SOURCE_TAG]
    if continue_latest:
        command.append("--continue")
    if model:
        command.extend(["-m", model])
    if provider:
        command.extend(["--provider", provider])
    if skills:
        command.extend(["-s", ",".join(skills)])
    return command


def prepare_isolated_hermes_home(source_home: Path, dest_home: Path, repo_skill_dir: Path) -> None:
    dest_home.mkdir(parents=True, exist_ok=True)
    for filename in ("config.yaml", ".env", "auth.json"):
        source_path = source_home / filename
        if source_path.exists():
            shutil.copy2(source_path, dest_home / filename)

    soul_template = PROJECT_ROOT / "hermes" / "SOUL.patrol.template.md"
    if not soul_template.exists():
        soul_template = PROJECT_ROOT / "hermes" / "SOUL.template.md"
    shutil.copy2(soul_template, dest_home / "SOUL.md")

    (dest_home / "skills").mkdir(parents=True, exist_ok=True)
    target_skill_dir = dest_home / "skills" / repo_skill_dir.name
    if target_skill_dir.exists():
        shutil.rmtree(target_skill_dir)
    shutil.copytree(repo_skill_dir, target_skill_dir)


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((DEFAULT_MCP_HOST, 0))
        return int(sock.getsockname()[1])


def _run_command(
    command: list[str],
    *,
    env: dict[str, str],
    cwd: Path,
    timeout_sec: int,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
        check=False,
    )


def _tail_text(path: Path, max_lines: int = 40) -> str:
    if not path.exists():
        return ""
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    return "\n".join(lines[-max_lines:])


def _emit_progress(step: int, total: int, message: str) -> None:
    print(f"[{step}/{total}] {message}", file=sys.stderr, flush=True)


def _wait_for_port(host: str, port: int, timeout_sec: int) -> None:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            try:
                sock.connect((host, port))
                return
            except OSError:
                time.sleep(0.2)
    raise HermesSlowVerificationError("mcp_server", f"port not ready: {host}:{port}")


def _start_mcp_server(
    *,
    db_path: Path,
    artifact_dir: Path,
) -> tuple[subprocess.Popen[str], str]:
    port = _find_free_port()
    stdout_path = artifact_dir / "mcp-server.stdout.log"
    stderr_path = artifact_dir / "mcp-server.stderr.log"
    stdout_handle = stdout_path.open("w", encoding="utf-8")
    stderr_handle = stderr_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [
            "uv",
            "run",
            "python",
            "-m",
            "security_analyst_agent.mcp_server",
            "--db-path",
            str(db_path),
            "--transport",
            "streamable-http",
            "--host",
            DEFAULT_MCP_HOST,
            "--port",
            str(port),
            "--streamable-http-path",
            "/mcp",
        ],
        cwd=str(PROJECT_ROOT),
        stdout=stdout_handle,
        stderr=stderr_handle,
        text=True,
        env=os.environ.copy(),
    )
    try:
        _wait_for_port(DEFAULT_MCP_HOST, port, timeout_sec=20)
    except Exception:
        process.terminate()
        process.wait(timeout=5)
        raise
    return process, f"http://{DEFAULT_MCP_HOST}:{port}/mcp"


def _terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _configure_temp_hermes_mcp(env: dict[str, str], *, mcp_url: str) -> str:
    result = _run_command(
        ["hermes", "config", "set", "mcp_servers.secagent.url", mcp_url],
        env=env,
        cwd=PROJECT_ROOT,
        timeout_sec=20,
    )
    if result.returncode != 0:
        raise HermesSlowVerificationError("hermes_config", result.stderr.strip() or result.stdout.strip())

    test_result = _run_command(
        ["hermes", "mcp", "test", "secagent"],
        env=env,
        cwd=PROJECT_ROOT,
        timeout_sec=30,
    )
    output = f"{test_result.stdout}\n{test_result.stderr}".strip()
    if test_result.returncode != 0:
        raise HermesSlowVerificationError("hermes_mcp_test", output)
    return output


def _preflight_hermes_chat(
    *,
    env: dict[str, str],
    manifest: dict[str, Any],
    model: str | None,
    provider: str | None,
    artifact_dir: Path,
) -> str:
    result = _run_command(
        build_chat_command(
            query=manifest["preflight_query"],
            max_turns=1,
            model=model,
            provider=provider,
            skills=[],
        ),
        env=env,
        cwd=PROJECT_ROOT,
        timeout_sec=90,
    )
    output = f"{result.stdout}\n{result.stderr}".strip()
    if result.returncode != 0 or "READY" not in output:
        log_tail = _tail_text(artifact_dir / "hermes-home" / "logs" / "errors.log")
        detail = output or "Hermes chat preflight failed; check model/provider credentials"
        if log_tail:
            detail = f"{detail}\n--- hermes errors.log ---\n{log_tail}"
        raise HermesSlowVerificationError(
            "hermes_preflight",
            detail,
            artifact_dir=str(artifact_dir),
        )
    return output


def _bootstrap_db(db_path: Path) -> None:
    bootstrap_memory_spike_database(db_path)


def _assert_tool_requirements(*, tool_names: list[str], expectations: dict[str, Any], stage: str) -> None:
    min_tool_calls = int(expectations.get("min_tool_calls", 0))
    if len(tool_names) < min_tool_calls:
        raise HermesSlowVerificationError(stage, f"expected at least {min_tool_calls} tool calls, got {tool_names}")
    max_tool_calls = expectations.get("max_tool_calls")
    if max_tool_calls is not None and len(tool_names) > int(max_tool_calls):
        raise HermesSlowVerificationError(stage, f"expected at most {max_tool_calls} tool calls, got {tool_names}")

    required_tool_names = expectations.get("required_tool_names", [])
    for tool_name in required_tool_names:
        if tool_name not in tool_names:
            raise HermesSlowVerificationError(stage, f"missing required tool: {tool_name}")

    for group in expectations.get("required_any_tool_names", []):
        if not any(tool_name in tool_names for tool_name in group):
            raise HermesSlowVerificationError(stage, f"missing any-of tool group: {group}")

    first_tool_name = expectations.get("first_tool_name")
    if first_tool_name:
        if not tool_names:
            raise HermesSlowVerificationError(stage, "expected at least one tool call")
        if tool_names[0] != first_tool_name:
            raise HermesSlowVerificationError(stage, f"first tool call must be {first_tool_name}, got {tool_names[0]}")


def _verify_chat_output(*, chat_stdout: str, round_spec: dict[str, Any], artifact_dir: Path) -> None:
    round_id = round_spec["round_id"]
    normalized_lines = [line.strip() for line in chat_stdout.splitlines() if line.strip()]
    if chat_stdout.strip() == "[SILENT]" or "[SILENT]" in normalized_lines:
        return
    expected_exact_output = round_spec.get("required_exact_output")
    if expected_exact_output is not None:
        if chat_stdout.strip() != expected_exact_output:
            raise HermesSlowVerificationError(
                "chat_output",
                f"round {round_id} expected exact output {expected_exact_output!r}, got {chat_stdout.strip()!r}",
                artifact_dir=str(artifact_dir),
            )
        return

    for header in round_spec.get("required_output_headers", []):
        if header not in chat_stdout:
            raise HermesSlowVerificationError(
                "chat_output",
                f"round {round_id} missing output header: {header}",
                artifact_dir=str(artifact_dir),
            )


def _run_chat_with_continue_fallback(
    *,
    run_command: Callable[..., subprocess.CompletedProcess[str]],
    query: str,
    max_turns: int,
    model: str | None,
    provider: str | None,
    skills: list[str],
    env: dict[str, str],
    cwd: Path,
    timeout_sec: int,
    artifact_dir: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    continue_result = run_command(
        build_chat_command(
            query=query,
            max_turns=max_turns,
            model=model,
            provider=provider,
            skills=skills,
            continue_latest=True,
        ),
        env=env,
        cwd=cwd,
        timeout_sec=timeout_sec,
    )
    if continue_result.returncode == 0:
        return continue_result

    fresh_result = run_command(
        build_chat_command(
            query=query,
            max_turns=max_turns,
            model=model,
            provider=provider,
            skills=skills,
            continue_latest=False,
        ),
        env=env,
        cwd=cwd,
        timeout_sec=timeout_sec,
    )
    if fresh_result.returncode == 0:
        return fresh_result

    continue_output = f"{continue_result.stdout}\n{continue_result.stderr}".strip()
    fresh_output = f"{fresh_result.stdout}\n{fresh_result.stderr}".strip()
    raise HermesSlowVerificationError(
        "hermes_chat",
        "continue and fresh chat both failed: "
        f"continue_rc={continue_result.returncode}, fresh_rc={fresh_result.returncode}, "
        f"continue_output={continue_output or '<empty>'}, fresh_output={fresh_output or '<empty>'}",
        artifact_dir=str(artifact_dir) if artifact_dir else None,
    )


def _is_missing_header_error(error: HermesSlowVerificationError, *, round_id: str) -> bool:
    return error.stage == "chat_output" and f"round {round_id} missing output header:" in error.detail


def _verify_round_db_state(conn, *, round_spec: dict[str, Any], started_at: str) -> dict[str, Any]:
    tool_rows = conn.execute(
        """
        select tool_name, occurred_at, source, run_id
        from agent_tool_calls
        where occurred_at >= ?
        order by occurred_at asc
        """,
        (started_at,),
    ).fetchall()
    tool_names = [row["tool_name"] for row in tool_rows]
    _assert_tool_requirements(
        tool_names=tool_names,
        expectations=round_spec,
        stage=f"round_db_assertions:{round_spec['round_id']}",
    )

    patrol_runs = conn.execute(
        """
        select run_id, trigger_source, status, summary, analysis_cutoff_at
        from patrol_runs
        where started_at >= ?
        order by started_at asc
        """,
        (started_at,),
    ).fetchall()
    if not patrol_runs:
        raise HermesSlowVerificationError(
            f"round_db_assertions:{round_spec['round_id']}",
            "no patrol_runs created by Hermes flow",
        )
    if not any(row["trigger_source"] == "mcp_auto" for row in patrol_runs):
        raise HermesSlowVerificationError(
            f"round_db_assertions:{round_spec['round_id']}",
            "no mcp_auto patrol_runs created by Hermes flow",
        )

    return {
        "round_id": round_spec["round_id"],
        "tool_calls_count": len(tool_names),
        "tool_names": tool_names,
        "patrol_runs": [dict(row) for row in patrol_runs],
    }


def _verify_final_db_state(conn, *, manifest: dict[str, Any], round_count: int) -> dict[str, Any]:
    tool_rows = conn.execute(
        """
        select tool_name, occurred_at, source, run_id, result_ok, result_summary
        from agent_tool_calls
        order by occurred_at asc
        """
    ).fetchall()
    succeeded_tools_in_run = {
        (row["run_id"], row["tool_name"]) for row in tool_rows if int(row["result_ok"]) == 1
    }
    tool_names = [row["tool_name"] for row in tool_rows]
    final_assertions = manifest.get("final_assertions", {})
    _assert_tool_requirements(tool_names=tool_names, expectations=final_assertions, stage="final_db_assertions")

    def _is_ignorable_failed_tool_call(row: Any) -> bool:
        if (row["run_id"], row["tool_name"]) in succeeded_tools_in_run:
            return True
        summary = row["result_summary"] or ""
        if str(summary).startswith("未找到案件 "):
            return row["tool_name"] in {"case.get", "actor.case-find-candidates"}
        return False

    failed_tool_rows = [
        row
        for row in tool_rows
        if int(row["result_ok"]) == 0 and not _is_ignorable_failed_tool_call(row)
    ]
    max_failed_tool_calls = int(final_assertions.get("max_failed_tool_calls", len(failed_tool_rows)))
    if len(failed_tool_rows) > max_failed_tool_calls:
        failed_summary = [f"{row['tool_name']}:{row['result_summary']}" for row in failed_tool_rows]
        raise HermesSlowVerificationError(
            "final_db_assertions",
            f"failed tool calls exceeded limit: {failed_summary}",
        )

    patrol_runs = conn.execute(
        """
        select run_id, trigger_source, status, summary, analysis_cutoff_at
        from patrol_runs
        where trigger_source = 'mcp_auto'
        order by started_at asc
        """
    ).fetchall()
    min_patrol_runs = int(final_assertions.get("min_patrol_runs", round_count))
    if len(patrol_runs) < min_patrol_runs:
        raise HermesSlowVerificationError(
            "final_db_assertions",
            f"expected at least {min_patrol_runs} mcp_auto patrol runs, got {len(patrol_runs)}",
        )

    entity_assessments_count = conn.execute("select count(*) from entity_assessments").fetchone()[0]
    min_entity_assessments = int(final_assertions.get("min_entity_assessments", 0))
    if entity_assessments_count < min_entity_assessments:
        raise HermesSlowVerificationError(
            "final_db_assertions",
            f"expected at least {min_entity_assessments} entity assessments, got {entity_assessments_count}",
        )

    alert_decisions_count = conn.execute("select count(*) from alert_decisions").fetchone()[0]
    min_alert_decisions = int(final_assertions.get("min_alert_decisions", 0))
    if alert_decisions_count < min_alert_decisions:
        raise HermesSlowVerificationError(
            "final_db_assertions",
            f"expected at least {min_alert_decisions} alert decisions, got {alert_decisions_count}",
        )

    case_assessments_count = conn.execute("select count(*) from case_assessments").fetchone()[0]
    min_case_assessments = int(final_assertions.get("min_case_assessments", 0))
    if case_assessments_count < min_case_assessments:
        raise HermesSlowVerificationError(
            "final_db_assertions",
            f"expected at least {min_case_assessments} case assessments, got {case_assessments_count}",
        )

    current_entities = [
        dict(row)
        for row in conn.execute(
            """
            select entity_type, entity_key, risk_level, verdict, related_case_id
            from entity_assessments
            where is_current = 1
            """
        ).fetchall()
    ]
    for required_entity in final_assertions.get("required_current_entities", []):
        matched = False
        for current_entity in current_entities:
            if current_entity["entity_type"] != required_entity["entity_type"]:
                continue
            if current_entity["entity_key"] != required_entity["entity_key"]:
                continue
            if current_entity["risk_level"] != required_entity["risk_level"]:
                continue
            if current_entity["verdict"] != required_entity["verdict"]:
                continue
            if "related_case_id" in required_entity and current_entity["related_case_id"] != required_entity["related_case_id"]:
                continue
            matched = True
            break
        if not matched:
                raise HermesSlowVerificationError(
                    "final_db_assertions",
                    f"missing required current entity: {required_entity}",
                )

    if final_assertions.get("require_primary_case_actor_for_single_chain", False):
        single_chain_case_ids: set[str] = set()
        for alert_id in final_assertions.get("required_single_chain_alert_ids", []):
            row = conn.execute(
                """
                select case_id
                from case_alert_links
                where alert_id = ? and is_active = 1
                limit 1
                """,
                (alert_id,),
            ).fetchone()
            if row is not None:
                single_chain_case_ids.add(row["case_id"])
        for case_id in single_chain_case_ids:
            row = conn.execute(
                """
                select case_actor_id
                from case_actor_profiles
                where case_id = ? and is_primary = 1
                limit 1
                """,
                (case_id,),
            ).fetchone()
            if row is None:
                raise HermesSlowVerificationError(
                    "final_db_assertions",
                    f"primary case actor missing for case_id={case_id}",
                )

    require_actor_coverage = bool(final_assertions.get("require_actor_coverage_for_high_signal_alerts", False))
    require_primary_for_high_signal_cases = bool(
        final_assertions.get("require_primary_case_actor_for_high_signal_cases", False)
    )
    if require_actor_coverage or require_primary_for_high_signal_cases:
        high_signal_stages = [
            str(item).lower()
            for item in final_assertions.get(
                "high_signal_actor_stages",
                ["exploit", "persistence", "command_execution", "lateral_prep"],
            )
        ]
        high_signal_severities = [
            str(item).lower() for item in final_assertions.get("high_signal_actor_severities", ["high", "critical"])
        ]
        if high_signal_stages and high_signal_severities:
            stage_placeholders = ", ".join("?" for _ in high_signal_stages)
            severity_placeholders = ", ".join("?" for _ in high_signal_severities)
            high_signal_alert_rows = conn.execute(
                f"""
                select case_alert_links.case_id, case_alert_links.alert_id
                from case_alert_links
                join alerts on alerts.alert_id = case_alert_links.alert_id
                where case_alert_links.is_active = 1
                  and lower(alerts.attack_stage) in ({stage_placeholders})
                  and lower(alerts.severity) in ({severity_placeholders})
                order by case_alert_links.case_id asc, case_alert_links.alert_id asc
                """,
                (*high_signal_stages, *high_signal_severities),
            ).fetchall()

            if require_actor_coverage:
                uncovered_alerts: list[str] = []
                for row in high_signal_alert_rows:
                    mapping = conn.execute(
                        """
                        select 1
                        from case_actor_links
                        join case_actor_profiles on case_actor_profiles.case_actor_id = case_actor_links.case_actor_id
                        where case_actor_profiles.case_id = ?
                          and case_actor_links.target_type = 'alert'
                          and case_actor_links.target_id = ?
                        limit 1
                        """,
                        (row["case_id"], row["alert_id"]),
                    ).fetchone()
                    if mapping is None:
                        uncovered_alerts.append(f"{row['case_id']}::{row['alert_id']}")
                if uncovered_alerts:
                    raise HermesSlowVerificationError(
                        "final_db_assertions",
                        f"high-signal alerts missing actor coverage: {uncovered_alerts}",
                    )

            if require_primary_for_high_signal_cases:
                high_signal_case_ids = sorted({row["case_id"] for row in high_signal_alert_rows})
                missing_primary_case_ids: list[str] = []
                for case_id in high_signal_case_ids:
                    row = conn.execute(
                        """
                        select primary_actor_id
                        from cases
                        where case_id = ?
                        limit 1
                        """,
                        (case_id,),
                    ).fetchone()
                    if row is None or not row["primary_actor_id"]:
                        missing_primary_case_ids.append(case_id)
                        continue
                    actor_exists = conn.execute(
                        """
                        select 1
                        from case_actor_profiles
                        where case_id = ? and case_actor_id = ?
                        limit 1
                        """,
                        (case_id, row["primary_actor_id"]),
                    ).fetchone()
                    if actor_exists is None:
                        missing_primary_case_ids.append(case_id)
                if missing_primary_case_ids:
                    raise HermesSlowVerificationError(
                        "final_db_assertions",
                        f"primary case actor missing for high-signal cases: {missing_primary_case_ids}",
                    )

    converged_case_clusters_count = conn.execute(
        """
        select count(*)
        from (
          select canonical_case_id
          from cases
          where canonical_case_id is not null
          group by canonical_case_id
          having count(*) >= 2
        )
        """
    ).fetchone()[0]
    min_converged_case_clusters = int(final_assertions.get("min_converged_case_clusters", 0))
    if converged_case_clusters_count < min_converged_case_clusters:
        raise HermesSlowVerificationError(
            "final_db_assertions",
            "expected at least "
            f"{min_converged_case_clusters} converged case clusters, got {converged_case_clusters_count}",
        )

    return {
        "tool_calls_count": len(tool_names),
        "tool_names": tool_names,
        "failed_tool_calls_count": len(failed_tool_rows),
        "patrol_runs": [dict(row) for row in patrol_runs],
        "link_decisions_count": conn.execute("select count(*) from link_decisions").fetchone()[0],
        "case_assessments_count": case_assessments_count,
        "entity_assessments_count": entity_assessments_count,
        "alert_decisions_count": alert_decisions_count,
        "converged_case_clusters_count": converged_case_clusters_count,
    }


def run_slow_integration(
    *,
    scenario: str,
    db_path: Path | None = None,
    model: str | None = None,
    provider: str | None = None,
    keep_artifacts: bool = False,
    progress: ProgressReporter | None = None,
) -> dict[str, Any]:
    reporter = progress or (lambda _step, _total, _message: None)
    manifest = load_integration_manifest(scenario)
    round_specs = resolve_round_specs(manifest)
    total_steps = 6 + len(round_specs) * 2

    reporter(1, total_steps, "读取慢速集成 manifest")
    target_db_path = db_path or DEFAULT_DB_PATH
    if target_db_path.exists():
        target_db_path.unlink()

    artifact_root = Path(tempfile.mkdtemp(prefix="hermes-slow-verify-"))
    hermes_home = artifact_root / "hermes-home"
    reporter(2, total_steps, "准备隔离 Hermes Home")
    prepare_isolated_hermes_home(
        source_home=DEFAULT_SOURCE_HERMES_HOME,
        dest_home=hermes_home,
        repo_skill_dir=PROJECT_ROOT / "skills" / "secagent-patrol",
    )

    reporter(3, total_steps, "初始化测试数据库")
    _bootstrap_db(target_db_path)
    env = os.environ.copy()
    env["HERMES_HOME"] = str(hermes_home)
    env["SPIKE_DB_PATH"] = str(target_db_path)

    process: subprocess.Popen[str] | None = None
    try:
        reporter(4, total_steps, "启动 MCP server")
        process, mcp_url = _start_mcp_server(db_path=target_db_path, artifact_dir=artifact_root)
        reporter(5, total_steps, "配置 Hermes MCP 并做 preflight")
        mcp_test_output = _configure_temp_hermes_mcp(env, mcp_url=mcp_url)
        preflight_output = _preflight_hermes_chat(
            env=env,
            manifest=manifest,
            model=model,
            provider=provider,
            artifact_dir=artifact_root,
        )

        round_summaries: list[dict[str, Any]] = []
        step = 6
        for round_spec in round_specs:
            round_id = round_spec["round_id"]
            reporter(step, total_steps, f"应用 {round_id}")
            apply_memory_spike_round(target_db_path, round_id)
            step += 1

            started_at_iso = datetime.now(timezone.utc).isoformat()
            reporter(step, total_steps, f"运行并校验 Hermes patrol {round_id}")
            result = _run_chat_with_continue_fallback(
                run_command=_run_command,
                query=round_spec["query"],
                max_turns=int(round_spec["max_turns"]),
                model=model,
                provider=provider,
                skills=list(manifest.get("skills", [])),
                env=env,
                cwd=PROJECT_ROOT,
                timeout_sec=240,
                artifact_dir=artifact_root,
            )
            chat_output = f"{result.stdout}\n{result.stderr}".strip()
            chat_stdout = result.stdout.strip()

            try:
                _verify_chat_output(chat_stdout=chat_stdout, round_spec=round_spec, artifact_dir=artifact_root)
            except HermesSlowVerificationError as exc:
                if not _is_missing_header_error(exc, round_id=round_id):
                    raise
                finalize_result = _run_command(
                    build_chat_command(
                        query=str(round_spec.get("finalize_query", DEFAULT_FINALIZE_QUERY)),
                        max_turns=int(round_spec.get("finalize_max_turns", 2)),
                        model=model,
                        provider=provider,
                        continue_latest=True,
                    ),
                    env=env,
                    cwd=PROJECT_ROOT,
                    timeout_sec=120,
                )
                finalize_output = f"{finalize_result.stdout}\n{finalize_result.stderr}".strip()
                if finalize_result.returncode != 0:
                    raise HermesSlowVerificationError(
                        "hermes_chat_finalize",
                        f"round {round_id}: {finalize_output or 'Hermes chat finalize failed'}",
                        artifact_dir=str(artifact_root),
                    ) from exc
                chat_stdout = finalize_result.stdout.strip()
                chat_output = finalize_output
                _verify_chat_output(chat_stdout=chat_stdout, round_spec=round_spec, artifact_dir=artifact_root)

            conn = connect_db(target_db_path)
            try:
                round_summary = _verify_round_db_state(conn, round_spec=round_spec, started_at=started_at_iso)
            finally:
                conn.close()
            round_summary["chat_output_excerpt"] = chat_output[:2000]
            round_summaries.append(round_summary)
            step += 1

        conn = connect_db(target_db_path)
        try:
            reporter(step, total_steps, "校验聚合数据库结果")
            db_summary = _verify_final_db_state(conn, manifest=manifest, round_count=len(round_specs))
        finally:
            conn.close()

        summary = {
            "scenario": scenario,
            "db_path": str(target_db_path),
            "mcp_url": mcp_url,
            "artifact_dir": str(artifact_root),
            "mcp_test_output": mcp_test_output,
            "preflight_output": preflight_output,
            "round_summaries": round_summaries,
            **db_summary,
        }
        if not keep_artifacts:
            summary["artifact_dir"] = None
            shutil.rmtree(artifact_root, ignore_errors=True)
        return summary
    except Exception as exc:
        if isinstance(exc, HermesSlowVerificationError):
            raise
        raise HermesSlowVerificationError("unknown", str(exc), artifact_dir=str(artifact_root)) from exc
    finally:
        if process is not None:
            _terminate_process(process)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run real Hermes + MCP slow integration verification")
    parser.add_argument("--scenario", default="hermes-slow-integration")
    parser.add_argument("--db-path", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--model", default=None)
    parser.add_argument("--provider", default=None)
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()

    try:
        summary = run_slow_integration(
            scenario=args.scenario,
            db_path=args.db_path,
            model=args.model,
            provider=args.provider,
            keep_artifacts=args.keep_artifacts,
            progress=_emit_progress,
        )
    except HermesSlowVerificationError as exc:
        print(f"FAIL: hermes slow integration verify\n{exc}")
        raise SystemExit(1) from exc

    print(f"PASS: hermes slow integration verify {args.scenario}")
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
