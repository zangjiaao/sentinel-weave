import json
import subprocess

from security_analyst_agent.bootstrap import bootstrap_spike_database
from security_analyst_agent.db import connect_db
from security_analyst_agent.ingest import ingest_alert_bundle
import security_analyst_agent.openai_patrol_runner as runner_module
from security_analyst_agent.openai_patrol_runner import OpenAIPatrolResult
from security_analyst_agent.patrol_trigger import trigger_patrol_from_ingest


def _build_alert(alert_id: str) -> dict:
    return {
        "alert_id": alert_id,
        "case_id": None,
        "occurred_at": "2026-04-14T01:00:00+08:00",
        "title": f"ingested alert {alert_id}",
        "status": "new",
        "severity": "medium",
        "attack_stage": "recon",
        "src_ip": "198.51.100.88",
        "dst_ip": "203.0.113.10",
        "asset_id": "asset_api_prod",
    }


class _FakeOpenAIResponses:
    def __init__(self, rounds: list[dict]) -> None:
        self._rounds = rounds
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        index = len(self.calls) - 1
        return self._rounds[index]


class _FakeOpenAIClient:
    def __init__(self, rounds: list[dict]) -> None:
        self.responses = _FakeOpenAIResponses(rounds)


def test_ingest_alert_bundle_writes_pending_events(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)

    result = ingest_alert_bundle(db_path, [_build_alert("alt_ingest_001")], source="manual_import")
    assert result["inserted_alerts"] == 1
    assert result["pending_events"] == 1

    conn = connect_db(db_path)
    alert = conn.execute("select alert_id, status from alerts where alert_id = ?", ("alt_ingest_001",)).fetchone()
    event = conn.execute(
        "select alert_id, trigger_state from alert_ingest_events where alert_id = ?",
        ("alt_ingest_001",),
    ).fetchone()
    assert alert["status"] == "new"
    assert event["trigger_state"] == "pending"
    conn.close()


def test_trigger_patrol_processes_pending_events_with_single_run(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    ingest_alert_bundle(db_path, [_build_alert("alt_ingest_002"), _build_alert("alt_ingest_003")], source="siem")
    source_home = tmp_path / "source-hermes-home"
    patrol_home = tmp_path / "patrol-hermes-home"
    source_home.mkdir(parents=True, exist_ok=True)
    (source_home / "auth.json").write_text('{"token":"demo"}', encoding="utf-8")

    commands: list[list[str]] = []
    envs: list[dict[str, str]] = []

    def fake_runner(command: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        envs.append(env or {})
        if "--continue" in command:
            return subprocess.CompletedProcess(
                args=command,
                returncode=0,
                stdout="ok\n\nsession_id: sess_ingest_demo_001",
                stderr="",
            )
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="ok", stderr="")

    result = trigger_patrol_from_ingest(
        db_path,
        job_id="job_demo_001",
        command_runner=fake_runner,
        hermes_home=patrol_home,
        source_hermes_home=source_home,
        trigger_mode="chat",
    )
    assert result["triggered"] is True
    assert result["processed_events"] == 2
    assert result["status"] == "success"
    assert len(commands) == 2
    assert commands[0][:3] == ["hermes", "chat", "-q"]
    assert "--continue" not in commands[0]
    assert "--max-turns" in commands[0]
    assert "18" in commands[0]
    assert "-s" in commands[0]
    assert "secagent-patrol" in commands[0]
    assert commands[1][:3] == ["hermes", "chat", "-q"]
    assert "--continue" in commands[1]
    assert "--max-turns" in commands[1]
    assert "2" in commands[1]
    assert envs and all(item["HERMES_HOME"] == str(patrol_home) for item in envs)
    assert (patrol_home / "SOUL.md").exists()
    assert (patrol_home / "auth.json").exists()
    assert (patrol_home / "skills" / "secagent-patrol" / "SKILL.md").exists()

    conn = connect_db(db_path)
    pending_count = conn.execute(
        "select count(*) from alert_ingest_events where trigger_state in ('pending', 'failed')"
    ).fetchone()[0]
    run_status = conn.execute("select status from patrol_runs where run_id = ?", (result["run_id"],)).fetchone()
    run_times = conn.execute(
        "select started_at, analysis_cutoff_at from patrol_runs where run_id = ?",
        (result["run_id"],),
    ).fetchone()
    processed_rows = conn.execute(
        """
        select processed_run_id
        from alert_ingest_events
        where trigger_state = 'processed'
        order by event_id asc
        """
    ).fetchall()
    assert pending_count == 0
    assert run_status["status"] == "success"
    assert run_times["analysis_cutoff_at"] == run_times["started_at"]
    assert processed_rows
    assert all(str(row["processed_run_id"] or "") == str(result["run_id"]) for row in processed_rows)
    state_rows = conn.execute("select state_key, state_value_json from patrol_state").fetchall()
    state_values = {row["state_key"]: json.loads(row["state_value_json"]) for row in state_rows}
    assert "hermes_patrol_session" in state_values
    assert state_values["hermes_patrol_session"]["session_id"] == "sess_ingest_demo_001"
    conn.close()


def test_trigger_patrol_marks_failed_and_retries(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    ingest_alert_bundle(db_path, [_build_alert("alt_ingest_004")], source="siem")

    def fail_runner(command: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=command, returncode=1, stdout="", stderr="boom")

    failed = trigger_patrol_from_ingest(
        db_path,
        job_id="job_demo_002",
        command_runner=fail_runner,
        trigger_mode="chat",
    )
    assert failed["status"] == "failed"

    conn = connect_db(db_path)
    failed_state = conn.execute(
        "select trigger_state from alert_ingest_events where alert_id = ?",
        ("alt_ingest_004",),
    ).fetchone()
    assert failed_state["trigger_state"] == "failed"
    conn.close()

    def success_runner(command: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="ok", stderr="")

    retried = trigger_patrol_from_ingest(
        db_path,
        job_id="job_demo_002",
        command_runner=success_runner,
        trigger_mode="chat",
    )
    assert retried["status"] == "success"
    assert retried["processed_events"] == 1


def test_trigger_patrol_chat_falls_back_to_new_session_when_resume_and_continue_fail(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    ingest_alert_bundle(db_path, [_build_alert("alt_ingest_005")], source="siem")
    source_home = tmp_path / "source-hermes-home"
    patrol_home = tmp_path / "patrol-hermes-home"
    source_home.mkdir(parents=True, exist_ok=True)

    conn = connect_db(db_path)
    conn.execute(
        """
        insert into patrol_state (state_key, state_value_json, updated_at)
        values (?, ?, ?)
        """,
        (
            "hermes_patrol_session",
            json.dumps({"session_id": "sess_existing_001"}, ensure_ascii=False),
            "2026-04-14T00:00:00+00:00",
        ),
    )
    conn.commit()
    conn.close()

    commands: list[list[str]] = []

    def flaky_runner(command: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        del env
        commands.append(command)
        if len(commands) == 1 and "--resume" in command:
            return subprocess.CompletedProcess(args=command, returncode=1, stdout="", stderr="missing session")
        if len(commands) == 2 and "--continue" in command:
            return subprocess.CompletedProcess(args=command, returncode=1, stdout="", stderr="no latest session")
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="ok", stderr="")

    result = trigger_patrol_from_ingest(
        db_path,
        command_runner=flaky_runner,
        hermes_home=patrol_home,
        source_hermes_home=source_home,
        trigger_mode="chat",
    )
    assert result["status"] == "success"
    assert len(commands) == 4
    assert "--resume" in commands[0]
    assert "sess_existing_001" in commands[0]
    assert "--continue" in commands[1]
    assert "--continue" not in commands[2]
    assert "--resume" in commands[3]


def test_trigger_patrol_reuses_session_and_switches_to_lightweight_query(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    source_home = tmp_path / "source-hermes-home"
    patrol_home = tmp_path / "patrol-hermes-home"
    source_home.mkdir(parents=True, exist_ok=True)

    commands: list[list[str]] = []

    def fake_runner(command: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        del env
        commands.append(command)
        if "--resume" in command:
            return subprocess.CompletedProcess(
                args=command,
                returncode=0,
                stdout="ok\n\nsession_id: sess_reuse_002",
                stderr="",
            )
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="ok\n\nsession_id: sess_reuse_001",
            stderr="",
        )

    ingest_alert_bundle(db_path, [_build_alert("alt_ingest_006")], source="siem")
    first_result = trigger_patrol_from_ingest(
        db_path,
        command_runner=fake_runner,
        hermes_home=patrol_home,
        source_hermes_home=source_home,
        trigger_mode="chat",
    )
    assert first_result["status"] == "success"
    first_round_command_count = len(commands)
    assert first_round_command_count >= 1
    assert "--continue" not in commands[0]
    conn = connect_db(db_path)
    session_state_after_first = json.loads(
        conn.execute(
            "select state_value_json from patrol_state where state_key = 'hermes_patrol_session'"
        ).fetchone()["state_value_json"]
    )
    conn.close()

    ingest_alert_bundle(db_path, [_build_alert("alt_ingest_007")], source="siem")
    second_result = trigger_patrol_from_ingest(
        db_path,
        command_runner=fake_runner,
        hermes_home=patrol_home,
        source_hermes_home=source_home,
        trigger_mode="chat",
    )
    assert second_result["status"] == "success"
    second_round_first_command = commands[first_round_command_count]
    assert "--resume" in second_round_first_command
    assert session_state_after_first["session_id"] in second_round_first_command
    assert any("New ingest events detected" in item for item in second_round_first_command)


def test_trigger_patrol_openai_mode_executes_tools_and_persists_response_state(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    ingest_alert_bundle(db_path, [_build_alert("alt_ingest_openai_001")], source="siem")

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_openai_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_openai_001",
                        "arguments": '{"status":["new","open"],"limit":20}',
                    }
                ],
            },
            {
                "id": "resp_openai_002",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_ack",
                        "call_id": "call_openai_002",
                        "arguments": '{"alert_ids":["alt_ingest_openai_001"],"status":"triaged"}',
                    }
                ],
            },
            {
                "id": "resp_openai_003",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = trigger_patrol_from_ingest(
        db_path,
        trigger_mode="openai",
        openai_client_factory=lambda: fake_client,
    )
    assert result["status"] == "success"
    first_openai_call = fake_client.responses.calls[0]
    instructions = str(first_openai_call.get("instructions", ""))
    assert "Run patrol loop for the security analyst spike." in instructions
    assert "Patrol Runtime SOUL Template" in instructions
    assert "SecAgent Patrol" in instructions

    conn = connect_db(db_path)
    state_rows = conn.execute("select state_key, state_value_json from patrol_state").fetchall()
    state_values = {row["state_key"]: json.loads(row["state_value_json"]) for row in state_rows}
    assert "openai_patrol_session" in state_values
    assert state_values["openai_patrol_session"]["response_id"] == "resp_openai_003"

    alert_status = conn.execute(
        "select status from alerts where alert_id = ?",
        ("alt_ingest_openai_001",),
    ).fetchone()["status"]
    assert alert_status == "triaged"

    tool_calls = conn.execute(
        "select run_id, tool_name from agent_tool_calls order by occurred_at asc, rowid asc"
    ).fetchall()
    run_cost = conn.execute(
        """
        select trigger_mode, status, tool_calls, usage_input_tokens, usage_output_tokens, usage_total_tokens
        from patrol_run_costs
        where run_id = ?
        """,
        (result["run_id"],),
    ).fetchone()
    conn.close()
    assert [row["tool_name"] for row in tool_calls] == ["alert.fetch", "alert.ack"]
    assert all(row["run_id"] == result["run_id"] for row in tool_calls)
    assert run_cost is not None
    assert run_cost["trigger_mode"] == "openai"
    assert run_cost["status"] == "success"
    assert run_cost["tool_calls"] == 2
    assert run_cost["usage_input_tokens"] == 0
    assert run_cost["usage_output_tokens"] == 0
    assert run_cost["usage_total_tokens"] == 0


def test_trigger_patrol_openai_mode_runs_case_convergence_after_success(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    ingest_alert_bundle(db_path, [_build_alert("alt_ingest_openai_conv_001")], source="siem")

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_openai_conv_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_openai_conv_fetch",
                        "arguments": '{"status":["new","open"],"limit":20}',
                    }
                ],
            },
            {
                "id": "resp_openai_conv_002",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_ack",
                        "call_id": "call_openai_conv_ack",
                        "arguments": '{"alert_ids":["alt_ingest_openai_conv_001"],"status":"triaged"}',
                    }
                ],
            },
            {
                "id": "resp_openai_conv_003",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    convergence_run_ids: list[str] = []

    def _fake_convergence(_conn, *, run_id: str):
        convergence_run_ids.append(run_id)
        return {"confirmed_relations_count": 0, "merge_events_count": 0, "orphan_absorbed_cases_count": 0}

    monkeypatch.setattr("security_analyst_agent.patrol_trigger.run_case_convergence_for_run", _fake_convergence)

    result = trigger_patrol_from_ingest(
        db_path,
        trigger_mode="openai",
        openai_client_factory=lambda: fake_client,
    )
    assert result["status"] == "success"
    assert convergence_run_ids == [result["run_id"]]


def test_trigger_patrol_openai_mode_skips_case_convergence_on_failure(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    ingest_alert_bundle(db_path, [_build_alert("alt_ingest_openai_conv_002")], source="siem")

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_openai_conv_fail_001",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
            {
                "id": "resp_openai_conv_fail_002",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    convergence_run_ids: list[str] = []

    def _fake_convergence(_conn, *, run_id: str):
        convergence_run_ids.append(run_id)
        return {"confirmed_relations_count": 0, "merge_events_count": 0, "orphan_absorbed_cases_count": 0}

    monkeypatch.setattr("security_analyst_agent.patrol_trigger.run_case_convergence_for_run", _fake_convergence)

    result = trigger_patrol_from_ingest(
        db_path,
        trigger_mode="openai",
        openai_client_factory=lambda: fake_client,
    )
    assert result["status"] == "failed"
    assert convergence_run_ids == []


def test_trigger_patrol_openai_mode_reuses_previous_response_id(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    ingest_alert_bundle(db_path, [_build_alert("alt_ingest_openai_002")], source="siem")

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_openai_bootstrap",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_openai_bootstrap_fetch",
                        "arguments": '{"status":["new","open"],"limit":20}',
                    }
                ],
            },
            {
                "id": "resp_openai_bootstrap_done",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
            {
                "id": "resp_openai_resume",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_openai_resume_fetch",
                        "arguments": '{"status":["new","open"],"limit":20}',
                    }
                ],
            },
            {
                "id": "resp_openai_resume_done",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    first = trigger_patrol_from_ingest(
        db_path,
        trigger_mode="openai",
        openai_client_factory=lambda: fake_client,
    )
    assert first["status"] == "success"

    ingest_alert_bundle(db_path, [_build_alert("alt_ingest_openai_003")], source="siem")
    second = trigger_patrol_from_ingest(
        db_path,
        trigger_mode="openai",
        openai_client_factory=lambda: fake_client,
    )
    assert second["status"] == "success"
    assert len(fake_client.responses.calls) == 4
    assert "previous_response_id" not in fake_client.responses.calls[0]
    assert fake_client.responses.calls[2]["previous_response_id"] == "resp_openai_bootstrap_done"
    assert "New ingest events detected" in fake_client.responses.calls[2]["input"]


def test_trigger_patrol_openai_mode_fails_without_backend_tool_calls(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    ingest_alert_bundle(db_path, [_build_alert("alt_ingest_openai_004")], source="siem")

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_openai_no_tools",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
            {
                "id": "resp_openai_no_tools_retry",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = trigger_patrol_from_ingest(
        db_path,
        trigger_mode="openai",
        openai_client_factory=lambda: fake_client,
    )
    assert result["status"] == "failed"

    conn = connect_db(db_path)
    run_row = conn.execute(
        "select status, summary from patrol_runs where run_id = ?",
        (result["run_id"],),
    ).fetchone()
    run_cost = conn.execute(
        """
        select trigger_mode, status, tool_calls, usage_input_tokens, usage_output_tokens, usage_total_tokens
        from patrol_run_costs
        where run_id = ?
        """,
        (result["run_id"],),
    ).fetchone()
    output_rows = conn.execute(
        """
        select turn_index, has_tool_calls, output_text
        from agent_outputs
        where run_id = ?
        order by occurred_at asc, rowid asc
        """,
        (result["run_id"],),
    ).fetchall()
    event_row = conn.execute(
        "select trigger_state from alert_ingest_events order by rowid desc limit 1"
    ).fetchone()
    conn.close()

    assert run_row["status"] == "failed"
    assert "no backend tool calls" in str(run_row["summary"])
    assert event_row["trigger_state"] == "failed"
    assert run_cost is not None
    assert run_cost["trigger_mode"] == "openai"
    assert run_cost["status"] == "failed"
    assert len(output_rows) == 2
    assert all(row["has_tool_calls"] == 0 for row in output_rows)
    assert all(row["output_text"] == "[SILENT]" for row in output_rows)


def test_trigger_patrol_openai_mode_rolls_session_when_limits_reached(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    ingest_alert_bundle(db_path, [_build_alert("alt_ingest_openai_roll_001")], source="siem")

    conn = connect_db(db_path)
    conn.execute(
        """
        insert into patrol_state (state_key, state_value_json, updated_at)
        values (?, ?, ?)
        """,
        (
            "openai_patrol_session",
            json.dumps(
                {
                    "response_id": "resp_old_session_001",
                    "run_count": 9,
                    "cumulative_input_tokens": 1999,
                },
                ensure_ascii=False,
            ),
            "2026-04-14T00:00:00+00:00",
        ),
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr("security_analyst_agent.patrol_trigger.DEFAULT_OPENAI_PATROL_SESSION_MAX_RUNS", 8)
    monkeypatch.setattr("security_analyst_agent.patrol_trigger.DEFAULT_OPENAI_PATROL_SESSION_MAX_INPUT_TOKENS", 2000)

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_openai_roll_001",
                "usage": {
                    "input_tokens": 120,
                    "output_tokens": 30,
                    "input_tokens_details": {"cached_tokens": 20},
                },
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_openai_roll_fetch",
                        "arguments": '{"status":["new","open"],"limit":20}',
                    }
                ],
            },
            {
                "id": "resp_openai_roll_002",
                "usage": {
                    "input_tokens": 80,
                    "output_tokens": 10,
                    "input_tokens_details": {"cached_tokens": 15},
                },
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = trigger_patrol_from_ingest(
        db_path,
        trigger_mode="openai",
        openai_client_factory=lambda: fake_client,
    )
    assert result["status"] == "success"
    assert "previous_response_id" not in fake_client.responses.calls[0]

    conn = connect_db(db_path)
    state_value = json.loads(
        conn.execute(
            "select state_value_json from patrol_state where state_key = 'openai_patrol_session'"
        ).fetchone()["state_value_json"]
    )
    conn.close()
    assert state_value["response_id"] == "resp_openai_roll_002"
    assert state_value["run_count"] == 1
    assert state_value["cumulative_input_tokens"] == 200
    assert state_value["cumulative_output_tokens"] == 40
    assert state_value["cumulative_cached_input_tokens"] == 35


def test_trigger_patrol_openai_mode_retries_fresh_when_resume_returns_no_tool_calls(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    ingest_alert_bundle(db_path, [_build_alert("alt_ingest_openai_retry_001")], source="siem")

    conn = connect_db(db_path)
    conn.execute(
        """
        insert into patrol_state (state_key, state_value_json, updated_at)
        values (?, ?, ?)
        """,
        (
            "openai_patrol_session",
            json.dumps({"response_id": "resp_existing_retry_001", "run_count": 3}, ensure_ascii=False),
            "2026-04-14T00:00:00+00:00",
        ),
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr("security_analyst_agent.patrol_trigger.DEFAULT_OPENAI_PATROL_RETRY_FRESH_ON_NO_TOOL", True)
    monkeypatch.setattr(runner_module, "DEFAULT_OPENAI_WIRE_API", "responses")

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_retry_resume_001",
                "usage": {"input_tokens": 50, "output_tokens": 5},
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
            {
                "id": "resp_retry_fresh_001",
                "usage": {"input_tokens": 100, "output_tokens": 20},
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_openai_retry_fetch",
                        "arguments": '{"status":["new","open"],"limit":20}',
                    }
                ],
            },
            {
                "id": "resp_retry_fresh_002",
                "usage": {"input_tokens": 70, "output_tokens": 8},
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = trigger_patrol_from_ingest(
        db_path,
        trigger_mode="openai",
        openai_client_factory=lambda: fake_client,
    )

    assert result["status"] == "success"
    assert len(fake_client.responses.calls) == 3
    assert fake_client.responses.calls[0]["previous_response_id"] == "resp_existing_retry_001"
    assert "previous_response_id" not in fake_client.responses.calls[1]

    conn = connect_db(db_path)
    run_row = conn.execute(
        "select summary from patrol_runs where run_id = ?",
        (result["run_id"],),
    ).fetchone()
    conn.close()
    assert "retried_fresh_after_no_tool=1" in str(run_row["summary"])


def test_trigger_patrol_openai_mode_retries_fresh_when_resume_session_incompatible(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    ingest_alert_bundle(db_path, [_build_alert("alt_ingest_openai_retry_compat_001")], source="siem")

    conn = connect_db(db_path)
    conn.execute(
        """
        insert into patrol_state (state_key, state_value_json, updated_at)
        values (?, ?, ?)
        """,
        (
            "openai_patrol_session",
            json.dumps({"response_id": "resp_existing_model_old_001", "run_count": 4}, ensure_ascii=False),
            "2026-04-14T00:00:00+00:00",
        ),
    )
    conn.commit()
    conn.close()

    call_history: list[dict] = []
    monkeypatch.setattr(runner_module, "DEFAULT_OPENAI_WIRE_API", "responses")

    def fake_run_openai_patrol(_conn, **kwargs):
        call_history.append(dict(kwargs))
        if len(call_history) == 1:
            return OpenAIPatrolResult(
                status="failed",
                detail="Error code: 404 - {'error': {'message': 'Model not found gpt-5.4', 'type': 'not_found_error'}}",
                response_id=None,
            )
        return OpenAIPatrolResult(
            status="success",
            detail="ok",
            response_id="resp_openai_fresh_retry_ok_001",
            turns=2,
            tool_calls=1,
            usage_input_tokens=120,
            usage_output_tokens=20,
        )

    monkeypatch.setattr("security_analyst_agent.patrol_trigger.run_openai_patrol", fake_run_openai_patrol)

    result = trigger_patrol_from_ingest(
        db_path,
        trigger_mode="openai",
        openai_client_factory=lambda: _FakeOpenAIClient([]),
    )
    assert result["status"] == "success"
    assert len(call_history) == 2
    assert call_history[0]["previous_response_id"] == "resp_existing_model_old_001"
    assert call_history[1]["previous_response_id"] is None

    conn = connect_db(db_path)
    run_row = conn.execute(
        "select summary from patrol_runs where run_id = ?",
        (result["run_id"],),
    ).fetchone()
    state_row = conn.execute(
        "select state_value_json from patrol_state where state_key = 'openai_patrol_session'"
    ).fetchone()
    conn.close()
    assert run_row is not None
    assert "retried_fresh_after_incompatible_session=1" in str(run_row["summary"])
    assert state_row is not None
    state_value = json.loads(state_row["state_value_json"])
    assert state_value["response_id"] == "resp_openai_fresh_retry_ok_001"
    assert state_value["last_recovery"] == "fresh_retry_after_incompatible_session"


def test_trigger_patrol_openai_mode_retries_once_when_fresh_attempt_returns_no_tool_calls(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    ingest_alert_bundle(db_path, [_build_alert("alt_ingest_openai_fresh_retry_001")], source="siem")

    monkeypatch.setattr("security_analyst_agent.patrol_trigger.DEFAULT_OPENAI_PATROL_RETRY_FRESH_ON_NO_TOOL", True)
    monkeypatch.setattr(runner_module, "DEFAULT_OPENAI_WIRE_API", "responses")

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_fresh_retry_first_001",
                "usage": {"input_tokens": 44, "output_tokens": 6},
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
            {
                "id": "resp_fresh_retry_second_001",
                "usage": {"input_tokens": 101, "output_tokens": 23},
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_openai_fresh_retry_fetch",
                        "arguments": '{"status":["new","open"],"limit":20}',
                    }
                ],
            },
            {
                "id": "resp_fresh_retry_second_002",
                "usage": {"input_tokens": 70, "output_tokens": 8},
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = trigger_patrol_from_ingest(
        db_path,
        trigger_mode="openai",
        openai_client_factory=lambda: fake_client,
    )

    assert result["status"] == "success"
    assert len(fake_client.responses.calls) == 3
    assert "previous_response_id" not in fake_client.responses.calls[0]
    assert "previous_response_id" not in fake_client.responses.calls[1]

    conn = connect_db(db_path)
    run_row = conn.execute(
        "select summary from patrol_runs where run_id = ?",
        (result["run_id"],),
    ).fetchone()
    conn.close()
    assert "retried_fresh_after_no_tool=1" in str(run_row["summary"])


def test_trigger_patrol_openai_mode_normalizes_malformed_actor_batch_payload(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    ingest_alert_bundle(db_path, [_build_alert("alt_ingest_openai_005")], source="siem")

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_openai_norm_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_openai_norm_fetch",
                        "arguments": '{"status":["new","open"],"limit":20}',
                    }
                ],
            },
            {
                "id": "resp_openai_norm_002",
                "output": [
                    {
                        "type": "function_call",
                        "name": "actor_case_link_batch",
                        "call_id": "call_openai_norm_actor_link",
                        "arguments": (
                            '{"items":[{"actor_id":"act_missing_schema","target_type":"timeline",'
                            '"alert_id":"alt_ingest_openai_005","reason":"same chain"}]}'
                        ),
                    }
                ],
            },
            {
                "id": "resp_openai_norm_003",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = trigger_patrol_from_ingest(
        db_path,
        trigger_mode="openai",
        openai_client_factory=lambda: fake_client,
    )
    assert result["status"] == "success"

    conn = connect_db(db_path)
    rows = conn.execute(
        """
        select tool_name, result_ok, result_summary
        from agent_tool_calls
        where run_id = ?
        order by occurred_at asc, rowid asc
        """,
        (result["run_id"],),
    ).fetchall()
    conn.close()

    assert [row["tool_name"] for row in rows] == ["alert.fetch", "actor.case-link-batch"]
    assert rows[1]["result_ok"] == 1


def test_trigger_patrol_openai_mode_persists_fetch_cursor_but_resets_cross_run_offset(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    monkeypatch.setattr(runner_module, "DEFAULT_OPENAI_WIRE_API", "responses")
    alert_one = _build_alert("alt_ingest_openai_cursor_001")
    alert_two = _build_alert("alt_ingest_openai_cursor_002")
    alert_two["src_ip"] = "198.51.100.89"
    ingest_alert_bundle(
        db_path,
        [alert_one, alert_two],
        source="siem",
    )

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_openai_cursor_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_openai_cursor_001",
                        "arguments": '{"status":["new","open"],"mode":"clusters","cluster_min_count":1,"limit":1}',
                    }
                ],
            },
            {
                "id": "resp_openai_cursor_002",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
            {
                "id": "resp_openai_cursor_003",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_openai_cursor_003",
                        "arguments": '{"status":["new","open"],"mode":"clusters","cluster_min_count":1,"limit":1}',
                    }
                ],
            },
            {
                "id": "resp_openai_cursor_004",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    first = trigger_patrol_from_ingest(
        db_path,
        trigger_mode="openai",
        openai_client_factory=lambda: fake_client,
    )
    assert first["status"] == "success"

    conn = connect_db(db_path)
    first_state = json.loads(
        conn.execute(
            "select state_value_json from patrol_state where state_key = 'openai_patrol_session'"
        ).fetchone()["state_value_json"]
    )
    resume_payload = first_state.get("fetch_resume_payload")
    assert isinstance(resume_payload, dict)
    resume_cursor = resume_payload.get("cursor")
    assert isinstance(resume_cursor, str) and resume_cursor != ""
    conn.close()

    ingest_alert_bundle(db_path, [_build_alert("alt_ingest_openai_cursor_003")], source="siem")
    second = trigger_patrol_from_ingest(
        db_path,
        trigger_mode="openai",
        openai_client_factory=lambda: fake_client,
    )
    assert second["status"] == "success"

    conn = connect_db(db_path)
    second_fetch_payload = json.loads(
        conn.execute(
            """
            select payload_json
            from agent_tool_calls
            where run_id = ? and tool_name = 'alert.fetch'
            order by occurred_at asc, rowid asc
            limit 1
            """,
            (second["run_id"],),
        ).fetchone()["payload_json"]
    )
    conn.close()
    assert second_fetch_payload.get("cursor") != resume_cursor
    assert "cursor" not in second_fetch_payload


def test_trigger_patrol_openai_mode_marks_processed_new_alerts_open(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    monkeypatch.setattr(runner_module, "DEFAULT_OPENAI_WIRE_API", "responses")
    ingest_alert_bundle(db_path, [_build_alert("alt_ingest_openai_open_001")], source="siem")

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_openai_open_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_openai_open_001",
                        "arguments": '{"status":["new","open"],"limit":20}',
                    }
                ],
            },
            {
                "id": "resp_openai_open_002",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = trigger_patrol_from_ingest(
        db_path,
        trigger_mode="openai",
        openai_client_factory=lambda: fake_client,
    )
    assert result["status"] == "success"

    conn = connect_db(db_path)
    alert_status = conn.execute(
        "select status from alerts where alert_id = ?",
        ("alt_ingest_openai_open_001",),
    ).fetchone()["status"]
    run_summary = conn.execute(
        "select summary from patrol_runs where run_id = ?",
        (result["run_id"],),
    ).fetchone()["summary"]
    conn.close()

    assert alert_status == "open"
    assert "opened_alerts=1" in str(run_summary)


def test_trigger_patrol_processes_only_selected_event_ids(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    monkeypatch.setattr(runner_module, "DEFAULT_OPENAI_WIRE_API", "responses")
    ingest_alert_bundle(db_path, [_build_alert("alt_scope_001"), _build_alert("alt_scope_002")], source="siem")

    conn = connect_db(db_path)
    event_rows = conn.execute(
        """
        select event_id
        from alert_ingest_events
        order by ingested_at asc, rowid asc
        """
    ).fetchall()
    conn.close()
    selected_event_id = str(event_rows[0]["event_id"])

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_scope_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_scope_001",
                        "arguments": '{"status":["new","open"],"limit":20}',
                    }
                ],
            },
            {
                "id": "resp_scope_002",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = trigger_patrol_from_ingest(
        db_path,
        trigger_mode="openai",
        openai_client_factory=lambda: fake_client,
        event_ids=[selected_event_id],
    )
    assert result["status"] == "success"
    assert result["processed_events"] == 1

    conn = connect_db(db_path)
    states = conn.execute(
        """
        select event_id, trigger_state
        from alert_ingest_events
        order by ingested_at asc, rowid asc
        """
    ).fetchall()
    conn.close()
    assert str(states[0]["event_id"]) == selected_event_id
    assert states[0]["trigger_state"] == "processed"
    assert states[1]["trigger_state"] == "pending"


def test_trigger_patrol_openai_mode_applies_large_queue_tool_budget(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    alerts = [_build_alert(f"alt_ingest_budget_{index:04d}") for index in range(500)]
    ingest_alert_bundle(db_path, alerts, source="siem")

    captured_kwargs: dict[str, object] = {}

    def fake_run_openai_patrol(_conn, **kwargs):
        captured_kwargs.update(kwargs)
        return OpenAIPatrolResult(
            status="success",
            detail="ok",
            response_id="resp_budget_ok_001",
            turns=2,
            tool_calls=1,
        )

    monkeypatch.setattr("security_analyst_agent.patrol_trigger.run_openai_patrol", fake_run_openai_patrol)

    result = trigger_patrol_from_ingest(
        db_path,
        trigger_mode="openai",
        openai_client_factory=lambda: _FakeOpenAIClient([]),
    )
    assert result["status"] == "success"
    assert captured_kwargs["max_tool_calls"] == 10
    assert captured_kwargs["max_read_tool_calls"] == 7
    assert captured_kwargs["max_write_tool_calls"] == 3
    assert captured_kwargs["enforce_read_phase_gate"] is True
