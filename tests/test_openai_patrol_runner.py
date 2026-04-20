from __future__ import annotations

import json
from dataclasses import dataclass

import pytest
from security_analyst_agent.bootstrap import bootstrap_spike_database
from security_analyst_agent.db import connect_db
import security_analyst_agent.openai_patrol_runner as runner_module
from security_analyst_agent.openai_patrol_runner import run_openai_patrol
from security_analyst_agent.openai_patrol_runner import _normalize_payload_for_tool


def test_normalize_assessment_upsert_batch_payload_with_alias_fields() -> None:
    payload = {
        "items": [
            {
                "entity_type": "attacker",
                "src_ip": "198.51.100.23",
                "severity": "high",
                "confidence": "0.9",
                "assessment": "attacker",
                "reason": "confirmed exploit chain",
                "alert_ids": ["alt_demo_001"],
            }
        ]
    }

    normalized = _normalize_payload_for_tool("assessment.upsert-batch", payload)
    item = normalized["items"][0]
    assert item["entity_type"] == "ip"
    assert item["entity_key"] == "198.51.100.23"
    assert item["risk_level"] == "high"
    assert item["verdict"] == "attacker"
    assert item["assessment_confidence"] == 0.9
    assert item["supporting_alert_ids"] == ["alt_demo_001"]


def test_normalize_actor_case_link_batch_fills_required_fields() -> None:
    payload = {
        "items": [
            {
                "actor_id": "act_demo_001",
                "target_type": "timeline",
                "alert_id": "alt_demo_002",
                "reason": "same activity",
            }
        ]
    }

    normalized = _normalize_payload_for_tool("actor.case-link-batch", payload)
    item = normalized["items"][0]
    assert item["case_actor_id"] == "act_demo_001"
    assert item["target_type"] == "timeline_event"
    assert item["target_id"] == "alt_demo_002"
    assert item["link_confidence"] == 0.8
    assert item["link_reason"] == "same activity"


def test_normalize_case_upsert_batch_accepts_single_object_payload() -> None:
    payload = {
        "case_id": "case_single_001",
        "summary": "single payload without items array",
        "severity": "high",
        "attack_stage": "persistence",
        "status": "active",
    }

    normalized = _normalize_payload_for_tool("case.upsert-batch", payload)
    assert isinstance(normalized.get("items"), list)
    assert len(normalized["items"]) == 1
    item = normalized["items"][0]
    assert item["case_id"] == "case_single_001"
    assert item["title"] == "single payload without items array"
    assert item["overall_severity"] == "high"
    assert item["current_stage"] == "persistence"
    assert item["status"] == "active"


def test_normalize_alert_fetch_payload_sets_cluster_defaults() -> None:
    normalized = _normalize_payload_for_tool("alert.fetch", {"status": ["new"]})
    assert normalized["status"] == ["new"]
    assert normalized["limit"] == 20
    assert normalized["mode"] == "auto"
    assert normalized["auto_cluster_threshold"] == 8


def test_normalize_alert_fetch_payload_keeps_explicit_mode() -> None:
    normalized = _normalize_payload_for_tool(
        "alert.fetch",
        {"status": ["open"], "limit": 10, "mode": "clusters"},
    )
    assert normalized["status"] == ["open"]
    assert normalized["limit"] == 10
    assert normalized["mode"] == "clusters"
    assert "auto_cluster_threshold" not in normalized


def test_normalize_alert_fetch_payload_disables_strategy_hints_in_objective_mode() -> None:
    normalized = _normalize_payload_for_tool(
        "alert.fetch",
        {"status": ["new", "open"], "limit": 10},
        objective_mode=True,
    )
    assert normalized["include_strategy_hints"] is False


def test_run_openai_patrol_drops_cross_run_fetch_cursor_from_first_override(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    monkeypatch.setattr(runner_module, "DEFAULT_OPENAI_WIRE_API", "responses")

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_cursor_override_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_cursor_override_001",
                        "arguments": '{"status":["new","open"],"mode":"clusters","limit":5}',
                    }
                ],
            },
            {
                "id": "resp_cursor_override_002",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5-mini",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=4,
        first_fetch_payload_override={
            "status": ["new", "open"],
            "mode": "clusters",
            "limit": 5,
            "cursor": "120",
        },
        client_factory=lambda: fake_client,
        tool_profile="compact",
    )

    first_fetch_payload = json.loads(
        conn.execute(
            """
            select payload_json
            from agent_tool_calls
            where tool_name = 'alert.fetch'
            order by occurred_at asc, rowid asc
            limit 1
            """
        ).fetchone()["payload_json"]
    )
    conn.close()

    assert result.status == "success"
    assert "cursor" not in first_fetch_payload
    assert first_fetch_payload["mode"] == "clusters"


@dataclass
class _UsageDetailsObject:
    cached_tokens: int


@dataclass
class _UsageObject:
    input_tokens: int
    output_tokens: int
    input_tokens_details: _UsageDetailsObject


class _FakeOpenAIResponses:
    def __init__(self, rounds: list[dict]) -> None:
        self._rounds = rounds
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        index = len(self.calls) - 1
        current = self._rounds[index]
        if isinstance(current, Exception):
            raise current
        return current


class _FakeOpenAIClient:
    def __init__(self, rounds: list[dict | Exception], chat_rounds: list[dict | Exception] | None = None) -> None:
        self.responses = _FakeOpenAIResponses(rounds)
        self.chat = _FakeOpenAIChat(chat_rounds or [])


class _FakeOpenAIChatCompletions:
    def __init__(self, rounds: list[dict | Exception]) -> None:
        self._rounds = rounds
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        index = len(self.calls) - 1
        current = self._rounds[index]
        if isinstance(current, Exception):
            raise current
        return current


class _FakeOpenAIChat:
    def __init__(self, rounds: list[dict | Exception]) -> None:
        self.completions = _FakeOpenAIChatCompletions(rounds)


def test_run_openai_patrol_keeps_tools_on_every_turn_and_collects_usage(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_runner_001",
                "usage": _UsageObject(
                    input_tokens=123,
                    output_tokens=17,
                    input_tokens_details=_UsageDetailsObject(cached_tokens=20),
                ),
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_runner_001",
                        "arguments": '{"status":["new","open"],"limit":5}',
                    }
                ],
            },
            {
                "id": "resp_runner_002",
                "usage": _UsageObject(
                    input_tokens=77,
                    output_tokens=11,
                    input_tokens_details=_UsageDetailsObject(cached_tokens=9),
                ),
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5-mini",
        instructions="run patrol",
        query="start",
        previous_response_id="resp_prev_001",
        max_turns=5,
        client_factory=lambda: fake_client,
        tool_profile="compact",
    )
    output_rows = conn.execute(
        """
        select turn_index, response_id, has_tool_calls, output_text, meta_json
        from agent_outputs
        order by occurred_at asc, rowid asc
        """
    ).fetchall()
    conn.close()

    assert result.status == "success"
    assert result.turns == 2
    assert result.tool_calls == 1
    assert result.usage_input_tokens == 200
    assert result.usage_output_tokens == 28
    assert result.usage_cached_input_tokens == 29
    assert len(fake_client.responses.calls) == 2
    assert "tools" in fake_client.responses.calls[0]
    assert "tools" in fake_client.responses.calls[1]
    assert fake_client.responses.calls[0]["tool_choice"] == "required"
    assert fake_client.responses.calls[0]["previous_response_id"] == "resp_prev_001"
    assert fake_client.responses.calls[1]["previous_response_id"] == "resp_runner_001"
    assert "instructions" in fake_client.responses.calls[0]
    assert "instructions" not in fake_client.responses.calls[1]
    assert len(output_rows) == 2
    assert output_rows[0]["turn_index"] == 1
    assert output_rows[0]["response_id"] == "resp_runner_001"
    assert output_rows[0]["has_tool_calls"] == 1
    assert output_rows[1]["turn_index"] == 2
    assert output_rows[1]["response_id"] == "resp_runner_002"
    assert output_rows[1]["has_tool_calls"] == 0
    assert output_rows[1]["output_text"] == "[SILENT]"


def test_run_openai_patrol_retries_once_when_first_response_is_text_without_tools(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_text_no_tool_001",
                "output_text": "## Patrol Action Summary\n- planning only",
                "output": [{"type": "message", "role": "assistant"}],
            },
            {
                "id": "resp_text_no_tool_002",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_text_no_tool_fetch",
                        "arguments": '{"status":["new","open"],"limit":5}',
                    }
                ],
            },
            {
                "id": "resp_text_no_tool_003",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5-mini",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=5,
        client_factory=lambda: fake_client,
        tool_profile="compact",
    )

    output_rows = conn.execute(
        """
        select turn_index, has_tool_calls, output_text
        from agent_outputs
        order by occurred_at asc, rowid asc
        """
    ).fetchall()
    conn.close()

    assert result.status == "success"
    assert result.turns == 3
    assert result.tool_calls == 1
    assert len(fake_client.responses.calls) == 3
    assert "previous_response_id" not in fake_client.responses.calls[1]
    assert fake_client.responses.calls[1]["tool_choice"] == "required"
    assert len(output_rows) == 3
    assert output_rows[0]["has_tool_calls"] == 0
    assert output_rows[1]["has_tool_calls"] == 1


def test_run_openai_patrol_logs_diagnostics_when_provider_returns_empty_output_without_tools(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_no_tool_empty_001",
                "status": "completed",
                "usage": _UsageObject(
                    input_tokens=8850,
                    output_tokens=80,
                    input_tokens_details=_UsageDetailsObject(cached_tokens=0),
                ),
                "output": [],
            }
        ]
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5.3",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=1,
        client_factory=lambda: fake_client,
        tool_profile="compact",
    )

    output_row = conn.execute(
        """
        select meta_json
        from agent_outputs
        order by occurred_at asc, rowid asc
        limit 1
        """
    ).fetchone()
    conn.close()

    assert result.status == "failed"
    assert "response_status=completed" in result.detail
    assert "output_items=0" in result.detail
    assert output_row is not None
    meta = json.loads(output_row["meta_json"])
    assert meta["output_item_count"] == 0
    assert meta["output_item_types"] == []
    assert meta["response_status"] == "completed"
    assert meta["tool_call_names"] == []


def test_run_openai_patrol_accepts_tuple_output_items_for_tool_calls(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_tuple_output_001",
                "output": (
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_tuple_output_fetch",
                        "arguments": '{"status":["new","open"],"limit":3}',
                    },
                ),
            },
            {
                "id": "resp_tuple_output_002",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5.3",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=3,
        client_factory=lambda: fake_client,
        tool_profile="compact",
    )

    alert_fetch_calls = conn.execute(
        "select count(*) from agent_tool_calls where tool_name = 'alert.fetch'"
    ).fetchone()[0]
    conn.close()

    assert result.status == "success"
    assert result.tool_calls == 1
    assert alert_fetch_calls == 1


def test_run_openai_patrol_retries_transient_provider_error_then_succeeds(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    monkeypatch.setattr(runner_module, "_provider_retry_delay_seconds", lambda _retry_index: 0.0)

    fake_client = _FakeOpenAIClient(
        rounds=[
            RuntimeError("Error code: 503 - {'error': {'message': 'Service temporarily unavailable'}}"),
            {
                "id": "resp_retry_success_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_retry_success_fetch",
                        "arguments": '{"status":["new","open"],"limit":3}',
                    }
                ],
            },
            {
                "id": "resp_retry_success_002",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5.4",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=5,
        client_factory=lambda: fake_client,
        tool_profile="compact",
    )

    alert_fetch_calls = conn.execute(
        "select count(*) from agent_tool_calls where tool_name = 'alert.fetch'"
    ).fetchone()[0]
    conn.close()

    assert result.status == "success"
    assert result.tool_calls == 1
    assert alert_fetch_calls == 1
    assert len(fake_client.responses.calls) == 3


def test_run_openai_patrol_fails_fast_on_non_retryable_provider_error(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    monkeypatch.setattr(runner_module, "_provider_retry_delay_seconds", lambda _retry_index: 0.0)

    fake_client = _FakeOpenAIClient(
        rounds=[
            RuntimeError("Error code: 400 - {'error': {'message': 'invalid_request_error'}}"),
            RuntimeError("Error code: 400 - {'error': {'message': 'invalid_request_error'}}"),
        ]
    )

    with pytest.raises(RuntimeError, match="invalid_request_error"):
        run_openai_patrol(
            conn,
            model="gpt-5.4",
            instructions="run patrol",
            query="start",
            previous_response_id=None,
            max_turns=3,
            client_factory=lambda: fake_client,
            tool_profile="compact",
        )
    conn.close()

    assert len(fake_client.responses.calls) == 2


def test_run_openai_patrol_falls_back_to_chat_completions_on_responses_call_id_error(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    monkeypatch.setattr(runner_module, "DEFAULT_OPENAI_WIRE_API", "responses")
    monkeypatch.setattr(runner_module, "DEFAULT_OPENAI_ENABLE_CHAT_FALLBACK", True)

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_fallback_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_fallback_fetch_001",
                        "arguments": '{"status":["new","open"],"limit":3}',
                    }
                ],
            },
            RuntimeError(
                "Error code: 400 - {'error': {'message': 'No tool call found for function call output with call_id call_fallback_fetch_001.'}}"
            ),
        ],
        chat_rounds=[
            {
                "id": "chat_resp_fallback_001",
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "[SILENT]",
                        }
                    }
                ],
                "usage": {"prompt_tokens": 20, "completion_tokens": 6},
            }
        ],
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5.4",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=5,
        client_factory=lambda: fake_client,
        tool_profile="compact",
    )

    output_rows = conn.execute(
        """
        select meta_json
        from agent_outputs
        order by occurred_at asc, rowid asc
        """
    ).fetchall()
    alert_fetch_calls = conn.execute(
        "select count(*) from agent_tool_calls where tool_name = 'alert.fetch'"
    ).fetchone()[0]
    conn.close()

    assert result.status == "success"
    assert result.tool_calls == 1
    assert "wire_fallback_used=1" in result.detail
    assert len(fake_client.responses.calls) == 2
    assert len(fake_client.chat.completions.calls) == 1
    assert alert_fetch_calls == 1
    assert any('"wire_api": "chat_completions"' in row["meta_json"] for row in output_rows)


def test_run_openai_patrol_blocks_repeated_invalid_tool_payload_in_same_run(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_invalid_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_invalid_fetch_001",
                        "arguments": '{"status":["new","open"],"limit":1}',
                    }
                ],
            },
            {
                "id": "resp_invalid_002",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_detail_batch",
                        "call_id": "call_invalid_001",
                        "arguments": '{"alert_ids":["alt_day1_scan_01"]}',
                    }
                ],
            },
            {
                "id": "resp_invalid_003",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_detail_batch",
                        "call_id": "call_invalid_002",
                        "arguments": '{"alert_ids":["alt_day1_scan_01"]}',
                    }
                ],
            },
            {
                "id": "resp_invalid_004",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5-mini",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=5,
        client_factory=lambda: fake_client,
        tool_profile="compact",
    )

    recorded_calls = conn.execute(
        "select count(*) from agent_tool_calls where tool_name = 'alert.detail-batch'"
    ).fetchone()[0]
    conn.close()

    assert result.status == "success"
    assert result.turns == 4
    assert result.tool_calls == 2
    assert recorded_calls == 1


def test_run_openai_patrol_local_precheck_blocks_empty_batch_without_backend_dispatch(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_local_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "case_upsert_batch",
                        "call_id": "call_local_001",
                        "arguments": '{"items":[]}',
                    }
                ],
            },
            {
                "id": "resp_local_002",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_local_002",
                        "arguments": '{"status":["new","open"],"limit":2}',
                    }
                ],
            },
            {
                "id": "resp_local_003",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5-mini",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=5,
        client_factory=lambda: fake_client,
        tool_profile="compact",
    )

    case_upsert_calls = conn.execute(
        "select count(*) from agent_tool_calls where tool_name = 'case.upsert-batch'"
    ).fetchone()[0]
    alert_fetch_calls = conn.execute(
        "select count(*) from agent_tool_calls where tool_name = 'alert.fetch'"
    ).fetchone()[0]
    conn.close()

    assert result.status == "success"
    assert result.turns == 3
    assert result.tool_calls == 1
    assert case_upsert_calls == 0
    assert alert_fetch_calls == 1


def test_run_openai_patrol_requires_alert_fetch_before_other_tools(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_guard_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "case_upsert_batch",
                        "call_id": "call_guard_001",
                        "arguments": '{"items":[{"case_id":"case_guard_001","title":"guard","status":"open","overall_severity":"high","current_stage":"persistence"}]}',
                    }
                ],
            },
            {
                "id": "resp_guard_002",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_guard_002",
                        "arguments": '{"status":["new","open"],"limit":5}',
                    }
                ],
            },
            {
                "id": "resp_guard_003",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5-mini",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=5,
        client_factory=lambda: fake_client,
        tool_profile="compact",
    )

    case_upsert_calls = conn.execute(
        "select count(*) from agent_tool_calls where tool_name = 'case.upsert-batch'"
    ).fetchone()[0]
    alert_fetch_calls = conn.execute(
        "select count(*) from agent_tool_calls where tool_name = 'alert.fetch'"
    ).fetchone()[0]
    conn.close()

    assert result.status == "success"
    assert result.turns == 3
    assert result.tool_calls == 1
    assert case_upsert_calls == 0
    assert alert_fetch_calls == 1


def test_run_openai_patrol_enforces_total_tool_budget(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_budget_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_budget_001",
                        "arguments": '{"status":["new","open"],"limit":2}',
                    }
                ],
            },
            {
                "id": "resp_budget_002",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_budget_002",
                        "arguments": '{"status":["new","open"],"limit":2}',
                    }
                ],
            },
            {
                "id": "resp_budget_003",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_budget_003",
                        "arguments": '{"status":["new","open"],"limit":2}',
                    }
                ],
            },
            {
                "id": "resp_budget_004",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5-mini",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=5,
        max_tool_calls=2,
        client_factory=lambda: fake_client,
        tool_profile="compact",
    )

    alert_fetch_calls = conn.execute(
        "select count(*) from agent_tool_calls where tool_name = 'alert.fetch'"
    ).fetchone()[0]
    conn.close()

    assert result.status == "success"
    assert result.tool_calls == 2
    assert alert_fetch_calls == 2


def test_run_openai_patrol_blocks_persistence_writes_until_read_phase_ready(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_phase_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_phase_fetch",
                        "arguments": '{"status":["new","open"],"limit":5}',
                    }
                ],
            },
            {
                "id": "resp_phase_002",
                "output": [
                    {
                        "type": "function_call",
                        "name": "case_upsert_batch",
                        "call_id": "call_phase_case_upsert",
                        "arguments": '{"items":[{"case_id":"case_phase_001","title":"phase","status":"open","overall_severity":"high","current_stage":"recon"}]}',
                    }
                ],
            },
            {
                "id": "resp_phase_003",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5-mini",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=5,
        enforce_read_phase_gate=True,
        client_factory=lambda: fake_client,
        tool_profile="compact",
    )

    case_upsert_calls = conn.execute(
        "select count(*) from agent_tool_calls where tool_name = 'case.upsert-batch'"
    ).fetchone()[0]
    alert_fetch_calls = conn.execute(
        "select count(*) from agent_tool_calls where tool_name = 'alert.fetch'"
    ).fetchone()[0]
    conn.close()

    assert result.status == "success"
    assert result.tool_calls == 1
    assert case_upsert_calls == 0
    assert alert_fetch_calls == 1


def test_run_openai_patrol_allows_case_upsert_after_core_discovery_without_ip_context(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_gate_relax_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_gate_relax_fetch",
                        "arguments": '{"status":["new","open"],"limit":5}',
                    }
                ],
            },
            {
                "id": "resp_gate_relax_002",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_suspect_ip_topk",
                        "call_id": "call_gate_relax_topk",
                        "arguments": '{"status":["new","open"],"limit":5}',
                    }
                ],
            },
            {
                "id": "resp_gate_relax_003",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_detail_batch",
                        "call_id": "call_gate_relax_detail",
                        "arguments": '{"alert_ids":["alt_day1_scan_01"]}',
                    }
                ],
            },
            {
                "id": "resp_gate_relax_004",
                "output": [
                    {
                        "type": "function_call",
                        "name": "case_upsert_batch",
                        "call_id": "call_gate_relax_case_upsert",
                        "arguments": '{"items":[{"case_id":"case_gate_relax_001","title":"gate relax","status":"open","overall_severity":"high","current_stage":"recon"}]}',
                    }
                ],
            },
            {
                "id": "resp_gate_relax_005",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    dispatched_tools: list[str] = []

    def _fake_dispatch(_conn, tool_name: str, _payload: dict, *, source: str = "mcp") -> dict:
        dispatched_tools.append(f"{source}:{tool_name}")
        return {
            "ok": True,
            "summary": "ok",
            "data": {},
            "warnings": [],
            "refs": {},
            "page": {"next_cursor": None, "has_more": False},
            "meta": {},
        }

    monkeypatch.setattr("security_analyst_agent.openai_patrol_runner.dispatch_tool", _fake_dispatch)

    result = run_openai_patrol(
        conn,
        model="gpt-5-mini",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=6,
        enforce_read_phase_gate=True,
        client_factory=lambda: fake_client,
        tool_profile="compact",
    )
    conn.close()

    assert result.status == "success"
    assert result.tool_calls == 4
    assert "mcp:case.upsert-batch" in dispatched_tools


def test_run_openai_patrol_precheck_blocks_case_link_batch_when_case_missing(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_case_link_guard_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_case_link_guard_fetch",
                        "arguments": '{"status":["new","open"],"limit":5}',
                    }
                ],
            },
            {
                "id": "resp_case_link_guard_002",
                "output": [
                    {
                        "type": "function_call",
                        "name": "case_link_alert_batch",
                        "call_id": "call_case_link_guard_link",
                        "arguments": '{"items":[{"case_id":"case_missing_for_link_guard","alert_id":"alt_day1_scan_01","confidence":0.8,"reason":"guard test"}]}',
                    }
                ],
            },
            {
                "id": "resp_case_link_guard_003",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5-mini",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=5,
        client_factory=lambda: fake_client,
        tool_profile="compact",
    )

    alert_fetch_calls = conn.execute(
        "select count(*) from agent_tool_calls where tool_name = 'alert.fetch'"
    ).fetchone()[0]
    case_link_batch_calls = conn.execute(
        "select count(*) from agent_tool_calls where tool_name = 'case.link-alert-batch'"
    ).fetchone()[0]
    conn.close()

    assert result.status == "success"
    assert result.tool_calls == 1
    assert alert_fetch_calls == 1
    assert case_link_batch_calls == 0


def test_run_openai_patrol_retries_empty_provider_response_before_failing(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_empty_001",
                "usage": {"input_tokens": 0, "output_tokens": 0, "input_tokens_details": {"cached_tokens": 0}},
                "output": [],
            },
            {
                "id": "resp_recover_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_recover_fetch_001",
                        "arguments": '{"status":["new","open"],"limit":2}',
                    }
                ],
            },
            {
                "id": "resp_recover_002",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5-mini",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=5,
        client_factory=lambda: fake_client,
        tool_profile="compact",
    )

    alert_fetch_calls = conn.execute(
        "select count(*) from agent_tool_calls where tool_name = 'alert.fetch'"
    ).fetchone()[0]
    conn.close()

    assert result.status == "success"
    assert result.tool_calls == 1
    assert alert_fetch_calls == 1
    assert len(fake_client.responses.calls) == 3


def test_run_openai_patrol_alert_ack_guard_filters_unlinked_high_signal_alerts(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute(
        """
        insert into alerts (
          alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "alt_ack_guard_high_001",
            "2026-04-13T14:00:00+08:00",
            "high signal for ack guard",
            "open",
            "critical",
            "persistence",
            "198.51.100.23",
            "203.0.113.10",
            "asset_api_prod",
        ),
    )
    conn.execute(
        """
        insert into alerts (
          alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "alt_ack_guard_low_001",
            "2026-04-13T14:01:00+08:00",
            "low signal for ack guard",
            "open",
            "low",
            "recon",
            "198.51.100.200",
            "203.0.113.11",
            "asset_static_www",
        ),
    )
    conn.commit()

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_ack_guard_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_ack_guard_fetch",
                        "arguments": '{"status":["new","open"],"limit":5}',
                    }
                ],
            },
            {
                "id": "resp_ack_guard_002",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_ack",
                        "call_id": "call_ack_guard_ack",
                        "arguments": '{"alert_ids":["alt_ack_guard_high_001","alt_ack_guard_low_001"],"status":"triaged"}',
                    }
                ],
            },
            {
                "id": "resp_ack_guard_003",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5-mini",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=5,
        client_factory=lambda: fake_client,
        tool_profile="compact",
    )

    high_status = conn.execute(
        "select status from alerts where alert_id = ?",
        ("alt_ack_guard_high_001",),
    ).fetchone()[0]
    low_status = conn.execute(
        "select status from alerts where alert_id = ?",
        ("alt_ack_guard_low_001",),
    ).fetchone()[0]
    ack_call = conn.execute(
        """
        select result_json
        from agent_tool_calls
        where tool_name = 'alert.ack'
        order by occurred_at desc, rowid desc
        limit 1
        """
    ).fetchone()
    conn.close()

    assert result.status == "success"
    assert result.tool_calls == 2
    assert high_status == "open"
    assert low_status == "triaged"
    assert ack_call is not None


def test_run_openai_patrol_alert_ack_guard_can_skip_entire_ack_call(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute(
        """
        insert into alerts (
          alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "alt_ack_guard_high_only_001",
            "2026-04-13T14:10:00+08:00",
            "high signal only",
            "open",
            "high",
            "command_execution",
            "198.51.100.23",
            "203.0.113.10",
            "asset_api_prod",
        ),
    )
    conn.commit()

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_ack_guard_only_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_ack_guard_only_fetch",
                        "arguments": '{"status":["new","open"],"limit":5}',
                    }
                ],
            },
            {
                "id": "resp_ack_guard_only_002",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_ack",
                        "call_id": "call_ack_guard_only_ack",
                        "arguments": '{"alert_ids":["alt_ack_guard_high_only_001"],"status":"triaged"}',
                    }
                ],
            },
            {
                "id": "resp_ack_guard_only_003",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5-mini",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=5,
        client_factory=lambda: fake_client,
        tool_profile="compact",
    )

    high_status = conn.execute(
        "select status from alerts where alert_id = ?",
        ("alt_ack_guard_high_only_001",),
    ).fetchone()[0]
    ack_call_count = conn.execute(
        "select count(*) from agent_tool_calls where tool_name = 'alert.ack'"
    ).fetchone()[0]
    conn.close()

    assert result.status == "success"
    assert result.tool_calls == 1
    assert high_status == "open"
    assert ack_call_count == 0


def test_run_openai_patrol_stops_after_repeated_blocked_tool_loop(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_block_loop_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_block_loop_fetch",
                        "arguments": '{"status":["new","open"],"limit":2}',
                    }
                ],
            },
            *[
                {
                    "id": f"resp_block_loop_{index:03d}",
                    "output": [
                        {
                            "type": "function_call",
                            "name": "case_upsert_batch",
                            "call_id": f"call_block_loop_{index:03d}",
                            "arguments": '{"items":[]}',
                        }
                    ],
                }
                for index in range(2, 13)
            ],
        ]
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5-mini",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=12,
        client_factory=lambda: fake_client,
        tool_profile="compact",
    )
    conn.close()

    assert result.status == "success"
    assert result.tool_calls == 1
    assert "stopped_after_blocked_tool_loop" in result.detail


def test_run_openai_patrol_autofills_empty_case_upsert_and_seeds_links(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)

    for alert_id, src_ip, stage, occurred_at in [
        ("alt_auto_case_001", "198.51.100.23", "exploit", "2026-04-13T10:00:00+08:00"),
        ("alt_auto_case_002", "198.51.100.23", "persistence", "2026-04-13T10:02:00+08:00"),
        ("alt_auto_case_003", "198.51.100.23", "command_execution", "2026-04-13T10:04:00+08:00"),
        ("alt_auto_case_004", "203.0.113.88", "exploit", "2026-04-13T10:01:00+08:00"),
        ("alt_auto_case_005", "203.0.113.88", "persistence", "2026-04-13T10:03:00+08:00"),
        ("alt_auto_case_006", "203.0.113.88", "reactivation", "2026-04-13T10:05:00+08:00"),
    ]:
        conn.execute(
            """
            insert into alerts (
              alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                occurred_at,
                f"auto-case {alert_id}",
                "open",
                "high",
                stage,
                src_ip,
                "203.0.113.10",
                "asset_auto_case_api",
            ),
        )
    conn.commit()

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_auto_case_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_auto_case_fetch",
                        "arguments": '{"status":["new","open"],"limit":20}',
                    }
                ],
            },
            {
                "id": "resp_auto_case_002",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_suspect_ip_topk",
                        "call_id": "call_auto_case_topk",
                        "arguments": '{"status":["new","open"],"top_k":5}',
                    }
                ],
            },
            {
                "id": "resp_auto_case_003",
                "output": [
                    {
                        "type": "function_call",
                        "name": "case_upsert_batch",
                        "call_id": "call_auto_case_upsert",
                        "arguments": '{"items":[]}',
                    }
                ],
            },
            {
                "id": "resp_auto_case_004",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5-mini",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=6,
        client_factory=lambda: fake_client,
        tool_profile="compact",
    )

    auto_case_rows = conn.execute(
        """
        select case_id
        from cases
        where case_id like 'case_auto_hotspot_%'
        order by case_id asc
        """
    ).fetchall()
    auto_link_count = conn.execute(
        """
        select count(*)
        from case_alert_links
        where is_active = 1
          and case_id like 'case_auto_hotspot_%'
        """
    ).fetchone()[0]
    conn.close()

    assert result.status == "success"
    assert result.tool_calls >= 4
    assert len(auto_case_rows) >= 1
    assert auto_link_count >= 1


def test_run_openai_patrol_auto_acks_low_recon_noise_when_model_does_not_ack(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute(
        """
        insert into alerts (
          alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "alt_auto_noise_001",
            "2026-04-13T09:00:00+08:00",
            "auto ack low recon",
            "open",
            "low",
            "recon",
            "192.0.2.21",
            "203.0.113.10",
            "asset_static_www",
        ),
    )
    conn.commit()

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_auto_ack_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_auto_ack_fetch",
                        "arguments": '{"status":["new","open"],"limit":5}',
                    }
                ],
            },
            {
                "id": "resp_auto_ack_002",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5-mini",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=4,
        client_factory=lambda: fake_client,
        tool_profile="compact",
    )

    ack_count = conn.execute(
        "select count(*) from agent_tool_calls where tool_name = 'alert.ack'"
    ).fetchone()[0]
    low_recon_status = conn.execute(
        "select status from alerts where alert_id = 'alt_auto_noise_001'"
    ).fetchone()[0]
    conn.close()

    assert result.status == "success"
    assert result.tool_calls == 2
    assert "auto_noise_ack=" in result.detail
    assert ack_count == 1
    assert low_recon_status == "triaged"


def test_run_openai_patrol_objective_mode_disables_auto_case_seed_assist(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    rows = []
    for index in range(6):
        rows.append(
            (
                f"alt_auto_case_objective_{index}",
                f"2026-04-13T11:{index:02d}:00+08:00",
                f"auto-case objective alt_auto_case_objective_{index}",
                "open",
                "high",
                "command_execution",
                "198.51.100.250",
                "203.0.113.10",
                "asset_auto_case_api",
            )
        )
    conn.executemany(
        """
        insert into alerts (
          alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_auto_case_objective_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_auto_case_objective_fetch",
                        "arguments": '{"status":["new","open"],"limit":20}',
                    }
                ],
            },
            {
                "id": "resp_auto_case_objective_002",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_suspect_ip_topk",
                        "call_id": "call_auto_case_objective_topk",
                        "arguments": '{"status":["new","open"],"top_k":5}',
                    }
                ],
            },
            {
                "id": "resp_auto_case_objective_003",
                "output": [
                    {
                        "type": "function_call",
                        "name": "case_upsert_batch",
                        "call_id": "call_auto_case_objective_upsert",
                        "arguments": '{"items":[]}',
                    }
                ],
            },
            {
                "id": "resp_auto_case_objective_004",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5-mini",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=6,
        client_factory=lambda: fake_client,
        tool_profile="compact",
        objective_mode=True,
    )

    auto_case_count = conn.execute(
        """
        select count(*)
        from cases
        where case_id like 'case_auto_hotspot_%'
        """
    ).fetchone()[0]
    conn.close()

    assert result.status == "success"
    assert auto_case_count == 0


def test_run_openai_patrol_objective_mode_disables_auto_ack_fallback(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    conn = connect_db(db_path)
    conn.execute(
        """
        insert into alerts (
          alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "alt_auto_noise_objective_001",
            "2026-04-13T09:00:00+08:00",
            "auto ack low recon objective",
            "open",
            "low",
            "recon",
            "192.0.2.23",
            "203.0.113.10",
            "asset_static_www",
        ),
    )
    conn.commit()

    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_auto_ack_objective_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_auto_ack_objective_fetch",
                        "arguments": '{"status":["new","open"],"limit":5}',
                    }
                ],
            },
            {
                "id": "resp_auto_ack_objective_002",
                "output_text": "[SILENT]",
                "output": [{"type": "message", "role": "assistant"}],
            },
        ]
    )

    result = run_openai_patrol(
        conn,
        model="gpt-5-mini",
        instructions="run patrol",
        query="start",
        previous_response_id=None,
        max_turns=4,
        client_factory=lambda: fake_client,
        tool_profile="compact",
        objective_mode=True,
    )

    ack_count = conn.execute(
        "select count(*) from agent_tool_calls where tool_name = 'alert.ack'"
    ).fetchone()[0]
    low_recon_status = conn.execute(
        "select status from alerts where alert_id = 'alt_auto_noise_objective_001'"
    ).fetchone()[0]
    conn.close()

    assert result.status == "success"
    assert result.tool_calls == 1
    assert "auto_noise_ack=" not in result.detail
    assert ack_count == 0
    assert low_recon_status == "open"
