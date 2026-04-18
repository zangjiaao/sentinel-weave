from __future__ import annotations

from dataclasses import dataclass

from security_analyst_agent.bootstrap import bootstrap_spike_database
from security_analyst_agent.db import connect_db
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
        return self._rounds[index]


class _FakeOpenAIClient:
    def __init__(self, rounds: list[dict]) -> None:
        self.responses = _FakeOpenAIResponses(rounds)


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
    assert fake_client.responses.calls[0]["previous_response_id"] == "resp_prev_001"
    assert fake_client.responses.calls[1]["previous_response_id"] == "resp_runner_001"
    assert "instructions" in fake_client.responses.calls[0]
    assert "instructions" not in fake_client.responses.calls[1]


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
