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
