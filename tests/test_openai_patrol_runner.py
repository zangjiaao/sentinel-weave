from __future__ import annotations

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

