import pytest
from pydantic import ValidationError

from security_analyst_agent.tools.assessment_tools import assessment_upsert, assessment_upsert_batch


def test_assessment_upsert_batch_writes_multiple_entities(db_conn) -> None:
    result = assessment_upsert_batch(
        db_conn,
        {
            "items": [
                {
                    "entity_type": "ip",
                    "entity_key": "198.51.100.23",
                    "entity_label": "198.51.100.23",
                    "related_case_id": "case_demo_001",
                    "risk_level": "high",
                    "assessment_confidence": 0.93,
                    "verdict": "attacker",
                    "reason_summary": "batch attacker assessment",
                    "supporting_alert_ids": ["alt_day2_webshell_01"],
                    "supporting_evidence_ids": [],
                },
                {
                    "entity_type": "asset",
                    "entity_key": "asset_api_prod",
                    "entity_label": "asset_api_prod",
                    "related_case_id": "case_demo_001",
                    "risk_level": "high",
                    "assessment_confidence": 0.91,
                    "verdict": "compromised_host",
                    "reason_summary": "batch compromised host assessment",
                    "supporting_alert_ids": ["alt_day3_shell_01"],
                    "supporting_evidence_ids": [],
                },
            ]
        },
    )

    assert result["ok"] is True
    assert len(result["data"]["assessments"]) == 2
    assert result["data"]["failures"] == []


def test_assessment_upsert_batch_matches_single_tool_behavior(db_conn) -> None:
    single = assessment_upsert(
        db_conn,
        {
            "entity_type": "ip",
            "entity_key": "203.0.113.200",
            "entity_label": "203.0.113.200",
            "related_case_id": None,
            "risk_level": "low",
            "assessment_confidence": 0.7,
            "verdict": "noise",
            "reason_summary": "single assessment",
            "supporting_alert_ids": ["alt_day1_scan_01"],
            "supporting_evidence_ids": [],
        },
    )
    batch = assessment_upsert_batch(
        db_conn,
        {
            "items": [
                {
                    "entity_type": "ip",
                    "entity_key": "203.0.113.201",
                    "entity_label": "203.0.113.201",
                    "related_case_id": None,
                    "risk_level": "low",
                    "assessment_confidence": 0.7,
                    "verdict": "noise",
                    "reason_summary": "batch assessment",
                    "supporting_alert_ids": ["alt_day1_scan_01"],
                    "supporting_evidence_ids": [],
                }
            ]
        },
    )

    assert single["ok"] is True
    assert batch["ok"] is True
    assert len(batch["data"]["assessments"]) == 1


def test_assessment_upsert_batch_empty_payload_raises_validation_error(db_conn) -> None:
    with pytest.raises(ValidationError):
        assessment_upsert_batch(db_conn, {})


def test_assessment_upsert_infers_related_case_id_from_alert_links(db_conn) -> None:
    result = assessment_upsert(
        db_conn,
        {
            "entity_type": "ip",
            "entity_key": "198.51.100.77",
            "entity_label": "198.51.100.77",
            "related_case_id": None,
            "risk_level": "high",
            "assessment_confidence": 0.85,
            "verdict": "attacker",
            "reason_summary": "infer case from linked alert",
            "supporting_alert_ids": ["alt_day3_shell_01"],
            "supporting_evidence_ids": [],
        },
    )

    assert result["ok"] is True
    assert result["data"]["assessment"]["related_case_id"] == "case_demo_001"
    assert "related_case_id_inferred_from_alert_links" in result["warnings"]


def test_assessment_upsert_global_current_is_suppressed_when_case_current_exists(db_conn) -> None:
    scoped = assessment_upsert(
        db_conn,
        {
            "entity_type": "ip",
            "entity_key": "198.51.100.77",
            "entity_label": "198.51.100.77",
            "related_case_id": "case_demo_001",
            "risk_level": "high",
            "assessment_confidence": 0.9,
            "verdict": "attacker",
            "reason_summary": "case scoped attacker",
            "supporting_alert_ids": ["alt_day3_shell_01"],
            "supporting_evidence_ids": [],
        },
    )
    global_row = assessment_upsert(
        db_conn,
        {
            "entity_type": "ip",
            "entity_key": "198.51.100.77",
            "entity_label": "198.51.100.77",
            "related_case_id": None,
            "risk_level": "high",
            "assessment_confidence": 0.8,
            "verdict": "attacker",
            "reason_summary": "global attacker without case",
            "supporting_alert_ids": [],
            "supporting_evidence_ids": [],
        },
    )

    assert scoped["ok"] is True
    assert scoped["data"]["assessment"]["is_current"] == 1
    assert global_row["ok"] is True
    assert global_row["data"]["assessment"]["is_current"] == 0

    current_rows = db_conn.execute(
        """
        select related_case_id
        from entity_assessments
        where entity_type = 'ip'
          and entity_key = '198.51.100.77'
          and is_current = 1
        """
    ).fetchall()
    assert len(current_rows) == 1
    assert current_rows[0]["related_case_id"] == "case_demo_001"
