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
