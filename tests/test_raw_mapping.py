from security_analyst_agent.db import connect_db
from security_analyst_agent.raw_mapping import (
    apply_alert_normalization_maps,
    ingest_raw_alert_bundle,
    list_unmapped_alert_events,
    sample_raw_alert_groups,
    upsert_alert_normalization_maps,
)


def test_raw_mapping_pipeline_maps_and_queues_unmapped(tmp_path) -> None:
    db_path = tmp_path / "raw-map.db"

    ingest_raw_alert_bundle(
        db_path=db_path,
        source="waf_import",
        events=[
            {
                "raw_event_id": "raw_evt_ok_001",
                "source": "waf_import",
                "vendor": "acme",
                "product": "waf",
                "log_type": "attack",
                "rule_id": "RCE-001",
                "payload": {
                    "ts": "2026-04-20T16:00:00+08:00",
                    "message": "OGNL payload blocked",
                    "severity": "critical",
                    "stage": "rce",
                    "src": "198.51.100.23",
                    "dst": "203.0.113.10",
                    "asset": "asset_api_prod",
                },
            },
            {
                "raw_event_id": "raw_evt_unknown_001",
                "source": "waf_import",
                "vendor": "unknown_vendor",
                "product": "unknown_product",
                "log_type": "other",
                "rule_id": "N/A",
                "payload": {"foo": "bar"},
            },
        ],
    )

    upsert_alert_normalization_maps(
        db_path=db_path,
        maps=[
            {
                "map_id": "map_waf_attack_v1",
                "priority": 200,
                "enabled": True,
                "match": {
                    "source": "waf_import",
                    "vendor": "acme",
                    "product": "waf",
                    "log_type": "attack",
                },
                "mapping": {
                    "field_map": {
                        "occurred_at": "payload.ts",
                        "title": "payload.message",
                        "severity": "payload.severity",
                        "attack_stage": "payload.stage",
                        "src_ip": "payload.src",
                        "dst_ip": "payload.dst",
                        "asset_id": "payload.asset",
                    },
                    "defaults": {"status": "new"},
                    "value_maps": {
                        "attack_stage": {
                            "rce": "exploit",
                        }
                    },
                    "confidence": 0.92,
                    "reason": "waf_attack_signature_mapping",
                },
            }
        ],
    )

    result = apply_alert_normalization_maps(db_path=db_path, limit=100)
    assert result["processed"] == 2
    assert result["mapped"] == 1
    assert result["unmapped"] == 1

    conn = connect_db(db_path)
    try:
        alert = conn.execute(
            """
            select alert_id, title, severity, attack_stage, src_ip, asset_id
            from alerts
            where src_ip = ?
            """,
            ("198.51.100.23",),
        ).fetchone()
        assert alert is not None
        assert alert["title"] == "OGNL payload blocked"
        assert alert["severity"] == "critical"
        assert alert["attack_stage"] == "exploit"
        assert alert["asset_id"] == "asset_api_prod"

        mapped_row = conn.execute(
            "select map_status, map_id, normalized_alert_id from raw_alert_events where raw_event_id = ?",
            ("raw_evt_ok_001",),
        ).fetchone()
        assert mapped_row["map_status"] == "mapped"
        assert mapped_row["map_id"] == "map_waf_attack_v1"
        assert mapped_row["normalized_alert_id"] is not None

        unmapped_row = conn.execute(
            "select map_status, map_reason from raw_alert_events where raw_event_id = ?",
            ("raw_evt_unknown_001",),
        ).fetchone()
        assert unmapped_row["map_status"] == "unmapped"
        assert unmapped_row["map_reason"] == "no_matching_map"

        ingest_event = conn.execute(
            "select source, trigger_state from alert_ingest_events where alert_id = ?",
            (mapped_row["normalized_alert_id"],),
        ).fetchone()
        assert ingest_event is not None
        assert ingest_event["source"] == "raw_map:map_waf_attack_v1"
        assert ingest_event["trigger_state"] == "pending"
    finally:
        conn.close()

    unmapped = list_unmapped_alert_events(db_path=db_path, unresolved_only=True, limit=10)
    assert len(unmapped["items"]) == 1
    assert unmapped["items"][0]["raw_event_id"] == "raw_evt_unknown_001"


def test_raw_group_sampling_returns_clustered_samples(tmp_path) -> None:
    db_path = tmp_path / "raw-sample.db"
    ingest_raw_alert_bundle(
        db_path=db_path,
        source="siem_import",
        events=[
            {
                "raw_event_id": "raw_sample_001",
                "source": "siem_import",
                "vendor": "foo",
                "product": "bar",
                "log_type": "waf",
                "rule_id": "RULE-01",
                "payload": {"msg": "a"},
            },
            {
                "raw_event_id": "raw_sample_002",
                "source": "siem_import",
                "vendor": "foo",
                "product": "bar",
                "log_type": "waf",
                "rule_id": "RULE-01",
                "payload": {"msg": "b"},
            },
        ],
    )

    sampled = sample_raw_alert_groups(db_path=db_path, limit_groups=5, samples_per_group=2)
    assert sampled["groups"]
    first = sampled["groups"][0]
    assert first["event_count"] == 2
    assert first["group_key"]["source"] == "siem_import"
    assert first["group_key"]["rule_id"] == "RULE-01"
    assert len(first["samples"]) == 2
