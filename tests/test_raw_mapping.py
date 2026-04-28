from security_analyst_agent.db import connect_db, create_schema
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


def test_raw_mapping_resolves_asset_identity_and_creates_temp_asset(tmp_path) -> None:
    db_path = tmp_path / "raw-asset-resolve.db"
    conn = connect_db(db_path)
    create_schema(conn)
    conn.execute(
        """
        insert into assets (
          asset_id, asset_name, system_name, owner_team, internet_exposed, public_ip, domain
        ) values (?, ?, ?, ?, ?, ?, ?)
        """,
        ("asset_api_prod", "API Prod", "api-prod", "secops", 1, "203.0.113.10", "api.example.com"),
    )
    conn.execute(
        """
        insert into asset_identities (
          identity_id, asset_id, identity_type, identity_value, is_primary, confidence, created_at
        ) values (?, ?, ?, ?, ?, ?, ?)
        """,
        ("idn_asset_api_prod_ip", "asset_api_prod", "ip", "203.0.113.10", 1, 0.99, "2026-04-20T00:00:00Z"),
    )
    conn.commit()
    conn.close()

    ingest_raw_alert_bundle(
        db_path=db_path,
        source="waf_import_asset",
        events=[
            {
                "raw_event_id": "raw_asset_evt_001",
                "source": "waf_import_asset",
                "vendor": "acme",
                "product": "waf",
                "log_type": "attack",
                "rule_id": "R-001",
                "payload": {
                    "ts": "2026-04-20T11:00:00+08:00",
                    "message": "existing-target",
                    "severity": "high",
                    "stage": "recon",
                    "src": "198.51.100.10",
                    "dst_ip": "203.0.113.10",
                },
            },
            {
                "raw_event_id": "raw_asset_evt_002",
                "source": "waf_import_asset",
                "vendor": "acme",
                "product": "waf",
                "log_type": "attack",
                "rule_id": "R-002",
                "payload": {
                    "ts": "2026-04-20T11:01:00+08:00",
                    "message": "new-target-first",
                    "severity": "medium",
                    "stage": "recon",
                    "src": "198.51.100.11",
                    "dst_ip": "203.0.113.250",
                },
            },
            {
                "raw_event_id": "raw_asset_evt_003",
                "source": "waf_import_asset",
                "vendor": "acme",
                "product": "waf",
                "log_type": "attack",
                "rule_id": "R-003",
                "payload": {
                    "ts": "2026-04-20T11:02:00+08:00",
                    "message": "new-target-repeat",
                    "severity": "medium",
                    "stage": "recon",
                    "src": "198.51.100.12",
                    "dst_ip": "203.0.113.250",
                },
            },
        ],
    )

    upsert_alert_normalization_maps(
        db_path=db_path,
        maps=[
            {
                "map_id": "map_asset_resolve_v1",
                "priority": 100,
                "enabled": True,
                "match": {
                    "source": "waf_import_asset",
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
                        "dst_ip": "payload.dst_ip",
                    },
                    "defaults": {
                        "status": "new",
                    },
                },
            }
        ],
    )

    result = apply_alert_normalization_maps(db_path=db_path, limit=100)
    assert result["processed"] == 3
    assert result["mapped"] == 3
    assert result["unmapped"] == 0
    assert result["asset_resolved_count"] == 2
    assert result["asset_auto_created_count"] == 1
    assert result["asset_unresolved_count"] == 0

    conn = connect_db(db_path)
    try:
        existing_asset_alert = conn.execute(
            "select asset_id from alerts where title = ?",
            ("existing-target",),
        ).fetchone()
        assert existing_asset_alert is not None
        assert existing_asset_alert["asset_id"] == "asset_api_prod"

        first_temp_alert = conn.execute(
            "select asset_id from alerts where title = ?",
            ("new-target-first",),
        ).fetchone()
        second_temp_alert = conn.execute(
            "select asset_id from alerts where title = ?",
            ("new-target-repeat",),
        ).fetchone()
        assert first_temp_alert is not None
        assert second_temp_alert is not None
        assert first_temp_alert["asset_id"] == second_temp_alert["asset_id"]
        assert str(first_temp_alert["asset_id"]).startswith("asset_tmp_")

        temp_asset = conn.execute(
            "select public_ip from assets where asset_id = ?",
            (first_temp_alert["asset_id"],),
        ).fetchone()
        assert temp_asset is not None
        assert temp_asset["public_ip"] == "203.0.113.250"

        temp_identity = conn.execute(
            """
            select identity_value
            from asset_identities
            where asset_id = ? and identity_type = 'ip'
            """,
            (first_temp_alert["asset_id"],),
        ).fetchone()
        assert temp_identity is not None
        assert temp_identity["identity_value"] == "203.0.113.250"
    finally:
        conn.close()


def test_raw_mapping_infers_stage_severity_and_target_from_cn_threat_payload(tmp_path) -> None:
    db_path = tmp_path / "raw-threat-intel-infer.db"
    ingest_raw_alert_bundle(
        db_path=db_path,
        source="cn_honeypot_import",
        events=[
            {
                "raw_event_id": "raw_cn_evt_001",
                "source": "cn_honeypot_import",
                "vendor": "unknown_vendor",
                "product": "kibana",
                "log_type": "csv_row",
                "rule_id": "扫描,漏洞利用,CVE-2017-9841",
                "payload": {
                    "row": {
                        "攻击时间": "2026-04-20 11:00:00",
                        "攻击IP": "198.51.100.88",
                        "威胁情报": "扫描,傀儡机,漏洞利用,垃圾邮件,CVE-2017-9841",
                        "蜜罐名称": "kibana",
                        "攻击详情": (
                            '{"host":"203.0.113.77:80","remote_addr":"198.51.100.88:40152",'
                            '"method":"GET","url":"/index.php"}'
                        ),
                    }
                },
            }
        ],
    )
    upsert_alert_normalization_maps(
        db_path=db_path,
        maps=[
            {
                "map_id": "map_cn_honeypot_v1",
                "priority": 100,
                "enabled": True,
                "match": {"source": "cn_honeypot_import"},
                "mapping": {
                    "field_map": {
                        "occurred_at": "payload.row.攻击时间",
                        "src_ip": "payload.row.攻击IP",
                        "title": "payload.row.威胁情报",
                        "attack_stage": "payload.row.威胁情报",
                        "severity": "payload.row.威胁情报",
                    },
                    "defaults": {
                        "status": "new",
                        "attack_stage": "recon",
                        "severity": "medium",
                    },
                    "value_maps": {
                        "attack_stage": {
                            "扫描": "recon",
                            "漏洞利用": "exploit",
                            "cve": "exploit",
                        },
                        "severity": {
                            "扫描": "medium",
                            "漏洞利用": "high",
                            "cve": "high",
                        },
                    },
                },
            }
        ],
    )

    result = apply_alert_normalization_maps(db_path=db_path, limit=10)
    assert result["mapped"] == 1
    assert result["asset_auto_created_count"] == 1

    conn = connect_db(db_path)
    try:
        alert = conn.execute(
            """
            select severity, attack_stage, src_ip, dst_ip, asset_id
            from alerts
            where alert_id = 'alt_raw_raw_cn_evt_001'
            """
        ).fetchone()
        assert alert is not None
        assert alert["severity"] == "high"
        assert alert["attack_stage"] == "exploit"
        assert alert["src_ip"] == "198.51.100.88"
        assert alert["dst_ip"] == "203.0.113.77"
        assert str(alert["asset_id"]).startswith("asset_tmp_")
    finally:
        conn.close()
