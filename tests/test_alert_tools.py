from security_analyst_agent.schemas.alert_tools import AlertFetchRequest
from security_analyst_agent.schemas.common import ToolResponse
from security_analyst_agent.tools.alert_tools import (
    alert_ack,
    alert_detail,
    alert_detail_batch,
    alert_fetch,
    alert_ip_context,
    alert_suspect_ip_topk,
)


def test_alert_fetch_request_defaults_limit_to_20() -> None:
    request = AlertFetchRequest.model_validate({})
    assert request.limit == 20
    assert request.mode == "auto"
    assert request.hotspot_top_n == 3


def test_tool_response_requires_summary() -> None:
    response = ToolResponse(ok=True, summary="ok", data={})
    assert response.summary == "ok"
    assert response.meta.partial is False


def test_alert_fetch_returns_ranked_queue(db_conn) -> None:
    result = alert_fetch(db_conn, {"status": ["new", "open"], "limit": 10})
    assert result["ok"] is True
    assert result["data"]["mode"] == "alerts"
    assert result["data"]["alerts"][0]["alert_id"] == "alt_day3_shell_01"


def test_alert_fetch_includes_current_ingest_batch_summary(db_conn) -> None:
    db_conn.execute(
        """
        insert into alert_ingest_events (event_id, alert_id, source, ingested_at, trigger_state)
        values (?, ?, ?, ?, ?), (?, ?, ?, ?, ?)
        """,
        (
            "evt_fetch_summary_001",
            "alt_day2_webshell_01",
            "unit",
            "2026-04-12T12:00:00+08:00",
            "processing",
            "evt_fetch_summary_002",
            "alt_day3_shell_01",
            "unit",
            "2026-04-12T12:00:01+08:00",
            "processing",
        ),
    )
    db_conn.commit()

    result = alert_fetch(db_conn, {"status": ["new", "open"], "limit": 10})
    summary = result["data"]["ingest_batch_summary"]
    assert summary["has_current_queue"] is True
    assert summary["queue_event_count"] == 2
    assert summary["queue_alert_count"] == 2
    assert summary["severity_breakdown"]["high"] == 2
    assert summary["top_src_ips"][0]["src_ip"] in {"198.51.100.23", "198.51.100.77"}


def test_alert_suspect_ip_topk_returns_ranked_sources(db_conn) -> None:
    rows = []
    for index in range(6):
        rows.append(
            (
                f"alt_suspect_rank_{index}",
                f"2026-04-13T15:{index:02d}:00+08:00",
                "高危链路活动",
                "open",
                "high",
                "command_execution",
                "203.0.113.88",
                "203.0.113.10",
                "asset_api_prod" if index < 3 else "asset_admin_portal",
            )
        )
    for index in range(3):
        rows.append(
            (
                f"alt_suspect_rank_low_{index}",
                f"2026-04-13T15:3{index}:00+08:00",
                "低危扫描噪音",
                "open",
                "low",
                "recon",
                "198.51.100.200",
                "203.0.113.12",
                "asset_static_www",
            )
        )
    db_conn.executemany(
        """
        insert into alerts (
          alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    db_conn.commit()

    result = alert_suspect_ip_topk(
        db_conn,
        {
            "status": ["open"],
            "top_k": 3,
            "queue_only": False,
            "min_alert_count": 2,
        },
    )
    assert result["ok"] is True
    suspects = result["data"]["suspects"]
    assert len(suspects) >= 1
    assert suspects[0]["src_ip"] == "203.0.113.88"
    assert "high_severity_activity_detected" in suspects[0]["reason_codes"]
    assert suspects[0]["asset_spread"] >= 2


def test_alert_ip_context_returns_summary_and_alert_samples(db_conn) -> None:
    result = alert_ip_context(
        db_conn,
        {
            "src_ip": "198.51.100.23",
            "status": ["open"],
            "queue_only": False,
            "limit": 10,
        },
    )
    assert result["ok"] is True
    assert result["data"]["src_ip"] == "198.51.100.23"
    assert result["data"]["summary"]["alert_count"] >= 2
    assert len(result["data"]["alerts"]) >= 2


def test_alert_detail_returns_parser_and_evidence_refs(db_conn) -> None:
    result = alert_detail(db_conn, {"alert_id": "alt_day2_webshell_01"})
    assert result["data"]["alert"]["attack_stage"] == "persistence"
    assert "parser_profile_version_id" in result["data"]["alert"]


def test_alert_detail_batch_returns_multiple_alerts(db_conn) -> None:
    result = alert_detail_batch(db_conn, {"alert_ids": ["alt_day2_webshell_01", "alt_day1_scan_01"]})

    assert result["ok"] is True
    assert len(result["data"]["alerts"]) == 2
    assert result["data"]["missing_alert_ids"] == []
    assert all("parser_profile_version_id" in alert for alert in result["data"]["alerts"])


def test_alert_ack_updates_status_and_removes_from_queue(db_conn) -> None:
    ack_result = alert_ack(
        db_conn,
        {
            "alert_ids": ["alt_day1_scan_01", "alt_day2_webshell_01"],
            "status": "triaged",
        },
    )
    assert ack_result["ok"] is True
    assert ack_result["data"]["ack"]["updated_count"] == 2

    fetch_result = alert_fetch(db_conn, {"status": ["new", "open"], "limit": 10})
    ids = {item["alert_id"] for item in fetch_result["data"]["alerts"]}
    assert "alt_day1_scan_01" not in ids
    assert "alt_day2_webshell_01" not in ids


def test_alert_fetch_respects_active_analysis_cutoff(db_conn) -> None:
    db_conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at)
        values (?, ?, ?, ?, ?, ?)
        """,
        (
            "run_cutoff_001",
            "ingest_event",
            "running",
            "cutoff test",
            "2026-04-14T09:00:00+08:00",
            "2026-04-10T23:59:59+08:00",
        ),
    )
    result = alert_fetch(db_conn, {"status": ["new", "open"], "limit": 10})
    assert result["ok"] is True
    assert [item["alert_id"] for item in result["data"]["alerts"]] == ["alt_day1_scan_01"]


def test_alert_detail_respects_active_analysis_cutoff(db_conn) -> None:
    db_conn.execute(
        """
        insert into patrol_runs (run_id, trigger_source, status, summary, started_at, analysis_cutoff_at)
        values (?, ?, ?, ?, ?, ?)
        """,
        (
            "run_cutoff_002",
            "ingest_event",
            "running",
            "cutoff test detail",
            "2026-04-14T09:01:00+08:00",
            "2026-04-10T23:59:59+08:00",
        ),
    )
    result = alert_detail(db_conn, {"alert_id": "alt_day1_scan_01"})
    evidence_ids = result["refs"]["evidence_ids"]
    assert "evi_webshell_01" not in evidence_ids
    assert "evi_shell_conn_01" not in evidence_ids


def test_alert_detail_batch_reports_missing_ids(db_conn) -> None:
    result = alert_detail_batch(db_conn, {"alert_ids": ["alt_day2_webshell_01", "alt_missing_001"]})

    assert result["ok"] is True
    assert len(result["data"]["alerts"]) == 1
    assert result["data"]["missing_alert_ids"] == ["alt_missing_001"]
    assert "alert_not_found:alt_missing_001" in result["warnings"]


def test_alert_fetch_clusters_groups_repeated_alerts_and_keeps_high_singleton(db_conn) -> None:
    rows = []
    for index in range(5):
        rows.append(
            (
                f"alt_cluster_noise_{index}",
                f"2026-04-13T10:0{index}:00+08:00",
                "重复扫描噪音",
                "new",
                "low",
                "recon",
                "203.0.113.201",
                "203.0.113.12",
                "asset_static_www",
            )
        )
    rows.extend(
        [
            (
                "alt_cluster_high_singleton",
                "2026-04-13T10:10:00+08:00",
                "高危单点持久化",
                "new",
                "high",
                "persistence",
                "198.51.100.201",
                "203.0.113.10",
                "asset_api_prod",
            ),
            (
                "alt_cluster_medium_singleton",
                "2026-04-13T10:11:00+08:00",
                "中危单点探测",
                "new",
                "medium",
                "recon",
                "198.51.100.202",
                "203.0.113.11",
                "asset_admin_portal",
            ),
        ]
    )
    db_conn.executemany(
        """
        insert into alerts (
          alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    db_conn.commit()

    result = alert_fetch(
        db_conn,
        {
            "mode": "clusters",
            "status": ["new"],
            "limit": 10,
            "cluster_min_count": 3,
            "cluster_sample_size": 2,
        },
    )
    assert result["ok"] is True
    assert result["data"]["mode"] == "clusters"
    assert result["data"]["alerts"] == []
    assert result["data"]["total_candidates"] == 7
    assert result["data"]["omitted_alert_count"] == 1
    assert "cluster_filter_omitted_low_volume_alerts" in result["warnings"]

    clusters = result["data"]["clusters"]
    assert len(clusters) == 2
    repeated_cluster = next(item for item in clusters if item["src_ip"] == "203.0.113.201")
    assert repeated_cluster["alert_count"] == 5
    assert len(repeated_cluster["sample_alert_ids"]) == 2
    high_singleton_cluster = next(item for item in clusters if item["src_ip"] == "198.51.100.201")
    assert high_singleton_cluster["alert_count"] == 1
    assert high_singleton_cluster["max_severity"] == "high"


def test_alert_fetch_auto_switches_to_clusters_when_volume_exceeds_threshold(db_conn) -> None:
    rows = []
    for index in range(25):
        rows.append(
            (
                f"alt_auto_cluster_{index}",
                f"2026-04-13T11:{index:02d}:00+08:00",
                "大批量同源扫描",
                "new",
                "low",
                "recon",
                "192.0.2.201",
                "203.0.113.12",
                "asset_static_www",
            )
        )
    db_conn.executemany(
        """
        insert into alerts (
          alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    db_conn.commit()

    result = alert_fetch(
        db_conn,
        {
            "mode": "auto",
            "status": ["new"],
            "limit": 5,
            "auto_cluster_threshold": 20,
            "cluster_min_count": 2,
        },
    )
    assert result["ok"] is True
    assert result["data"]["mode"] == "clusters"
    assert result["data"]["alerts"] == []
    assert len(result["data"]["clusters"]) >= 1


def test_alert_fetch_clusters_fallbacks_to_alerts_when_no_cluster_candidates(db_conn) -> None:
    rows = []
    for index in range(12):
        rows.append(
            (
                f"alt_cluster_fallback_noise_{index}",
                f"2026-04-13T11:{index:02d}:00+08:00",
                "低危单点扫描",
                "new",
                "low",
                "recon",
                f"198.51.100.{100 + index}",
                "203.0.113.12",
                "asset_static_www",
            )
        )
    db_conn.executemany(
        """
        insert into alerts (
          alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    db_conn.commit()

    result = alert_fetch(
        db_conn,
        {
            "mode": "auto",
            "status": ["new"],
            "limit": 5,
            "auto_cluster_threshold": 8,
            "cluster_min_count": 2,
        },
    )
    assert result["ok"] is True
    assert result["data"]["mode"] == "alerts"
    assert len(result["data"]["alerts"]) == 5
    assert result["data"]["clusters"] == []
    assert "clusters_empty_fallback_to_alerts" in result["warnings"]


def test_alert_fetch_clusters_supports_backlog_cursor_and_priority_buckets(db_conn) -> None:
    rows = []
    for index in range(3):
        rows.append(
            (
                f"alt_backlog_p0_{index}",
                f"2026-04-13T12:0{index}:00+08:00",
                "高危命令执行",
                "new",
                "critical",
                "command_execution",
                "198.51.100.31",
                "203.0.113.10",
                "asset_api_prod",
            )
        )
        rows.append(
            (
                f"alt_backlog_p1_{index}",
                f"2026-04-13T12:1{index}:00+08:00",
                "高危持久化",
                "new",
                "high",
                "persistence",
                "198.51.100.32",
                "203.0.113.10",
                "asset_api_prod",
            )
        )
        rows.append(
            (
                f"alt_backlog_p2_{index}",
                f"2026-04-13T12:2{index}:00+08:00",
                "中危侦察",
                "new",
                "medium",
                "recon",
                "198.51.100.33",
                "203.0.113.11",
                "asset_admin_portal",
            )
        )
    rows.append(
        (
            "alt_backlog_omitted_single",
            "2026-04-13T12:59:00+08:00",
            "低危单点噪音",
            "new",
            "low",
            "recon",
            "203.0.113.201",
            "203.0.113.12",
            "asset_static_www",
        )
    )
    db_conn.executemany(
        """
        insert into alerts (
          alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    db_conn.commit()

    first = alert_fetch(
        db_conn,
        {
            "mode": "clusters",
            "status": ["new"],
            "limit": 1,
            "cluster_min_count": 2,
            "cluster_sample_size": 1,
        },
    )
    assert first["ok"] is True
    assert first["data"]["mode"] == "clusters"
    assert len(first["data"]["clusters"]) == 1
    assert first["data"]["clusters"][0]["src_ip"] == "198.51.100.31"
    assert first["data"]["total_cluster_candidates"] == 3
    assert first["data"]["priority_buckets"] == {
        "p0": {"cluster_count": 1, "alert_count": 3},
        "p1": {"cluster_count": 1, "alert_count": 3},
        "p2": {"cluster_count": 1, "alert_count": 3},
    }
    assert first["data"]["hotspot_summary"] == {
        "top_attack_stages": [
            {"attack_stage": "recon", "alert_count": 4},
            {"attack_stage": "command_execution", "alert_count": 3},
            {"attack_stage": "persistence", "alert_count": 3},
        ],
        "top_assets": [
            {"asset_id": "asset_api_prod", "alert_count": 6},
            {"asset_id": "asset_admin_portal", "alert_count": 3},
            {"asset_id": "asset_static_www", "alert_count": 1},
        ],
        "top_src_ips": [
            {"src_ip": "198.51.100.31", "alert_count": 3},
            {"src_ip": "198.51.100.32", "alert_count": 3},
            {"src_ip": "198.51.100.33", "alert_count": 3},
        ],
        "high_severity_alert_count": 6,
        "top_n": 3,
    }
    assert first["data"]["backlog_schedule"] == {
        "current_offset": 0,
        "returned_clusters": 1,
        "remaining_cluster_count": 2,
        "next_cursor": "1",
        "next_priority_bucket": "p1",
    }
    assert first["data"]["omitted_alert_count"] == 1
    assert first["page"]["has_more"] is True
    assert first["page"]["next_cursor"] == "1"
    assert "cluster_backlog_remaining" in first["warnings"]
    assert "cluster_filter_omitted_low_volume_alerts" in first["warnings"]

    second = alert_fetch(
        db_conn,
        {
            "mode": "clusters",
            "status": ["new"],
            "limit": 1,
            "cluster_min_count": 2,
            "cursor": first["page"]["next_cursor"],
        },
    )
    assert second["ok"] is True
    assert len(second["data"]["clusters"]) == 1
    assert second["data"]["clusters"][0]["src_ip"] == "198.51.100.32"
    assert second["data"]["backlog_schedule"] == {
        "current_offset": 1,
        "returned_clusters": 1,
        "remaining_cluster_count": 1,
        "next_cursor": "2",
        "next_priority_bucket": "p2",
    }
    assert second["page"]["has_more"] is True
    assert second["page"]["next_cursor"] == "2"


def test_alert_fetch_clusters_returns_budget_guardrails_and_next_actions(db_conn) -> None:
    rows = []
    for index in range(18):
        rows.append(
            (
                f"alt_guardrail_exec_{index}",
                f"2026-04-13T13:{index:02d}:00+08:00",
                "批量命令执行告警",
                "new",
                "high",
                "command_execution",
                "198.51.100.71",
                "203.0.113.10",
                "asset_api_prod",
            )
        )
    db_conn.executemany(
        """
        insert into alerts (
          alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    db_conn.commit()

    result = alert_fetch(
        db_conn,
        {
            "mode": "clusters",
            "status": ["new"],
            "limit": 5,
            "cluster_min_count": 2,
            "cluster_sample_size": 3,
        },
    )
    assert result["ok"] is True
    assert result["data"]["mode"] == "clusters"
    assert result["data"]["processing_guardrails"] == {
        "recommended_detail_batch_size": 2,
        "max_detail_batch_size": 5,
        "should_ack_homogeneous_noise": False,
        "detail_fanout_guardrail_applied": True,
    }
    assert result["data"]["ack_recommendations"] == [
        {
            "cluster_id": "clu::command_execution::198.51.100.71::asset_api_prod",
            "verdict": "needs_manual_review",
            "ack_score": 0,
            "confidence": 0.0,
            "suggested_status": None,
            "reason_codes": [
                "high_priority_cluster",
                "high_or_critical_severity_present",
                "contains_high_severity_alerts",
                "repeated_alert_pattern",
            ],
            "estimated_alert_count": 18,
            "sample_alert_ids": ["alt_guardrail_exec_17", "alt_guardrail_exec_16", "alt_guardrail_exec_15"],
        }
    ]
    assert result["data"]["recommended_next_actions"] == [
        {
            "tool_name": "alert.detail-batch",
            "reason": "优先补证当前页高优先级簇样本，控制单轮 fan-out",
            "payload": {
                "alert_ids": ["alt_guardrail_exec_17", "alt_guardrail_exec_16"],
            },
        },
        {
            "tool_name": "alert.fetch",
            "reason": "继续消化聚类积压，按游标推进",
            "payload": {
                "mode": "clusters",
                "status": ["new"],
                "limit": 5,
                "cluster_min_count": 2,
                "cursor": None,
            },
        },
    ]
    assert "detail_fanout_guardrail_applied" in result["warnings"]


def test_alert_fetch_clusters_returns_ack_recommendation_for_homogeneous_noise(db_conn) -> None:
    rows = []
    for index in range(12):
        rows.append(
            (
                f"alt_noise_ack_{index}",
                f"2026-04-13T14:{index:02d}:00+08:00",
                "低危重复扫描",
                "new",
                "low",
                "recon",
                "203.0.113.210",
                "203.0.113.12",
                "asset_static_www",
            )
        )
    db_conn.executemany(
        """
        insert into alerts (
          alert_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    db_conn.commit()

    result = alert_fetch(
        db_conn,
        {
            "mode": "clusters",
            "status": ["new"],
            "limit": 5,
            "cluster_min_count": 2,
            "cluster_sample_size": 3,
        },
    )
    assert result["ok"] is True
    assert result["data"]["processing_guardrails"]["should_ack_homogeneous_noise"] is True
    assert result["data"]["ack_recommendations"] == [
        {
            "cluster_id": "clu::recon::203.0.113.210::asset_static_www",
            "verdict": "suggest_ack_triaged",
            "ack_score": 100,
            "confidence": 1.0,
            "suggested_status": "triaged",
            "reason_codes": [
                "low_priority_cluster",
                "low_or_medium_severity_only",
                "no_high_severity_alerts",
                "repeated_alert_pattern",
                "recon_stage_noise_likely",
            ],
            "estimated_alert_count": 12,
            "sample_alert_ids": ["alt_noise_ack_11", "alt_noise_ack_10", "alt_noise_ack_9"],
        }
    ]
    assert "ack_recommendations_available" in result["warnings"]
