import csv
from pathlib import Path

from fastapi.testclient import TestClient

from security_analyst_agent.bootstrap import bootstrap_spike_database, materialize_spike_runtime_demo
from security_analyst_agent.db import connect_db
from security_analyst_agent.raw_mapping import upsert_alert_normalization_maps
from security_analyst_agent.services.web_backend import import_csv_job
from security_analyst_agent.web_api import create_app


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    if not rows:
        raise ValueError("rows required")
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def test_web_api_intake_routes(tmp_path) -> None:
    db_path = tmp_path / "web-api-intake.db"
    bootstrap_spike_database(db_path)

    conn = connect_db(db_path)
    try:
        conn.execute(
            """
            insert into data_sources (
              source_id, source_name, source_mode, device_type, vendor, product, enabled, schedule, status,
              parser_profile_id, created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "src_demo_001",
                "Demo API",
                "api",
                "waf",
                "demo_vendor",
                "demo_product",
                1,
                "*/5 * * * *",
                "active",
                "pp_demo_001",
                "2026-04-20T10:00:00Z",
                "2026-04-20T10:00:00Z",
            ),
        )
        conn.execute(
            """
            insert into parser_profiles (
              parser_profile_id, profile_name, device_type, vendor, product, input_format, status, created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "pp_demo_001",
                "Demo Parser",
                "waf",
                "demo_vendor",
                "demo_product",
                "json",
                "active",
                "2026-04-20T10:00:00Z",
                "2026-04-20T10:00:00Z",
            ),
        )
        conn.execute(
            """
            insert into parser_profile_versions (
              parser_profile_version_id, parser_profile_id, version_no, field_mapping_json, normalization_rules_json,
              validation_status, status, change_summary, created_at, effective_from
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "ppv_demo_001_v1",
                "pp_demo_001",
                1,
                '{"occurred_at":"ts"}',
                '{"severity":{"high":"high"}}',
                "validated",
                "active",
                "seed",
                "2026-04-20T10:00:00Z",
                "2026-04-20T10:00:00Z",
            ),
        )
        conn.execute(
            """
            insert into source_runs (
              source_run_id, source_id, trigger_type, status, started_at, ended_at,
              raw_event_count, normalized_count, failed_count, parser_profile_version_id, result_summary, error_summary
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "sr_demo_001",
                "src_demo_001",
                "schedule",
                "success",
                "2026-04-20T10:01:00Z",
                "2026-04-20T10:02:00Z",
                12,
                12,
                0,
                "ppv_demo_001_v1",
                "ok",
                None,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    csv_path = tmp_path / "alerts.csv"
    _write_csv(
        csv_path,
        [{"time": "2026-04-20 10:00:00", "src": "198.51.100.20", "signal": "scan"}],
    )
    imported = import_csv_job(db_path=db_path, csv_path=csv_path, occurred_at_column="time", job_id="job_api_001")
    upsert_alert_normalization_maps(
        db_path=db_path,
        maps=[
            {
                "map_id": "map_api_apply_001",
                "priority": 100,
                "enabled": True,
                "match": {
                    "source_prefix": "import_job:",
                    "payload.row.signal": "scan",
                },
                "mapping": {
                    "field_map": {
                        "occurred_at": "payload.row.time",
                        "src_ip": "payload.row.src",
                    },
                    "defaults": {
                        "title": "api apply mapped",
                        "status": "new",
                        "severity": "low",
                        "attack_stage": "recon",
                    },
                },
            }
        ],
    )

    client = TestClient(create_app(db_path=db_path))
    assert client.get("/healthz").status_code == 200

    source_resp = client.get("/api/intake/sources", params={"status": "active"})
    assert source_resp.status_code == 200
    assert source_resp.json()["items"][0]["source_id"] == "src_demo_001"

    run_resp = client.get("/api/intake/sources/src_demo_001/runs")
    assert run_resp.status_code == 200
    assert run_resp.json()["items"][0]["source_run_id"] == "sr_demo_001"

    upload_list_resp = client.get("/api/intake/uploads")
    assert upload_list_resp.status_code == 200
    assert upload_list_resp.json()["items"][0]["job_id"] == imported["job"]["job_id"]

    upload_file_resp = client.post(
        "/api/intake/uploads/import",
        data={
            "vendor": "demo_vendor",
            "product": "demo_product",
            "log_type": "demo_log",
            "occurred_at_column": "time",
            "apply_after_import": "false",
        },
        files={
            "file": (
                "uploaded.csv",
                "time,src,signal\n2026-04-20 11:00:00,198.51.100.50,scan\n",
                "text/csv",
            )
        },
    )
    assert upload_file_resp.status_code == 200
    upload_file_json = upload_file_resp.json()
    assert upload_file_json["import_result"]["job"]["total_rows"] == 1
    assert upload_file_json["map_bootstrap"]["map_id"].startswith("map_auto_")
    assert upload_file_json["apply_result"] is None

    upload_get_resp = client.get(f"/api/intake/uploads/{imported['job']['job_id']}")
    assert upload_get_resp.status_code == 200
    assert upload_get_resp.json()["job"]["job_id"] == imported["job"]["job_id"]

    apply_resp = client.post(
        f"/api/intake/uploads/{imported['job']['job_id']}/apply-map",
        json={"trigger_after_apply": True, "trigger_dry_run": True},
    )
    assert apply_resp.status_code == 200
    assert apply_resp.json()["trigger_result"]["status"] == "dry_run_success"
    assert apply_resp.json()["trigger_result"]["processed_events"] == 1
    assert "asset_resolved_count" in apply_resp.json()["apply_result"]
    assert "asset_auto_created_count" in apply_resp.json()["apply_result"]
    assert "asset_unresolved_count" in apply_resp.json()["apply_result"]

    trigger_analysis_resp = client.post(
        f"/api/intake/uploads/{imported['job']['job_id']}/trigger-analysis",
        json={"dry_run": True},
    )
    assert trigger_analysis_resp.status_code == 200
    assert "status" in trigger_analysis_resp.json()

    analysis_resp = client.get(f"/api/intake/uploads/{imported['job']['job_id']}/analysis")
    assert analysis_resp.status_code == 200
    assert "run" in analysis_resp.json()
    assert "cost" in analysis_resp.json()
    assert "steps" in analysis_resp.json()

    parser_list_resp = client.get("/api/intake/parsers")
    assert parser_list_resp.status_code == 200
    assert parser_list_resp.json()["items"][0]["parser_profile_id"] == "pp_demo_001"

    parser_versions_resp = client.get("/api/intake/parsers/pp_demo_001/versions")
    assert parser_versions_resp.status_code == 200
    assert parser_versions_resp.json()["items"][0]["parser_profile_version_id"] == "ppv_demo_001_v1"


def test_web_api_case_asset_notification_report_routes(tmp_path) -> None:
    db_path = tmp_path / "web-api-modules.db"
    bootstrap_spike_database(db_path)
    materialize_spike_runtime_demo(db_path)
    client = TestClient(create_app(db_path=db_path))

    cases_resp = client.get("/api/cases")
    assert cases_resp.status_code == 200
    assert cases_resp.json()["items"]

    case_id = "case_demo_001"
    case_resp = client.get(f"/api/cases/{case_id}")
    assert case_resp.status_code == 200
    assert case_resp.json()["case"]["case_id"] == case_id
    assert "targets" in case_resp.json()
    assert "agent_judgement" in case_resp.json()
    assert "attacker_target_map" in case_resp.json()
    assert "attack_alert_timeline" in case_resp.json()
    assert "attack_behavior_analysis" in case_resp.json()

    timeline_resp = client.get(f"/api/cases/{case_id}/timeline", params={"include_evidence": "true"})
    assert timeline_resp.status_code == 200
    assert timeline_resp.json()["items"]

    actors_resp = client.get(f"/api/cases/{case_id}/actors")
    assert actors_resp.status_code == 200
    assert "items" in actors_resp.json()

    asset_resp = client.get("/api/assets/asset_api_prod")
    assert asset_resp.status_code == 200
    assert asset_resp.json()["asset"]["asset_id"] == "asset_api_prod"

    asset_cases_resp = client.get("/api/assets/asset_api_prod/cases")
    assert asset_cases_resp.status_code == 200
    assert asset_cases_resp.json()["items"]

    notify_preview_resp = client.post(
        "/api/notifications/preview",
        json={"case_id": case_id, "channel": "feishu"},
    )
    assert notify_preview_resp.status_code == 200
    assert notify_preview_resp.json()["executed"] is False

    report_preview_resp = client.post(
        "/api/reports/preview",
        json={"case_id": case_id, "tone": "professional"},
    )
    assert report_preview_resp.status_code == 200
    assert report_preview_resp.json()["executed"] is False

    report_id = report_preview_resp.json()["report"]["report_id"]
    report_get_resp = client.get(f"/api/reports/{report_id}")
    assert report_get_resp.status_code == 200
    assert report_get_resp.json()["report"]["report_id"] == report_id


def test_web_api_upload_import_auto_map_avoids_waiting_mapping(tmp_path) -> None:
    db_path = tmp_path / "web-api-upload-auto-map.db"
    bootstrap_spike_database(db_path)
    client = TestClient(create_app(db_path=db_path))

    upload_resp = client.post(
        "/api/intake/uploads/import",
        data={
            "apply_after_import": "true",
            "trigger_after_apply": "false",
            "limit": "200",
        },
        files={
            "file": (
                "attacklist-mini.csv",
                "攻击时间,攻击IP,威胁情报,蜜罐名称\n2026-04-20 11:00:00,198.51.100.51,扫描,kibana\n2026-04-20 11:01:00,198.51.100.52,漏洞利用,nginx\n",
                "text/csv",
            )
        },
    )
    assert upload_resp.status_code == 200
    payload = upload_resp.json()
    assert payload["map_bootstrap"]["map_id"].startswith("map_auto_")
    assert payload["apply_result"]["job"]["status"] in {"completed", "processing", "needs_review"}
    assert payload["apply_result"]["job"]["pending_rows"] == 0
