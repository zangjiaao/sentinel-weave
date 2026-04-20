import csv
from pathlib import Path

from security_analyst_agent.bootstrap import bootstrap_spike_database, materialize_spike_runtime_demo
from security_analyst_agent.db import connect_db
from security_analyst_agent.services.web_backend import (
    apply_job,
    apply_job_with_trigger,
    get_asset_detail,
    get_case_detail,
    get_case_timeline,
    get_job,
    import_csv_job,
    list_asset_cases,
    list_assets_overview,
    list_cases_overview,
    list_parsers,
    list_parser_versions,
    list_reports,
    list_source_runs,
    list_sources,
    latest_patrol_summary,
    list_job_problem_rows,
    preview_notification,
    preview_report,
    preview_job_apply,
    sample_job,
    trigger_patrol,
    upsert_mapping_rules,
)


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    if not rows:
        raise ValueError("rows required")
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def test_web_backend_import_preview_apply_cycle(tmp_path) -> None:
    db_path = tmp_path / "web-backend.db"
    csv_path = tmp_path / "alerts.csv"
    _write_csv(
        csv_path,
        [
            {"event_time": "2026-04-20 09:00:00", "src_ip": "198.51.100.11", "signal": "good"},
            {"event_time": "2026-04-20 09:02:00", "src_ip": "198.51.100.12", "signal": "bad"},
        ],
    )

    imported = import_csv_job(
        db_path=db_path,
        csv_path=csv_path,
        vendor="web_vendor",
        product="web_product",
        log_type="web_log",
        occurred_at_column="event_time",
    )
    job_id = str(imported["job"]["job_id"])
    assert imported["job"]["pending_rows"] == 2

    sampled = sample_job(db_path=db_path, job_id=job_id, limit_groups=5, samples_per_group=2)
    assert sampled["groups"]

    upsert_mapping_rules(
        db_path=db_path,
        maps=[
            {
                "map_id": "web_map_good_only",
                "priority": 100,
                "enabled": True,
                "match": {
                    "source_prefix": "import_job:",
                    "payload.row.signal": "good",
                },
                "mapping": {
                    "field_map": {
                        "occurred_at": "payload.row.event_time",
                        "src_ip": "payload.row.src_ip",
                    },
                    "defaults": {
                        "title": "web-good",
                        "status": "new",
                        "severity": "medium",
                        "attack_stage": "recon",
                    },
                },
            }
        ],
    )

    preview = preview_job_apply(db_path=db_path, job_id=job_id, limit=50)
    assert preview["apply_result"]["processed"] == 2
    assert preview["job"]["mapped_rows"] == 0

    applied = apply_job(db_path=db_path, job_id=job_id, limit=50)
    assert applied["job"]["mapped_rows"] == 1
    assert applied["job"]["unmapped_rows"] == 1

    problems = list_job_problem_rows(db_path=db_path, job_id=job_id, limit=10)
    assert len(problems["items"]) == 1


def test_web_backend_trigger_patrol_openai_mode(tmp_path) -> None:
    db_path = tmp_path / "web-trigger.db"
    bootstrap_spike_database(db_path)

    conn = connect_db(db_path)
    try:
        conn.execute(
            """
            insert into alert_ingest_events (event_id, alert_id, source, ingested_at, trigger_state)
            values ('evt_demo_web_001', 'alt_day1_scan_01', 'manual_import', '2026-04-20T10:00:00+08:00', 'pending')
            """
        )
        conn.commit()
    finally:
        conn.close()

    result = trigger_patrol(db_path=db_path, job_id="web-trigger-job", dry_run=True)
    assert result["triggered"] is True
    assert result["status"] == "dry_run_success"

    summary = latest_patrol_summary(db_path=db_path)
    assert summary["run"] is not None
    assert summary["run"]["status"] == "dry_run_success"


def test_web_backend_apply_job_with_trigger_dry_run(tmp_path) -> None:
    db_path = tmp_path / "web-backend-apply-trigger.db"
    csv_path = tmp_path / "alerts.csv"
    _write_csv(
        csv_path,
        [{"event_time": "2026-04-20 09:00:00", "src_ip": "198.51.100.99", "signal": "x"}],
    )
    imported = import_csv_job(
        db_path=db_path,
        csv_path=csv_path,
        occurred_at_column="event_time",
        job_id="job_apply_trigger_001",
    )
    upsert_mapping_rules(
        db_path=db_path,
        maps=[
            {
                "map_id": "web_apply_trigger_map",
                "priority": 100,
                "enabled": True,
                "match": {"source_prefix": "import_job:", "payload.row.signal": "x"},
                "mapping": {
                    "field_map": {
                        "occurred_at": "payload.row.event_time",
                        "src_ip": "payload.row.src_ip",
                    },
                    "defaults": {
                        "title": "mapped trigger",
                        "status": "new",
                        "severity": "low",
                        "attack_stage": "recon",
                    },
                },
            }
        ],
    )
    result = apply_job_with_trigger(
        db_path=db_path,
        job_id=str(imported["job"]["job_id"]),
        trigger_after_apply=True,
        trigger_dry_run=True,
    )
    assert result["apply_result"]["mapped"] == 1
    assert result["trigger_result"]["status"] == "dry_run_success"
    assert result["trigger_result"]["processed_events"] == 1


def test_web_backend_read_models_for_mvp_modules(tmp_path) -> None:
    db_path = tmp_path / "web-mvp.db"
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
                "src_waf_demo_01",
                "WAF Demo",
                "api",
                "waf",
                "demo_vendor",
                "demo_waf",
                1,
                "*/5 * * * *",
                "active",
                "pp_demo_waf",
                "2026-04-20T08:00:00Z",
                "2026-04-20T08:00:00Z",
            ),
        )
        conn.execute(
            """
            insert into parser_profiles (
              parser_profile_id, profile_name, device_type, vendor, product, input_format, status, created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "pp_demo_waf",
                "Demo WAF Parser",
                "waf",
                "demo_vendor",
                "demo_waf",
                "json",
                "active",
                "2026-04-20T08:00:00Z",
                "2026-04-20T08:00:00Z",
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
                "ppv_demo_waf_v1",
                "pp_demo_waf",
                1,
                '{"occurred_at":"ts","src_ip":"sip"}',
                '{"severity":{"critical":"high"}}',
                "validated",
                "active",
                "seed",
                "2026-04-20T08:00:00Z",
                "2026-04-20T08:00:00Z",
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
                "src_waf_demo_01",
                "schedule",
                "partial_success",
                "2026-04-20T09:00:00Z",
                "2026-04-20T09:01:00Z",
                120,
                118,
                2,
                "ppv_demo_waf_v1",
                "2 rows need review",
                "field missing",
            ),
        )
        conn.execute(
            """
            insert into asset_identities (
              identity_id, asset_id, identity_type, identity_value, is_primary, confidence, created_at
            ) values (?, ?, ?, ?, ?, ?, ?)
            """,
            ("aid_001", "asset_api_prod", "hostname", "api.prod.local", 1, 0.9, "2026-04-20T08:00:00Z"),
        )
        conn.commit()
    finally:
        conn.close()

    csv_path = tmp_path / "alerts.csv"
    _write_csv(
        csv_path,
        [{"time": "2026-04-20 10:00:00", "src": "198.51.100.10", "signal": "scan"}],
    )
    import_csv_job(
        db_path=db_path,
        csv_path=csv_path,
        job_id="job_web_001",
        occurred_at_column="time",
    )

    sources = list_sources(db_path=db_path, limit=10)
    assert sources["items"][0]["source_id"] == "src_waf_demo_01"
    runs = list_source_runs(db_path=db_path, source_id="src_waf_demo_01", limit=10)
    assert runs["items"][0]["source_run_id"] == "sr_demo_001"

    parsers = list_parsers(db_path=db_path, limit=10)
    assert parsers["items"][0]["parser_profile_id"] == "pp_demo_waf"
    versions = list_parser_versions(db_path=db_path, parser_profile_id="pp_demo_waf", limit=10)
    assert versions["items"][0]["parser_profile_version_id"] == "ppv_demo_waf_v1"
    assert versions["items"][0]["field_mapping"]["occurred_at"] == "ts"

    job = get_job(db_path=db_path, job_id="job_web_001")
    assert job["job"]["job_id"] == "job_web_001"
    assert job["job"]["status"] == "uploaded"

    materialize_db_path = tmp_path / "web-mvp-cases.db"
    bootstrap_spike_database(materialize_db_path)

    materialize_spike_runtime_demo(materialize_db_path)
    cases = list_cases_overview(db_path=materialize_db_path, limit=10)
    assert cases["items"]
    case_detail = get_case_detail(db_path=materialize_db_path, case_id="case_demo_001")
    assert case_detail["case"]["case_id"] == "case_demo_001"
    assert "targets" in case_detail
    assert "agent_judgement" in case_detail
    assert "attacker_target_map" in case_detail
    assert "attack_alert_timeline" in case_detail
    assert "attack_behavior_analysis" in case_detail
    timeline = get_case_timeline(db_path=materialize_db_path, case_id="case_demo_001", include_evidence=True)
    assert timeline["items"]
    assets = list_assets_overview(db_path=materialize_db_path, limit=10)
    assert assets["items"]
    asset_detail = get_asset_detail(db_path=materialize_db_path, asset_id="asset_api_prod")
    assert asset_detail["asset"]["asset_id"] == "asset_api_prod"
    assert list_asset_cases(db_path=materialize_db_path, asset_id="asset_api_prod", limit=10)["items"]

    notify_preview = preview_notification(db_path=materialize_db_path, case_id="case_demo_001")
    assert notify_preview["executed"] is False

    report_preview = preview_report(db_path=materialize_db_path, case_id="case_demo_001")
    assert report_preview["executed"] is False
    reports = list_reports(db_path=materialize_db_path, limit=10)
    assert reports["items"]
