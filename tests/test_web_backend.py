import csv
from pathlib import Path

from security_analyst_agent.bootstrap import bootstrap_spike_database
from security_analyst_agent.db import connect_db
from security_analyst_agent.services.web_backend import (
    apply_job,
    import_csv_job,
    latest_patrol_summary,
    list_job_problem_rows,
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
