import csv
from pathlib import Path

from security_analyst_agent.db import connect_db
from security_analyst_agent.raw_mapping import (
    apply_import_job_mapping,
    import_csv_alert_file,
    list_import_job_problem_rows,
    list_import_jobs,
    sample_import_job,
    upsert_alert_normalization_maps,
)


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    if not rows:
        raise ValueError("rows required")
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def test_import_csv_creates_job_and_samples_by_job_scope(tmp_path) -> None:
    db_path = tmp_path / "import.db"
    csv_path = tmp_path / "alerts.csv"
    _write_csv(
        csv_path,
        [
            {"time": "2026-04-20 10:00:00", "src": "198.51.100.10", "signal": "scan"},
            {"time": "2026-04-20 10:01:00", "src": "198.51.100.10", "signal": "scan"},
        ],
    )

    imported = import_csv_alert_file(
        db_path=db_path,
        csv_path=csv_path,
        vendor="demo_vendor",
        product="demo_product",
        log_type="demo_log",
        occurred_at_column="time",
    )
    job = imported["job"]
    assert job["status"] == "uploaded"
    assert job["total_rows"] == 2
    assert job["pending_rows"] == 2

    sampled = sample_import_job(db_path=db_path, job_id=job["job_id"], limit_groups=5, samples_per_group=2)
    assert sampled["job"]["job_id"] == job["job_id"]
    assert sampled["source_scope"] == f"import_job:{job['job_id']}"
    assert sampled["groups"]
    assert sampled["groups"][0]["event_count"] == 2

    jobs = list_import_jobs(db_path=db_path, limit=10)
    assert len(jobs["items"]) == 1
    assert jobs["items"][0]["job_id"] == job["job_id"]


def test_import_apply_and_retry_problem_rows(tmp_path) -> None:
    db_path = tmp_path / "import-apply.db"
    csv_path = tmp_path / "alerts.csv"
    _write_csv(
        csv_path,
        [
            {"time": "2026-04-20 11:00:00", "src": "198.51.100.23", "signal": "good"},
            {"time": "2026-04-20 11:01:00", "src": "198.51.100.24", "signal": "bad"},
        ],
    )

    imported = import_csv_alert_file(
        db_path=db_path,
        csv_path=csv_path,
        vendor="demo_vendor",
        product="demo_product",
        log_type="demo_log",
        occurred_at_column="time",
    )
    job_id = imported["job"]["job_id"]

    upsert_alert_normalization_maps(
        db_path=db_path,
        maps=[
            {
                "map_id": "map_good_only",
                "priority": 100,
                "enabled": True,
                "match": {
                    "source_prefix": "import_job:",
                    "payload.row.signal": "good",
                },
                "mapping": {
                    "field_map": {
                        "occurred_at": "payload.row.time",
                        "src_ip": "payload.row.src",
                    },
                    "defaults": {
                        "title": "good signal",
                        "status": "new",
                        "severity": "medium",
                        "attack_stage": "recon",
                    },
                },
            }
        ],
    )

    first_apply = apply_import_job_mapping(db_path=db_path, job_id=job_id, limit=100)
    assert first_apply["job"]["status"] == "needs_review"
    assert first_apply["job"]["mapped_rows"] == 1
    assert first_apply["job"]["unmapped_rows"] == 1

    problems = list_import_job_problem_rows(db_path=db_path, job_id=job_id, limit=10)
    assert len(problems["items"]) == 1
    problem_raw_event_id = problems["items"][0]["raw_event_id"]
    assert problems["items"][0]["map_status"] == "unmapped"

    upsert_alert_normalization_maps(
        db_path=db_path,
        maps=[
            {
                "map_id": "map_bad_only",
                "priority": 90,
                "enabled": True,
                "match": {
                    "source_prefix": "import_job:",
                    "payload.row.signal": "bad",
                },
                "mapping": {
                    "field_map": {
                        "occurred_at": "payload.row.time",
                        "src_ip": "payload.row.src",
                    },
                    "defaults": {
                        "title": "bad signal",
                        "status": "new",
                        "severity": "high",
                        "attack_stage": "exploit",
                    },
                },
            }
        ],
    )

    second_apply = apply_import_job_mapping(
        db_path=db_path,
        job_id=job_id,
        raw_event_ids=[problem_raw_event_id],
        include_unmapped=True,
        limit=10,
    )
    assert second_apply["job"]["status"] == "completed"
    assert second_apply["job"]["mapped_rows"] == 2
    assert second_apply["job"]["unmapped_rows"] == 0

    conn = connect_db(db_path)
    try:
        alert_rows = conn.execute("select count(*) from alerts").fetchone()[0]
        assert alert_rows == 2
    finally:
        conn.close()
