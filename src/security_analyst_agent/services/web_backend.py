from __future__ import annotations

from pathlib import Path
from typing import Any

from security_analyst_agent.db import connect_db, create_schema
from security_analyst_agent.patrol_trigger import trigger_patrol_from_ingest
from security_analyst_agent.raw_mapping import (
    apply_import_job_mapping,
    import_csv_alert_file,
    list_import_job_problem_rows,
    list_import_jobs,
    sample_import_job,
    upsert_alert_normalization_maps,
)


def import_csv_job(
    *,
    db_path: Path,
    csv_path: Path,
    file_name: str | None = None,
    vendor: str | None = None,
    product: str | None = None,
    log_type: str | None = None,
    occurred_at_column: str | None = None,
    rule_id_column: str | None = None,
    job_id: str | None = None,
) -> dict[str, Any]:
    return import_csv_alert_file(
        db_path=db_path,
        csv_path=csv_path,
        file_name=file_name,
        vendor=vendor,
        product=product,
        log_type=log_type,
        occurred_at_column=occurred_at_column,
        rule_id_column=rule_id_column,
        job_id=job_id,
    )


def upsert_mapping_rules(*, db_path: Path, maps: list[dict[str, Any]]) -> dict[str, Any]:
    return upsert_alert_normalization_maps(db_path=db_path, maps=maps)


def list_jobs(*, db_path: Path, limit: int = 20, statuses: list[str] | None = None) -> dict[str, Any]:
    return list_import_jobs(db_path=db_path, limit=limit, statuses=statuses)


def sample_job(
    *,
    db_path: Path,
    job_id: str,
    limit_groups: int = 20,
    samples_per_group: int = 3,
    statuses: list[str] | None = None,
) -> dict[str, Any]:
    return sample_import_job(
        db_path=db_path,
        job_id=job_id,
        limit_groups=limit_groups,
        samples_per_group=samples_per_group,
        statuses=statuses,
    )


def preview_job_apply(
    *,
    db_path: Path,
    job_id: str,
    limit: int = 500,
    include_unmapped: bool = False,
    raw_event_ids: list[str] | None = None,
) -> dict[str, Any]:
    return apply_import_job_mapping(
        db_path=db_path,
        job_id=job_id,
        limit=limit,
        dry_run=True,
        include_unmapped=include_unmapped,
        raw_event_ids=raw_event_ids,
    )


def apply_job(
    *,
    db_path: Path,
    job_id: str,
    limit: int = 500,
    include_unmapped: bool = False,
    raw_event_ids: list[str] | None = None,
) -> dict[str, Any]:
    return apply_import_job_mapping(
        db_path=db_path,
        job_id=job_id,
        limit=limit,
        dry_run=False,
        include_unmapped=include_unmapped,
        raw_event_ids=raw_event_ids,
    )


def list_job_problem_rows(*, db_path: Path, job_id: str, limit: int = 100) -> dict[str, Any]:
    return list_import_job_problem_rows(db_path=db_path, job_id=job_id, limit=limit)


def trigger_patrol(*, db_path: Path, job_id: str, dry_run: bool = False) -> dict[str, Any]:
    return trigger_patrol_from_ingest(
        db_path=db_path,
        job_id=job_id,
        dry_run=dry_run,
        trigger_mode="openai",
    )


def latest_patrol_summary(*, db_path: Path) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        run = conn.execute(
            """
            select run_id, trigger_source, status, summary, started_at, finished_at
            from patrol_runs
            order by started_at desc
            limit 1
            """
        ).fetchone()
        if run is None:
            return {"run": None}

        tool_calls = conn.execute(
            """
            select tool_name, count(*) as call_count
            from agent_tool_calls
            where run_id = ?
            group by tool_name
            order by call_count desc, tool_name asc
            """,
            (run["run_id"],),
        ).fetchall()
        cases = conn.execute(
            """
            select case_id, status, overall_severity, current_stage
            from cases
            order by case_id asc
            """
        ).fetchall()
        return {
            "run": dict(run),
            "tool_calls": [dict(item) for item in tool_calls],
            "cases": [dict(item) for item in cases],
        }
    finally:
        conn.close()
