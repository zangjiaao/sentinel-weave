from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

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
from security_analyst_agent.repositories.actors import list_case_actor_profiles
from security_analyst_agent.repositories.assets import search_assets
from security_analyst_agent.repositories.cases import (
    list_cases,
    load_case,
    load_case_timeline,
    load_evidence_by_ids,
    resolve_canonical_case_id,
)
from security_analyst_agent.services.output import build_notify_preview, build_report


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_load(payload: str | None, default: Any) -> Any:
    if not payload:
        return default
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return default


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


def get_job(*, db_path: Path, job_id: str) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        row = conn.execute(
            """
            select
              job_id,
              source,
              file_name,
              file_hash,
              status,
              total_rows,
              mapped_rows,
              unmapped_rows,
              pending_rows,
              error_rows,
              last_map_id,
              created_at,
              updated_at,
              notes_json
            from import_jobs
            where job_id = ?
            """,
            (job_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"import job not found: {job_id}")
        return {
            "job": {
                "job_id": row["job_id"],
                "source": row["source"],
                "file_name": row["file_name"],
                "file_hash": row["file_hash"],
                "status": row["status"],
                "total_rows": int(row["total_rows"]),
                "mapped_rows": int(row["mapped_rows"]),
                "unmapped_rows": int(row["unmapped_rows"]),
                "pending_rows": int(row["pending_rows"]),
                "error_rows": int(row["error_rows"]),
                "last_map_id": row["last_map_id"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "notes": _json_load(row["notes_json"], {}),
            }
        }
    finally:
        conn.close()


def list_sources(
    *,
    db_path: Path,
    limit: int = 50,
    statuses: list[str] | None = None,
    source_modes: list[str] | None = None,
) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        where_clauses: list[str] = []
        params: list[Any] = []
        if statuses:
            normalized = [item.strip().lower() for item in statuses if item.strip()]
            if normalized:
                where_clauses.append(f"lower(status) in ({', '.join('?' for _ in normalized)})")
                params.extend(normalized)
        if source_modes:
            normalized = [item.strip().lower() for item in source_modes if item.strip()]
            if normalized:
                where_clauses.append(f"lower(source_mode) in ({', '.join('?' for _ in normalized)})")
                params.extend(normalized)
        where_sql = f"where {' and '.join(where_clauses)}" if where_clauses else ""
        rows = conn.execute(
            f"""
            select
              source_id,
              source_name,
              source_mode,
              device_type,
              vendor,
              product,
              enabled,
              schedule,
              status,
              parser_profile_id,
              created_at,
              updated_at
            from data_sources
            {where_sql}
            order by updated_at desc, source_id asc
            limit ?
            """,
            (*params, max(1, limit)),
        ).fetchall()
        return {"items": [{**dict(row), "enabled": bool(row["enabled"])} for row in rows]}
    finally:
        conn.close()


def list_source_runs(
    *,
    db_path: Path,
    source_id: str,
    limit: int = 100,
    statuses: list[str] | None = None,
) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        where_clauses = ["source_id = ?"]
        params: list[Any] = [source_id]
        if statuses:
            normalized = [item.strip().lower() for item in statuses if item.strip()]
            if normalized:
                where_clauses.append(f"lower(status) in ({', '.join('?' for _ in normalized)})")
                params.extend(normalized)
        where_sql = " and ".join(where_clauses)
        rows = conn.execute(
            f"""
            select
              source_run_id,
              source_id,
              trigger_type,
              status,
              started_at,
              ended_at,
              raw_event_count,
              normalized_count,
              failed_count,
              parser_profile_version_id,
              result_summary,
              error_summary
            from source_runs
            where {where_sql}
            order by started_at desc, source_run_id asc
            limit ?
            """,
            (*params, max(1, limit)),
        ).fetchall()
        return {"items": [dict(row) for row in rows]}
    finally:
        conn.close()


def list_parsers(*, db_path: Path, limit: int = 50, statuses: list[str] | None = None) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        where_clauses: list[str] = []
        params: list[Any] = []
        if statuses:
            normalized = [item.strip().lower() for item in statuses if item.strip()]
            if normalized:
                where_clauses.append(f"lower(status) in ({', '.join('?' for _ in normalized)})")
                params.extend(normalized)
        where_sql = f"where {' and '.join(where_clauses)}" if where_clauses else ""
        rows = conn.execute(
            f"""
            select
              parser_profile_id,
              profile_name,
              device_type,
              vendor,
              product,
              input_format,
              status,
              created_at,
              updated_at
            from parser_profiles
            {where_sql}
            order by updated_at desc, parser_profile_id asc
            limit ?
            """,
            (*params, max(1, limit)),
        ).fetchall()
        return {"items": [dict(row) for row in rows]}
    finally:
        conn.close()


def list_parser_versions(*, db_path: Path, parser_profile_id: str, limit: int = 50) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        rows = conn.execute(
            """
            select
              parser_profile_version_id,
              parser_profile_id,
              version_no,
              field_mapping_json,
              normalization_rules_json,
              validation_status,
              status,
              change_summary,
              created_at,
              effective_from
            from parser_profile_versions
            where parser_profile_id = ?
            order by version_no desc, created_at desc
            limit ?
            """,
            (parser_profile_id, max(1, limit)),
        ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["field_mapping"] = _json_load(item.pop("field_mapping_json"), {})
            item["normalization_rules"] = _json_load(item.pop("normalization_rules_json"), {})
            items.append(item)
        return {"items": items}
    finally:
        conn.close()


def list_cases_overview(
    *,
    db_path: Path,
    limit: int = 50,
    statuses: list[str] | None = None,
    min_severity: str | None = None,
    current_stage: str | None = None,
    include_merged: bool = True,
    keyword: str | None = None,
) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        items = list_cases(
            conn,
            statuses=statuses or [],
            min_severity=min_severity,
            current_stage=current_stage,
            include_merged=include_merged,
            keyword=keyword,
            limit=max(1, limit),
            analysis_cutoff_at=None,
        )
        return {"items": items}
    finally:
        conn.close()


def get_case_detail(*, db_path: Path, case_id: str) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        effective_case_id = resolve_canonical_case_id(conn, case_id)
        case = load_case(conn, effective_case_id)
        if case is None:
            raise ValueError(f"case not found: {case_id}")
        timeline = load_case_timeline(conn, effective_case_id, analysis_cutoff_at=None)
        actors = list_case_actor_profiles(conn, effective_case_id)
        assessments = conn.execute(
            """
            select
              assessment_id,
              occurred_at,
              run_id,
              case_id,
              risk_level,
              assessment_confidence,
              current_stage,
              verdict,
              reason_summary,
              supporting_alert_ids_json,
              supporting_evidence_ids_json,
              analysis_cutoff_at
            from case_assessments
            where case_id = ?
            order by occurred_at desc
            limit 20
            """,
            (effective_case_id,),
        ).fetchall()
        link_decisions = conn.execute(
            """
            select
              decision_id,
              occurred_at,
              run_id,
              alert_id,
              case_id,
              link_confidence,
              reason_summary,
              positive_factors_json,
              negative_factors_json,
              uncertainties_json,
              supporting_evidence_ids_json,
              analysis_cutoff_at
            from link_decisions
            where case_id = ?
            order by occurred_at desc
            limit 50
            """,
            (effective_case_id,),
        ).fetchall()
        return {
            "case": case,
            "timeline": timeline,
            "actors": actors,
            "assessments": [
                {
                    **dict(item),
                    "supporting_alert_ids": _json_load(item["supporting_alert_ids_json"], []),
                    "supporting_evidence_ids": _json_load(item["supporting_evidence_ids_json"], []),
                }
                for item in assessments
            ],
            "link_explanations": [
                {
                    **dict(item),
                    "positive_factors": _json_load(item["positive_factors_json"], []),
                    "negative_factors": _json_load(item["negative_factors_json"], []),
                    "uncertainties": _json_load(item["uncertainties_json"], []),
                    "supporting_evidence_ids": _json_load(item["supporting_evidence_ids_json"], []),
                }
                for item in link_decisions
            ],
            "canonical_case_id": effective_case_id,
            "requested_case_id": case_id,
        }
    finally:
        conn.close()


def get_case_timeline(*, db_path: Path, case_id: str, include_evidence: bool = False) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        effective_case_id = resolve_canonical_case_id(conn, case_id)
        events = load_case_timeline(conn, effective_case_id, analysis_cutoff_at=None)
        if include_evidence:
            for event in events:
                event["evidence"] = load_evidence_by_ids(conn, event["related_evidence_ids"])
        return {
            "items": events,
            "canonical_case_id": effective_case_id,
            "requested_case_id": case_id,
        }
    finally:
        conn.close()


def get_case_actors(*, db_path: Path, case_id: str) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        effective_case_id = resolve_canonical_case_id(conn, case_id)
        return {
            "items": list_case_actor_profiles(conn, effective_case_id),
            "canonical_case_id": effective_case_id,
            "requested_case_id": case_id,
        }
    finally:
        conn.close()


def list_assets_overview(
    *,
    db_path: Path,
    query: str | None = None,
    indicators: list[str] | None = None,
    include_inactive: bool = True,
    limit: int = 50,
) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        items = search_assets(
            conn,
            query=query,
            indicators=indicators or [],
            include_inactive=include_inactive,
            limit=max(1, limit),
        )
        return {"items": items}
    finally:
        conn.close()


def _list_asset_case_rows(conn: Any, asset_id: str, limit: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        select
          cases.case_id,
          cases.title,
          cases.status,
          cases.overall_severity,
          cases.current_stage,
          max(alerts.occurred_at) as last_alert_at,
          count(*) as alert_count
        from alerts
        join case_alert_links
          on case_alert_links.alert_id = alerts.alert_id and case_alert_links.is_active = 1
        join cases
          on cases.case_id = case_alert_links.case_id
        where alerts.asset_id = ?
        group by cases.case_id
        order by last_alert_at desc, cases.case_id asc
        limit ?
        """,
        (asset_id, max(1, limit)),
    ).fetchall()
    return [dict(row) for row in rows]


def get_asset_detail(*, db_path: Path, asset_id: str) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        row = conn.execute(
            """
            select asset_id, asset_name, system_name, owner_team, internet_exposed, public_ip, domain
            from assets
            where asset_id = ?
            """,
            (asset_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"asset not found: {asset_id}")
        identities = conn.execute(
            """
            select identity_id, asset_id, identity_type, identity_value, is_primary, confidence, created_at
            from asset_identities
            where asset_id = ?
            order by is_primary desc, confidence desc, identity_type asc, identity_value asc
            """,
            (asset_id,),
        ).fetchall()
        items = [dict(item) for item in identities]
        if not items:
            if row["public_ip"]:
                items.append(
                    {
                        "identity_id": f"derived_ip_{asset_id}",
                        "asset_id": asset_id,
                        "identity_type": "ip",
                        "identity_value": row["public_ip"],
                        "is_primary": 1,
                        "confidence": 1.0,
                        "created_at": _now_iso(),
                    }
                )
            if row["domain"]:
                items.append(
                    {
                        "identity_id": f"derived_domain_{asset_id}",
                        "asset_id": asset_id,
                        "identity_type": "domain",
                        "identity_value": row["domain"],
                        "is_primary": 1,
                        "confidence": 1.0,
                        "created_at": _now_iso(),
                    }
                )
        return {
            "asset": {**dict(row), "internet_exposed": bool(row["internet_exposed"])},
            "identities": [{**item, "is_primary": bool(item["is_primary"])} for item in items],
            "cases": _list_asset_case_rows(conn, asset_id, 20),
        }
    finally:
        conn.close()


def list_asset_cases(*, db_path: Path, asset_id: str, limit: int = 20) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        return {"items": _list_asset_case_rows(conn, asset_id, limit)}
    finally:
        conn.close()


def list_notifications(
    *,
    db_path: Path,
    limit: int = 50,
    statuses: list[str] | None = None,
    channels: list[str] | None = None,
) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        where_clauses: list[str] = []
        params: list[Any] = []
        if statuses:
            normalized = [item.strip().lower() for item in statuses if item.strip()]
            if normalized:
                where_clauses.append(f"lower(status) in ({', '.join('?' for _ in normalized)})")
                params.extend(normalized)
        if channels:
            normalized = [item.strip().lower() for item in channels if item.strip()]
            if normalized:
                where_clauses.append(f"lower(channel) in ({', '.join('?' for _ in normalized)})")
                params.extend(normalized)
        where_sql = f"where {' and '.join(where_clauses)}" if where_clauses else ""
        rows = conn.execute(
            f"""
            select
              notification_id,
              case_id,
              channel,
              template,
              title,
              body,
              dedupe_key,
              status,
              created_at,
              sent_at
            from notification_outbox
            {where_sql}
            order by created_at desc, notification_id asc
            limit ?
            """,
            (*params, max(1, limit)),
        ).fetchall()
        return {"items": [dict(row) for row in rows]}
    finally:
        conn.close()


def get_notification(*, db_path: Path, notification_id: str) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        row = conn.execute(
            """
            select
              notification_id,
              case_id,
              channel,
              template,
              title,
              body,
              dedupe_key,
              status,
              created_at,
              sent_at
            from notification_outbox
            where notification_id = ?
            """,
            (notification_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"notification not found: {notification_id}")
        return {"notification": dict(row)}
    finally:
        conn.close()


def preview_notification(*, db_path: Path, case_id: str, channel: str = "feishu") -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        case = load_case(conn, case_id)
        if case is None:
            raise ValueError(f"case not found: {case_id}")
        preview = build_notify_preview(case, channel)
        return {"preview": preview, "executed": False}
    finally:
        conn.close()


def list_reports(*, db_path: Path, limit: int = 50, statuses: list[str] | None = None) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        where_clauses: list[str] = []
        params: list[Any] = []
        if statuses:
            normalized = [item.strip().lower() for item in statuses if item.strip()]
            if normalized:
                where_clauses.append(f"lower(status) in ({', '.join('?' for _ in normalized)})")
                params.extend(normalized)
        where_sql = f"where {' and '.join(where_clauses)}" if where_clauses else ""
        rows = conn.execute(
            f"""
            select report_id, case_id, title, content_md, status, created_at, updated_at
            from report_drafts
            {where_sql}
            order by updated_at desc, report_id asc
            limit ?
            """,
            (*params, max(1, limit)),
        ).fetchall()
        return {"items": [dict(item) for item in rows]}
    finally:
        conn.close()


def get_report(*, db_path: Path, report_id: str) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        row = conn.execute(
            """
            select report_id, case_id, title, content_md, status, created_at, updated_at
            from report_drafts
            where report_id = ?
            """,
            (report_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"report not found: {report_id}")
        return {"report": dict(row)}
    finally:
        conn.close()


def preview_report(*, db_path: Path, case_id: str, tone: str = "professional", title: str | None = None) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        case = load_case(conn, case_id)
        if case is None:
            raise ValueError(f"case not found: {case_id}")
        timeline = load_case_timeline(conn, case_id, analysis_cutoff_at=None)
        report_preview = build_report(case, timeline, tone)
        report_id = str(report_preview.get("report_id") or f"report_{uuid4().hex[:12]}")
        report_title = title or str(report_preview.get("title") or case["title"])
        content_md = str(report_preview.get("draft_markdown") or "")
        now = _now_iso()
        conn.execute(
            """
            insert into report_drafts (report_id, case_id, title, content_md, status, created_at, updated_at)
            values (?, ?, ?, ?, ?, ?, ?)
            on conflict(report_id) do update set
              case_id = excluded.case_id,
              title = excluded.title,
              content_md = excluded.content_md,
              status = excluded.status,
              updated_at = excluded.updated_at
            """,
            (
                report_id,
                case_id,
                report_title,
                content_md,
                "previewed",
                now,
                now,
            ),
        )
        conn.commit()
        return {
            "report": {
                "report_id": report_id,
                "case_id": case_id,
                "title": report_title,
                "content_md": content_md,
                "status": "previewed",
                "created_at": now,
                "updated_at": now,
            },
            "preview": report_preview,
            "executed": False,
        }
    finally:
        conn.close()
