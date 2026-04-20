import json
from pathlib import Path

import typer

from security_analyst_agent.config import DEFAULT_HERMES_CRON_JOB_ID
from security_analyst_agent.db import connect_db
from security_analyst_agent.ingest import ingest_alert_bundle
from security_analyst_agent.patrol_trigger import trigger_patrol_from_ingest
from security_analyst_agent.raw_mapping import (
    apply_alert_normalization_maps,
    apply_import_job_mapping,
    import_csv_alert_file,
    ingest_raw_alert_bundle,
    list_import_job_problem_rows,
    list_import_jobs,
    list_unmapped_alert_events,
    sample_import_job,
    sample_raw_alert_groups,
    upsert_alert_normalization_maps,
)
from security_analyst_agent.schemas.common import ToolResponse
from security_analyst_agent.services.audit_retention import compact_audit_logs
from security_analyst_agent.tool_dispatch import dispatch_tool

app = typer.Typer(help="Hermes security analyst spike CLI")


def _run_tool(tool_name: str, db_path: Path, payload: str) -> None:
    try:
        body = json.loads(payload) if payload else {}
    except json.JSONDecodeError as exc:
        error = ToolResponse(
            ok=False,
            summary="payload 不是合法 JSON",
            data={"tool": tool_name},
            warnings=[f"invalid_json:{exc.msg}"],
        )
        typer.echo(json.dumps(error.model_dump(mode="json", by_alias=True), ensure_ascii=False))
        raise typer.Exit(code=2) from exc

    conn = connect_db(db_path)
    try:
        result = dispatch_tool(conn, tool_name, body, source="cli")
    except ValueError as exc:
        error = ToolResponse(
            ok=False,
            summary=str(exc),
            data={"tool": tool_name},
            warnings=["unsupported_tool"],
        )
        typer.echo(json.dumps(error.model_dump(mode="json", by_alias=True), ensure_ascii=False))
        raise typer.Exit(code=2) from exc
    finally:
        conn.close()

    typer.echo(json.dumps(result, ensure_ascii=False))


@app.callback()
def main() -> None:
    return None


def _parse_payload(payload: str, command_name: str) -> dict:
    try:
        return json.loads(payload) if payload else {}
    except json.JSONDecodeError as exc:
        error = ToolResponse(
            ok=False,
            summary=f"{command_name} payload 不是合法 JSON",
            data={"command": command_name},
            warnings=[f"invalid_json:{exc.msg}"],
        )
        typer.echo(json.dumps(error.model_dump(mode="json", by_alias=True), ensure_ascii=False))
        raise typer.Exit(code=2) from exc


def _query_rows(db_path: Path, sql: str, params: tuple[object, ...] = ()) -> list[dict]:
    conn = connect_db(db_path)
    try:
        rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def _decode_json_fields(rows: list[dict], fields: list[str]) -> list[dict]:
    decoded: list[dict] = []
    for row in rows:
        parsed = dict(row)
        for field in fields:
            raw_value = parsed.get(field)
            if isinstance(raw_value, str):
                try:
                    parsed[field] = json.loads(raw_value)
                except json.JSONDecodeError:
                    continue
        decoded.append(parsed)
    return decoded


@app.command("alert.fetch")
def alert_fetch_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("alert.fetch", db_path, payload)


@app.command("alert.suspect-ip-topk")
def alert_suspect_ip_topk_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("alert.suspect-ip-topk", db_path, payload)


@app.command("alert.ip-context")
def alert_ip_context_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("alert.ip-context", db_path, payload)


@app.command("alert.detail")
def alert_detail_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("alert.detail", db_path, payload)


@app.command("alert.detail-batch")
def alert_detail_batch_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("alert.detail-batch", db_path, payload)


@app.command("alert.ack")
def alert_ack_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("alert.ack", db_path, payload)


@app.command("asset.search")
def asset_search_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("asset.search", db_path, payload)


@app.command("actor.case-list")
def actor_case_list_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("actor.case-list", db_path, payload)


@app.command("actor.case-get")
def actor_case_get_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("actor.case-get", db_path, payload)


@app.command("actor.case-find-candidates")
def actor_case_find_candidates_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("actor.case-find-candidates", db_path, payload)


@app.command("actor.case-upsert")
def actor_case_upsert_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("actor.case-upsert", db_path, payload)


@app.command("actor.case-add-observation")
def actor_case_add_observation_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("actor.case-add-observation", db_path, payload)


@app.command("actor.case-add-observation-batch")
def actor_case_add_observation_batch_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("actor.case-add-observation-batch", db_path, payload)


@app.command("actor.case-link")
def actor_case_link_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("actor.case-link", db_path, payload)


@app.command("actor.case-link-batch")
def actor_case_link_batch_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("actor.case-link-batch", db_path, payload)


@app.command("case.get")
def case_get_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("case.get", db_path, payload)


@app.command("case.list")
def case_list_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("case.list", db_path, payload)


@app.command("case.search")
def case_search_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("case.search", db_path, payload)


@app.command("case.timeline")
def case_timeline_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("case.timeline", db_path, payload)


@app.command("case.explain-link")
def case_explain_link_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("case.explain-link", db_path, payload)


@app.command("case.upsert")
def case_upsert_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("case.upsert", db_path, payload)


@app.command("case.upsert-batch")
def case_upsert_batch_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("case.upsert-batch", db_path, payload)


@app.command("case.link-alert")
def case_link_alert_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("case.link-alert", db_path, payload)


@app.command("case.link-alert-batch")
def case_link_alert_batch_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("case.link-alert-batch", db_path, payload)


@app.command("case.update-risk")
def case_update_risk_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("case.update-risk", db_path, payload)


@app.command("evidence.upsert")
def evidence_upsert_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("evidence.upsert", db_path, payload)


@app.command("timeline.upsert")
def timeline_upsert_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("timeline.upsert", db_path, payload)


@app.command("assessment.upsert")
def assessment_upsert_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("assessment.upsert", db_path, payload)


@app.command("assessment.upsert-batch")
def assessment_upsert_batch_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("assessment.upsert-batch", db_path, payload)


@app.command("intel.lookup")
def intel_lookup_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("intel.lookup", db_path, payload)


@app.command("notify.send")
def notify_send_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("notify.send", db_path, payload)


@app.command("notify.preview")
def notify_preview_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("notify.preview", db_path, payload)


@app.command("report.draft")
def report_draft_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("report.draft", db_path, payload)


@app.command("alert.ingest")
def alert_ingest_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
    trigger_now: bool = typer.Option(True, "--trigger-now/--no-trigger-now"),
    job_id: str = typer.Option(DEFAULT_HERMES_CRON_JOB_ID, "--job-id"),
    trigger_dry_run: bool = typer.Option(False, "--trigger-dry-run"),
) -> None:
    body = _parse_payload(payload, "alert.ingest")
    alerts = body.get("alerts", [])
    source = body.get("source", "manual_import")
    result = ingest_alert_bundle(db_path=db_path, alerts=alerts, source=source)
    if trigger_now:
        result["trigger"] = trigger_patrol_from_ingest(
            db_path=db_path,
            job_id=job_id,
            dry_run=trigger_dry_run,
        )
    else:
        result["trigger"] = {
            "triggered": False,
            "status": "disabled",
            "processed_events": 0,
            "run_id": None,
            "job_id": job_id,
        }
    typer.echo(json.dumps(result, ensure_ascii=False))


@app.command("alert.raw-ingest")
def alert_raw_ingest_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    body = _parse_payload(payload, "alert.raw-ingest")
    events = body.get("events", [])
    source = body.get("source", "raw_manual_import")
    result = ingest_raw_alert_bundle(db_path=db_path, events=events, source=source)
    typer.echo(json.dumps(result, ensure_ascii=False))


@app.command("alert.raw-sample")
def alert_raw_sample_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    body = _parse_payload(payload, "alert.raw-sample")
    result = sample_raw_alert_groups(
        db_path=db_path,
        limit_groups=int(body.get("limit_groups", 20)),
        samples_per_group=int(body.get("samples_per_group", 3)),
        statuses=body.get("statuses"),
    )
    typer.echo(json.dumps(result, ensure_ascii=False))


@app.command("alert.map-upsert")
def alert_map_upsert_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    body = _parse_payload(payload, "alert.map-upsert")
    maps = body.get("maps", [])
    result = upsert_alert_normalization_maps(db_path=db_path, maps=maps)
    typer.echo(json.dumps(result, ensure_ascii=False))


@app.command("alert.map-apply")
def alert_map_apply_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    body = _parse_payload(payload, "alert.map-apply")
    result = apply_alert_normalization_maps(
        db_path=db_path,
        limit=int(body.get("limit", 500)),
        source=body.get("source"),
        raw_event_ids=body.get("raw_event_ids"),
        include_unmapped=bool(body.get("include_unmapped", False)),
        dry_run=bool(body.get("dry_run", False)),
    )
    typer.echo(json.dumps(result, ensure_ascii=False))


@app.command("alert.unmapped-list")
def alert_unmapped_list_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    body = _parse_payload(payload, "alert.unmapped-list")
    result = list_unmapped_alert_events(
        db_path=db_path,
        limit=int(body.get("limit", 100)),
        unresolved_only=bool(body.get("unresolved_only", True)),
    )
    typer.echo(json.dumps(result, ensure_ascii=False))


@app.command("alert.import-csv")
def alert_import_csv_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    body = _parse_payload(payload, "alert.import-csv")
    csv_path_value = body.get("csv_path")
    if not csv_path_value:
        error = ToolResponse(
            ok=False,
            summary="alert.import-csv 缺少 csv_path",
            data={"command": "alert.import-csv"},
            warnings=["csv_path_required"],
        )
        typer.echo(json.dumps(error.model_dump(mode="json", by_alias=True), ensure_ascii=False))
        raise typer.Exit(code=2)
    result = import_csv_alert_file(
        db_path=db_path,
        csv_path=Path(str(csv_path_value)),
        file_name=body.get("file_name"),
        vendor=body.get("vendor"),
        product=body.get("product"),
        log_type=body.get("log_type"),
        occurred_at_column=body.get("occurred_at_column"),
        rule_id_column=body.get("rule_id_column"),
        job_id=body.get("job_id"),
    )
    typer.echo(json.dumps(result, ensure_ascii=False))


@app.command("alert.import-jobs")
def alert_import_jobs_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    body = _parse_payload(payload, "alert.import-jobs")
    result = list_import_jobs(
        db_path=db_path,
        limit=int(body.get("limit", 20)),
        statuses=body.get("statuses"),
    )
    typer.echo(json.dumps(result, ensure_ascii=False))


@app.command("alert.import-sample")
def alert_import_sample_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    body = _parse_payload(payload, "alert.import-sample")
    job_id = body.get("job_id")
    if not job_id:
        error = ToolResponse(
            ok=False,
            summary="alert.import-sample 缺少 job_id",
            data={"command": "alert.import-sample"},
            warnings=["job_id_required"],
        )
        typer.echo(json.dumps(error.model_dump(mode="json", by_alias=True), ensure_ascii=False))
        raise typer.Exit(code=2)
    result = sample_import_job(
        db_path=db_path,
        job_id=str(job_id),
        limit_groups=int(body.get("limit_groups", 20)),
        samples_per_group=int(body.get("samples_per_group", 3)),
        statuses=body.get("statuses"),
    )
    typer.echo(json.dumps(result, ensure_ascii=False))


@app.command("alert.import-apply")
def alert_import_apply_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    body = _parse_payload(payload, "alert.import-apply")
    job_id = body.get("job_id")
    if not job_id:
        error = ToolResponse(
            ok=False,
            summary="alert.import-apply 缺少 job_id",
            data={"command": "alert.import-apply"},
            warnings=["job_id_required"],
        )
        typer.echo(json.dumps(error.model_dump(mode="json", by_alias=True), ensure_ascii=False))
        raise typer.Exit(code=2)
    result = apply_import_job_mapping(
        db_path=db_path,
        job_id=str(job_id),
        limit=int(body.get("limit", 500)),
        dry_run=bool(body.get("dry_run", False)),
        include_unmapped=bool(body.get("include_unmapped", False)),
        raw_event_ids=body.get("raw_event_ids"),
    )
    typer.echo(json.dumps(result, ensure_ascii=False))


@app.command("alert.import-problems")
def alert_import_problems_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    body = _parse_payload(payload, "alert.import-problems")
    job_id = body.get("job_id")
    if not job_id:
        error = ToolResponse(
            ok=False,
            summary="alert.import-problems 缺少 job_id",
            data={"command": "alert.import-problems"},
            warnings=["job_id_required"],
        )
        typer.echo(json.dumps(error.model_dump(mode="json", by_alias=True), ensure_ascii=False))
        raise typer.Exit(code=2)
    result = list_import_job_problem_rows(
        db_path=db_path,
        job_id=str(job_id),
        limit=int(body.get("limit", 100)),
    )
    typer.echo(json.dumps(result, ensure_ascii=False))


@app.command("patrol.trigger")
def patrol_trigger_command(
    db_path: Path = typer.Option(..., "--db-path"),
    job_id: str = typer.Option(DEFAULT_HERMES_CRON_JOB_ID, "--job-id"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    result = trigger_patrol_from_ingest(db_path=db_path, job_id=job_id, dry_run=dry_run)
    typer.echo(json.dumps(result, ensure_ascii=False))


@app.command("audit.agent-outputs")
def audit_agent_outputs_command(
    db_path: Path = typer.Option(..., "--db-path"),
    limit: int = typer.Option(50, "--limit"),
    run_id: str | None = typer.Option(None, "--run-id"),
) -> None:
    if run_id:
        rows = _query_rows(
            db_path,
            """
            select
              output_id,
              occurred_at,
              run_id,
              source,
              turn_index,
              response_id,
              has_tool_calls,
              output_text,
              usage_input_tokens,
              usage_output_tokens,
              usage_cached_input_tokens,
              meta_json
            from agent_outputs
            where run_id = ?
            order by occurred_at desc
            limit ?
            """,
            (run_id, limit),
        )
    else:
        rows = _query_rows(
            db_path,
            """
            select
              output_id,
              occurred_at,
              run_id,
              source,
              turn_index,
              response_id,
              has_tool_calls,
              output_text,
              usage_input_tokens,
              usage_output_tokens,
              usage_cached_input_tokens,
              meta_json
            from agent_outputs
            order by occurred_at desc
            limit ?
            """,
            (limit,),
        )
    rows = _decode_json_fields(rows, ["meta_json"])
    typer.echo(json.dumps({"rows": rows}, ensure_ascii=False))


@app.command("audit.tool-calls")
def audit_tool_calls_command(
    db_path: Path = typer.Option(..., "--db-path"),
    limit: int = typer.Option(50, "--limit"),
    run_id: str | None = typer.Option(None, "--run-id"),
) -> None:
    if run_id:
        rows = _query_rows(
            db_path,
            """
            select call_id, occurred_at, run_id, source, tool_name, result_ok, result_summary, latency_ms
            from agent_tool_calls
            where run_id = ?
            order by occurred_at desc
            limit ?
            """,
            (run_id, limit),
        )
    else:
        rows = _query_rows(
            db_path,
            """
            select call_id, occurred_at, run_id, source, tool_name, result_ok, result_summary, latency_ms
            from agent_tool_calls
            order by occurred_at desc
            limit ?
            """,
            (limit,),
        )
    typer.echo(json.dumps({"rows": rows}, ensure_ascii=False))


@app.command("audit.alert-decisions")
def audit_alert_decisions_command(
    db_path: Path = typer.Option(..., "--db-path"),
    limit: int = typer.Option(50, "--limit"),
    run_id: str | None = typer.Option(None, "--run-id"),
) -> None:
    if run_id:
        rows = _query_rows(
            db_path,
            """
            select decision_id, occurred_at, run_id, alert_id, decision, case_id, confidence, reason
            from alert_decisions
            where run_id = ?
            order by occurred_at desc
            limit ?
            """,
            (run_id, limit),
        )
    else:
        rows = _query_rows(
            db_path,
            """
            select decision_id, occurred_at, run_id, alert_id, decision, case_id, confidence, reason
            from alert_decisions
            order by occurred_at desc
            limit ?
            """,
            (limit,),
        )
    typer.echo(json.dumps({"rows": rows}, ensure_ascii=False))


@app.command("audit.case-changes")
def audit_case_changes_command(
    db_path: Path = typer.Option(..., "--db-path"),
    limit: int = typer.Option(50, "--limit"),
    run_id: str | None = typer.Option(None, "--run-id"),
) -> None:
    if run_id:
        rows = _query_rows(
            db_path,
            """
            select change_id, occurred_at, run_id, case_id, action, reason
            from case_changes
            where run_id = ?
            order by occurred_at desc
            limit ?
            """,
            (run_id, limit),
        )
    else:
        rows = _query_rows(
            db_path,
            """
            select change_id, occurred_at, run_id, case_id, action, reason
            from case_changes
            order by occurred_at desc
            limit ?
            """,
            (limit,),
        )
    typer.echo(json.dumps({"rows": rows}, ensure_ascii=False))


@app.command("audit.link-decisions")
def audit_link_decisions_command(
    db_path: Path = typer.Option(..., "--db-path"),
    limit: int = typer.Option(50, "--limit"),
    run_id: str | None = typer.Option(None, "--run-id"),
) -> None:
    if run_id:
        rows = _query_rows(
            db_path,
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
            where run_id = ?
            order by occurred_at desc
            limit ?
            """,
            (run_id, limit),
        )
    else:
        rows = _query_rows(
            db_path,
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
            order by occurred_at desc
            limit ?
            """,
            (limit,),
        )
    rows = _decode_json_fields(
        rows,
        [
            "positive_factors_json",
            "negative_factors_json",
            "uncertainties_json",
            "supporting_evidence_ids_json",
        ],
    )
    typer.echo(json.dumps({"rows": rows}, ensure_ascii=False))


@app.command("audit.case-assessments")
def audit_case_assessments_command(
    db_path: Path = typer.Option(..., "--db-path"),
    limit: int = typer.Option(50, "--limit"),
    run_id: str | None = typer.Option(None, "--run-id"),
) -> None:
    if run_id:
        rows = _query_rows(
            db_path,
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
            where run_id = ?
            order by occurred_at desc
            limit ?
            """,
            (run_id, limit),
        )
    else:
        rows = _query_rows(
            db_path,
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
            order by occurred_at desc
            limit ?
            """,
            (limit,),
        )
    rows = _decode_json_fields(rows, ["supporting_alert_ids_json", "supporting_evidence_ids_json"])
    typer.echo(json.dumps({"rows": rows}, ensure_ascii=False))


@app.command("audit.entity-assessments")
def audit_entity_assessments_command(
    db_path: Path = typer.Option(..., "--db-path"),
    limit: int = typer.Option(50, "--limit"),
    run_id: str | None = typer.Option(None, "--run-id"),
    entity_type: str | None = typer.Option(None, "--entity-type"),
    risk_level: str | None = typer.Option(None, "--risk-level"),
) -> None:
    conditions: list[str] = []
    params: list[object] = []
    if run_id:
        conditions.append("run_id = ?")
        params.append(run_id)
    if entity_type:
        conditions.append("entity_type = ?")
        params.append(entity_type)
    if risk_level:
        conditions.append("risk_level = ?")
        params.append(risk_level)
    where_clause = f"where {' and '.join(conditions)}" if conditions else ""
    params.append(limit)
    rows = _query_rows(
        db_path,
        f"""
        select
          assessment_id,
          occurred_at,
          run_id,
          entity_type,
          entity_key,
          entity_label,
          related_case_id,
          risk_level,
          assessment_confidence,
          verdict,
          reason_summary,
          supporting_alert_ids_json,
          supporting_evidence_ids_json,
          first_seen_at,
          last_seen_at,
          analysis_cutoff_at,
          is_current
        from entity_assessments
        {where_clause}
        order by occurred_at desc
        limit ?
        """,
        tuple(params),
    )
    rows = _decode_json_fields(rows, ["supporting_alert_ids_json", "supporting_evidence_ids_json"])
    typer.echo(json.dumps({"rows": rows}, ensure_ascii=False))


@app.command("audit.escalations")
def audit_escalations_command(
    db_path: Path = typer.Option(..., "--db-path"),
    limit: int = typer.Option(50, "--limit"),
    run_id: str | None = typer.Option(None, "--run-id"),
) -> None:
    if run_id:
        rows = _query_rows(
            db_path,
            """
            select escalation_id, occurred_at, run_id, case_id, triggered, channel, template, notification_id, reason
            from escalation_decisions
            where run_id = ?
            order by occurred_at desc
            limit ?
            """,
            (run_id, limit),
        )
    else:
        rows = _query_rows(
            db_path,
            """
            select escalation_id, occurred_at, run_id, case_id, triggered, channel, template, notification_id, reason
            from escalation_decisions
            order by occurred_at desc
            limit ?
            """,
            (limit,),
        )
    typer.echo(json.dumps({"rows": rows}, ensure_ascii=False))


@app.command("audit.compact")
def audit_compact_command(
    db_path: Path = typer.Option(..., "--db-path"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    vacuum: bool = typer.Option(False, "--vacuum"),
    now_iso: str | None = typer.Option(None, "--now-iso"),
    agent_outputs_days: int = typer.Option(30, "--agent-outputs-days"),
    agent_tool_calls_days: int = typer.Option(30, "--agent-tool-calls-days"),
    case_changes_days: int = typer.Option(90, "--case-changes-days"),
    link_decisions_days: int = typer.Option(90, "--link-decisions-days"),
    alert_decisions_days: int = typer.Option(90, "--alert-decisions-days"),
) -> None:
    conn = connect_db(db_path)
    try:
        body = compact_audit_logs(
            conn,
            retention_days={
                "agent_outputs": agent_outputs_days,
                "agent_tool_calls": agent_tool_calls_days,
                "case_changes": case_changes_days,
                "link_decisions": link_decisions_days,
                "alert_decisions": alert_decisions_days,
            },
            dry_run=dry_run,
            vacuum=vacuum,
            now_iso=now_iso,
        )
    finally:
        conn.close()
    typer.echo(json.dumps(body, ensure_ascii=False))


@app.command("context.case-digest")
def context_case_digest_command(
    db_path: Path = typer.Option(..., "--db-path"),
    case_id: str = typer.Option(..., "--case-id"),
) -> None:
    rows = _query_rows(
        db_path,
        """
        select case_id, digest_text, facts_json, updated_at
        from case_digests
        where case_id = ?
        """,
        (case_id,),
    )
    typer.echo(json.dumps({"rows": rows}, ensure_ascii=False))


@app.command("context.patrol-state")
def context_patrol_state_command(
    db_path: Path = typer.Option(..., "--db-path"),
    key: str | None = typer.Option(None, "--key"),
) -> None:
    conn = connect_db(db_path)
    try:
        latest_run = conn.execute(
            """
            select run_id, status, started_at, finished_at, trigger_source
            from patrol_runs
            order by started_at desc
            limit 1
            """
        ).fetchone()
        rows: list[dict] = []
        if latest_run is not None:
            run_id = latest_run["run_id"]
            finished_at = latest_run["finished_at"]
            started_at = latest_run["started_at"]
            updated_at = finished_at or started_at
            processed_events = 0
            if latest_run["trigger_source"] == "ingest_event" and finished_at:
                processed_events = int(
                    conn.execute(
                        """
                        select count(*)
                        from alert_ingest_events
                        where processed_at = ?
                        """,
                        (finished_at,),
                    ).fetchone()[0]
                )
            derived_rows = [
                {"state_key": "last_patrol_run_id", "state_value_json": run_id, "updated_at": updated_at},
                {"state_key": "last_patrol_status", "state_value_json": latest_run["status"], "updated_at": updated_at},
                {"state_key": "last_patrol_finished_at", "state_value_json": finished_at, "updated_at": updated_at},
                {
                    "state_key": "last_patrol_processed_events",
                    "state_value_json": processed_events,
                    "updated_at": updated_at,
                },
            ]
            if key:
                rows = [row for row in derived_rows if row["state_key"] == key]
            else:
                rows = derived_rows
    finally:
        conn.close()
    typer.echo(json.dumps({"rows": rows}, ensure_ascii=False))


if __name__ == "__main__":
    app()
