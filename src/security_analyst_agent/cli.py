import json
from pathlib import Path

import typer

from security_analyst_agent.config import DEFAULT_HERMES_CRON_JOB_ID
from security_analyst_agent.db import connect_db
from security_analyst_agent.ingest import ingest_alert_bundle
from security_analyst_agent.patrol_trigger import trigger_patrol_from_ingest
from security_analyst_agent.schemas.common import ToolResponse
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


@app.command("alert.fetch")
def alert_fetch_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("alert.fetch", db_path, payload)


@app.command("alert.detail")
def alert_detail_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("alert.detail", db_path, payload)


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


@app.command("case.get")
def case_get_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("case.get", db_path, payload)


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


@app.command("case.link-alert")
def case_link_alert_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("case.link-alert", db_path, payload)


@app.command("case.update-risk")
def case_update_risk_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("case.update-risk", db_path, payload)


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


@app.command("patrol.trigger")
def patrol_trigger_command(
    db_path: Path = typer.Option(..., "--db-path"),
    job_id: str = typer.Option(DEFAULT_HERMES_CRON_JOB_ID, "--job-id"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    result = trigger_patrol_from_ingest(db_path=db_path, job_id=job_id, dry_run=dry_run)
    typer.echo(json.dumps(result, ensure_ascii=False))


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
    if key:
        rows = _query_rows(
            db_path,
            """
            select state_key, state_value_json, updated_at
            from patrol_state
            where state_key = ?
            """,
            (key,),
        )
    else:
        rows = _query_rows(
            db_path,
            """
            select state_key, state_value_json, updated_at
            from patrol_state
            order by state_key asc
            """,
        )
    typer.echo(json.dumps({"rows": rows}, ensure_ascii=False))


if __name__ == "__main__":
    app()
