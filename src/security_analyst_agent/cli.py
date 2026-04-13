import json
from pathlib import Path

import typer

from security_analyst_agent.db import connect_db
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
        result = dispatch_tool(conn, tool_name, body)
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


@app.command("intel.lookup")
def intel_lookup_command(
    db_path: Path = typer.Option(..., "--db-path"),
    payload: str = typer.Option("{}", "--payload"),
) -> None:
    _run_tool("intel.lookup", db_path, payload)


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


if __name__ == "__main__":
    app()
