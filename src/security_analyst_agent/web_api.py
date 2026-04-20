from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from security_analyst_agent.config import DEFAULT_DB_PATH
from security_analyst_agent.services import web_backend


class PreviewMapRequest(BaseModel):
    limit: int = 500
    include_unmapped: bool = False
    raw_event_ids: list[str] | None = None


class NotificationPreviewRequest(BaseModel):
    case_id: str
    channel: str = "feishu"


class ReportPreviewRequest(BaseModel):
    case_id: str
    tone: str = "professional"
    title: str | None = None


def _translate_service_error(exc: ValueError) -> HTTPException:
    message = str(exc)
    if "not found" in message:
        return HTTPException(status_code=404, detail=message)
    return HTTPException(status_code=400, detail=message)


def create_app(*, db_path: Path | None = None) -> FastAPI:
    app = FastAPI(title="Security Analyst Agent Web API", version="0.1.0")
    app.state.db_path = db_path or DEFAULT_DB_PATH

    def _db_path() -> Path:
        return Path(app.state.db_path)

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    @app.get("/api/intake/sources")
    def list_intake_sources(
        limit: int = 50,
        statuses: Annotated[list[str] | None, Query(alias="status")] = None,
        source_modes: Annotated[list[str] | None, Query(alias="source_mode")] = None,
    ) -> dict:
        return web_backend.list_sources(
            db_path=_db_path(),
            limit=limit,
            statuses=statuses,
            source_modes=source_modes,
        )

    @app.get("/api/intake/sources/{source_id}/runs")
    def list_intake_source_runs(
        source_id: str,
        limit: int = 100,
        statuses: Annotated[list[str] | None, Query(alias="status")] = None,
    ) -> dict:
        return web_backend.list_source_runs(
            db_path=_db_path(),
            source_id=source_id,
            limit=limit,
            statuses=statuses,
        )

    @app.get("/api/intake/uploads")
    def list_intake_uploads(
        limit: int = 20,
        statuses: Annotated[list[str] | None, Query(alias="status")] = None,
    ) -> dict:
        return web_backend.list_jobs(db_path=_db_path(), limit=limit, statuses=statuses)

    @app.get("/api/intake/uploads/{job_id}")
    def get_intake_upload(job_id: str) -> dict:
        try:
            return web_backend.get_job(db_path=_db_path(), job_id=job_id)
        except ValueError as exc:
            raise _translate_service_error(exc) from exc

    @app.get("/api/intake/uploads/{job_id}/sample")
    def sample_intake_upload(job_id: str, limit_groups: int = 20, samples_per_group: int = 3) -> dict:
        try:
            return web_backend.sample_job(
                db_path=_db_path(),
                job_id=job_id,
                limit_groups=limit_groups,
                samples_per_group=samples_per_group,
            )
        except ValueError as exc:
            raise _translate_service_error(exc) from exc

    @app.post("/api/intake/uploads/{job_id}/preview-map")
    def preview_intake_upload_mapping(job_id: str, body: PreviewMapRequest) -> dict:
        try:
            return web_backend.preview_job_apply(
                db_path=_db_path(),
                job_id=job_id,
                limit=body.limit,
                include_unmapped=body.include_unmapped,
                raw_event_ids=body.raw_event_ids,
            )
        except ValueError as exc:
            raise _translate_service_error(exc) from exc

    @app.get("/api/intake/parsers")
    def list_intake_parsers(
        limit: int = 50,
        statuses: Annotated[list[str] | None, Query(alias="status")] = None,
    ) -> dict:
        return web_backend.list_parsers(db_path=_db_path(), limit=limit, statuses=statuses)

    @app.get("/api/intake/parsers/{parser_profile_id}/versions")
    def list_intake_parser_versions(parser_profile_id: str, limit: int = 50) -> dict:
        return web_backend.list_parser_versions(
            db_path=_db_path(),
            parser_profile_id=parser_profile_id,
            limit=limit,
        )

    @app.get("/api/cases")
    def list_cases(
        limit: int = 50,
        statuses: Annotated[list[str] | None, Query(alias="status")] = None,
        min_severity: str | None = None,
        current_stage: str | None = None,
        include_merged: bool = True,
        keyword: str | None = None,
    ) -> dict:
        return web_backend.list_cases_overview(
            db_path=_db_path(),
            limit=limit,
            statuses=statuses,
            min_severity=min_severity,
            current_stage=current_stage,
            include_merged=include_merged,
            keyword=keyword,
        )

    @app.get("/api/cases/{case_id}")
    def get_case(case_id: str) -> dict:
        try:
            return web_backend.get_case_detail(db_path=_db_path(), case_id=case_id)
        except ValueError as exc:
            raise _translate_service_error(exc) from exc

    @app.get("/api/cases/{case_id}/timeline")
    def get_case_timeline(case_id: str, include_evidence: bool = False) -> dict:
        return web_backend.get_case_timeline(
            db_path=_db_path(),
            case_id=case_id,
            include_evidence=include_evidence,
        )

    @app.get("/api/cases/{case_id}/actors")
    def get_case_actors(case_id: str) -> dict:
        return web_backend.get_case_actors(db_path=_db_path(), case_id=case_id)

    @app.get("/api/assets")
    def list_assets(query: str | None = None, include_inactive: bool = True, limit: int = 50) -> dict:
        return web_backend.list_assets_overview(
            db_path=_db_path(),
            query=query,
            include_inactive=include_inactive,
            limit=limit,
        )

    @app.get("/api/assets/{asset_id}")
    def get_asset(asset_id: str) -> dict:
        try:
            return web_backend.get_asset_detail(db_path=_db_path(), asset_id=asset_id)
        except ValueError as exc:
            raise _translate_service_error(exc) from exc

    @app.get("/api/assets/{asset_id}/cases")
    def get_asset_cases(asset_id: str, limit: int = 20) -> dict:
        return web_backend.list_asset_cases(db_path=_db_path(), asset_id=asset_id, limit=limit)

    @app.get("/api/notifications")
    def list_notifications(
        limit: int = 50,
        statuses: Annotated[list[str] | None, Query(alias="status")] = None,
        channels: Annotated[list[str] | None, Query(alias="channel")] = None,
    ) -> dict:
        return web_backend.list_notifications(
            db_path=_db_path(),
            limit=limit,
            statuses=statuses,
            channels=channels,
        )

    @app.get("/api/notifications/{notification_id}")
    def get_notification(notification_id: str) -> dict:
        try:
            return web_backend.get_notification(db_path=_db_path(), notification_id=notification_id)
        except ValueError as exc:
            raise _translate_service_error(exc) from exc

    @app.post("/api/notifications/preview")
    def preview_notification(body: NotificationPreviewRequest) -> dict:
        try:
            return web_backend.preview_notification(
                db_path=_db_path(),
                case_id=body.case_id,
                channel=body.channel,
            )
        except ValueError as exc:
            raise _translate_service_error(exc) from exc

    @app.get("/api/reports")
    def list_reports(
        limit: int = 50,
        statuses: Annotated[list[str] | None, Query(alias="status")] = None,
    ) -> dict:
        return web_backend.list_reports(db_path=_db_path(), limit=limit, statuses=statuses)

    @app.get("/api/reports/{report_id}")
    def get_report(report_id: str) -> dict:
        try:
            return web_backend.get_report(db_path=_db_path(), report_id=report_id)
        except ValueError as exc:
            raise _translate_service_error(exc) from exc

    @app.post("/api/reports/preview")
    def preview_report(body: ReportPreviewRequest) -> dict:
        try:
            return web_backend.preview_report(
                db_path=_db_path(),
                case_id=body.case_id,
                tone=body.tone,
                title=body.title,
            )
        except ValueError as exc:
            raise _translate_service_error(exc) from exc

    return app


app = create_app()

