from pydantic import BaseModel, Field


class EvidenceUpsertRequest(BaseModel):
    evidence_id: str
    case_id: str
    occurred_at: str | None = None
    evidence_type: str
    summary: str


class TimelineUpsertRequest(BaseModel):
    timeline_event_id: str
    case_id: str
    occurred_at: str
    stage: str
    title: str
    related_alert_ids: list[str] = Field(default_factory=list)
    related_evidence_ids: list[str] = Field(default_factory=list)
