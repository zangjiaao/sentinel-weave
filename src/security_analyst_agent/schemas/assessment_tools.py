from typing import Literal

from pydantic import BaseModel, Field


class AssessmentUpsertRequest(BaseModel):
    entity_type: Literal["ip", "asset", "actor"]
    entity_key: str
    entity_label: str | None = None
    related_case_id: str | None = None
    risk_level: Literal["low", "medium", "high", "critical"]
    assessment_confidence: float = Field(ge=0.0, le=1.0)
    verdict: Literal["attacker", "compromised_host", "noise", "unknown"]
    reason_summary: str
    supporting_alert_ids: list[str] = Field(default_factory=list)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    first_seen_at: str | None = None
    last_seen_at: str | None = None


class AssessmentUpsertBatchRequest(BaseModel):
    items: list[AssessmentUpsertRequest] = Field(min_length=1)
