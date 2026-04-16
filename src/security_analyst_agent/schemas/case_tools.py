from pydantic import BaseModel, Field


class CaseGetRequest(BaseModel):
    case_id: str


class CaseTimelineRequest(BaseModel):
    case_id: str
    include_evidence: bool = False


class CaseExplainLinkRequest(BaseModel):
    case_id: str
    target_type: str
    target_id: str


class CaseUpsertRequest(BaseModel):
    case_id: str
    title: str
    status: str
    overall_severity: str
    current_stage: str
    primary_actor_id: str | None = None


class CaseUpsertBatchRequest(BaseModel):
    items: list[CaseUpsertRequest] = Field(min_length=1)


class CaseLinkAlertRequest(BaseModel):
    case_id: str
    alert_id: str
    confidence: float
    reason: str


class CaseLinkAlertBatchRequest(BaseModel):
    items: list[CaseLinkAlertRequest] = Field(min_length=1)


class CaseUpdateRiskRequest(BaseModel):
    case_id: str
    overall_severity: str
    current_stage: str
    status: str
    force_downgrade: bool = False
