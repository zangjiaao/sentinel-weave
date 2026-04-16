from typing import Literal

from pydantic import BaseModel, Field


class ActorCaseListRequest(BaseModel):
    case_id: str


class ActorCaseGetRequest(BaseModel):
    case_actor_id: str


class ActorCaseFindCandidatesRequest(BaseModel):
    case_id: str
    alert_id: str
    limit: int = 5


class ActorCaseUpsertRequest(BaseModel):
    case_actor_id: str
    case_id: str
    label: str
    status: str
    profile_confidence: float = Field(ge=0.0, le=1.0)
    risk_level: str
    is_primary: bool = False
    current_stage: str
    first_seen_at: str | None = None
    last_seen_at: str | None = None
    summary: str


class ActorCaseAddObservationRequest(BaseModel):
    case_actor_id: str
    observation_type: str
    observation_key: str
    observation_value: str
    confidence: float = Field(ge=0.0, le=1.0)
    first_seen_at: str | None = None
    last_seen_at: str | None = None
    source_count: int = 1


class ActorCaseAddObservationBatchRequest(BaseModel):
    items: list[ActorCaseAddObservationRequest] = Field(min_length=1)


class ActorCaseLinkRequest(BaseModel):
    case_actor_id: str
    target_type: Literal["alert", "evidence", "timeline_event", "artifact", "entity_assessment"]
    target_id: str
    link_confidence: float = Field(ge=0.0, le=1.0)
    link_reason: str


class ActorCaseLinkBatchRequest(BaseModel):
    items: list[ActorCaseLinkRequest] = Field(min_length=1)
