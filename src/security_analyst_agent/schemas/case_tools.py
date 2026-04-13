from pydantic import BaseModel


class CaseGetRequest(BaseModel):
    case_id: str


class CaseTimelineRequest(BaseModel):
    case_id: str
    include_evidence: bool = False


class CaseExplainLinkRequest(BaseModel):
    case_id: str
    target_type: str
    target_id: str

