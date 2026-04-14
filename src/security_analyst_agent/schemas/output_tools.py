from pydantic import BaseModel


class NotifyPreviewRequest(BaseModel):
    case_id: str
    channel: str
    template: str


class NotifySendRequest(BaseModel):
    case_id: str
    channel: str
    template: str


class ReportDraftRequest(BaseModel):
    case_id: str
    template: str
    tone: str
