from typing import Literal

from pydantic import BaseModel, Field

from security_analyst_agent.schemas.common import TimeRange


class AlertFetchRequest(BaseModel):
    time_range: TimeRange | None = None
    source_ids: list[str] = Field(default_factory=list)
    min_severity: str | None = None
    status: list[str] = Field(default_factory=list)
    limit: int = 20
    cursor: str | None = None
    mode: Literal["auto", "alerts", "clusters"] = "auto"
    auto_cluster_threshold: int = Field(default=200, ge=1)
    cluster_min_count: int = Field(default=2, ge=1)
    cluster_sample_size: int = Field(default=3, ge=1, le=10)


class AlertDetailRequest(BaseModel):
    alert_id: str


class AlertDetailBatchRequest(BaseModel):
    alert_ids: list[str] = Field(min_length=1)


class AlertAckRequest(BaseModel):
    alert_ids: list[str] = Field(min_length=1)
    status: Literal["triaged", "closed"] = "triaged"
