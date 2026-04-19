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
    hotspot_top_n: int = Field(default=3, ge=1, le=10)


class AlertSuspectIpTopkRequest(BaseModel):
    status: list[str] = Field(default_factory=list)
    min_severity: str | None = None
    top_k: int = Field(default=5, ge=1, le=50)
    min_alert_count: int = Field(default=2, ge=1, le=1000)
    queue_only: bool = True


class AlertIpContextRequest(BaseModel):
    src_ip: str
    status: list[str] = Field(default_factory=list)
    min_severity: str | None = None
    limit: int = Field(default=30, ge=1, le=200)
    queue_only: bool = False


class AlertDetailRequest(BaseModel):
    alert_id: str


class AlertDetailBatchRequest(BaseModel):
    alert_ids: list[str] = Field(min_length=1)


class AlertAckRequest(BaseModel):
    alert_ids: list[str] = Field(min_length=1)
    status: Literal["triaged", "closed"] = "triaged"
