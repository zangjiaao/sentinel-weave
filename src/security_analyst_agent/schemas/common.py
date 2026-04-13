from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class TimeRange(BaseModel):
    from_: datetime | None = Field(default=None, alias="from")
    to: datetime | None = None
    timezone: str = "Asia/Shanghai"


class ToolMeta(BaseModel):
    cache_hit: bool = False
    partial: bool = False
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ToolPage(BaseModel):
    next_cursor: str | None = None
    has_more: bool = False


class ToolResponse(BaseModel):
    ok: bool
    summary: str
    data: dict[str, Any]
    warnings: list[str] = Field(default_factory=list)
    refs: dict[str, list[str]] = Field(default_factory=dict)
    page: ToolPage = Field(default_factory=ToolPage)
    meta: ToolMeta = Field(default_factory=ToolMeta)

