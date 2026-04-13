from pydantic import BaseModel, Field


class AssetSearchRequest(BaseModel):
    query: str | None = None
    indicators: list[str] = Field(default_factory=list)
    include_inactive: bool = False
    limit: int = 10

