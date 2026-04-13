import sqlite3

from security_analyst_agent.repositories.assets import search_assets
from security_analyst_agent.schemas.asset_tools import AssetSearchRequest
from security_analyst_agent.schemas.common import ToolResponse


def asset_search(conn: sqlite3.Connection, payload: dict) -> dict:
    request = AssetSearchRequest.model_validate(payload)
    candidates = search_assets(
        conn,
        query=request.query,
        indicators=request.indicators,
        include_inactive=request.include_inactive,
        limit=request.limit,
    )
    response = ToolResponse(
        ok=True,
        summary=f"匹配到 {len(candidates)} 个资产候选",
        data={"candidates": candidates},
        refs={"asset_ids": [item["asset_id"] for item in candidates]},
    )
    return response.model_dump(mode="json", by_alias=True)

