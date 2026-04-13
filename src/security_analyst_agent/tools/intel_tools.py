import sqlite3

from security_analyst_agent.schemas.common import ToolMeta, ToolResponse
from security_analyst_agent.schemas.intel_tools import IntelLookupRequest
from security_analyst_agent.services.intel import lookup_cached_indicator


def intel_lookup(conn: sqlite3.Connection, payload: dict) -> dict:
    request = IntelLookupRequest.model_validate(payload)
    cached = lookup_cached_indicator(conn, request.indicator, request.indicator_type)

    if cached:
        result = {**cached, "cache_hit": True}
        response = ToolResponse(
            ok=True,
            summary=f"命中情报缓存: {request.indicator}",
            data={"result": result},
            refs={"indicators": [request.indicator]},
            meta=ToolMeta(cache_hit=True),
        )
        return response.model_dump(mode="json", by_alias=True)

    response = ToolResponse(
        ok=True,
        summary=f"未命中情报缓存: {request.indicator}",
        data={
            "result": {
                "indicator": request.indicator,
                "indicator_type": request.indicator_type,
                "verdict": "unknown",
                "confidence": 0.0,
                "cache_hit": False,
            }
        },
        warnings=[f"intel_cache_miss:{request.indicator}"],
        refs={"indicators": [request.indicator]},
    )
    return response.model_dump(mode="json", by_alias=True)

