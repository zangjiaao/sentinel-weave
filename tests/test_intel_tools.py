from security_analyst_agent.tools.intel_tools import intel_lookup


def test_intel_lookup_returns_cached_verdict(db_conn) -> None:
    result = intel_lookup(db_conn, {"indicator": "198.51.100.23", "indicator_type": "ip"})
    assert result["data"]["result"]["verdict"] == "malicious"
    assert result["data"]["result"]["cache_hit"] is True
