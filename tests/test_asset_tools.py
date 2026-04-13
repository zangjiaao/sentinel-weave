from security_analyst_agent.tools.asset_tools import asset_search


def test_asset_search_matches_ip_and_domain_candidates(db_conn) -> None:
    result = asset_search(db_conn, {"indicators": ["203.0.113.10", "api.example.com"]})
    assert result["data"]["candidates"][0]["asset_id"] == "asset_api_prod"
