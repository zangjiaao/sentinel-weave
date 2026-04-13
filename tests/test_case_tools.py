from security_analyst_agent.tools.case_tools import case_explain_link, case_get, case_timeline


def test_case_get_returns_actor_and_target_summary(db_conn) -> None:
    result = case_get(db_conn, {"case_id": "case_demo_001"})
    assert result["data"]["case"]["overall_severity"] == "high"
    assert result["data"]["case"]["primary_actor_id"] == "actor_demo_001"


def test_case_timeline_returns_ordered_attack_steps(db_conn) -> None:
    result = case_timeline(db_conn, {"case_id": "case_demo_001", "include_evidence": True})
    stages = [item["stage"] for item in result["data"]["events"]]
    assert stages == ["recon", "persistence", "command_execution"]


def test_case_explain_link_shows_positive_factors(db_conn) -> None:
    result = case_explain_link(
        db_conn,
        {"case_id": "case_demo_001", "target_type": "alert", "target_id": "alt_day3_shell_01"},
    )
    assert result["data"]["link_decision"]["is_linked"] is True
    assert result["data"]["link_decision"]["positive_factors"]
