from security_analyst_agent.repositories.case_relations import upsert_case_relation_candidate


def test_upsert_case_relation_increments_streak_for_consecutive_runs(db_conn) -> None:
    r1 = upsert_case_relation_candidate(db_conn, "run_1", "case_a", "case_b", 0.8, "reason", [], [])
    r2 = upsert_case_relation_candidate(db_conn, "run_2", "case_a", "case_b", 0.82, "reason", [], [])
    assert r1["streak_count"] == 1
    assert r2["streak_count"] == 2


def test_upsert_case_relation_resets_streak_when_score_drops(db_conn) -> None:
    upsert_case_relation_candidate(db_conn, "run_1", "case_a", "case_b", 0.8, "reason", [], [])
    r2 = upsert_case_relation_candidate(db_conn, "run_2", "case_a", "case_b", 0.5, "reason", [], [])
    assert r2["streak_count"] == 0
