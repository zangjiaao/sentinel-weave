from security_analyst_agent.services.case_relation_scoring import score_case_relation


def test_case_relation_score_is_high_for_same_asset_stage_chain() -> None:
    score = score_case_relation(
        left={
            "current_stage": "persistence",
            "asset_ids": {"asset_api_prod"},
            "src_ips": {"198.51.100.23"},
        },
        right={
            "current_stage": "command_execution",
            "asset_ids": {"asset_api_prod"},
            "src_ips": {"198.51.100.77"},
        },
    )
    assert score.total >= 0.78


def test_case_relation_score_is_low_for_noise_mismatch() -> None:
    score = score_case_relation(
        left={
            "current_stage": "recon",
            "asset_ids": {"asset_static_www"},
            "src_ips": {"203.0.113.200"},
        },
        right={
            "current_stage": "lateral_prep",
            "asset_ids": {"asset_api_prod"},
            "src_ips": {"198.51.100.77"},
        },
    )
    assert score.total < 0.68


def test_case_relation_score_boosts_recon_to_attack_continuation() -> None:
    score = score_case_relation(
        left={
            "current_stage": "recon",
            "overall_severity": "medium",
            "asset_ids": {"asset_api_prod", "asset_admin_portal", "asset_static_www"},
            "src_ips": {"198.51.100.23"},
            "last_event_at": "2026-04-10T09:12:00+08:00",
        },
        right={
            "current_stage": "persistence",
            "overall_severity": "high",
            "asset_ids": {"asset_api_prod"},
            "src_ips": {"198.51.100.23"},
            "last_event_at": "2026-04-11T14:20:00+08:00",
        },
    )
    assert score.total >= 0.78
