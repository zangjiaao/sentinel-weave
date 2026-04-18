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


def test_case_relation_score_treats_reactivation_close_to_command_execution() -> None:
    score = score_case_relation(
        left={
            "current_stage": "command_execution",
            "asset_ids": {"asset_api_prod"},
            "src_ips": {"198.51.100.77"},
        },
        right={
            "current_stage": "reactivation",
            "asset_ids": {"asset_api_prod"},
            "src_ips": {"198.51.100.91"},
        },
    )
    stage_factor = next(item for item in score.factors if item["factor_type"] == "stage_continuity")
    assert stage_factor["score"] >= 0.85


def test_case_relation_score_boosts_same_asset_stage_progress_with_source_rotation() -> None:
    score = score_case_relation(
        left={
            "current_stage": "persistence",
            "overall_severity": "high",
            "asset_ids": {"asset_api_prod", "asset_admin_portal", "asset_static_www"},
            "src_ips": {"198.51.100.23"},
            "last_event_at": "2026-04-11T14:20:00+08:00",
        },
        right={
            "current_stage": "lateral_prep",
            "overall_severity": "high",
            "asset_ids": {"asset_api_prod"},
            "src_ips": {"198.51.100.77"},
            "last_event_at": "2026-04-12T11:05:00+08:00",
        },
    )
    progress_factor = next(item for item in score.factors if item["factor_type"] == "same_asset_stage_progress")
    assert progress_factor["score"] == 1.0
    assert score.total >= 0.78
