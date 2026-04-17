from __future__ import annotations

STAGE_ORDER = {
    "recon": 1,
    "exploit": 2,
    "persistence": 3,
    "command_execution": 4,
    "reactivation": 4,
    "lateral_prep": 5,
}

_STAGE_ALIASES = {
    "reconnaissance": "recon",
    "execution": "command_execution",
    "reactivate": "reactivation",
    "webshell_reactivation": "reactivation",
}


def normalize_stage(stage: str | None) -> str:
    normalized = str(stage or "").strip().lower()
    if not normalized:
        return ""
    canonical = _STAGE_ALIASES.get(normalized, normalized)
    return canonical


def stage_rank(stage: str | None) -> int:
    return STAGE_ORDER.get(normalize_stage(stage), 0)


def is_stage_at_least(stage: str | None, minimum_stage: str) -> bool:
    return stage_rank(stage) >= stage_rank(minimum_stage)
