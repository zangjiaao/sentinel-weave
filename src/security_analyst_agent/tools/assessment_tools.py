import sqlite3

from security_analyst_agent.repositories.assessments import upsert_entity_assessment
from security_analyst_agent.repositories.audit import load_active_analysis_cutoff, load_active_patrol_run_id
from security_analyst_agent.repositories.cases import resolve_canonical_case_id
from security_analyst_agent.schemas.assessment_tools import AssessmentUpsertBatchRequest, AssessmentUpsertRequest
from security_analyst_agent.schemas.common import ToolResponse
from security_analyst_agent.stages import stage_rank

_COMPROMISED_HOST_MIN_HIGH_SIGNAL_ALERTS = 2
_COMPROMISED_HOST_STRONG_STAGES = {
    "exploit",
    "persistence",
    "command_execution",
    "lateral_prep",
    "reactivation",
}
_COMPROMISED_HOST_STRONG_SEVERITIES = {"high", "critical"}


def _infer_related_case_id_from_alert_links(conn: sqlite3.Connection, *, alert_ids: list[str]) -> str | None:
    deduped_alert_ids = [alert_id for alert_id in dict.fromkeys(alert_ids) if alert_id]
    inferred_case_ids: list[str] = []
    for alert_id in deduped_alert_ids:
        row = conn.execute(
            """
            select case_id
            from case_alert_links
            where alert_id = ? and is_active = 1
            order by linked_at desc, rowid desc
            limit 1
            """,
            (alert_id,),
        ).fetchone()
        if row is None or not row["case_id"]:
            continue
        inferred_case_ids.append(resolve_canonical_case_id(conn, str(row["case_id"])))
    unique_case_ids = list(dict.fromkeys(inferred_case_ids))
    if len(unique_case_ids) == 1:
        return unique_case_ids[0]
    return None


def _count_high_signal_alert_support(conn: sqlite3.Connection, *, alert_ids: list[str]) -> int:
    deduped_alert_ids = [alert_id for alert_id in dict.fromkeys(alert_ids) if alert_id]
    if not deduped_alert_ids:
        return 0
    rows = conn.execute(
        f"""
        select lower(severity) as severity, lower(attack_stage) as attack_stage
        from alerts
        where alert_id in ({", ".join("?" for _ in deduped_alert_ids)})
        """,
        deduped_alert_ids,
    ).fetchall()
    count = 0
    for row in rows:
        severity = str(row["severity"] or "")
        attack_stage = str(row["attack_stage"] or "")
        if severity not in _COMPROMISED_HOST_STRONG_SEVERITIES:
            continue
        if attack_stage in _COMPROMISED_HOST_STRONG_STAGES or stage_rank(attack_stage) >= stage_rank("persistence"):
            count += 1
    return count


def _apply_strong_verdict_guard(
    conn: sqlite3.Connection,
    *,
    request: AssessmentUpsertRequest,
    warnings: list[str],
) -> tuple[str, str, str]:
    verdict = request.verdict
    risk_level = request.risk_level
    reason_summary = request.reason_summary
    if verdict != "compromised_host":
        return verdict, risk_level, reason_summary

    evidence_count = len([item for item in request.supporting_evidence_ids if item])
    high_signal_alert_support_count = _count_high_signal_alert_support(conn, alert_ids=request.supporting_alert_ids)
    if evidence_count > 0 or high_signal_alert_support_count >= _COMPROMISED_HOST_MIN_HIGH_SIGNAL_ALERTS:
        return verdict, risk_level, reason_summary

    warnings.append("compromised_host_insufficient_support_downgraded_to_unknown")
    return "unknown", "medium", f"{reason_summary}; auto_guard:insufficient_compromised_host_support"


def assessment_upsert(conn: sqlite3.Connection, payload: dict) -> dict:
    request = AssessmentUpsertRequest.model_validate(payload)
    run_id = load_active_patrol_run_id(conn)
    analysis_cutoff_at = load_active_analysis_cutoff(conn)
    warnings: list[str] = []
    effective_related_case_id = request.related_case_id
    if not effective_related_case_id and request.supporting_alert_ids:
        inferred_case_id = _infer_related_case_id_from_alert_links(conn, alert_ids=request.supporting_alert_ids)
        if inferred_case_id:
            effective_related_case_id = inferred_case_id
            warnings.append("related_case_id_inferred_from_alert_links")
    effective_verdict, effective_risk_level, effective_reason_summary = _apply_strong_verdict_guard(
        conn,
        request=request,
        warnings=warnings,
    )

    entity = upsert_entity_assessment(
        conn,
        entity_type=request.entity_type,
        entity_key=request.entity_key,
        entity_label=request.entity_label or request.entity_key,
        related_case_id=effective_related_case_id,
        risk_level=effective_risk_level,
        assessment_confidence=request.assessment_confidence,
        verdict=effective_verdict,
        reason_summary=effective_reason_summary,
        supporting_alert_ids=request.supporting_alert_ids,
        supporting_evidence_ids=request.supporting_evidence_ids,
        first_seen_at=request.first_seen_at,
        last_seen_at=request.last_seen_at,
        run_id=run_id,
        analysis_cutoff_at=analysis_cutoff_at,
    )
    conn.commit()

    response = ToolResponse(
        ok=True,
        summary=f"已更新实体评估 {entity['entity_type']}:{entity['entity_key']}",
        data={"assessment": entity},
        refs={
            "case_ids": [effective_related_case_id] if effective_related_case_id else [],
            "alert_ids": request.supporting_alert_ids,
            "evidence_ids": request.supporting_evidence_ids,
        },
        warnings=warnings,
    )
    return response.model_dump(mode="json", by_alias=True)


def assessment_upsert_batch(conn: sqlite3.Connection, payload: dict) -> dict:
    request = AssessmentUpsertBatchRequest.model_validate(payload)
    assessments: list[dict] = []
    failures: list[dict] = []
    warnings: list[str] = []
    refs_case_ids: list[str] = []
    refs_alert_ids: list[str] = []
    refs_evidence_ids: list[str] = []

    for index, item in enumerate(request.items):
        result = assessment_upsert(conn, item.model_dump(mode="python"))
        if result.get("ok"):
            assessment = result.get("data", {}).get("assessment")
            if isinstance(assessment, dict):
                assessments.append(assessment)
            refs = result.get("refs", {})
            refs_case_ids.extend(refs.get("case_ids", []))
            refs_alert_ids.extend(refs.get("alert_ids", []))
            refs_evidence_ids.extend(refs.get("evidence_ids", []))
            continue

        failures.append(
            {
                "index": index,
                "item": item.model_dump(mode="python"),
                "summary": result.get("summary", "assessment.upsert failed"),
                "warnings": result.get("warnings", []),
            }
        )
        warnings.extend(result.get("warnings", []))

    response = ToolResponse(
        ok=len(failures) == 0,
        summary=f"批量写入实体评估：成功 {len(assessments)} 条，失败 {len(failures)} 条",
        data={"assessments": assessments, "failures": failures},
        refs={
            "case_ids": list(dict.fromkeys(refs_case_ids)),
            "alert_ids": list(dict.fromkeys(refs_alert_ids)),
            "evidence_ids": list(dict.fromkeys(refs_evidence_ids)),
        },
        warnings=list(dict.fromkeys(warnings)),
    )
    return response.model_dump(mode="json", by_alias=True)
