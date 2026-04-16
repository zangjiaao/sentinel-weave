import sqlite3

from security_analyst_agent.repositories.assessments import upsert_entity_assessment
from security_analyst_agent.repositories.audit import load_active_analysis_cutoff, load_active_patrol_run_id
from security_analyst_agent.schemas.assessment_tools import AssessmentUpsertBatchRequest, AssessmentUpsertRequest
from security_analyst_agent.schemas.common import ToolResponse


def assessment_upsert(conn: sqlite3.Connection, payload: dict) -> dict:
    request = AssessmentUpsertRequest.model_validate(payload)
    run_id = load_active_patrol_run_id(conn)
    analysis_cutoff_at = load_active_analysis_cutoff(conn)
    entity = upsert_entity_assessment(
        conn,
        entity_type=request.entity_type,
        entity_key=request.entity_key,
        entity_label=request.entity_label or request.entity_key,
        related_case_id=request.related_case_id,
        risk_level=request.risk_level,
        assessment_confidence=request.assessment_confidence,
        verdict=request.verdict,
        reason_summary=request.reason_summary,
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
            "case_ids": [request.related_case_id] if request.related_case_id else [],
            "alert_ids": request.supporting_alert_ids,
            "evidence_ids": request.supporting_evidence_ids,
        },
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
