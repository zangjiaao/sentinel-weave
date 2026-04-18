import sqlite3
from datetime import datetime, timezone

from security_analyst_agent.repositories.cases import (
    append_timeline_event_for_alert,
    link_alert_to_case,
    load_alert,
    load_case_alert_ids,
    load_case,
    list_cases,
    search_cases,
    resolve_canonical_case_id,
    load_supporting_evidence_ids_for_alert,
    load_case_timeline,
    load_evidence_by_ids,
    update_case_risk,
    upsert_case,
)
from security_analyst_agent.repositories.audit import (
    insert_case_assessment_log,
    insert_case_change_log,
    insert_link_decision_log,
    load_active_analysis_cutoff,
)
from security_analyst_agent.repositories.context_memory import build_case_digest, load_case_digest, upsert_case_digest
from security_analyst_agent.schemas.case_tools import (
    CaseExplainLinkRequest,
    CaseGetRequest,
    CaseListRequest,
    CaseLinkAlertBatchRequest,
    CaseLinkAlertRequest,
    CaseSearchRequest,
    CaseTimelineRequest,
    CaseUpsertBatchRequest,
    CaseUpdateRiskRequest,
    CaseUpsertRequest,
)
from security_analyst_agent.schemas.common import ToolResponse
from security_analyst_agent.stages import normalize_stage, stage_rank
from security_analyst_agent.services.link_explainer import explain_alert_link

def _resolve_stage_with_guard(current_stage: str, requested_stage: str, force_downgrade: bool) -> tuple[str, bool]:
    normalized_requested_stage = normalize_stage(requested_stage) or requested_stage
    current_rank = stage_rank(current_stage)
    requested_rank = stage_rank(normalized_requested_stage)
    if current_rank == 0 or requested_rank == 0:
        return normalized_requested_stage, False
    if requested_rank < current_rank and not force_downgrade:
        return current_stage, True
    return normalized_requested_stage, False


def _load_case_supporting_evidence_ids(
    conn: sqlite3.Connection, case_id: str, analysis_cutoff_at: str | None
) -> list[str]:
    if analysis_cutoff_at:
        rows = conn.execute(
            """
            select distinct related_evidence_ids.value as evidence_id
            from timeline_events
            join json_each(timeline_events.related_evidence_ids) as related_evidence_ids
            where timeline_events.case_id = ?
              and timeline_events.occurred_at <= ?
            order by related_evidence_ids.value asc
            """,
            (case_id, analysis_cutoff_at),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            select distinct related_evidence_ids.value as evidence_id
            from timeline_events
            join json_each(timeline_events.related_evidence_ids) as related_evidence_ids
            where timeline_events.case_id = ?
            order by related_evidence_ids.value asc
            """,
            (case_id,),
        ).fetchall()
    return [row["evidence_id"] for row in rows]


def case_get(conn: sqlite3.Connection, payload: dict) -> dict:
    request = CaseGetRequest.model_validate(payload)
    warnings: list[str] = []
    effective_case_id = resolve_canonical_case_id(conn, request.case_id)
    if effective_case_id != request.case_id:
        warnings.append("case_redirected_to_canonical")
    case = load_case(conn, effective_case_id)
    if case is None:
        not_found_warnings = [
            f"case_not_found:{request.case_id}",
            "case_discovery_required:list_then_search",
        ]
        response = ToolResponse(
            ok=False,
            summary=f"未找到案件 {request.case_id}",
            data={
                "case": None,
                "recommended_next_actions": [
                    {
                        "tool": "case.list",
                        "reason": "case_id unknown and no reliable lookup keys yet",
                    },
                    {
                        "tool": "case.search",
                        "reason": "refine candidates after obtaining src_ip/asset_id/attack_stage/keyword",
                    },
                ],
            },
            warnings=not_found_warnings,
        )
        return response.model_dump(mode="json", by_alias=True)

    analysis_cutoff_at = load_active_analysis_cutoff(conn)
    case_with_memory = dict(case)
    if analysis_cutoff_at:
        memory_digest = build_case_digest(conn, effective_case_id, analysis_cutoff_at=analysis_cutoff_at)
    else:
        memory_digest = load_case_digest(conn, effective_case_id)
        if memory_digest is None:
            memory_digest = upsert_case_digest(conn, effective_case_id) or build_case_digest(conn, effective_case_id)
    case_with_memory["memory_digest"] = memory_digest

    response = ToolResponse(
        ok=True,
        summary=f"读取案件 {effective_case_id}",
        data={"case": case_with_memory},
        refs={"case_ids": [effective_case_id]},
        warnings=warnings,
    )
    return response.model_dump(mode="json", by_alias=True)


def case_list(conn: sqlite3.Connection, payload: dict) -> dict:
    request = CaseListRequest.model_validate(payload)
    analysis_cutoff_at = load_active_analysis_cutoff(conn)
    cases = list_cases(
        conn,
        statuses=request.status,
        min_severity=request.min_severity,
        current_stage=request.current_stage,
        include_merged=request.include_merged,
        keyword=request.keyword,
        limit=request.limit,
        analysis_cutoff_at=analysis_cutoff_at,
    )
    response = ToolResponse(
        ok=True,
        summary=f"返回案件摘要 {len(cases)} 条",
        data={"cases": cases},
        refs={"case_ids": [item["case_id"] for item in cases]},
    )
    return response.model_dump(mode="json", by_alias=True)


def case_search(conn: sqlite3.Connection, payload: dict) -> dict:
    request = CaseSearchRequest.model_validate(payload)
    analysis_cutoff_at = load_active_analysis_cutoff(conn)
    cases = search_cases(
        conn,
        statuses=request.status,
        min_severity=request.min_severity,
        src_ip=request.src_ip,
        asset_id=request.asset_id,
        attack_stage=request.attack_stage,
        include_merged=request.include_merged,
        keyword=request.keyword,
        limit=request.limit,
        analysis_cutoff_at=analysis_cutoff_at,
    )
    response = ToolResponse(
        ok=True,
        summary=f"搜索候选案件 {len(cases)} 条",
        data={"cases": cases},
        refs={"case_ids": [item["case_id"] for item in cases]},
    )
    return response.model_dump(mode="json", by_alias=True)


def case_timeline(conn: sqlite3.Connection, payload: dict) -> dict:
    request = CaseTimelineRequest.model_validate(payload)
    warnings: list[str] = []
    effective_case_id = resolve_canonical_case_id(conn, request.case_id)
    if effective_case_id != request.case_id:
        warnings.append("case_redirected_to_canonical")
    analysis_cutoff_at = load_active_analysis_cutoff(conn)
    events = load_case_timeline(conn, effective_case_id, analysis_cutoff_at=analysis_cutoff_at)
    if request.include_evidence:
        for event in events:
            event["evidence"] = load_evidence_by_ids(
                conn,
                event["related_evidence_ids"],
                analysis_cutoff_at=analysis_cutoff_at,
            )

    response = ToolResponse(
        ok=True,
        summary=f"返回案件 {effective_case_id} 时间线，共 {len(events)} 个节点",
        data={"events": events},
        refs={
            "case_ids": [effective_case_id],
            "alert_ids": [item for event in events for item in event["related_alert_ids"]],
            "evidence_ids": [item for event in events for item in event["related_evidence_ids"]],
        },
        warnings=warnings,
    )
    return response.model_dump(mode="json", by_alias=True)


def case_explain_link(conn: sqlite3.Connection, payload: dict) -> dict:
    request = CaseExplainLinkRequest.model_validate(payload)
    if request.target_type != "alert":
        response = ToolResponse(
            ok=False,
            summary=f"暂不支持的 target_type: {request.target_type}",
            data={"link_decision": None},
            warnings=[f"unsupported_target_type:{request.target_type}"],
        )
        return response.model_dump(mode="json", by_alias=True)

    analysis_cutoff_at = load_active_analysis_cutoff(conn)
    alert = load_alert(conn, request.target_id, analysis_cutoff_at=analysis_cutoff_at)
    if alert is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到告警 {request.target_id}",
            data={"link_decision": None},
            warnings=[f"alert_not_found:{request.target_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)

    supporting_evidence_ids = load_supporting_evidence_ids_for_alert(
        conn,
        case_id=request.case_id,
        alert_id=request.target_id,
        analysis_cutoff_at=analysis_cutoff_at,
    )
    decision = explain_alert_link(alert, request.case_id, supporting_evidence_ids=supporting_evidence_ids)
    response = ToolResponse(
        ok=True,
        summary=f"生成关联解释：{request.target_id}",
        data={"link_decision": decision},
        refs={
            "case_ids": [request.case_id],
            "alert_ids": [request.target_id],
            "evidence_ids": decision["supporting_evidence_ids"],
        },
    )
    return response.model_dump(mode="json", by_alias=True)


def case_upsert(conn: sqlite3.Connection, payload: dict) -> dict:
    request = CaseUpsertRequest.model_validate(payload)
    before_case = load_case(conn, request.case_id)
    case_body = request.model_dump(mode="python")
    upsert_case(conn, case_body)
    case = load_case(conn, request.case_id)
    upsert_case_digest(conn, request.case_id)
    insert_case_change_log(
        conn,
        case_id=request.case_id,
        action="case_upsert",
        before_state=before_case,
        after_state=case,
        reason="tool:case.upsert",
    )
    conn.commit()
    response = ToolResponse(
        ok=True,
        summary=f"已写入案件 {request.case_id}",
        data={"case": case},
        refs={"case_ids": [request.case_id]},
    )
    return response.model_dump(mode="json", by_alias=True)


def case_upsert_batch(conn: sqlite3.Connection, payload: dict) -> dict:
    request = CaseUpsertBatchRequest.model_validate(payload)
    cases: list[dict] = []
    failures: list[dict] = []
    warnings: list[str] = []
    refs_case_ids: list[str] = []

    for index, item in enumerate(request.items):
        result = case_upsert(conn, item.model_dump(mode="python"))
        if result.get("ok"):
            case = result.get("data", {}).get("case")
            if isinstance(case, dict):
                cases.append(case)
            refs_case_ids.extend(result.get("refs", {}).get("case_ids", []))
            continue

        failures.append(
            {
                "index": index,
                "item": item.model_dump(mode="python"),
                "summary": result.get("summary", "case.upsert failed"),
                "warnings": result.get("warnings", []),
            }
        )
        warnings.extend(result.get("warnings", []))

    response = ToolResponse(
        ok=len(failures) == 0,
        summary=f"批量写入案件：成功 {len(cases)} 条，失败 {len(failures)} 条",
        data={"cases": cases, "failures": failures},
        refs={"case_ids": list(dict.fromkeys(refs_case_ids))},
        warnings=list(dict.fromkeys(warnings)),
    )
    return response.model_dump(mode="json", by_alias=True)


def case_link_alert(conn: sqlite3.Connection, payload: dict) -> dict:
    request = CaseLinkAlertRequest.model_validate(payload)
    warnings: list[str] = []
    effective_case_id = resolve_canonical_case_id(conn, request.case_id)
    if effective_case_id != request.case_id:
        warnings.append("case_redirected_to_canonical")
    case = load_case(conn, effective_case_id)
    if case is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到案件 {request.case_id}",
            data={"link": None},
            warnings=[f"case_not_found:{request.case_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)

    alert = load_alert(conn, request.alert_id)
    if alert is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到告警 {request.alert_id}",
            data={"link": None},
            warnings=[f"alert_not_found:{request.alert_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)

    linked_at = datetime.now(timezone.utc).isoformat()
    link_alert_to_case(
        conn=conn,
        case_id=effective_case_id,
        alert_id=request.alert_id,
        confidence=request.confidence,
        reason=request.reason,
        linked_at=linked_at,
    )
    timeline_event_id = append_timeline_event_for_alert(conn=conn, case_id=effective_case_id, alert=alert)
    upsert_case_digest(conn, effective_case_id)
    analysis_cutoff_at = load_active_analysis_cutoff(conn)
    supporting_evidence_ids = load_supporting_evidence_ids_for_alert(
        conn,
        case_id=effective_case_id,
        alert_id=request.alert_id,
        analysis_cutoff_at=analysis_cutoff_at,
    )
    decision = explain_alert_link(alert, effective_case_id, supporting_evidence_ids=supporting_evidence_ids)
    insert_link_decision_log(
        conn,
        alert_id=request.alert_id,
        case_id=effective_case_id,
        link_confidence=request.confidence,
        reason_summary=request.reason,
        positive_factors=decision["positive_factors"],
        negative_factors=decision["negative_factors"],
        uncertainties=decision["uncertainties"],
        supporting_evidence_ids=decision["supporting_evidence_ids"],
    )
    conn.commit()

    response = ToolResponse(
        ok=True,
        summary=f"已关联告警 {request.alert_id} 到案件 {effective_case_id}",
        data={
            "link": {
                "case_id": effective_case_id,
                "alert_id": request.alert_id,
                "confidence": request.confidence,
                "reason": request.reason,
                "linked_at": linked_at,
                "timeline_event_id": timeline_event_id,
            }
        },
        refs={
            "case_ids": [effective_case_id],
            "alert_ids": [request.alert_id],
            "timeline_event_ids": [timeline_event_id],
        },
        warnings=warnings,
    )
    return response.model_dump(mode="json", by_alias=True)


def case_link_alert_batch(conn: sqlite3.Connection, payload: dict) -> dict:
    request = CaseLinkAlertBatchRequest.model_validate(payload)
    links: list[dict] = []
    failures: list[dict] = []
    warnings: list[str] = []
    refs_case_ids: list[str] = []
    refs_alert_ids: list[str] = []
    refs_timeline_event_ids: list[str] = []

    for index, item in enumerate(request.items):
        result = case_link_alert(conn, item.model_dump(mode="python"))
        if result.get("ok"):
            link = result.get("data", {}).get("link")
            if isinstance(link, dict):
                links.append(link)
            refs = result.get("refs", {})
            refs_case_ids.extend(refs.get("case_ids", []))
            refs_alert_ids.extend(refs.get("alert_ids", []))
            refs_timeline_event_ids.extend(refs.get("timeline_event_ids", []))
            continue

        failures.append(
            {
                "index": index,
                "item": item.model_dump(mode="python"),
                "summary": result.get("summary", "case.link-alert failed"),
                "warnings": result.get("warnings", []),
            }
        )
        warnings.extend(result.get("warnings", []))

    response = ToolResponse(
        ok=len(failures) == 0,
        summary=f"批量关联告警：成功 {len(links)} 条，失败 {len(failures)} 条",
        data={"links": links, "failures": failures},
        refs={
            "case_ids": list(dict.fromkeys(refs_case_ids)),
            "alert_ids": list(dict.fromkeys(refs_alert_ids)),
            "timeline_event_ids": list(dict.fromkeys(refs_timeline_event_ids)),
        },
        warnings=list(dict.fromkeys(warnings)),
    )
    return response.model_dump(mode="json", by_alias=True)


def case_update_risk(conn: sqlite3.Connection, payload: dict) -> dict:
    request = CaseUpdateRiskRequest.model_validate(payload)
    warnings: list[str] = []
    effective_case_id = resolve_canonical_case_id(conn, request.case_id)
    if effective_case_id != request.case_id:
        warnings.append("case_redirected_to_canonical")
    case = load_case(conn, effective_case_id)
    if case is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到案件 {request.case_id}",
            data={"case": None},
            warnings=[f"case_not_found:{request.case_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)

    before_case = dict(case)
    analysis_cutoff_at = load_active_analysis_cutoff(conn)
    effective_stage, downgraded_blocked = _resolve_stage_with_guard(
        current_stage=before_case["current_stage"],
        requested_stage=request.current_stage,
        force_downgrade=request.force_downgrade,
    )

    update_case_risk(
        conn=conn,
        case_id=effective_case_id,
        overall_severity=request.overall_severity,
        current_stage=effective_stage,
        status=request.status,
    )
    updated_case = load_case(conn, effective_case_id)
    upsert_case_digest(conn, effective_case_id)
    insert_case_change_log(
        conn,
        case_id=effective_case_id,
        action="case_update_risk",
        before_state=before_case,
        after_state=updated_case,
        reason="tool:case.update-risk_stage_guard" if downgraded_blocked else "tool:case.update-risk",
    )
    supporting_alert_ids = load_case_alert_ids(
        conn,
        effective_case_id,
        analysis_cutoff_at=analysis_cutoff_at,
    )
    supporting_evidence_ids = _load_case_supporting_evidence_ids(
        conn,
        effective_case_id,
        analysis_cutoff_at=analysis_cutoff_at,
    )
    verdict = (
        "high_risk_active"
        if request.overall_severity in {"high", "critical"}
        else "under_investigation"
        if request.overall_severity == "medium"
        else "monitoring"
    )
    insert_case_assessment_log(
        conn,
        case_id=effective_case_id,
        risk_level=request.overall_severity,
        assessment_confidence=0.9 if request.overall_severity in {"high", "critical"} else 0.7,
        current_stage=effective_stage,
        verdict=verdict,
        reason_summary="tool:case.update-risk_stage_guard" if downgraded_blocked else "tool:case.update-risk",
        supporting_alert_ids=supporting_alert_ids,
        supporting_evidence_ids=supporting_evidence_ids,
    )
    conn.commit()
    if downgraded_blocked:
        warnings.append("stage_downgrade_blocked")
    summary = (
        f"已更新案件风险 {effective_case_id}（阶段回退已阻止，保持 {before_case['current_stage']}）"
        if downgraded_blocked
        else f"已更新案件风险 {effective_case_id}"
    )
    response = ToolResponse(
        ok=True,
        summary=summary,
        data={"case": updated_case},
        refs={"case_ids": [effective_case_id]},
        warnings=warnings,
    )
    return response.model_dump(mode="json", by_alias=True)
