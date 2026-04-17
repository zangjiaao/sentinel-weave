from __future__ import annotations

import sqlite3

from security_analyst_agent.repositories.actors import (
    add_case_actor_link,
    add_case_actor_observation,
    list_case_actor_profiles,
    load_case_actor_candidate_contexts,
    load_case_actor_profile,
    upsert_case_actor_profile,
)
from security_analyst_agent.repositories.cases import load_alert, load_case, resolve_canonical_case_id
from security_analyst_agent.schemas.actor_tools import (
    ActorCaseAddObservationRequest,
    ActorCaseAddObservationBatchRequest,
    ActorCaseFindCandidatesRequest,
    ActorCaseGetRequest,
    ActorCaseLinkRequest,
    ActorCaseLinkBatchRequest,
    ActorCaseListRequest,
    ActorCaseUpsertRequest,
)
from security_analyst_agent.schemas.common import ToolResponse
from security_analyst_agent.services.case_actor_scoring import score_case_actor_candidate


def actor_case_list(conn: sqlite3.Connection, payload: dict) -> dict:
    request = ActorCaseListRequest.model_validate(payload)
    actors = list_case_actor_profiles(conn, request.case_id)
    response = ToolResponse(
        ok=True,
        summary=f"返回案件 {request.case_id} 的案内画像 {len(actors)} 个",
        data={"actors": actors},
        refs={"case_ids": [request.case_id], "case_actor_ids": [item["case_actor_id"] for item in actors]},
    )
    return response.model_dump(mode="json", by_alias=True)


def actor_case_get(conn: sqlite3.Connection, payload: dict) -> dict:
    request = ActorCaseGetRequest.model_validate(payload)
    actor = load_case_actor_profile(conn, request.case_actor_id)
    if actor is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到案内画像 {request.case_actor_id}",
            data={"actor": None},
            warnings=[f"case_actor_not_found:{request.case_actor_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)
    response = ToolResponse(
        ok=True,
        summary=f"读取案内画像 {request.case_actor_id}",
        data={"actor": actor},
        refs={"case_actor_ids": [request.case_actor_id], "case_ids": [actor["case_id"]]},
    )
    return response.model_dump(mode="json", by_alias=True)


def actor_case_find_candidates(conn: sqlite3.Connection, payload: dict) -> dict:
    request = ActorCaseFindCandidatesRequest.model_validate(payload)
    warnings: list[str] = []
    alert = load_alert(conn, request.alert_id)
    raw_case_id = str(request.case_id or "")
    effective_case_id = raw_case_id.strip()
    if not effective_case_id and alert is not None and alert.get("case_id"):
        effective_case_id = resolve_canonical_case_id(conn, alert["case_id"])
        warnings.append("case_id_inferred_from_alert")
    elif effective_case_id:
        effective_case_id = resolve_canonical_case_id(conn, effective_case_id)

    if alert is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到告警 {request.alert_id}",
            data={"candidates": []},
            warnings=[f"alert_not_found:{request.alert_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)

    case = load_case(conn, effective_case_id) if effective_case_id else None
    if not effective_case_id:
        response = ToolResponse(
            ok=True,
            summary="告警未关联案件，暂无案内画像候选",
            data={"case": None, "alert": alert, "candidates": []},
            refs={"alert_ids": [request.alert_id]},
            warnings=["case_id_missing_for_candidate_lookup"],
        )
        return response.model_dump(mode="json", by_alias=True)
    if case is None:
        case_id_for_warning = request.case_id or effective_case_id or ""
        response = ToolResponse(
            ok=False,
            summary=f"未找到案件 {case_id_for_warning}",
            data={"candidates": []},
            warnings=[f"case_not_found:{case_id_for_warning}"],
        )
        return response.model_dump(mode="json", by_alias=True)
    contexts = load_case_actor_candidate_contexts(conn, case_id=effective_case_id, alert_id=request.alert_id)
    candidates = sorted(
        [score_case_actor_candidate(context) for context in contexts],
        key=lambda item: item["relation_score"],
        reverse=True,
    )[: request.limit]
    response = ToolResponse(
        ok=True,
        summary=f"返回案内画像候选 {len(candidates)} 个",
        data={"case": case, "alert": alert, "candidates": candidates},
        refs={
            "case_ids": [effective_case_id],
            "alert_ids": [request.alert_id],
            "case_actor_ids": [item["case_actor_id"] for item in candidates],
        },
        warnings=warnings,
    )
    return response.model_dump(mode="json", by_alias=True)


def actor_case_upsert(conn: sqlite3.Connection, payload: dict) -> dict:
    request = ActorCaseUpsertRequest.model_validate(payload)
    case = load_case(conn, request.case_id)
    if case is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到案件 {request.case_id}",
            data={"actor": None},
            warnings=[f"case_not_found:{request.case_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)
    actor = upsert_case_actor_profile(conn, request.model_dump(mode="python"))
    conn.commit()
    response = ToolResponse(
        ok=True,
        summary=f"已写入案内画像 {request.case_actor_id}",
        data={"actor": actor},
        refs={"case_ids": [request.case_id], "case_actor_ids": [request.case_actor_id]},
    )
    return response.model_dump(mode="json", by_alias=True)


def actor_case_add_observation(conn: sqlite3.Connection, payload: dict) -> dict:
    request = ActorCaseAddObservationRequest.model_validate(payload)
    actor = load_case_actor_profile(conn, request.case_actor_id)
    if actor is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到案内画像 {request.case_actor_id}",
            data={"observation": None},
            warnings=[f"case_actor_not_found:{request.case_actor_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)
    observation = add_case_actor_observation(conn, request.model_dump(mode="python"))
    conn.commit()
    response = ToolResponse(
        ok=True,
        summary=f"已写入案内画像观测 {request.observation_type}:{request.observation_key}",
        data={"observation": observation},
        refs={"case_actor_ids": [request.case_actor_id]},
    )
    return response.model_dump(mode="json", by_alias=True)


def actor_case_add_observation_batch(conn: sqlite3.Connection, payload: dict) -> dict:
    request = ActorCaseAddObservationBatchRequest.model_validate(payload)
    observations: list[dict] = []
    failures: list[dict] = []
    warnings: list[str] = []
    refs_case_actor_ids: list[str] = []

    for index, item in enumerate(request.items):
        result = actor_case_add_observation(conn, item.model_dump(mode="python"))
        if result.get("ok"):
            observation = result.get("data", {}).get("observation")
            if isinstance(observation, dict):
                observations.append(observation)
            refs_case_actor_ids.extend(result.get("refs", {}).get("case_actor_ids", []))
            continue

        failures.append(
            {
                "index": index,
                "item": item.model_dump(mode="python"),
                "summary": result.get("summary", "actor.case-add-observation failed"),
                "warnings": result.get("warnings", []),
            }
        )
        warnings.extend(result.get("warnings", []))

    response = ToolResponse(
        ok=len(failures) == 0,
        summary=f"批量写入案内画像观测：成功 {len(observations)} 条，失败 {len(failures)} 条",
        data={"observations": observations, "failures": failures},
        refs={"case_actor_ids": list(dict.fromkeys(refs_case_actor_ids))},
        warnings=list(dict.fromkeys(warnings)),
    )
    return response.model_dump(mode="json", by_alias=True)


def actor_case_link(conn: sqlite3.Connection, payload: dict) -> dict:
    request = ActorCaseLinkRequest.model_validate(payload)
    actor = load_case_actor_profile(conn, request.case_actor_id)
    if actor is None:
        response = ToolResponse(
            ok=False,
            summary=f"未找到案内画像 {request.case_actor_id}",
            data={"link": None},
            warnings=[f"case_actor_not_found:{request.case_actor_id}"],
        )
        return response.model_dump(mode="json", by_alias=True)
    link = add_case_actor_link(conn, request.model_dump(mode="python"))
    conn.commit()
    response = ToolResponse(
        ok=True,
        summary=f"已关联案内画像 {request.case_actor_id} 到 {request.target_type}:{request.target_id}",
        data={"link": link},
        refs={"case_actor_ids": [request.case_actor_id], f"{request.target_type}_ids": [request.target_id]},
    )
    return response.model_dump(mode="json", by_alias=True)


def actor_case_link_batch(conn: sqlite3.Connection, payload: dict) -> dict:
    request = ActorCaseLinkBatchRequest.model_validate(payload)
    links: list[dict] = []
    failures: list[dict] = []
    warnings: list[str] = []
    refs_case_actor_ids: list[str] = []
    refs_target_ids: list[str] = []

    for index, item in enumerate(request.items):
        result = actor_case_link(conn, item.model_dump(mode="python"))
        if result.get("ok"):
            link = result.get("data", {}).get("link")
            if isinstance(link, dict):
                links.append(link)
            refs = result.get("refs", {})
            refs_case_actor_ids.extend(refs.get("case_actor_ids", []))
            refs_target_ids.append(item.target_id)
            continue

        failures.append(
            {
                "index": index,
                "item": item.model_dump(mode="python"),
                "summary": result.get("summary", "actor.case-link failed"),
                "warnings": result.get("warnings", []),
            }
        )
        warnings.extend(result.get("warnings", []))

    response = ToolResponse(
        ok=len(failures) == 0,
        summary=f"批量关联案内画像：成功 {len(links)} 条，失败 {len(failures)} 条",
        data={"links": links, "failures": failures},
        refs={
            "case_actor_ids": list(dict.fromkeys(refs_case_actor_ids)),
            "target_ids": list(dict.fromkeys(refs_target_ids)),
        },
        warnings=list(dict.fromkeys(warnings)),
    )
    return response.model_dump(mode="json", by_alias=True)
