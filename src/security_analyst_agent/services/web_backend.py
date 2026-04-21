from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from security_analyst_agent.db import connect_db, create_schema
from security_analyst_agent.patrol_trigger import trigger_patrol_from_ingest
from security_analyst_agent.raw_mapping import (
    apply_import_job_mapping,
    import_csv_alert_file,
    list_import_job_problem_rows,
    list_import_jobs,
    sample_import_job,
    upsert_alert_normalization_maps,
)
from security_analyst_agent.repositories.actors import list_case_actor_profiles
from security_analyst_agent.repositories.assets import search_assets
from security_analyst_agent.repositories.cases import (
    list_cases,
    load_case,
    load_case_timeline,
    load_evidence_by_ids,
    resolve_canonical_case_id,
)
from security_analyst_agent.services.output import build_notify_preview, build_report


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_load(payload: str | None, default: Any) -> Any:
    if not payload:
        return default
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return default


def _to_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def _pick_first_existing_column(field_names: list[str], candidates: list[str]) -> str | None:
    if not field_names:
        return None
    normalized_map = {str(item).strip().lower(): str(item) for item in field_names if str(item).strip()}
    for candidate in candidates:
        key = str(candidate).strip().lower()
        matched = normalized_map.get(key)
        if matched:
            return matched
    return None


def ensure_default_mapping_for_job(*, db_path: Path, job_id: str) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        job_row = conn.execute(
            """
            select source, notes_json
            from import_jobs
            where job_id = ?
            """,
            (job_id,),
        ).fetchone()
        if job_row is None:
            raise ValueError(f"import job not found: {job_id}")

        source = str(job_row["source"])
        notes = _json_load(job_row["notes_json"], {})
        field_names = notes.get("field_names") if isinstance(notes, dict) else None
        parsed_field_names = [str(item) for item in field_names] if isinstance(field_names, list) else []

        if not parsed_field_names:
            sample_row = conn.execute(
                """
                select payload_json
                from raw_alert_events
                where source = ?
                order by ingested_at asc, raw_event_id asc
                limit 1
                """,
                (source,),
            ).fetchone()
            if sample_row is not None:
                payload = _json_load(sample_row["payload_json"], {})
                row_obj = payload.get("row") if isinstance(payload, dict) else None
                if isinstance(row_obj, dict):
                    parsed_field_names = [str(key) for key in row_obj.keys()]

        occurred_at_column = _pick_first_existing_column(
            parsed_field_names,
            ["occurred_at", "event_time", "timestamp", "攻击时间", "时间", "发生时间"],
        )
        src_ip_column = _pick_first_existing_column(
            parsed_field_names,
            ["src_ip", "src", "source_ip", "攻击IP", "源IP", "remote_addr"],
        )
        dst_ip_column = _pick_first_existing_column(
            parsed_field_names,
            ["dst_ip", "dst", "destination_ip", "目标IP", "目的IP", "target_ip", "host"],
        )
        title_column = _pick_first_existing_column(
            parsed_field_names,
            ["title", "alert_title", "告警标题", "攻击类型", "威胁情报", "蜜罐名称"],
        )
        severity_column = _pick_first_existing_column(
            parsed_field_names,
            ["severity", "risk_level", "level", "风险等级", "告警等级", "级别", "威胁情报"],
        )
        attack_stage_column = _pick_first_existing_column(
            parsed_field_names,
            ["attack_stage", "stage", "攻击阶段", "威胁情报"],
        )

        field_map: dict[str, str] = {}
        if occurred_at_column:
            field_map["occurred_at"] = f"payload.row.{occurred_at_column}"
        if src_ip_column:
            field_map["src_ip"] = f"payload.row.{src_ip_column}"
        if dst_ip_column:
            field_map["dst_ip"] = f"payload.row.{dst_ip_column}"
        if title_column:
            field_map["title"] = f"payload.row.{title_column}"
        if severity_column:
            field_map["severity"] = f"payload.row.{severity_column}"
        if attack_stage_column:
            field_map["attack_stage"] = f"payload.row.{attack_stage_column}"

        auto_map_id = f"map_auto_{job_id}"
        mapping_payload: dict[str, Any] = {
            "field_map": field_map,
            "defaults": {
                "title": "imported csv alert",
                "status": "new",
                "severity": "medium",
                "attack_stage": "recon",
            },
            "value_maps": {
                "severity": {
                    "严重": "critical",
                    "高": "high",
                    "中": "medium",
                    "低": "low",
                    "漏洞利用": "high",
                    "webshell": "critical",
                    "命令执行": "critical",
                    "cve": "high",
                    "critical": "critical",
                    "high": "high",
                    "medium": "medium",
                    "low": "low",
                },
                "attack_stage": {
                    "扫描": "recon",
                    "探测": "recon",
                    "漏洞利用": "exploit",
                    "webshell": "persistence",
                    "cve": "exploit",
                    "横向移动": "lateral_prep",
                    "命令执行": "command_execution",
                    "持久化": "persistence",
                    "recon": "recon",
                    "exploit": "exploit",
                    "persistence": "persistence",
                    "command_execution": "command_execution",
                    "lateral_prep": "lateral_prep",
                },
            },
            "confidence": 0.55,
            "reason": "auto_generated_upload_map",
            "title_template": "{蜜罐名称} {威胁情报}",
        }
    finally:
        conn.close()

    upsert_alert_normalization_maps(
        db_path=db_path,
        maps=[
            {
                "map_id": auto_map_id,
                "priority": 30,
                "enabled": True,
                "match": {"source": source},
                "mapping": mapping_payload,
            }
        ],
    )
    return {
            "map_id": auto_map_id,
            "source": source,
            "field_map_keys": sorted(field_map.keys()),
            "field_names": parsed_field_names,
    }


def _is_high_signal_severity(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"high", "critical"}


def _normalize_stage(value: str | None) -> str:
    stage = str(value or "").strip().lower()
    if stage == "reconnaissance":
        return "recon"
    return stage or "unknown"


def _build_case_attack_alert_rows(conn: Any, *, case_id: str, limit: int = 500) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        select
          alerts.alert_id,
          alerts.occurred_at,
          alerts.title,
          lower(alerts.attack_stage) as attack_stage,
          lower(alerts.severity) as severity,
          coalesce(alerts.src_ip, '') as src_ip,
          coalesce(alerts.asset_id, '') as asset_id,
          coalesce(alerts.dst_ip, '') as dst_ip,
          case_alert_links.confidence as link_confidence
        from case_alert_links
        join alerts on alerts.alert_id = case_alert_links.alert_id
        where case_alert_links.case_id = ?
          and case_alert_links.is_active = 1
        order by alerts.occurred_at desc, case_alert_links.linked_at desc, alerts.alert_id asc
        limit ?
        """,
        (case_id, max(1, limit)),
    ).fetchall()
    items: list[dict[str, Any]] = []
    for row in rows:
        asset_id = str(row["asset_id"] or "").strip() or None
        dst_ip = str(row["dst_ip"] or "").strip() or None
        target = asset_id or dst_ip or "unknown_target"
        items.append(
            {
                "alert_id": row["alert_id"],
                "occurred_at": row["occurred_at"],
                "src_ip": str(row["src_ip"] or "").strip() or "unknown_attacker",
                "attack_type": _normalize_stage(row["attack_stage"]),
                "attack_description": str(row["title"] or ""),
                "severity": str(row["severity"] or "").strip().lower() or "unknown",
                "asset_id": asset_id,
                "dst_ip": dst_ip,
                "target": target,
                "link_confidence": float(row["link_confidence"] or 0.0),
            }
        )
    return items


def _build_attacker_target_map(attack_alert_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_attacker: dict[str, dict[str, Any]] = {}
    for row in attack_alert_rows:
        attacker_key = row["src_ip"]
        bucket = by_attacker.setdefault(
            attacker_key,
            {
                "attacker": attacker_key,
                "alert_count": 0,
                "high_signal_count": 0,
                "first_seen_at": None,
                "last_seen_at": None,
                "stages": set(),
                "targets": {},
            },
        )
        occurred_at = row.get("occurred_at")
        bucket["alert_count"] += 1
        if _is_high_signal_severity(row.get("severity")):
            bucket["high_signal_count"] += 1
        bucket["stages"].add(_normalize_stage(row.get("attack_type")))
        if occurred_at:
            if bucket["first_seen_at"] is None or str(occurred_at) < str(bucket["first_seen_at"]):
                bucket["first_seen_at"] = occurred_at
            if bucket["last_seen_at"] is None or str(occurred_at) > str(bucket["last_seen_at"]):
                bucket["last_seen_at"] = occurred_at
        target_key = f"{row.get('asset_id') or ''}|{row.get('dst_ip') or ''}"
        target_bucket = bucket["targets"].setdefault(
            target_key,
            {
                "asset_id": row.get("asset_id"),
                "dst_ip": row.get("dst_ip"),
                "target": row.get("target"),
                "alert_count": 0,
                "high_signal_count": 0,
            },
        )
        target_bucket["alert_count"] += 1
        if _is_high_signal_severity(row.get("severity")):
            target_bucket["high_signal_count"] += 1

    result: list[dict[str, Any]] = []
    for bucket in by_attacker.values():
        targets = list(bucket["targets"].values())
        targets.sort(
            key=lambda item: (
                int(item.get("high_signal_count") or 0),
                int(item.get("alert_count") or 0),
                str(item.get("target") or ""),
            ),
            reverse=True,
        )
        result.append(
            {
                "attacker": bucket["attacker"],
                "alert_count": int(bucket["alert_count"]),
                "high_signal_count": int(bucket["high_signal_count"]),
                "stage_count": len(bucket["stages"]),
                "stages": sorted(bucket["stages"]),
                "first_seen_at": bucket["first_seen_at"],
                "last_seen_at": bucket["last_seen_at"],
                "targets": targets,
            }
        )

    result.sort(
        key=lambda item: (
            int(item.get("high_signal_count") or 0),
            int(item.get("alert_count") or 0),
            str(item.get("last_seen_at") or ""),
            str(item.get("attacker") or ""),
        ),
        reverse=True,
    )
    return result


def _build_attack_behavior_analysis(
    *,
    attack_alert_rows: list[dict[str, Any]],
    attacker_target_map: list[dict[str, Any]],
) -> dict[str, Any]:
    if not attack_alert_rows:
        return {
            "summary": "当前案件暂无可用于行为分析的告警记录。",
            "highlights": [],
            "stage_progression": [],
        }

    total_alerts = len(attack_alert_rows)
    attackers = {str(item.get("src_ip") or "") for item in attack_alert_rows if item.get("src_ip")}
    targets = {str(item.get("target") or "") for item in attack_alert_rows if item.get("target")}
    stage_stats: dict[str, dict[str, Any]] = {}
    for row in attack_alert_rows:
        stage = _normalize_stage(row.get("attack_type"))
        stat = stage_stats.setdefault(
            stage,
            {"stage": stage, "alert_count": 0, "first_seen_at": None, "last_seen_at": None},
        )
        stat["alert_count"] += 1
        occurred_at = row.get("occurred_at")
        if occurred_at:
            if stat["first_seen_at"] is None or str(occurred_at) < str(stat["first_seen_at"]):
                stat["first_seen_at"] = occurred_at
            if stat["last_seen_at"] is None or str(occurred_at) > str(stat["last_seen_at"]):
                stat["last_seen_at"] = occurred_at
    stage_order = {
        "recon": 1,
        "exploit": 2,
        "persistence": 3,
        "command_execution": 4,
        "lateral_prep": 5,
        "reactivation": 6,
        "unknown": 99,
    }
    stage_progression = sorted(
        stage_stats.values(),
        key=lambda item: (
            stage_order.get(str(item.get("stage")), 99),
            str(item.get("first_seen_at") or ""),
        ),
    )

    top_attacker = attacker_target_map[0] if attacker_target_map else None
    high_signal_total = len([item for item in attack_alert_rows if _is_high_signal_severity(item.get("severity"))])
    highlights = [
        f"共关联 {total_alerts} 条攻击告警，涉及 {len(attackers)} 个攻击源与 {len(targets)} 个目标系统。",
        f"高危信号（high/critical）共 {high_signal_total} 条。",
    ]
    if top_attacker:
        highlights.append(
            f"最活跃攻击源 {top_attacker['attacker']}，关联 {top_attacker['alert_count']} 条告警，目标系统 {len(top_attacker['targets'])} 个。"
        )

    return {
        "summary": "；".join(highlights),
        "highlights": highlights,
        "stage_progression": stage_progression,
    }


def import_csv_job(
    *,
    db_path: Path,
    csv_path: Path,
    file_name: str | None = None,
    vendor: str | None = None,
    product: str | None = None,
    log_type: str | None = None,
    occurred_at_column: str | None = None,
    rule_id_column: str | None = None,
    job_id: str | None = None,
) -> dict[str, Any]:
    return import_csv_alert_file(
        db_path=db_path,
        csv_path=csv_path,
        file_name=file_name,
        vendor=vendor,
        product=product,
        log_type=log_type,
        occurred_at_column=occurred_at_column,
        rule_id_column=rule_id_column,
        job_id=job_id,
    )


def upsert_mapping_rules(*, db_path: Path, maps: list[dict[str, Any]]) -> dict[str, Any]:
    return upsert_alert_normalization_maps(db_path=db_path, maps=maps)


def list_jobs(*, db_path: Path, limit: int = 20, statuses: list[str] | None = None) -> dict[str, Any]:
    return list_import_jobs(db_path=db_path, limit=limit, statuses=statuses)


def sample_job(
    *,
    db_path: Path,
    job_id: str,
    limit_groups: int = 20,
    samples_per_group: int = 3,
    statuses: list[str] | None = None,
) -> dict[str, Any]:
    return sample_import_job(
        db_path=db_path,
        job_id=job_id,
        limit_groups=limit_groups,
        samples_per_group=samples_per_group,
        statuses=statuses,
    )


def preview_job_apply(
    *,
    db_path: Path,
    job_id: str,
    limit: int = 500,
    include_unmapped: bool = False,
    raw_event_ids: list[str] | None = None,
) -> dict[str, Any]:
    return apply_import_job_mapping(
        db_path=db_path,
        job_id=job_id,
        limit=limit,
        dry_run=True,
        include_unmapped=include_unmapped,
        raw_event_ids=raw_event_ids,
    )


def apply_job(
    *,
    db_path: Path,
    job_id: str,
    limit: int = 500,
    include_unmapped: bool = False,
    raw_event_ids: list[str] | None = None,
) -> dict[str, Any]:
    return apply_import_job_mapping(
        db_path=db_path,
        job_id=job_id,
        limit=limit,
        dry_run=False,
        include_unmapped=include_unmapped,
        raw_event_ids=raw_event_ids,
    )


def apply_job_with_trigger(
    *,
    db_path: Path,
    job_id: str,
    limit: int = 500,
    include_unmapped: bool = False,
    raw_event_ids: list[str] | None = None,
    trigger_after_apply: bool = True,
    trigger_dry_run: bool = False,
) -> dict[str, Any]:
    apply_result = apply_job(
        db_path=db_path,
        job_id=job_id,
        limit=limit,
        include_unmapped=include_unmapped,
        raw_event_ids=raw_event_ids,
    )
    trigger_result: dict[str, Any] | None = None
    if trigger_after_apply:
        trigger_result = trigger_patrol(
            db_path=db_path,
            job_id=job_id,
            dry_run=trigger_dry_run,
        )
    return {
        **apply_result,
        "trigger_result": trigger_result,
    }


def list_job_problem_rows(*, db_path: Path, job_id: str, limit: int = 100) -> dict[str, Any]:
    return list_import_job_problem_rows(db_path=db_path, job_id=job_id, limit=limit)


def _job_source_key(job_id: str) -> str:
    normalized_job_id = _to_str(job_id)
    if normalized_job_id is None:
        raise ValueError("job_id is required")
    return f"import_job:{normalized_job_id}"


def _resolve_job_pending_event_ids(conn: Any, *, job_id: str) -> list[str]:
    source = _job_source_key(job_id)
    rows = conn.execute(
        """
        select distinct e.event_id
        from alert_ingest_events e
        join raw_alert_events r on r.normalized_alert_id = e.alert_id
        where r.source = ?
          and e.trigger_state in ('pending', 'failed')
        order by e.ingested_at asc, e.rowid asc
        """,
        (source,),
    ).fetchall()
    return [str(row["event_id"]) for row in rows]


def trigger_patrol(*, db_path: Path, job_id: str, dry_run: bool = False) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        event_ids = _resolve_job_pending_event_ids(conn, job_id=job_id)
    finally:
        conn.close()
    return trigger_patrol_from_ingest(
        db_path=db_path,
        job_id=job_id,
        dry_run=dry_run,
        trigger_mode="openai",
        event_ids=event_ids,
    )


def get_job_analysis_status(*, db_path: Path, job_id: str) -> dict[str, Any]:
    source = _job_source_key(job_id)
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        _ = conn.execute(
            """
            select job_id
            from import_jobs
            where job_id = ?
            limit 1
            """,
            (job_id,),
        ).fetchone()
        if _ is None:
            raise ValueError(f"import job not found: {job_id}")

        state_rows = conn.execute(
            """
            select e.trigger_state, count(*) as event_count
            from alert_ingest_events e
            join raw_alert_events r on r.normalized_alert_id = e.alert_id
            where r.source = ?
            group by e.trigger_state
            """,
            (source,),
        ).fetchall()
        event_state_counts = {str(row["trigger_state"]): int(row["event_count"]) for row in state_rows}

        run_rows = conn.execute(
            """
            select distinct e.processed_run_id, max(e.processed_at) as latest_processed_at
            from alert_ingest_events e
            join raw_alert_events r on r.normalized_alert_id = e.alert_id
            where r.source = ?
              and e.processed_run_id is not null
            group by e.processed_run_id
            order by latest_processed_at desc, e.processed_run_id desc
            """,
            (source,),
        ).fetchall()
        run_ids = [str(row["processed_run_id"]) for row in run_rows if row["processed_run_id"]]

        run: dict[str, Any] | None = None
        cost: dict[str, Any] | None = None
        steps: list[dict[str, Any]] = []
        if run_ids:
            placeholders = ", ".join("?" for _ in run_ids)
            run_row = conn.execute(
                f"""
                select run_id, trigger_source, status, summary, started_at, finished_at
                from patrol_runs
                where run_id in ({placeholders})
                order by started_at desc, run_id desc
                limit 1
                """,
                tuple(run_ids),
            ).fetchone()
            if run_row is not None:
                active_run_id = str(run_row["run_id"])
                run = dict(run_row)
                cost_row = conn.execute(
                    """
                    select
                      run_id,
                      trigger_source,
                      trigger_mode,
                      model,
                      status,
                      started_at,
                      finished_at,
                      duration_ms,
                      turns,
                      tool_calls,
                      usage_input_tokens,
                      usage_output_tokens,
                      usage_cached_input_tokens,
                      usage_total_tokens,
                      recorded_at
                    from patrol_run_costs
                    where run_id = ?
                    limit 1
                    """,
                    (active_run_id,),
                ).fetchone()
                if cost_row is not None:
                    cost = dict(cost_row)
                step_rows = conn.execute(
                    """
                    select tool_name, count(*) as call_count
                    from agent_tool_calls
                    where run_id = ?
                    group by tool_name
                    order by call_count desc, tool_name asc
                    """,
                    (active_run_id,),
                ).fetchall()
                steps = [
                    {
                        "tool_name": str(row["tool_name"]),
                        "call_count": int(row["call_count"]),
                    }
                    for row in step_rows
                ]

        return {
            "job_id": job_id,
            "source": source,
            "event_state_counts": event_state_counts,
            "run": run,
            "cost": cost,
            "steps": steps,
        }
    finally:
        conn.close()


def apply_job_until_stable(
    *,
    db_path: Path,
    job_id: str,
    limit: int = 500,
    include_unmapped: bool = True,
    max_passes: int = 20,
) -> dict[str, Any]:
    last_result: dict[str, Any] = apply_job(
        db_path=db_path,
        job_id=job_id,
        limit=limit,
        include_unmapped=include_unmapped,
    )
    last_signature = (
        int(last_result["job"]["mapped_rows"]),
        int(last_result["job"]["unmapped_rows"]),
        int(last_result["job"]["pending_rows"]),
        int(last_result["job"]["error_rows"]),
    )
    if int(last_result["job"]["pending_rows"]) == 0:
        return last_result

    for _ in range(max(1, max_passes) - 1):
        current = apply_job(
            db_path=db_path,
            job_id=job_id,
            limit=limit,
            include_unmapped=include_unmapped,
        )
        signature = (
            int(current["job"]["mapped_rows"]),
            int(current["job"]["unmapped_rows"]),
            int(current["job"]["pending_rows"]),
            int(current["job"]["error_rows"]),
        )
        last_result = current
        if int(current["job"]["pending_rows"]) == 0:
            break
        if signature == last_signature:
            break
        last_signature = signature
    return last_result


def latest_patrol_summary(*, db_path: Path) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        run = conn.execute(
            """
            select run_id, trigger_source, status, summary, started_at, finished_at
            from patrol_runs
            order by started_at desc
            limit 1
            """
        ).fetchone()
        if run is None:
            return {"run": None}

        tool_calls = conn.execute(
            """
            select tool_name, count(*) as call_count
            from agent_tool_calls
            where run_id = ?
            group by tool_name
            order by call_count desc, tool_name asc
            """,
            (run["run_id"],),
        ).fetchall()
        cases = conn.execute(
            """
            select case_id, status, overall_severity, current_stage
            from cases
            order by case_id asc
            """
        ).fetchall()
        return {
            "run": dict(run),
            "tool_calls": [dict(item) for item in tool_calls],
            "cases": [dict(item) for item in cases],
        }
    finally:
        conn.close()


def get_job(*, db_path: Path, job_id: str) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        row = conn.execute(
            """
            select
              job_id,
              source,
              file_name,
              file_hash,
              status,
              total_rows,
              mapped_rows,
              unmapped_rows,
              pending_rows,
              error_rows,
              last_map_id,
              created_at,
              updated_at,
              notes_json
            from import_jobs
            where job_id = ?
            """,
            (job_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"import job not found: {job_id}")
        return {
            "job": {
                "job_id": row["job_id"],
                "source": row["source"],
                "file_name": row["file_name"],
                "file_hash": row["file_hash"],
                "status": row["status"],
                "total_rows": int(row["total_rows"]),
                "mapped_rows": int(row["mapped_rows"]),
                "unmapped_rows": int(row["unmapped_rows"]),
                "pending_rows": int(row["pending_rows"]),
                "error_rows": int(row["error_rows"]),
                "last_map_id": row["last_map_id"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "notes": _json_load(row["notes_json"], {}),
            }
        }
    finally:
        conn.close()


def list_sources(
    *,
    db_path: Path,
    limit: int = 50,
    statuses: list[str] | None = None,
    source_modes: list[str] | None = None,
) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        where_clauses: list[str] = []
        params: list[Any] = []
        if statuses:
            normalized = [item.strip().lower() for item in statuses if item.strip()]
            if normalized:
                where_clauses.append(f"lower(status) in ({', '.join('?' for _ in normalized)})")
                params.extend(normalized)
        if source_modes:
            normalized = [item.strip().lower() for item in source_modes if item.strip()]
            if normalized:
                where_clauses.append(f"lower(source_mode) in ({', '.join('?' for _ in normalized)})")
                params.extend(normalized)
        where_sql = f"where {' and '.join(where_clauses)}" if where_clauses else ""
        rows = conn.execute(
            f"""
            select
              source_id,
              source_name,
              source_mode,
              device_type,
              vendor,
              product,
              enabled,
              schedule,
              status,
              parser_profile_id,
              created_at,
              updated_at
            from data_sources
            {where_sql}
            order by updated_at desc, source_id asc
            limit ?
            """,
            (*params, max(1, limit)),
        ).fetchall()
        return {"items": [{**dict(row), "enabled": bool(row["enabled"])} for row in rows]}
    finally:
        conn.close()


def list_source_runs(
    *,
    db_path: Path,
    source_id: str,
    limit: int = 100,
    statuses: list[str] | None = None,
) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        where_clauses = ["source_id = ?"]
        params: list[Any] = [source_id]
        if statuses:
            normalized = [item.strip().lower() for item in statuses if item.strip()]
            if normalized:
                where_clauses.append(f"lower(status) in ({', '.join('?' for _ in normalized)})")
                params.extend(normalized)
        where_sql = " and ".join(where_clauses)
        rows = conn.execute(
            f"""
            select
              source_run_id,
              source_id,
              trigger_type,
              status,
              started_at,
              ended_at,
              raw_event_count,
              normalized_count,
              failed_count,
              parser_profile_version_id,
              result_summary,
              error_summary
            from source_runs
            where {where_sql}
            order by started_at desc, source_run_id asc
            limit ?
            """,
            (*params, max(1, limit)),
        ).fetchall()
        return {"items": [dict(row) for row in rows]}
    finally:
        conn.close()


def list_parsers(*, db_path: Path, limit: int = 50, statuses: list[str] | None = None) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        where_clauses: list[str] = []
        params: list[Any] = []
        if statuses:
            normalized = [item.strip().lower() for item in statuses if item.strip()]
            if normalized:
                where_clauses.append(f"lower(status) in ({', '.join('?' for _ in normalized)})")
                params.extend(normalized)
        where_sql = f"where {' and '.join(where_clauses)}" if where_clauses else ""
        rows = conn.execute(
            f"""
            select
              parser_profile_id,
              profile_name,
              device_type,
              vendor,
              product,
              input_format,
              status,
              created_at,
              updated_at
            from parser_profiles
            {where_sql}
            order by updated_at desc, parser_profile_id asc
            limit ?
            """,
            (*params, max(1, limit)),
        ).fetchall()
        return {"items": [dict(row) for row in rows]}
    finally:
        conn.close()


def list_parser_versions(*, db_path: Path, parser_profile_id: str, limit: int = 50) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        rows = conn.execute(
            """
            select
              parser_profile_version_id,
              parser_profile_id,
              version_no,
              field_mapping_json,
              normalization_rules_json,
              validation_status,
              status,
              change_summary,
              created_at,
              effective_from
            from parser_profile_versions
            where parser_profile_id = ?
            order by version_no desc, created_at desc
            limit ?
            """,
            (parser_profile_id, max(1, limit)),
        ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["field_mapping"] = _json_load(item.pop("field_mapping_json"), {})
            item["normalization_rules"] = _json_load(item.pop("normalization_rules_json"), {})
            items.append(item)
        return {"items": items}
    finally:
        conn.close()


def list_cases_overview(
    *,
    db_path: Path,
    limit: int = 50,
    statuses: list[str] | None = None,
    min_severity: str | None = None,
    current_stage: str | None = None,
    include_merged: bool = True,
    keyword: str | None = None,
) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        items = list_cases(
            conn,
            statuses=statuses or [],
            min_severity=min_severity,
            current_stage=current_stage,
            include_merged=include_merged,
            keyword=keyword,
            limit=max(1, limit),
            analysis_cutoff_at=None,
        )
        return {"items": items}
    finally:
        conn.close()


def get_case_detail(*, db_path: Path, case_id: str) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        effective_case_id = resolve_canonical_case_id(conn, case_id)
        case = load_case(conn, effective_case_id)
        if case is None:
            raise ValueError(f"case not found: {case_id}")
        timeline = load_case_timeline(conn, effective_case_id, analysis_cutoff_at=None)
        actors = list_case_actor_profiles(conn, effective_case_id)
        assessments = conn.execute(
            """
            select
              assessment_id,
              occurred_at,
              run_id,
              case_id,
              risk_level,
              assessment_confidence,
              current_stage,
              verdict,
              reason_summary,
              supporting_alert_ids_json,
              supporting_evidence_ids_json,
              analysis_cutoff_at
            from case_assessments
            where case_id = ?
            order by occurred_at desc
            limit 20
            """,
            (effective_case_id,),
        ).fetchall()
        link_decisions = conn.execute(
            """
            select
              link_decisions.decision_id,
              link_decisions.occurred_at,
              link_decisions.run_id,
              link_decisions.alert_id,
              link_decisions.case_id,
              link_decisions.link_confidence,
              link_decisions.reason_summary,
              link_decisions.positive_factors_json,
              link_decisions.negative_factors_json,
              link_decisions.uncertainties_json,
              link_decisions.supporting_evidence_ids_json,
              link_decisions.analysis_cutoff_at,
              alerts.attack_stage as alert_stage,
              alerts.title as alert_title,
              alerts.occurred_at as alert_occurred_at
            from link_decisions
            left join alerts on alerts.alert_id = link_decisions.alert_id
            where link_decisions.case_id = ?
            order by link_decisions.occurred_at desc
            limit 50
            """,
            (effective_case_id,),
        ).fetchall()
        target_rows = conn.execute(
            """
            select
              coalesce(alerts.asset_id, '') as asset_id,
              coalesce(alerts.dst_ip, '') as dst_ip,
              count(*) as alert_count,
              sum(case when lower(alerts.severity) in ('high', 'critical') then 1 else 0 end) as high_signal_count,
              count(distinct lower(alerts.attack_stage)) as stage_count,
              max(alerts.occurred_at) as last_seen_at
            from case_alert_links
            join alerts on alerts.alert_id = case_alert_links.alert_id
            where case_alert_links.case_id = ?
              and case_alert_links.is_active = 1
            group by coalesce(alerts.asset_id, ''), coalesce(alerts.dst_ip, '')
            order by high_signal_count desc, alert_count desc, last_seen_at desc
            limit 20
            """,
            (effective_case_id,),
        ).fetchall()
        assessment_items = [
            {
                **dict(item),
                "supporting_alert_ids": _json_load(item["supporting_alert_ids_json"], []),
                "supporting_evidence_ids": _json_load(item["supporting_evidence_ids_json"], []),
            }
            for item in assessments
        ]
        link_explanations = [
            {
                **dict(item),
                "positive_factors": _json_load(item["positive_factors_json"], []),
                "negative_factors": _json_load(item["negative_factors_json"], []),
                "uncertainties": _json_load(item["uncertainties_json"], []),
                "supporting_evidence_ids": _json_load(item["supporting_evidence_ids_json"], []),
            }
            for item in link_decisions
        ]
        attack_alert_timeline = _build_case_attack_alert_rows(conn, case_id=effective_case_id, limit=1000)
        attacker_target_map = _build_attacker_target_map(attack_alert_timeline)
        attack_behavior_analysis = _build_attack_behavior_analysis(
            attack_alert_rows=attack_alert_timeline,
            attacker_target_map=attacker_target_map,
        )
        targets = [
            {
                "asset_id": str(item["asset_id"] or "").strip() or None,
                "dst_ip": str(item["dst_ip"] or "").strip() or None,
                "alert_count": int(item["alert_count"] or 0),
                "high_signal_count": int(item["high_signal_count"] or 0),
                "stage_count": int(item["stage_count"] or 0),
                "last_seen_at": item["last_seen_at"],
            }
            for item in target_rows
            if str(item["asset_id"] or "").strip() or str(item["dst_ip"] or "").strip()
        ]
        confidence_values = [
            float(item["link_confidence"])
            for item in link_explanations
            if item.get("link_confidence") is not None
        ]
        high_confidence_count = len([value for value in confidence_values if value >= 0.8])
        medium_confidence_count = len([value for value in confidence_values if 0.6 <= value < 0.8])
        low_confidence_count = len([value for value in confidence_values if value < 0.6])
        total_uncertainty_count = sum(len(item.get("uncertainties", [])) for item in link_explanations)
        latest_assessment = assessment_items[0] if assessment_items else None
        return {
            "case": case,
            "timeline": timeline,
            "actors": actors,
            "attacker_target_map": attacker_target_map,
            "attack_alert_timeline": attack_alert_timeline,
            "attack_behavior_analysis": attack_behavior_analysis,
            "targets": targets,
            "assessments": assessment_items,
            "link_explanations": link_explanations,
            "agent_judgement": {
                "latest_assessment": latest_assessment,
                "link_confidence_summary": {
                    "total": len(confidence_values),
                    "high_confidence_count": high_confidence_count,
                    "medium_confidence_count": medium_confidence_count,
                    "low_confidence_count": low_confidence_count,
                    "avg_confidence": round(sum(confidence_values) / len(confidence_values), 4)
                    if confidence_values
                    else None,
                },
                "total_uncertainty_count": total_uncertainty_count,
            },
            "canonical_case_id": effective_case_id,
            "requested_case_id": case_id,
        }
    finally:
        conn.close()


def get_case_timeline(*, db_path: Path, case_id: str, include_evidence: bool = False) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        effective_case_id = resolve_canonical_case_id(conn, case_id)
        events = load_case_timeline(conn, effective_case_id, analysis_cutoff_at=None)
        if include_evidence:
            for event in events:
                event["evidence"] = load_evidence_by_ids(conn, event["related_evidence_ids"])
        return {
            "items": events,
            "canonical_case_id": effective_case_id,
            "requested_case_id": case_id,
        }
    finally:
        conn.close()


def get_case_actors(*, db_path: Path, case_id: str) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        effective_case_id = resolve_canonical_case_id(conn, case_id)
        return {
            "items": list_case_actor_profiles(conn, effective_case_id),
            "canonical_case_id": effective_case_id,
            "requested_case_id": case_id,
        }
    finally:
        conn.close()


def list_assets_overview(
    *,
    db_path: Path,
    query: str | None = None,
    indicators: list[str] | None = None,
    include_inactive: bool = True,
    limit: int = 50,
) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        items = search_assets(
            conn,
            query=query,
            indicators=indicators or [],
            include_inactive=include_inactive,
            limit=max(1, limit),
        )
        return {"items": items}
    finally:
        conn.close()


def _list_asset_case_rows(conn: Any, asset_id: str, limit: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        select
          cases.case_id,
          cases.title,
          cases.status,
          cases.overall_severity,
          cases.current_stage,
          max(alerts.occurred_at) as last_alert_at,
          count(*) as alert_count
        from alerts
        join case_alert_links
          on case_alert_links.alert_id = alerts.alert_id and case_alert_links.is_active = 1
        join cases
          on cases.case_id = case_alert_links.case_id
        where alerts.asset_id = ?
        group by cases.case_id
        order by last_alert_at desc, cases.case_id asc
        limit ?
        """,
        (asset_id, max(1, limit)),
    ).fetchall()
    return [dict(row) for row in rows]


def get_asset_detail(*, db_path: Path, asset_id: str) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        row = conn.execute(
            """
            select asset_id, asset_name, system_name, owner_team, internet_exposed, public_ip, domain
            from assets
            where asset_id = ?
            """,
            (asset_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"asset not found: {asset_id}")
        identities = conn.execute(
            """
            select identity_id, asset_id, identity_type, identity_value, is_primary, confidence, created_at
            from asset_identities
            where asset_id = ?
            order by is_primary desc, confidence desc, identity_type asc, identity_value asc
            """,
            (asset_id,),
        ).fetchall()
        items = [dict(item) for item in identities]
        if not items:
            if row["public_ip"]:
                items.append(
                    {
                        "identity_id": f"derived_ip_{asset_id}",
                        "asset_id": asset_id,
                        "identity_type": "ip",
                        "identity_value": row["public_ip"],
                        "is_primary": 1,
                        "confidence": 1.0,
                        "created_at": _now_iso(),
                    }
                )
            if row["domain"]:
                items.append(
                    {
                        "identity_id": f"derived_domain_{asset_id}",
                        "asset_id": asset_id,
                        "identity_type": "domain",
                        "identity_value": row["domain"],
                        "is_primary": 1,
                        "confidence": 1.0,
                        "created_at": _now_iso(),
                    }
                )
        return {
            "asset": {**dict(row), "internet_exposed": bool(row["internet_exposed"])},
            "identities": [{**item, "is_primary": bool(item["is_primary"])} for item in items],
            "cases": _list_asset_case_rows(conn, asset_id, 20),
        }
    finally:
        conn.close()


def list_asset_cases(*, db_path: Path, asset_id: str, limit: int = 20) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        return {"items": _list_asset_case_rows(conn, asset_id, limit)}
    finally:
        conn.close()


def list_notifications(
    *,
    db_path: Path,
    limit: int = 50,
    statuses: list[str] | None = None,
    channels: list[str] | None = None,
) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        where_clauses: list[str] = []
        params: list[Any] = []
        if statuses:
            normalized = [item.strip().lower() for item in statuses if item.strip()]
            if normalized:
                where_clauses.append(f"lower(status) in ({', '.join('?' for _ in normalized)})")
                params.extend(normalized)
        if channels:
            normalized = [item.strip().lower() for item in channels if item.strip()]
            if normalized:
                where_clauses.append(f"lower(channel) in ({', '.join('?' for _ in normalized)})")
                params.extend(normalized)
        where_sql = f"where {' and '.join(where_clauses)}" if where_clauses else ""
        rows = conn.execute(
            f"""
            select
              notification_id,
              case_id,
              channel,
              template,
              title,
              body,
              dedupe_key,
              status,
              created_at,
              sent_at
            from notification_outbox
            {where_sql}
            order by created_at desc, notification_id asc
            limit ?
            """,
            (*params, max(1, limit)),
        ).fetchall()
        return {"items": [dict(row) for row in rows]}
    finally:
        conn.close()


def get_notification(*, db_path: Path, notification_id: str) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        row = conn.execute(
            """
            select
              notification_id,
              case_id,
              channel,
              template,
              title,
              body,
              dedupe_key,
              status,
              created_at,
              sent_at
            from notification_outbox
            where notification_id = ?
            """,
            (notification_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"notification not found: {notification_id}")
        return {"notification": dict(row)}
    finally:
        conn.close()


def preview_notification(*, db_path: Path, case_id: str, channel: str = "feishu") -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        case = load_case(conn, case_id)
        if case is None:
            raise ValueError(f"case not found: {case_id}")
        preview = build_notify_preview(case, channel)
        return {"preview": preview, "executed": False}
    finally:
        conn.close()


def list_reports(*, db_path: Path, limit: int = 50, statuses: list[str] | None = None) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        where_clauses: list[str] = []
        params: list[Any] = []
        if statuses:
            normalized = [item.strip().lower() for item in statuses if item.strip()]
            if normalized:
                where_clauses.append(f"lower(status) in ({', '.join('?' for _ in normalized)})")
                params.extend(normalized)
        where_sql = f"where {' and '.join(where_clauses)}" if where_clauses else ""
        rows = conn.execute(
            f"""
            select report_id, case_id, title, content_md, status, created_at, updated_at
            from report_drafts
            {where_sql}
            order by updated_at desc, report_id asc
            limit ?
            """,
            (*params, max(1, limit)),
        ).fetchall()
        return {"items": [dict(item) for item in rows]}
    finally:
        conn.close()


def get_report(*, db_path: Path, report_id: str) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        row = conn.execute(
            """
            select report_id, case_id, title, content_md, status, created_at, updated_at
            from report_drafts
            where report_id = ?
            """,
            (report_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"report not found: {report_id}")
        return {"report": dict(row)}
    finally:
        conn.close()


def preview_report(*, db_path: Path, case_id: str, tone: str = "professional", title: str | None = None) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        case = load_case(conn, case_id)
        if case is None:
            raise ValueError(f"case not found: {case_id}")
        timeline = load_case_timeline(conn, case_id, analysis_cutoff_at=None)
        report_preview = build_report(case, timeline, tone)
        report_id = str(report_preview.get("report_id") or f"report_{uuid4().hex[:12]}")
        report_title = title or str(report_preview.get("title") or case["title"])
        content_md = str(report_preview.get("draft_markdown") or "")
        now = _now_iso()
        conn.execute(
            """
            insert into report_drafts (report_id, case_id, title, content_md, status, created_at, updated_at)
            values (?, ?, ?, ?, ?, ?, ?)
            on conflict(report_id) do update set
              case_id = excluded.case_id,
              title = excluded.title,
              content_md = excluded.content_md,
              status = excluded.status,
              updated_at = excluded.updated_at
            """,
            (
                report_id,
                case_id,
                report_title,
                content_md,
                "previewed",
                now,
                now,
            ),
        )
        conn.commit()
        return {
            "report": {
                "report_id": report_id,
                "case_id": case_id,
                "title": report_title,
                "content_md": content_md,
                "status": "previewed",
                "created_at": now,
                "updated_at": now,
            },
            "preview": report_preview,
            "executed": False,
        }
    finally:
        conn.close()
