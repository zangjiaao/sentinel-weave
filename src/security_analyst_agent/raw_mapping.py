from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any
from uuid import uuid4

from security_analyst_agent.db import connect_db, create_schema
from security_analyst_agent.stages import normalize_stage

_ALERT_COLUMNS = [
    "alert_id",
    "occurred_at",
    "title",
    "status",
    "severity",
    "attack_stage",
    "raw_attack_stage",
    "src_ip",
    "dst_ip",
    "asset_id",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_json_dumps(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _safe_json_loads(payload: str | None, default: Any) -> Any:
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


def _normalize_severity(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    alias = {
        "critical": "critical",
        "crit": "critical",
        "high": "high",
        "medium": "medium",
        "med": "medium",
        "low": "low",
        "info": "low",
        "informational": "low",
        "notice": "low",
    }
    return alias.get(normalized, "low")


def _normalize_status(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized else "new"


def _lookup_path(context: dict[str, Any], path: str) -> Any:
    normalized_path = str(path).strip()
    if not normalized_path:
        return None

    if normalized_path.startswith("$."):
        normalized_path = normalized_path[2:]
    if normalized_path.startswith("payload."):
        normalized_path = normalized_path

    cursor: Any = context
    for part in normalized_path.split("."):
        if isinstance(cursor, dict) and part in cursor:
            cursor = cursor[part]
            continue
        return None
    return cursor


def _flatten_template_context(payload: dict[str, Any], base: dict[str, Any]) -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    flattened.update(base)
    for key, value in payload.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            flattened[key] = value
    return flattened


def _match_value(actual: Any, expected: Any) -> bool:
    if isinstance(expected, list):
        return any(_match_value(actual, item) for item in expected)
    if isinstance(actual, str) and isinstance(expected, str):
        return actual.strip().lower() == expected.strip().lower()
    return actual == expected


def _match_rule(rule_match: dict[str, Any], context: dict[str, Any]) -> bool:
    for raw_key, expected in rule_match.items():
        key = str(raw_key).strip()
        if not key:
            continue

        if key.endswith("_in"):
            field = key[:-3]
            actual = _lookup_path(context, field)
            if not isinstance(expected, list):
                return False
            if not any(_match_value(actual, item) for item in expected):
                return False
            continue

        if key.endswith("_prefix"):
            field = key[: -len("_prefix")]
            actual = _to_str(_lookup_path(context, field))
            expected_text = _to_str(expected)
            if actual is None or expected_text is None:
                return False
            if not actual.lower().startswith(expected_text.lower()):
                return False
            continue

        actual = _lookup_path(context, key)
        if not _match_value(actual, expected):
            return False
    return True


def _apply_value_map(value: Any, mapper: dict[str, Any]) -> Any:
    if value is None:
        return None
    if not mapper:
        return value
    if isinstance(value, str):
        lookup = mapper.get(value)
        if lookup is not None:
            return lookup
        lookup = mapper.get(value.lower())
        if lookup is not None:
            return lookup
    return mapper.get(value, value)


def ingest_raw_alert_bundle(
    db_path: Path,
    events: list[dict[str, Any]],
    source: str = "raw_manual_import",
) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    ingested_at = _now_iso()
    inserted = 0
    updated = 0
    rows: list[tuple[Any, ...]] = []
    for event in events:
        raw_event_id = _to_str(event.get("raw_event_id")) or f"raw_{uuid4().hex[:16]}"
        event_source = _to_str(event.get("source")) or source
        payload = event.get("payload")
        payload_dict = payload if isinstance(payload, dict) else {"raw": payload}
        rows.append(
            (
                raw_event_id,
                event_source,
                _to_str(event.get("vendor")),
                _to_str(event.get("product")),
                _to_str(event.get("log_type")),
                _to_str(event.get("rule_id")),
                _to_str(event.get("occurred_at")),
                _safe_json_dumps(payload_dict),
                ingested_at,
                "pending",
            )
        )

    if rows:
        conn.executemany(
            """
            insert into raw_alert_events (
              raw_event_id, source, vendor, product, log_type, rule_id, occurred_at,
              payload_json, ingested_at, map_status
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict(raw_event_id) do update set
              source = excluded.source,
              vendor = excluded.vendor,
              product = excluded.product,
              log_type = excluded.log_type,
              rule_id = excluded.rule_id,
              occurred_at = excluded.occurred_at,
              payload_json = excluded.payload_json,
              ingested_at = excluded.ingested_at,
              map_status = case
                when raw_alert_events.map_status = 'mapped' then raw_alert_events.map_status
                else 'pending'
              end
            """,
            rows,
        )
        changed = conn.total_changes
        inserted = len(rows)
        updated = max(changed - inserted, 0)

    conn.commit()
    conn.close()

    return {
        "inserted_or_updated": len(rows),
        "source": source,
        "ingested_at": ingested_at,
        "estimated_updates": updated,
    }


def upsert_alert_normalization_maps(db_path: Path, maps: list[dict[str, Any]]) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    updated_at = _now_iso()
    rows: list[tuple[Any, ...]] = []
    for item in maps:
        map_id = _to_str(item.get("map_id"))
        if not map_id:
            continue
        priority = int(item.get("priority", 100))
        enabled = 1 if bool(item.get("enabled", True)) else 0
        match = item.get("match") if isinstance(item.get("match"), dict) else {}
        mapping = item.get("mapping") if isinstance(item.get("mapping"), dict) else {}
        rows.append((map_id, priority, enabled, _safe_json_dumps(match), _safe_json_dumps(mapping), updated_at))

    if rows:
        conn.executemany(
            """
            insert into alert_normalization_maps (
              map_id, priority, enabled, match_json, mapping_json, updated_at
            ) values (?, ?, ?, ?, ?, ?)
            on conflict(map_id) do update set
              priority = excluded.priority,
              enabled = excluded.enabled,
              match_json = excluded.match_json,
              mapping_json = excluded.mapping_json,
              updated_at = excluded.updated_at
            """,
            rows,
        )
    conn.commit()
    conn.close()
    return {"upserted": len(rows), "updated_at": updated_at}


def sample_raw_alert_groups(
    db_path: Path,
    limit_groups: int = 20,
    samples_per_group: int = 3,
    statuses: list[str] | None = None,
) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    status_values = statuses or ["pending"]
    placeholders = ", ".join("?" for _ in status_values)
    groups = conn.execute(
        f"""
        select
          source,
          coalesce(vendor, '') as vendor,
          coalesce(product, '') as product,
          coalesce(log_type, '') as log_type,
          coalesce(rule_id, '') as rule_id,
          count(*) as event_count,
          min(ingested_at) as first_ingested_at,
          max(ingested_at) as last_ingested_at
        from raw_alert_events
        where map_status in ({placeholders})
        group by source, coalesce(vendor, ''), coalesce(product, ''), coalesce(log_type, ''), coalesce(rule_id, '')
        order by event_count desc, last_ingested_at desc
        limit ?
        """,
        (*status_values, max(1, limit_groups)),
    ).fetchall()

    result_groups: list[dict[str, Any]] = []
    for group in groups:
        sample_rows = conn.execute(
            """
            select raw_event_id, occurred_at, payload_json
            from raw_alert_events
            where map_status in ({})
              and source = ?
              and coalesce(vendor, '') = ?
              and coalesce(product, '') = ?
              and coalesce(log_type, '') = ?
              and coalesce(rule_id, '') = ?
            order by ingested_at asc, raw_event_id asc
            limit ?
            """.format(placeholders),
            (
                *status_values,
                group["source"],
                group["vendor"],
                group["product"],
                group["log_type"],
                group["rule_id"],
                max(1, samples_per_group),
            ),
        ).fetchall()
        samples = []
        for row in sample_rows:
            samples.append(
                {
                    "raw_event_id": row["raw_event_id"],
                    "occurred_at": row["occurred_at"],
                    "payload": _safe_json_loads(row["payload_json"], {}),
                }
            )
        result_groups.append(
            {
                "group_key": {
                    "source": group["source"],
                    "vendor": group["vendor"] or None,
                    "product": group["product"] or None,
                    "log_type": group["log_type"] or None,
                    "rule_id": group["rule_id"] or None,
                },
                "event_count": int(group["event_count"]),
                "first_ingested_at": group["first_ingested_at"],
                "last_ingested_at": group["last_ingested_at"],
                "samples": samples,
            }
        )
    conn.close()
    return {"groups": result_groups, "status_scope": status_values}


def _build_normalized_alert(
    raw_row: sqlite3.Row,
    map_row: sqlite3.Row,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    payload = _safe_json_loads(raw_row["payload_json"], {})
    payload = payload if isinstance(payload, dict) else {"raw": payload}

    base_context = {
        "raw_event_id": raw_row["raw_event_id"],
        "source": raw_row["source"],
        "vendor": raw_row["vendor"],
        "product": raw_row["product"],
        "log_type": raw_row["log_type"],
        "rule_id": raw_row["rule_id"],
        "occurred_at": raw_row["occurred_at"],
    }
    context: dict[str, Any] = dict(payload)
    context.update(base_context)
    context["payload"] = payload

    mapping = _safe_json_loads(map_row["mapping_json"], {})
    fields = mapping.get("field_map") if isinstance(mapping.get("field_map"), dict) else {}
    defaults = mapping.get("defaults") if isinstance(mapping.get("defaults"), dict) else {}
    value_maps = mapping.get("value_maps") if isinstance(mapping.get("value_maps"), dict) else {}
    confidence = float(mapping.get("confidence", 0.7))
    reason = _to_str(mapping.get("reason")) or "map_rule_match"

    def pick(field_name: str) -> Any:
        path = fields.get(field_name)
        if isinstance(path, str):
            return _lookup_path(context, path)
        return None

    title_template = _to_str(mapping.get("title_template"))
    title = _to_str(pick("title"))
    if title_template:
        template_context = _flatten_template_context(payload, base_context)
        title = title_template.format_map(defaultdict(str, template_context)).strip() or title
    title = title or _to_str(defaults.get("title")) or f"{raw_row['source']} mapped alert {raw_row['raw_event_id']}"

    occurred_at = (
        _to_str(pick("occurred_at"))
        or _to_str(defaults.get("occurred_at"))
        or _to_str(raw_row["occurred_at"])
        or _now_iso()
    )
    status = _normalize_status(pick("status") or defaults.get("status") or "new")

    raw_severity = pick("severity")
    mapped_severity = _apply_value_map(raw_severity, value_maps.get("severity", {}))
    severity = _normalize_severity(mapped_severity or defaults.get("severity") or "low")

    raw_stage = pick("attack_stage")
    mapped_stage = _apply_value_map(raw_stage, value_maps.get("attack_stage", {}))
    stage_candidate = _to_str(mapped_stage or defaults.get("attack_stage") or "unknown")
    attack_stage = normalize_stage(stage_candidate) or "unknown"
    raw_attack_stage = _to_str(raw_stage)

    normalized = {
        "alert_id": f"alt_raw_{raw_row['raw_event_id'][-16:]}",
        "occurred_at": occurred_at,
        "title": title,
        "status": status,
        "severity": severity,
        "attack_stage": attack_stage,
        "raw_attack_stage": raw_attack_stage,
        "src_ip": _to_str(pick("src_ip") or defaults.get("src_ip")),
        "dst_ip": _to_str(pick("dst_ip") or defaults.get("dst_ip")),
        "asset_id": _to_str(pick("asset_id") or defaults.get("asset_id")),
    }
    meta = {
        "map_id": map_row["map_id"],
        "map_confidence": confidence,
        "map_reason": reason,
        "raw_stage": raw_attack_stage,
    }
    return normalized, meta


def _upsert_unmapped(
    conn: sqlite3.Connection,
    *,
    raw_event_id: str,
    source: str,
    reason: str,
    details: dict[str, Any],
    now: str,
) -> None:
    conn.execute(
        """
        insert into unmapped_alert_events (
          raw_event_id, source, reason, details_json, first_seen_at, last_seen_at, hit_count, resolved
        ) values (?, ?, ?, ?, ?, ?, 1, 0)
        on conflict(raw_event_id) do update set
          source = excluded.source,
          reason = excluded.reason,
          details_json = excluded.details_json,
          last_seen_at = excluded.last_seen_at,
          hit_count = unmapped_alert_events.hit_count + 1,
          resolved = 0
        """,
        (raw_event_id, source, reason, _safe_json_dumps(details), now, now),
    )


def apply_alert_normalization_maps(
    db_path: Path,
    *,
    limit: int = 500,
    source: str | None = None,
    raw_event_ids: list[str] | None = None,
    include_unmapped: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    statuses = ["pending", "error"]
    if include_unmapped:
        statuses.append("unmapped")
    status_placeholders = ", ".join("?" for _ in statuses)

    where_clauses = [f"map_status in ({status_placeholders})"]
    params: list[Any] = [*statuses]
    if source:
        where_clauses.append("source = ?")
        params.append(source)
    normalized_ids: list[str] = []
    if raw_event_ids:
        normalized_ids = [str(item).strip() for item in raw_event_ids if str(item).strip()]
    if normalized_ids:
        id_placeholders = ", ".join("?" for _ in normalized_ids)
        where_clauses.append(f"raw_event_id in ({id_placeholders})")
        params.extend(normalized_ids)
    where_sql = " and ".join(where_clauses)

    raw_rows = conn.execute(
        f"""
        select *
        from raw_alert_events
        where {where_sql}
        order by ingested_at asc, raw_event_id asc
        limit ?
        """,
        (*params, max(1, limit)),
    ).fetchall()
    map_rows = conn.execute(
        """
        select map_id, priority, match_json, mapping_json
        from alert_normalization_maps
        where enabled = 1
        order by priority desc, updated_at desc, map_id asc
        """
    ).fetchall()

    mapped_count = 0
    unmapped_count = 0
    processed_count = 0
    created_alert_ids: list[str] = []
    now = _now_iso()

    map_entries: list[tuple[sqlite3.Row, dict[str, Any]]] = []
    for row in map_rows:
        map_entries.append((row, _safe_json_loads(row["match_json"], {})))

    for raw_row in raw_rows:
        processed_count += 1
        payload = _safe_json_loads(raw_row["payload_json"], {})
        payload = payload if isinstance(payload, dict) else {"raw": payload}
        context: dict[str, Any] = dict(payload)
        context.update(
            {
                "source": raw_row["source"],
                "vendor": raw_row["vendor"],
                "product": raw_row["product"],
                "log_type": raw_row["log_type"],
                "rule_id": raw_row["rule_id"],
                "occurred_at": raw_row["occurred_at"],
                "payload": payload,
            }
        )

        selected_map: sqlite3.Row | None = None
        for map_row, match in map_entries:
            if not isinstance(match, dict):
                continue
            if _match_rule(match, context):
                selected_map = map_row
                break

        if selected_map is None:
            unmapped_count += 1
            if not dry_run:
                conn.execute(
                    """
                    update raw_alert_events
                    set map_status = 'unmapped',
                        map_id = null,
                        map_confidence = null,
                        map_reason = ?,
                        normalized_alert_id = null,
                        mapped_at = ?
                    where raw_event_id = ?
                    """,
                    ("no_matching_map", now, raw_row["raw_event_id"]),
                )
                _upsert_unmapped(
                    conn,
                    raw_event_id=raw_row["raw_event_id"],
                    source=raw_row["source"],
                    reason="no_matching_map",
                    details={
                        "vendor": raw_row["vendor"],
                        "product": raw_row["product"],
                        "log_type": raw_row["log_type"],
                        "rule_id": raw_row["rule_id"],
                    },
                    now=now,
                )
            continue

        normalized_alert, meta = _build_normalized_alert(raw_row, selected_map)
        if normalized_alert is None:
            unmapped_count += 1
            if not dry_run:
                conn.execute(
                    """
                    update raw_alert_events
                    set map_status = 'error',
                        map_id = ?,
                        map_confidence = ?,
                        map_reason = ?,
                        normalized_alert_id = null,
                        mapped_at = ?
                    where raw_event_id = ?
                    """,
                    (
                        selected_map["map_id"],
                        meta.get("map_confidence"),
                        "mapping_error",
                        now,
                        raw_row["raw_event_id"],
                    ),
                )
                _upsert_unmapped(
                    conn,
                    raw_event_id=raw_row["raw_event_id"],
                    source=raw_row["source"],
                    reason="mapping_error",
                    details={"map_id": selected_map["map_id"]},
                    now=now,
                )
            continue

        mapped_count += 1
        created_alert_ids.append(normalized_alert["alert_id"])
        if dry_run:
            continue

        conn.execute(
            """
            insert into alerts (
              alert_id, occurred_at, title, status, severity, attack_stage, raw_attack_stage, src_ip, dst_ip, asset_id
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict(alert_id) do update set
              occurred_at = excluded.occurred_at,
              title = excluded.title,
              status = excluded.status,
              severity = excluded.severity,
              attack_stage = excluded.attack_stage,
              raw_attack_stage = excluded.raw_attack_stage,
              src_ip = excluded.src_ip,
              dst_ip = excluded.dst_ip,
              asset_id = excluded.asset_id
            """,
            tuple(normalized_alert[column] for column in _ALERT_COLUMNS),
        )
        conn.execute(
            """
            insert into alert_ingest_events (event_id, alert_id, source, ingested_at, trigger_state)
            values (?, ?, ?, ?, 'pending')
            """,
            (
                f"evt_rawmap_{uuid4().hex[:12]}",
                normalized_alert["alert_id"],
                f"raw_map:{selected_map['map_id']}",
                now,
            ),
        )
        conn.execute(
            """
            update raw_alert_events
            set map_status = 'mapped',
                map_id = ?,
                map_confidence = ?,
                map_reason = ?,
                normalized_alert_id = ?,
                mapped_at = ?
            where raw_event_id = ?
            """,
            (
                selected_map["map_id"],
                meta.get("map_confidence"),
                meta.get("map_reason"),
                normalized_alert["alert_id"],
                now,
                raw_row["raw_event_id"],
            ),
        )
        conn.execute(
            """
            update unmapped_alert_events
            set resolved = 1, last_seen_at = ?
            where raw_event_id = ?
            """,
            (now, raw_row["raw_event_id"]),
        )

    if not dry_run:
        conn.commit()
    conn.close()
    return {
        "processed": processed_count,
        "mapped": mapped_count,
        "unmapped": unmapped_count,
        "dry_run": dry_run,
        "created_alert_ids": created_alert_ids,
    }


def list_unmapped_alert_events(
    db_path: Path,
    *,
    limit: int = 100,
    unresolved_only: bool = True,
) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    if unresolved_only:
        rows = conn.execute(
            """
            select raw_event_id, source, reason, details_json, first_seen_at, last_seen_at, hit_count, resolved
            from unmapped_alert_events
            where resolved = 0
            order by last_seen_at desc
            limit ?
            """,
            (max(1, limit),),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            select raw_event_id, source, reason, details_json, first_seen_at, last_seen_at, hit_count, resolved
            from unmapped_alert_events
            order by last_seen_at desc
            limit ?
            """,
            (max(1, limit),),
        ).fetchall()
    items: list[dict[str, Any]] = []
    for row in rows:
        items.append(
            {
                "raw_event_id": row["raw_event_id"],
                "source": row["source"],
                "reason": row["reason"],
                "details": _safe_json_loads(row["details_json"], {}),
                "first_seen_at": row["first_seen_at"],
                "last_seen_at": row["last_seen_at"],
                "hit_count": int(row["hit_count"]),
                "resolved": bool(row["resolved"]),
            }
        )
    conn.close()
    return {"items": items}
