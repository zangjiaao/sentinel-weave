from __future__ import annotations

from collections import defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from security_analyst_agent.db import connect_db, create_schema
from security_analyst_agent.stages import normalize_stage, stage_rank

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

_ASSET_IDENTITY_LOOKUP_ORDER = ("asset_id", "ip", "domain", "hostname")
_IP_IDENTITY_KEYS = {
    "dst_ip",
    "destination_ip",
    "target_ip",
    "server_ip",
    "dip",
    "dst",
    "目标ip",
    "目标_ip",
}
_DOMAIN_IDENTITY_KEYS = {
    "domain",
    "target_domain",
    "dst_domain",
    "request_host",
    "host",
    "目标域名",
}
_HOSTNAME_IDENTITY_KEYS = {
    "hostname",
    "host_name",
    "target_hostname",
    "dst_hostname",
    "computer_name",
    "server_name",
    "主机名",
}
_URL_IDENTITY_KEYS = {"url", "request_url", "uri", "request_uri"}
_EMBEDDED_DETAIL_KEYS = {"攻击详情", "attack_detail", "detail", "details", "detail_json"}


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


def _normalize_occurred_at(value: Any) -> str | None:
    text = _to_str(value)
    if text is None:
        return None
    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        parsed = None
    if parsed is None:
        for pattern in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                parsed = datetime.strptime(text, pattern)
                break
            except ValueError:
                continue
    if parsed is None:
        return text
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.isoformat()


def _normalize_identity_value(identity_type: str, value: Any) -> str | None:
    text = _to_str(value)
    if text is None:
        return None
    normalized_type = str(identity_type).strip().lower()
    if normalized_type == "ip":
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return None
    if normalized_type in {"domain", "hostname", "asset_id"}:
        return text.lower()
    return text


def _build_temp_asset_id(identity_type: str, identity_value: str) -> str:
    digest = hashlib.sha1(f"{identity_type}:{identity_value}".encode("utf-8")).hexdigest()[:12]
    return f"asset_tmp_{digest}"


def _upsert_asset_identity(
    conn: sqlite3.Connection,
    *,
    asset_id: str,
    identity_type: str,
    identity_value: str,
    is_primary: bool,
    confidence: float,
    created_at: str,
) -> None:
    normalized_type = str(identity_type).strip().lower()
    normalized_value = _normalize_identity_value(normalized_type, identity_value)
    if normalized_value is None:
        return
    identity_seed = f"{asset_id}:{normalized_type}:{normalized_value}"
    identity_id = f"idn_{hashlib.sha1(identity_seed.encode('utf-8')).hexdigest()[:20]}"
    conn.execute(
        """
        insert into asset_identities (
          identity_id, asset_id, identity_type, identity_value, is_primary, confidence, created_at
        ) values (?, ?, ?, ?, ?, ?, ?)
        on conflict(asset_id, identity_type, identity_value) do update set
          is_primary = case
            when excluded.is_primary > asset_identities.is_primary then excluded.is_primary
            else asset_identities.is_primary
          end,
          confidence = case
            when excluded.confidence > asset_identities.confidence then excluded.confidence
            else asset_identities.confidence
          end
        """,
        (
            identity_id,
            asset_id,
            normalized_type,
            normalized_value,
            1 if is_primary else 0,
            max(0.0, min(float(confidence), 1.0)),
            created_at,
        ),
    )


def _extract_identity_candidates(
    normalized_alert: dict[str, Any],
    payload: dict[str, Any],
) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add_candidate(identity_type: str, value: Any, source: str) -> None:
        normalized_type = str(identity_type).strip().lower()
        normalized_value = _normalize_identity_value(normalized_type, value)
        if normalized_value is None:
            return
        key = (normalized_type, normalized_value)
        if key in seen:
            return
        seen.add(key)
        candidates.append(
            {
                "identity_type": normalized_type,
                "identity_value": normalized_value,
                "source": source,
            }
        )

    add_candidate("asset_id", normalized_alert.get("asset_id"), "normalized.asset_id")
    add_candidate("ip", normalized_alert.get("dst_ip"), "normalized.dst_ip")

    scan_targets: list[tuple[str, dict[str, Any]]] = [("payload", payload)]
    payload_row = payload.get("row")
    if isinstance(payload_row, dict):
        scan_targets.append(("payload.row", payload_row))

    for prefix, source_dict in scan_targets:
        for raw_key, raw_value in source_dict.items():
            key = str(raw_key).strip().lower()
            if isinstance(raw_value, (dict, list)):
                continue
            value_text = _to_str(raw_value)
            if value_text is None:
                continue

            if key in _IP_IDENTITY_KEYS or key.endswith("_ip"):
                add_candidate("ip", value_text, f"{prefix}.{raw_key}")
                continue
            if key in _DOMAIN_IDENTITY_KEYS or key.endswith("_domain"):
                add_candidate("domain", value_text, f"{prefix}.{raw_key}")
                continue
            if key in _HOSTNAME_IDENTITY_KEYS or key.endswith("_hostname"):
                add_candidate("hostname", value_text, f"{prefix}.{raw_key}")
                continue
            if key in _URL_IDENTITY_KEYS:
                parsed = urlparse(value_text if "://" in value_text else f"http://{value_text}")
                if parsed.hostname:
                    add_candidate("domain", parsed.hostname, f"{prefix}.{raw_key}")
                continue
            if key == "host":
                if _normalize_identity_value("ip", value_text):
                    add_candidate("ip", value_text, f"{prefix}.{raw_key}")
                else:
                    add_candidate("domain", value_text, f"{prefix}.{raw_key}")
                continue
    return candidates


def _find_asset_by_identity(
    conn: sqlite3.Connection,
    *,
    identity_type: str,
    identity_value: str,
) -> str | None:
    normalized_type = str(identity_type).strip().lower()
    normalized_value = _normalize_identity_value(normalized_type, identity_value)
    if normalized_value is None:
        return None

    identity_match = conn.execute(
        """
        select asset_id
        from asset_identities
        where lower(identity_type) = ?
          and lower(identity_value) = ?
        order by is_primary desc, confidence desc, created_at asc
        limit 1
        """,
        (normalized_type, normalized_value),
    ).fetchone()
    if identity_match is not None:
        return _to_str(identity_match["asset_id"])

    if normalized_type == "asset_id":
        row = conn.execute(
            """
            select asset_id
            from assets
            where lower(asset_id) = ?
            limit 1
            """,
            (normalized_value,),
        ).fetchone()
    elif normalized_type == "ip":
        row = conn.execute(
            """
            select asset_id
            from assets
            where public_ip = ?
            limit 1
            """,
            (normalized_value,),
        ).fetchone()
    elif normalized_type == "domain":
        row = conn.execute(
            """
            select asset_id
            from assets
            where lower(domain) = ?
            limit 1
            """,
            (normalized_value,),
        ).fetchone()
    elif normalized_type == "hostname":
        row = conn.execute(
            """
            select asset_id
            from assets
            where lower(system_name) = ? or lower(asset_name) = ?
            limit 1
            """,
            (normalized_value, normalized_value),
        ).fetchone()
    else:
        row = None
    return _to_str(row["asset_id"]) if row is not None else None


def _ensure_temp_asset(
    conn: sqlite3.Connection,
    *,
    identity_candidates: list[dict[str, str]],
    created_at: str,
    preferred_asset_id: str | None = None,
) -> tuple[str, bool]:
    primary_identity = identity_candidates[0]
    explicit_asset_id = _normalize_identity_value("asset_id", preferred_asset_id) if preferred_asset_id else None
    asset_id = explicit_asset_id or _build_temp_asset_id(primary_identity["identity_type"], primary_identity["identity_value"])
    existing_row = conn.execute(
        """
        select asset_id
        from assets
        where lower(asset_id) = lower(?)
        limit 1
        """,
        (asset_id,),
    ).fetchone()
    existed = existing_row is not None
    if existing_row is not None:
        asset_id = str(existing_row["asset_id"])
    if not existed:
        primary_label = primary_identity["identity_value"]
        ip_candidate = next((item["identity_value"] for item in identity_candidates if item["identity_type"] == "ip"), None)
        domain_candidate = next(
            (item["identity_value"] for item in identity_candidates if item["identity_type"] == "domain"),
            None,
        )
        host_candidate = next(
            (item["identity_value"] for item in identity_candidates if item["identity_type"] == "hostname"),
            None,
        )
        conn.execute(
            """
            insert into assets (
              asset_id, asset_name, system_name, owner_team, internet_exposed, public_ip, domain
            ) values (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                asset_id,
                f"Temporary Asset {primary_label}",
                host_candidate or primary_label,
                None,
                1,
                ip_candidate,
                domain_candidate,
            ),
        )

    for idx, candidate in enumerate(identity_candidates):
        _upsert_asset_identity(
            conn,
            asset_id=asset_id,
            identity_type=candidate["identity_type"],
            identity_value=candidate["identity_value"],
            is_primary=(idx == 0),
            confidence=0.95 if idx == 0 else 0.72,
            created_at=created_at,
        )
    return asset_id, not existed


def _resolve_alert_asset(
    conn: sqlite3.Connection,
    *,
    normalized_alert: dict[str, Any],
    payload: dict[str, Any],
    dry_run: bool,
    created_at: str,
) -> dict[str, Any]:
    candidates = _extract_identity_candidates(normalized_alert, payload)
    explicit_asset_id = _normalize_identity_value("asset_id", normalized_alert.get("asset_id"))
    by_type: dict[str, list[dict[str, str]]] = defaultdict(list)
    for item in candidates:
        by_type[item["identity_type"]].append(item)

    resolved_asset_id: str | None = None
    resolved_candidate: dict[str, str] | None = None
    for identity_type in _ASSET_IDENTITY_LOOKUP_ORDER:
        for candidate in by_type.get(identity_type, []):
            asset_id = _find_asset_by_identity(
                conn,
                identity_type=candidate["identity_type"],
                identity_value=candidate["identity_value"],
            )
            if asset_id:
                resolved_asset_id = asset_id
                resolved_candidate = candidate
                break
        if resolved_asset_id:
            break

    if resolved_asset_id:
        normalized_alert["asset_id"] = resolved_asset_id
        if not dry_run:
            for idx, candidate in enumerate(candidates):
                _upsert_asset_identity(
                    conn,
                    asset_id=resolved_asset_id,
                    identity_type=candidate["identity_type"],
                    identity_value=candidate["identity_value"],
                    is_primary=(idx == 0),
                    confidence=0.9 if idx == 0 else 0.7,
                    created_at=created_at,
                )
        return {
            "status": "resolved",
            "asset_id": resolved_asset_id,
            "match": resolved_candidate,
            "candidates": candidates,
        }

    if not candidates:
        normalized_alert["asset_id"] = None
        return {
            "status": "unresolved",
            "asset_id": None,
            "match": None,
            "candidates": [],
        }

    if explicit_asset_id:
        if dry_run:
            normalized_alert["asset_id"] = explicit_asset_id
            return {
                "status": "would_auto_create",
                "asset_id": explicit_asset_id,
                "match": candidates[0],
                "candidates": candidates,
            }
        asset_id, created = _ensure_temp_asset(
            conn,
            identity_candidates=candidates,
            created_at=created_at,
            preferred_asset_id=explicit_asset_id,
        )
        normalized_alert["asset_id"] = asset_id
        return {
            "status": "auto_created" if created else "resolved",
            "asset_id": asset_id,
            "match": candidates[0],
            "candidates": candidates,
        }

    if dry_run:
        normalized_alert["asset_id"] = None
        return {
            "status": "would_auto_create",
            "asset_id": None,
            "match": candidates[0],
            "candidates": candidates,
        }

    asset_id, created = _ensure_temp_asset(conn, identity_candidates=candidates, created_at=created_at)
    normalized_alert["asset_id"] = asset_id
    return {
        "status": "auto_created" if created else "resolved",
        "asset_id": asset_id,
        "match": candidates[0],
        "candidates": candidates,
    }


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
        value_text = value.strip()
        lookup = mapper.get(value_text)
        if lookup is not None:
            return lookup
        lookup = mapper.get(value_text.lower())
        if lookup is not None:
            return lookup
        tokens = [item.strip() for item in re.split(r"[,\s，;；|/]+", value_text) if item.strip()]
        for token in tokens:
            token_lookup = mapper.get(token)
            if token_lookup is not None:
                return token_lookup
            token_lookup = mapper.get(token.lower())
            if token_lookup is not None:
                return token_lookup

        lowered = value_text.lower()
        contains_matches: list[tuple[int, Any]] = []
        for raw_key, mapped_value in mapper.items():
            key_text = _to_str(raw_key)
            if not key_text:
                continue
            if key_text.lower() in lowered:
                contains_matches.append((len(key_text), mapped_value))
        if contains_matches:
            contains_matches.sort(key=lambda item: item[0], reverse=True)
            return contains_matches[0][1]
    return mapper.get(value, value)


def _extract_embedded_detail_dict(payload: dict[str, Any]) -> dict[str, Any] | None:
    candidates: list[Any] = []
    if isinstance(payload, dict):
        for key in _EMBEDDED_DETAIL_KEYS:
            candidates.append(payload.get(key))
        payload_row = payload.get("row")
        if isinstance(payload_row, dict):
            for key in _EMBEDDED_DETAIL_KEYS:
                candidates.append(payload_row.get(key))

    for item in candidates:
        if isinstance(item, dict):
            return item
        text = _to_str(item)
        if text is None:
            continue
        stripped = text.strip()
        if not stripped.startswith("{"):
            continue
        parsed = _safe_json_loads(stripped, default=None)
        if isinstance(parsed, dict):
            return parsed
    return None


def _extract_ip_candidate(value: Any) -> str | None:
    text = _to_str(value)
    if text is None:
        return None
    direct = _normalize_identity_value("ip", text)
    if direct:
        return direct
    if text.startswith("[") and "]" in text:
        host = text[1 : text.index("]")]
        direct = _normalize_identity_value("ip", host)
        if direct:
            return direct
    if ":" in text and text.count(":") == 1:
        host = text.split(":", 1)[0].strip()
        direct = _normalize_identity_value("ip", host)
        if direct:
            return direct
    return None


def _extract_dst_ip_from_payload(payload: dict[str, Any]) -> str | None:
    detail = _extract_embedded_detail_dict(payload)
    if detail is None:
        return None
    host = _to_str(detail.get("host"))
    if host:
        parsed = urlparse(host if "://" in host else f"http://{host}")
        hostname = parsed.hostname or host
        ip_candidate = _extract_ip_candidate(hostname)
        if ip_candidate:
            return ip_candidate
    return None


def _extract_src_ip_from_payload(payload: dict[str, Any]) -> str | None:
    detail = _extract_embedded_detail_dict(payload)
    if detail is None:
        return None
    return _extract_ip_candidate(detail.get("remote_addr"))


def _infer_stage_and_severity_from_payload(
    *,
    payload: dict[str, Any],
    title: str | None,
    rule_id: Any,
) -> tuple[str | None, str | None]:
    row = payload.get("row") if isinstance(payload.get("row"), dict) else {}
    intel_text = _to_str(row.get("威胁情报")) or _to_str(payload.get("threat_intel")) or ""
    detail_text = _to_str(row.get("攻击详情")) or _to_str(payload.get("attack_detail")) or ""
    rule_text = _to_str(rule_id) or ""
    title_text = _to_str(title) or ""
    normalized_text = " | ".join([intel_text, title_text, rule_text, detail_text[:1200]]).lower()

    stage_hints = [
        ("command_execution", ("命令执行", "shell", "exec", "cmd=")),
        ("persistence", ("webshell", "持久化", "落地")),
        ("lateral_prep", ("横向", "lateral")),
        ("exploit", ("漏洞利用", "exploit", "cve-", "cve_")),
        ("recon", ("扫描", "探测", "爬虫", "crawler", "scan")),
    ]
    severity_hints = [
        ("critical", ("webshell", "命令执行", "rce", "0day")),
        ("high", ("漏洞利用", "exploit", "cve-", "cve_")),
        ("medium", ("扫描", "探测", "probe")),
    ]

    inferred_stage: str | None = None
    for stage, keywords in stage_hints:
        if any(keyword in normalized_text for keyword in keywords):
            if inferred_stage is None or stage_rank(stage) > stage_rank(inferred_stage):
                inferred_stage = stage

    inferred_severity: str | None = None
    severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    for severity, keywords in severity_hints:
        if any(keyword in normalized_text for keyword in keywords):
            if (
                inferred_severity is None
                or severity_rank.get(severity, 1) > severity_rank.get(inferred_severity, 1)
            ):
                inferred_severity = severity

    return inferred_stage, inferred_severity


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
    source: str | None = None,
) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    status_values = statuses or ["pending"]
    placeholders = ", ".join("?" for _ in status_values)
    where_clauses = [f"map_status in ({placeholders})"]
    params: list[Any] = [*status_values]
    if source:
        where_clauses.append("source = ?")
        params.append(source)
    where_sql = " and ".join(where_clauses)
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
        where {where_sql}
        group by source, coalesce(vendor, ''), coalesce(product, ''), coalesce(log_type, ''), coalesce(rule_id, '')
        order by event_count desc, last_ingested_at desc
        limit ?
        """,
        (*params, max(1, limit_groups)),
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
    return {"groups": result_groups, "status_scope": status_values, "source_scope": source}


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
        _normalize_occurred_at(pick("occurred_at"))
        or _normalize_occurred_at(defaults.get("occurred_at"))
        or _normalize_occurred_at(raw_row["occurred_at"])
        or _now_iso()
    )
    status = _normalize_status(pick("status") or defaults.get("status") or "new")

    raw_severity = pick("severity")
    mapped_severity = _apply_value_map(raw_severity, value_maps.get("severity", {}))
    severity = _normalize_severity(mapped_severity or defaults.get("severity") or "low")

    raw_stage = pick("attack_stage")
    mapped_stage = _apply_value_map(raw_stage, value_maps.get("attack_stage", {}))
    stage_candidate = _to_str(mapped_stage or defaults.get("attack_stage") or "unknown")
    attack_stage = normalize_stage(stage_candidate)
    if stage_rank(attack_stage) <= 0:
        attack_stage = "unknown"
    raw_attack_stage = _to_str(raw_stage)

    inferred_stage, inferred_severity = _infer_stage_and_severity_from_payload(
        payload=payload,
        title=title,
        rule_id=raw_row["rule_id"],
    )
    if inferred_stage and stage_rank(inferred_stage) > stage_rank(attack_stage):
        attack_stage = inferred_stage
    if attack_stage == "unknown":
        attack_stage = "recon"
    severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    if inferred_severity and severity_rank.get(inferred_severity, 1) > severity_rank.get(severity, 1):
        severity = inferred_severity

    src_ip = _to_str(pick("src_ip") or defaults.get("src_ip")) or _extract_src_ip_from_payload(payload)
    dst_ip = _to_str(pick("dst_ip") or defaults.get("dst_ip")) or _extract_dst_ip_from_payload(payload)

    normalized = {
        "alert_id": f"alt_raw_{raw_row['raw_event_id'][-16:]}",
        "occurred_at": occurred_at,
        "title": title,
        "status": status,
        "severity": severity,
        "attack_stage": attack_stage,
        "raw_attack_stage": raw_attack_stage,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
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
    asset_resolved_count = 0
    asset_auto_created_count = 0
    asset_unresolved_count = 0
    asset_resolution_samples: list[dict[str, Any]] = []
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

        asset_resolution = _resolve_alert_asset(
            conn,
            normalized_alert=normalized_alert,
            payload=payload,
            dry_run=dry_run,
            created_at=now,
        )
        resolution_status = str(asset_resolution.get("status") or "").strip().lower()
        if resolution_status == "resolved":
            asset_resolved_count += 1
        elif resolution_status in {"auto_created", "would_auto_create"}:
            asset_auto_created_count += 1
        else:
            asset_unresolved_count += 1
        if len(asset_resolution_samples) < 20:
            asset_resolution_samples.append(
                {
                    "raw_event_id": raw_row["raw_event_id"],
                    "alert_id": normalized_alert["alert_id"],
                    "status": resolution_status or "unknown",
                    "asset_id": asset_resolution.get("asset_id"),
                    "match": asset_resolution.get("match"),
                }
            )

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
        "asset_resolved_count": asset_resolved_count,
        "asset_auto_created_count": asset_auto_created_count,
        "asset_unresolved_count": asset_unresolved_count,
        "asset_resolution_samples": asset_resolution_samples,
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


def _job_source(job_id: str) -> str:
    normalized = str(job_id).strip()
    if not normalized:
        raise ValueError("job_id is required")
    return f"import_job:{normalized}"


def _pick_first_non_empty(mapping: dict[str, Any], candidates: list[str]) -> str | None:
    for key in candidates:
        value = _to_str(mapping.get(key))
        if value:
            return value
    return None


def _refresh_import_job_metrics(conn: sqlite3.Connection, job_id: str) -> dict[str, Any]:
    source = _job_source(job_id)
    row = conn.execute(
        """
        select
          count(*) as total_rows,
          sum(case when map_status = 'mapped' then 1 else 0 end) as mapped_rows,
          sum(case when map_status = 'unmapped' then 1 else 0 end) as unmapped_rows,
          sum(case when map_status = 'pending' then 1 else 0 end) as pending_rows,
          sum(case when map_status = 'error' then 1 else 0 end) as error_rows
        from raw_alert_events
        where source = ?
        """,
        (source,),
    ).fetchone()
    total_rows = int(row["total_rows"] or 0)
    mapped_rows = int(row["mapped_rows"] or 0)
    unmapped_rows = int(row["unmapped_rows"] or 0)
    pending_rows = int(row["pending_rows"] or 0)
    error_rows = int(row["error_rows"] or 0)

    if total_rows == 0:
        status = "failed"
    elif mapped_rows == total_rows:
        status = "completed"
    elif pending_rows == total_rows and mapped_rows == 0 and unmapped_rows == 0 and error_rows == 0:
        status = "uploaded"
    elif mapped_rows > 0 and pending_rows > 0 and unmapped_rows == 0 and error_rows == 0:
        status = "processing"
    elif mapped_rows > 0:
        status = "needs_review"
    elif unmapped_rows > 0 or error_rows > 0:
        status = "waiting_mapping"
    elif pending_rows > 0:
        status = "queued"
    else:
        status = "uploaded"

    now = _now_iso()
    conn.execute(
        """
        update import_jobs
        set status = ?,
            total_rows = ?,
            mapped_rows = ?,
            unmapped_rows = ?,
            pending_rows = ?,
            error_rows = ?,
            updated_at = ?
        where job_id = ?
        """,
        (status, total_rows, mapped_rows, unmapped_rows, pending_rows, error_rows, now, job_id),
    )
    return {
        "job_id": job_id,
        "status": status,
        "total_rows": total_rows,
        "mapped_rows": mapped_rows,
        "unmapped_rows": unmapped_rows,
        "pending_rows": pending_rows,
        "error_rows": error_rows,
    }


def _get_import_job_row(conn: sqlite3.Connection, job_id: str) -> sqlite3.Row:
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
    return row


def _serialize_import_job(row: sqlite3.Row) -> dict[str, Any]:
    return {
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
        "notes": _safe_json_loads(row["notes_json"], {}),
    }


def import_csv_alert_file(
    db_path: Path,
    *,
    csv_path: Path,
    file_name: str | None = None,
    vendor: str | None = None,
    product: str | None = None,
    log_type: str | None = None,
    occurred_at_column: str | None = None,
    rule_id_column: str | None = None,
    job_id: str | None = None,
) -> dict[str, Any]:
    csv_real_path = Path(csv_path)
    if not csv_real_path.exists():
        raise ValueError(f"csv file not found: {csv_real_path}")

    active_job_id = _to_str(job_id) or f"job_{uuid4().hex[:12]}"
    source = _job_source(active_job_id)
    now = _now_iso()

    file_bytes = csv_real_path.read_bytes()
    file_hash = hashlib.sha256(file_bytes).hexdigest()

    with csv_real_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        field_names = list(reader.fieldnames or [])
        if not field_names:
            raise ValueError("csv has no header")
        events: list[dict[str, Any]] = []
        for idx, row in enumerate(reader, start=1):
            raw_event_id = f"{active_job_id}_{idx:08d}"
            normalized_row = {str(k).strip(): v for k, v in row.items() if k is not None}
            event_vendor = vendor or _pick_first_non_empty(
                normalized_row,
                ["vendor", "Vendor", "厂商", "设备厂商", "设备厂商名称"],
            )
            event_product = product or _pick_first_non_empty(
                normalized_row,
                ["product", "Product", "产品", "设备类型", "蜜罐名称"],
            )
            event_log_type = log_type or _pick_first_non_empty(
                normalized_row,
                ["log_type", "日志类型", "事件类型"],
            )

            event_occurred_at = _to_str(normalized_row.get(occurred_at_column or "")) if occurred_at_column else None
            if event_occurred_at is None:
                event_occurred_at = _pick_first_non_empty(
                    normalized_row,
                    ["occurred_at", "event_time", "timestamp", "攻击时间", "时间", "发生时间"],
                )

            event_rule_id = _to_str(normalized_row.get(rule_id_column or "")) if rule_id_column else None
            if event_rule_id is None:
                event_rule_id = _pick_first_non_empty(
                    normalized_row,
                    ["rule_id", "规则ID", "rule", "规则名", "威胁情报"],
                )

            events.append(
                {
                    "raw_event_id": raw_event_id,
                    "source": source,
                    "vendor": event_vendor or "unknown_vendor",
                    "product": event_product or "unknown_product",
                    "log_type": event_log_type or "csv_row",
                    "rule_id": event_rule_id,
                    "occurred_at": event_occurred_at,
                    "payload": {
                        "row": normalized_row,
                        "csv_metadata": {
                            "job_id": active_job_id,
                            "row_number": idx,
                            "file_name": file_name or csv_real_path.name,
                        },
                    },
                }
            )

    ingest_result = ingest_raw_alert_bundle(db_path=db_path, events=events, source=source)

    conn = connect_db(db_path)
    create_schema(conn)
    try:
        conn.execute(
            """
            insert into import_jobs (
              job_id, source, file_name, file_hash, status, total_rows, mapped_rows, unmapped_rows,
              pending_rows, error_rows, last_map_id, created_at, updated_at, notes_json
            ) values (?, ?, ?, ?, 'uploaded', ?, 0, 0, ?, 0, null, ?, ?, ?)
            on conflict(job_id) do update set
              source = excluded.source,
              file_name = excluded.file_name,
              file_hash = excluded.file_hash,
              status = excluded.status,
              total_rows = excluded.total_rows,
              mapped_rows = excluded.mapped_rows,
              unmapped_rows = excluded.unmapped_rows,
              pending_rows = excluded.pending_rows,
              error_rows = excluded.error_rows,
              updated_at = excluded.updated_at,
              notes_json = excluded.notes_json
            """,
            (
                active_job_id,
                source,
                file_name or csv_real_path.name,
                file_hash,
                len(events),
                len(events),
                now,
                now,
                _safe_json_dumps(
                    {
                        "field_names": field_names,
                        "csv_path": str(csv_real_path),
                    }
                ),
            ),
        )
        metrics = _refresh_import_job_metrics(conn, active_job_id)
        conn.commit()
        row = _get_import_job_row(conn, active_job_id)
        job = _serialize_import_job(row)
    finally:
        conn.close()

    return {
        "job": job,
        "ingest_result": ingest_result,
        "metrics": metrics,
    }


def list_import_jobs(
    db_path: Path,
    *,
    limit: int = 20,
    statuses: list[str] | None = None,
) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    params: list[Any] = []
    where_sql = ""
    if statuses:
        normalized = [str(item).strip().lower() for item in statuses if str(item).strip()]
        if normalized:
            placeholders = ", ".join("?" for _ in normalized)
            where_sql = f"where lower(status) in ({placeholders})"
            params.extend(normalized)
    rows = conn.execute(
        f"""
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
        {where_sql}
        order by updated_at desc, created_at desc
        limit ?
        """,
        (*params, max(1, limit)),
    ).fetchall()
    items = [_serialize_import_job(row) for row in rows]
    conn.close()
    return {"items": items}


def sample_import_job(
    db_path: Path,
    *,
    job_id: str,
    limit_groups: int = 20,
    samples_per_group: int = 3,
    statuses: list[str] | None = None,
) -> dict[str, Any]:
    source = _job_source(job_id)
    sampled = sample_raw_alert_groups(
        db_path=db_path,
        limit_groups=limit_groups,
        samples_per_group=samples_per_group,
        statuses=statuses or ["pending", "unmapped", "error"],
        source=source,
    )
    conn = connect_db(db_path)
    try:
        row = _get_import_job_row(conn, job_id)
        job = _serialize_import_job(row)
    finally:
        conn.close()
    return {"job": job, **sampled}


def apply_import_job_mapping(
    db_path: Path,
    *,
    job_id: str,
    limit: int = 500,
    dry_run: bool = False,
    include_unmapped: bool = False,
    raw_event_ids: list[str] | None = None,
) -> dict[str, Any]:
    source = _job_source(job_id)
    apply_result = apply_alert_normalization_maps(
        db_path=db_path,
        limit=limit,
        source=source,
        raw_event_ids=raw_event_ids,
        include_unmapped=include_unmapped,
        dry_run=dry_run,
    )

    conn = connect_db(db_path)
    create_schema(conn)
    try:
        _get_import_job_row(conn, job_id)
        if not dry_run:
            map_row = conn.execute(
                """
                select map_id
                from raw_alert_events
                where source = ? and map_id is not null
                order by mapped_at desc
                limit 1
                """,
                (source,),
            ).fetchone()
            conn.execute(
                """
                update import_jobs
                set last_map_id = coalesce(?, last_map_id), updated_at = ?
                where job_id = ?
                """,
                ((map_row["map_id"] if map_row else None), _now_iso(), job_id),
            )
            metrics = _refresh_import_job_metrics(conn, job_id)
            conn.commit()
        else:
            metrics = {}
        row = _get_import_job_row(conn, job_id)
        job = _serialize_import_job(row)
    finally:
        conn.close()

    return {"job": job, "apply_result": apply_result, "metrics": metrics}


def list_import_job_problem_rows(
    db_path: Path,
    *,
    job_id: str,
    limit: int = 100,
) -> dict[str, Any]:
    source = _job_source(job_id)
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        row = _get_import_job_row(conn, job_id)
        job = _serialize_import_job(row)
        rows = conn.execute(
            """
            select
              raw_alert_events.raw_event_id,
              raw_alert_events.map_status,
              raw_alert_events.map_id,
              raw_alert_events.map_reason,
              raw_alert_events.occurred_at,
              raw_alert_events.payload_json,
              raw_alert_events.mapped_at,
              unmapped_alert_events.reason as unmapped_reason,
              unmapped_alert_events.details_json as unmapped_details_json,
              unmapped_alert_events.hit_count as unmapped_hit_count,
              unmapped_alert_events.resolved as unmapped_resolved
            from raw_alert_events
            left join unmapped_alert_events
              on unmapped_alert_events.raw_event_id = raw_alert_events.raw_event_id
            where raw_alert_events.source = ?
              and raw_alert_events.map_status in ('unmapped', 'error')
            order by raw_alert_events.ingested_at asc, raw_alert_events.raw_event_id asc
            limit ?
            """,
            (source, max(1, limit)),
        ).fetchall()
        items: list[dict[str, Any]] = []
        for item in rows:
            items.append(
                {
                    "raw_event_id": item["raw_event_id"],
                    "map_status": item["map_status"],
                    "map_id": item["map_id"],
                    "map_reason": item["map_reason"],
                    "occurred_at": item["occurred_at"],
                    "payload": _safe_json_loads(item["payload_json"], {}),
                    "mapped_at": item["mapped_at"],
                    "unmapped_reason": item["unmapped_reason"],
                    "unmapped_details": _safe_json_loads(item["unmapped_details_json"], {}),
                    "unmapped_hit_count": int(item["unmapped_hit_count"] or 0),
                    "unmapped_resolved": bool(item["unmapped_resolved"] or 0),
                }
            )
    finally:
        conn.close()
    return {"job": job, "items": items}
