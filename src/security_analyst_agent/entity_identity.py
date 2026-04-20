from __future__ import annotations

import re

_IPV4_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IP_KEY_PREFIXES = ("ip:", "src_ip:", "source_ip:")


def looks_like_ipv4(value: str) -> bool:
    text = str(value or "").strip()
    return bool(_IPV4_PATTERN.fullmatch(text))


def normalize_ip_entity_key(entity_key: str) -> str:
    raw = str(entity_key or "").strip()
    if not raw:
        return ""
    lowered = raw.lower()
    for prefix in _IP_KEY_PREFIXES:
        if lowered.startswith(prefix):
            candidate = raw[len(prefix) :].strip()
            if looks_like_ipv4(candidate):
                return candidate
    if looks_like_ipv4(raw):
        return raw
    return raw


def normalize_entity_identity(entity_type: str, entity_key: str) -> tuple[str, str]:
    normalized_type = str(entity_type or "").strip().lower()
    normalized_key = str(entity_key or "").strip()
    if not normalized_key:
        return normalized_type or "ip", ""

    if normalized_type not in {"ip", "asset", "actor"}:
        normalized_type = "ip" if looks_like_ipv4(normalized_key) else "ip"

    if normalized_type == "ip":
        normalized_key = normalize_ip_entity_key(normalized_key)
    return normalized_type, normalized_key


def ip_entity_key_aliases(entity_key: str) -> list[str]:
    canonical = normalize_ip_entity_key(entity_key)
    if not canonical:
        return []
    aliases = [canonical]
    prefixed = [f"ip:{canonical}", f"src_ip:{canonical}", f"source_ip:{canonical}"]
    aliases.extend(prefixed)
    return list(dict.fromkeys(aliases))
