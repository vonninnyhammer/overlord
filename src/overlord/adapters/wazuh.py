from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import NAMESPACE_URL, uuid5

from ..models import MAX_RAW_PAYLOAD_BYTES, Fact, Provenance, Source

RULE_TAGS: dict[str, list[str]] = {
    "5710": ["authentication"],
    "5711": ["authentication", "suspicious_login"],
    "5712": ["authentication", "privilege_escalation"],
    "1001": ["privilege_escalation"],
    "1002": ["process_creation"],
    "8812": ["lateral_move"],
}
DEFAULT_TAGS = ["process_creation"]


def encode_payload(raw: Mapping[str, Any]) -> str:
    text = json.dumps(dict(raw), ensure_ascii=False, default=str)
    data = text.encode("utf-8")
    if len(data) > MAX_RAW_PAYLOAD_BYTES:
        data = data[:MAX_RAW_PAYLOAD_BYTES]
    return base64.b64encode(data).decode("ascii")


def parse_timestamp(value: Any, default: datetime) -> datetime:
    if not isinstance(value, str) or not value.strip():
        return default
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value.strip().replace("Z", "+00:00"))
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return default
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def coerce_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class WazuhAdapter:
    def normalize(self, raw: Mapping[str, Any], now: datetime) -> Fact:
        agent = raw.get("agent") or {}
        rule = raw.get("rule") or {}
        rule_id = str(rule.get("id", ""))
        stamp = raw.get("@timestamp") or raw.get("timestamp")
        alert_id = str(raw.get("id") or f"{rule_id}:{stamp or ''}")
        level = coerce_int(rule.get("level", raw.get("level")), 5)
        tags = RULE_TAGS.get(rule_id, DEFAULT_TAGS)
        return Fact(
            fact_id=uuid5(NAMESPACE_URL, f"wazuh:{alert_id}"),
            source=Source.WAZUH,
            timestamp=parse_timestamp(stamp, now),
            raw_payload=encode_payload(raw),
            normalized_tags=tags,
            confidence=min(1.0, max(0.1, level / 15)),
            provenance=Provenance(
                collector_id=str(raw.get("location") or "wazuh-manager"),
                host_id=str(agent.get("name") or agent.get("id") or "unknown"),
                sensor_uid=str(agent.get("id") or "unknown"),
            ),
            created_by="wazuh-s1-ingest",
        )
