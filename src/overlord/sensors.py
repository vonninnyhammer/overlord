from __future__ import annotations

import base64
from datetime import datetime
from typing import Any, Mapping
from uuid import NAMESPACE_URL, uuid5

from .adapters import FalcoAdapter, WazuhAdapter, ZeekAdapter
from .adapters.wazuh import parse_timestamp
from .models import MAX_RAW_PAYLOAD_BYTES, Fact, Provenance, Source

SUPPORTED_SOURCES = frozenset({"wazuh", "falco", "zeek"})


def _source(value: Any) -> Source:
    try:
        return Source(str(value))
    except ValueError:
        return Source.HUMAN


class FallbackSensor:
    def normalize(self, raw: Mapping[str, Any], now: datetime) -> Fact:
        text = str(raw.get("message") or raw)
        raw_stamp = raw.get("@timestamp") or raw.get("timestamp") or raw.get("time")
        stamp = parse_timestamp(raw_stamp, now)
        data = text.encode("utf-8", "replace")[:MAX_RAW_PAYLOAD_BYTES]
        return Fact(
            fact_id=uuid5(NAMESPACE_URL, f"fallback:{raw_stamp}:{text[:200]}"),
            source=_source(raw.get("source", Source.HUMAN.value)),
            timestamp=stamp,
            raw_payload=base64.b64encode(data).decode("ascii"),
            normalized_tags=["process_creation"],
            confidence=0.3,
            provenance=Provenance(
                collector_id="fallback",
                host_id="fallback",
                sensor_uid="fallback",
            ),
            created_by="fallback",
        )


def sensor_factory(source: str) -> Any:
    key = (source or "").strip().lower()
    if key == "wazuh":
        return WazuhAdapter()
    if key == "falco":
        return FalcoAdapter()
    if key == "zeek":
        return ZeekAdapter()
    return FallbackSensor()
