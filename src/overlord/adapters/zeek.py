from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import NAMESPACE_URL, uuid5

from ..models import Fact, Provenance, Source
from .wazuh import encode_payload

PATH_TAGS: dict[str, str] = {
    "conn": "network_connection",
    "dns": "network_connection",
    "http": "network_connection",
    "ssl": "network_connection",
    "files": "file_access",
    "notice": "process_creation",
    "weird": "process_creation",
}


def _timestamp(value: Any, default: datetime) -> datetime:
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return default


class ZeekAdapter:
    def normalize(self, raw: Mapping[str, Any], now: datetime) -> Fact:
        path = str(raw.get("_path") or "conn")
        uid = str(raw.get("uid") or "")
        origin = str(raw.get("id.orig_h") or raw.get("host") or "zeek")
        identity = uid or f"{raw.get('ts', '')}:{origin}:{raw.get('id.resp_h', '')}"
        return Fact(
            fact_id=uuid5(NAMESPACE_URL, f"zeek:{path}:{identity}"),
            source=Source.ZEEK,
            timestamp=_timestamp(raw.get("ts"), now),
            raw_payload=encode_payload(raw),
            normalized_tags=[PATH_TAGS.get(path, "network_connection")],
            confidence=0.8 if path in {"notice", "weird"} else 0.6,
            provenance=Provenance(
                collector_id=str(raw.get("sensor") or "zeek"),
                host_id=origin,
                sensor_uid=str(raw.get("uid") or "zeek"),
            ),
            created_by="zeek-s1-ingest",
        )
