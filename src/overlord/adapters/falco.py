from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping
from uuid import NAMESPACE_URL, uuid5

from ..models import Fact, Provenance, Source
from .wazuh import encode_payload, parse_timestamp

PRIORITY_CONFIDENCE: dict[str, float] = {
    "Emergency": 1.0,
    "Alert": 0.95,
    "Critical": 0.9,
    "Error": 0.8,
    "Warning": 0.6,
    "Notice": 0.5,
    "Informational": 0.3,
    "Debug": 0.2,
}
TAG_HINTS: tuple[tuple[str, str], ...] = (
    ("shell", "process_creation"),
    ("exec", "process_creation"),
    ("network", "network_connection"),
    ("connect", "network_connection"),
    ("file", "file_access"),
    ("open", "file_access"),
    ("mount", "privilege_escalation"),
    ("login", "authentication"),
    ("user", "authentication"),
)


def _tags(raw: Mapping[str, Any]) -> list[str]:
    text = f"{raw.get('rule', '')} {raw.get('output', '')}".lower()
    for hint, tag in TAG_HINTS:
        if hint in text:
            return [tag]
    return ["process_creation"]


class FalcoAdapter:
    def normalize(self, raw: Mapping[str, Any], now: datetime) -> Fact:
        fields = raw.get("output_fields") or {}
        rule = str(raw.get("rule") or "falco")
        timestamp = parse_timestamp(raw.get("time"), now)
        fact_id = uuid5(
            NAMESPACE_URL,
            f"falco:{rule}:{raw.get('time', '')}:{raw.get('output', '')}",
        )
        host = str(
            fields.get("k8s.pod.name")
            or fields.get("hostname")
            or fields.get("container.name")
            or "falco"
        )
        return Fact(
            fact_id=fact_id,
            source=Source.FALCO,
            timestamp=timestamp,
            raw_payload=encode_payload(raw),
            normalized_tags=_tags(raw),
            confidence=PRIORITY_CONFIDENCE.get(str(raw.get("priority")), 0.5),
            provenance=Provenance(
                collector_id="falco",
                host_id=host,
                sensor_uid=str(fields.get("container.id") or "falco"),
            ),
            created_by="falco-s1-ingest",
        )
