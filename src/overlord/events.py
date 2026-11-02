from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Mapping
from uuid import uuid4


class EventType(str, Enum):
    TASK_REQUEST = "task.request"
    TASK_REPLY = "task.reply"
    PATCH_READY = "patch.ready"
    EVENT_ACK = "event.ack"
    PIPELINE_STAGE = "pipeline.stage"


class EventStatus(str, Enum):
    OPEN = "open"
    CLAIMED = "claimed"
    READY = "ready"
    APPLIED = "applied"
    BLOCKED = "blocked"
    FAILED = "failed"
    SUPERSEDED = "superseded"


def build_event(
    event_type: EventType | str,
    stream: str,
    room: str,
    from_agent: str,
    to_agent: str | None = None,
    correlation_id: str | None = None,
    status: EventStatus | str | None = None,
    body: str | None = None,
    metadata: Mapping[str, Any] | None = None,
    artifact_ids: Iterable[str] = (),
    event_id: str | None = None,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    kind = EventType(event_type) if not isinstance(event_type, EventType) else event_type
    event: dict[str, Any] = {
        "event_id": event_id or str(uuid4()),
        "type": kind.value,
        "stream": stream,
        "room": room,
        "from_agent": from_agent,
        "to_agent": to_agent,
        "correlation_id": correlation_id,
        "status": (EventStatus(status).value if status is not None else None),
        "body": body,
        "metadata": dict(metadata or {}),
        "artifact_ids": list(artifact_ids),
        "created_at": (created_at or datetime.now(timezone.utc)).isoformat(),
    }
    return event


def build_ack(
    event: Mapping[str, Any],
    from_agent: str,
    status: EventStatus | str | None = None,
    body: str | None = None,
) -> dict[str, Any]:
    return build_event(
        event_type=EventType.EVENT_ACK,
        stream=str(event["stream"]),
        room=str(event["room"]),
        from_agent=from_agent,
        to_agent=str(event["from_agent"]),
        correlation_id=event.get("correlation_id"),
        status=status if status is not None else event.get("status"),
        body=body,
        metadata={"target_event_id": event["event_id"]},
        artifact_ids=event.get("artifact_ids") or (),
    )


def pair_requests_and_replies(
    events: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    requests: dict[str, Mapping[str, Any]] = {}
    replies: dict[str, list[Mapping[str, Any]]] = {}
    acks: dict[str, list[Mapping[str, Any]]] = {}

    for event in events:
        correlation = event.get("correlation_id")
        kind = event.get("type")
        if not correlation:
            continue
        if kind == EventType.TASK_REQUEST.value:
            requests[correlation] = event
        elif kind == EventType.TASK_REPLY.value:
            replies.setdefault(correlation, []).append(event)
        elif kind == EventType.EVENT_ACK.value:
            target = (event.get("metadata") or {}).get("target_event_id")
            if target:
                acks.setdefault(target, []).append(event)

    correlations = set(requests) | set(replies)
    unmatched_requests = sorted(c for c in requests if not replies.get(c))
    orphan_replies = sorted(c for c in replies if c not in requests)
    duplicate_replies = sorted(c for c, r in replies.items() if len(r) > 1)

    return {
        "correlations": sorted(correlations),
        "requests": requests,
        "replies": replies,
        "acks": acks,
        "unmatched_requests": unmatched_requests,
        "orphan_replies": orphan_replies,
        "duplicate_replies": duplicate_replies,
        "balanced": not unmatched_requests and not orphan_replies and not duplicate_replies,
    }
