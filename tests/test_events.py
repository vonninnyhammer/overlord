from __future__ import annotations

from overlord.events import (
    EventStatus,
    EventType,
    build_ack,
    build_event,
    pair_requests_and_replies,
)


def request_event(correlation: str = "req-1") -> dict:
    return build_event(
        EventType.TASK_REQUEST,
        stream="overlord/incident-1",
        room="pipeline-events",
        from_agent="n8n",
        to_agent="hermes_incident_cmdr_01",
        correlation_id=correlation,
        status=EventStatus.OPEN,
        body="analyse host-42",
    )


def reply_event(correlation: str = "req-1") -> dict:
    return build_event(
        EventType.TASK_REPLY,
        stream="overlord/incident-1",
        room="pipeline-events",
        from_agent="hermes_incident_cmdr_01",
        to_agent="n8n",
        correlation_id=correlation,
        status=EventStatus.READY,
        body='{"conclusion_id":"c1"}',
    )


def test_build_event_populates_rfc_fields():
    event = request_event()
    assert event["event_id"]
    assert event["type"] == "task.request"
    assert event["correlation_id"] == "req-1"
    assert event["status"] == "open"
    assert event["created_at"].endswith("+00:00") or event["created_at"].endswith("Z")


def test_ack_routes_back_without_mutating_target():
    original = request_event()
    snapshot = dict(original)
    ack = build_ack(original, from_agent="hermes_incident_cmdr_01")
    assert ack["type"] == "event.ack"
    assert ack["to_agent"] == "n8n"
    assert ack["correlation_id"] == original["correlation_id"]
    assert ack["metadata"]["target_event_id"] == original["event_id"]
    assert original == snapshot


def test_pairing_reports_balanced_chain():
    events = [
        request_event("req-1"),
        reply_event("req-1"),
        build_ack(request_event("req-1"), from_agent="hermes"),
    ]
    result = pair_requests_and_replies(events)
    assert "req-1" in result["correlations"]
    assert result["duplicate_replies"] == []
    assert result["orphan_replies"] == []


def test_pairing_flags_unmatched_request():
    result = pair_requests_and_replies([request_event("req-2")])
    assert result["unmatched_requests"] == ["req-2"]
    assert result["balanced"] is False


def test_pairing_flags_orphan_reply():
    result = pair_requests_and_replies([reply_event("req-ghost")])
    assert result["orphan_replies"] == ["req-ghost"]


def test_pairing_flags_duplicate_replies():
    result = pair_requests_and_replies(
        [request_event("req-3"), reply_event("req-3"), reply_event("req-3")]
    )
    assert result["duplicate_replies"] == ["req-3"]
    assert result["balanced"] is False
