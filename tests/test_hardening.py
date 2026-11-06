"""Regression tests for failures found by adversarial review."""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from overlord.authz import env_authorizer
from overlord.models import DecisionOutcome, DecisionStatus
from overlord.pending import PendingStore
from overlord.pipeline import DefaultAnalyst, OverlordPipeline
from overlord.sanitize import sanitize_telemetry
from overlord.sensors import sensor_factory

FIXED = datetime(2026, 1, 1, tzinfo=timezone.utc)
DIGEST = hashlib.sha256(b"correct-token").hexdigest()


def events(n=3, tag="authentication", source="wazuh"):
    return [
        {"message": f"evt {i}", "source": source, "normalized_tags": [tag], "confidence": 0.9}
        for i in range(n)
    ]


class Recorder:
    def __init__(self):
        self.calls = 0

    def execute(self, decision):
        self.calls += 1
        return DecisionOutcome.SUCCESS


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from overlord import api

    monkeypatch.setattr(api, "_PENDING", PendingStore(tmp_path / "pending.json"))
    monkeypatch.delenv("OVERLORD_API_TOKEN", raising=False)
    monkeypatch.delenv("OVERLORD_ALLOW_INLINE_APPROVAL", raising=False)
    monkeypatch.delenv("OVERLORD_TIER2_AUTHORIZERS", raising=False)
    return TestClient(api.app)


def test_replayed_identical_events_do_not_count_as_support():
    same = {"message": "same", "source": "wazuh", "normalized_tags": ["authentication"], "confidence": 0.9}
    result = OverlordPipeline().run_incident([same] * 3, approve=True)
    assert len(result.facts) == 1
    assert not result.applied


def test_independent_source_requirement_blocks_single_source():
    result = OverlordPipeline(min_independent_sources=2).run_incident(events(), approve=True)
    assert result.error == "insufficient_independent_sources"
    assert result.decision is None


def test_independent_source_requirement_accepts_two_sources():
    telemetry = events(2) + events(1, source="zeek")
    telemetry[2]["message"] = "zeek evt"
    result = OverlordPipeline(min_independent_sources=2).run_incident(telemetry, approve=True)
    assert result.applied


def test_arbitrary_string_cannot_authorize_tier2(monkeypatch):
    monkeypatch.delenv("OVERLORD_TIER2_AUTHORIZERS", raising=False)
    result = OverlordPipeline().run_incident(
        events(), requested_tier=2, asset_class="medical_workstation", authorization="x"
    )
    assert result.error == "authorization_invalid"
    assert not result.applied


def test_env_authorizer_verifies_token_and_records_identity(monkeypatch):
    monkeypatch.setenv("OVERLORD_TIER2_AUTHORIZERS", json.dumps({"dr-lee": DIGEST}))
    assert env_authorizer("wrong") is None
    result = OverlordPipeline().run_incident(
        events(), requested_tier=2, asset_class="medical_workstation", authorization="correct-token"
    )
    assert result.applied
    assert result.decision.approved_by == "dr-lee"


def test_malformed_authorizer_config_fails_closed(monkeypatch):
    monkeypatch.setenv("OVERLORD_TIER2_AUTHORIZERS", "{not json")
    assert env_authorizer("correct-token") is None


def test_api_refuses_self_approval(client):
    body = {"telemetry": events(), "requested_tier": 2, "asset_class": "hypervisor"}
    assert client.post("/pipeline/run", json={**body, "authorization": "x"}).status_code == 400
    assert client.post("/pipeline/run", json={"telemetry": events(), "approve": True}).status_code == 400


def test_tier2_waits_for_a_human_and_can_be_approved_later(client, monkeypatch):
    monkeypatch.setenv("OVERLORD_TIER2_AUTHORIZERS", json.dumps({"dr-lee": DIGEST}))
    body = {"telemetry": events(), "requested_tier": 2, "asset_class": "hypervisor"}
    run = client.post("/pipeline/run", json=body).json()
    assert run["summary"]["error"] == "authorization_required"
    pending = client.get("/pipeline/pending").json()["pending"]
    assert len(pending) == 1
    decision_id = pending[0]["decision_id"]

    denied = client.post(f"/pipeline/approve/{decision_id}", json={"authorization": "guess"})
    assert denied.status_code == 403
    assert len(client.get("/pipeline/pending").json()["pending"]) == 1

    approved = client.post(f"/pipeline/approve/{decision_id}", json={"authorization": "correct-token"})
    assert approved.json()["summary"]["status"] == "applied"
    assert approved.json()["result"]["decision"]["approved_by"] == "dr-lee"
    assert client.post(f"/pipeline/approve/{decision_id}", json={"authorization": "correct-token"}).status_code == 404


def test_api_token_is_enforced_when_set(client, monkeypatch):
    monkeypatch.setenv("OVERLORD_API_TOKEN", "s3cret-value")
    body = {"telemetry": events(), "stop_after": "S2"}
    assert client.post("/pipeline/run", json=body).status_code == 401
    assert client.get("/pipeline/pending").status_code == 401
    headers = {"Authorization": "Bearer s3cret-value"}
    assert client.post("/pipeline/run", json=body, headers=headers).status_code == 200
    assert client.get("/health").status_code == 200


def test_unknown_stop_after_never_reaches_execution(client):
    executor = Recorder()
    with pytest.raises(ValueError):
        OverlordPipeline(executor=executor).run_incident(events(), approve=True, stop_after="s2")
    assert executor.calls == 0
    assert client.post("/pipeline/run", json={"telemetry": events(), "stop_after": "s2"}).status_code == 422


@pytest.mark.parametrize("stage,last", [("S1", "S1"), ("S2", "S2"), ("S7", "S7")])
def test_stop_after_stops_at_that_stage_without_acting(stage, last):
    executor = Recorder()
    result = OverlordPipeline(executor=executor).run_incident(
        events(), requested_tier=0, asset_class="production_server", stop_after=stage
    )
    assert executor.calls == 0
    assert result.events[-1]["metadata"]["stage"] == last
    assert not result.applied


def test_tier0_really_calls_the_executor():
    executor = Recorder()
    result = OverlordPipeline(executor=executor).run_incident(
        events(), requested_tier=0, asset_class="production_server"
    )
    assert executor.calls == 1
    assert result.applied


def test_analyst_never_sees_raw_identifiers():
    seen = {}

    class Spy(DefaultAnalyst):
        def analyse(self, request, facts):
            seen["request"] = request
            seen["facts"] = facts
            return super().analyse(request, facts)

    telemetry = [
        {
            "message": f"admin from 10.1.2.3 via secret.corp.example.com {i}",
            "source": "wazuh",
            "normalized_tags": ["authentication"],
            "confidence": 0.9,
            "host_id": "dc01.corp.example.com",
        }
        for i in range(3)
    ]
    result = OverlordPipeline(analyst=Spy()).run_incident(telemetry)
    decoded = " ".join(
        base64.b64decode(fact["raw_payload"]).decode() for fact in seen["request"]["facts"]
    )
    blob = decoded + json.dumps(seen["request"]) + " ".join(f.provenance.host_id for f in seen["facts"])
    assert "10.1.2.3" not in blob
    assert "corp.example" not in blob
    # The original stays intact for forensics.
    original = next(iter(result.facts.values()))
    assert "10.1.2.3" in base64.b64decode(original.raw_payload).decode()


@pytest.mark.parametrize(
    "text,forbidden",
    [
        ("from 2001:db8::1 ok", "2001:db8"),
        ("mapped ::ffff:10.0.0.1 ok", "10.0.0.1"),
        ("user alice.smith@corp.example", "alice.smith"),
        ("host DC01-FIN rebooted", "DC01-FIN"),
        ("GET https://evil.example/a?token=abc123", "abc123"),
        ("key AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP"),
        ("password=hunter2 sent", "hunter2"),
        ('{"api_key": "abc12345"}', "abc12345"),
        ("Authorization: Bearer abcdef123456", "abcdef123456"),
        ("C:\\Users\\jsmith\\x.txt", "jsmith"),
        ("/home/jsmith/.ssh", "jsmith"),
        ("mac aa-bb-cc-dd-ee-ff", "aa-bb"),
    ],
)
def test_sanitizer_redacts(text, forbidden):
    assert forbidden not in sanitize_telemetry(text).text


@pytest.mark.parametrize(
    "text",
    ["seen at 12:30:45 today", "technique T1078 and CVE-2024-1234", "rule 5712 level 12", "host is down", "protocol 1.2"],
)
def test_sanitizer_keeps_useful_analysis_text(text):
    assert sanitize_telemetry(text).text == text


def test_same_input_always_gives_same_hypothesis():
    telemetry = events(1) + events(1, "data_exfiltration") + events(1, "file_access")
    telemetry[1]["message"], telemetry[2]["message"] = "b", "c"
    seen = set()
    for _ in range(50):
        result = OverlordPipeline(clock=lambda: FIXED).run_incident(telemetry, approve=True)
        seen.add(next(iter(result.conclusions.values())).hypothesis.value)
    assert seen == {"exfiltration"}


def test_analyst_failure_blocks_cleanly():
    class Broken:
        def analyse(self, request, facts):
            raise ValueError("model returned junk")

    pipeline = OverlordPipeline(analyst=Broken())
    result = pipeline.run_incident(events())
    assert result.blocked_at == "S4"
    assert result.error == "analyst_error"
    assert pipeline._in_flight[pipeline.requesting_agent] == 0


def test_executor_failure_is_recorded_not_lost():
    class Down:
        def execute(self, decision):
            raise RuntimeError("edr down")

    result = OverlordPipeline(executor=Down()).run_incident(events(), approve=True)
    assert result.decision.status == DecisionStatus.FAILED
    assert result.outcome == DecisionOutcome.ESCALATED
    assert result.events[-1]["metadata"]["stage"] == "S9"
    assert result.audit_errors == ["executor: RuntimeError"]


def test_unknown_source_blocks_instead_of_crashing(client):
    response = client.post("/pipeline/run", json={"telemetry": [{"source": "sim", "message": "x"}]})
    assert response.status_code == 200
    assert response.json()["summary"]["error"] == "invalid_telemetry"


def test_ledger_failure_is_not_reported_as_recorded():
    class Full:
        def __getattr__(self, name):
            def fail(*args):
                raise OSError("disk full")

            return fail

    result = OverlordPipeline(store=Full()).run_incident(events(), approve=True)
    assert result.error == "ledger_write_failed"
    assert "NOT recorded" in result.events[-1]["body"]
    assert "record_decision: OSError" in result.audit_errors


class Ledger:
    def __init__(self):
        self.decisions = []

    def record_fact(self, payload):
        pass

    def record_conclusion(self, payload):
        pass

    def record_decision(self, payload):
        self.decisions.append(payload)


def test_cancelled_decision_reaches_the_ledger():
    ledger = Ledger()
    result = OverlordPipeline(store=ledger).run_incident(events(), approve=False)
    assert result.error == "cancelled"
    assert [d["status"] for d in ledger.decisions] == ["rolled_back"]


def test_real_wazuh_alert_shape():
    alert = {
        "id": "1700",
        "timestamp": "2026-02-03T04:05:06.000+0000",
        "rule": {"level": 12, "id": "5712", "description": "brute force"},
        "agent": {"id": "001", "name": "web"},
    }
    fact = sensor_factory("wazuh").normalize(alert, FIXED)
    assert fact.confidence == pytest.approx(0.8)
    assert fact.timestamp == datetime(2026, 2, 3, 4, 5, 6, tzinfo=timezone.utc)


def test_asset_inventory_rejects_false_asset_class():
    executor = Recorder()
    result = OverlordPipeline(
        executor=executor, asset_inventory={"med-7": "medical_workstation"}
    ).run_incident(
        events(), requested_tier=0, asset_class="perimeter_firewall_ip", target_asset="med-7"
    )
    assert result.error == "asset_class_mismatch"
    assert executor.calls == 0


def test_inspection_runs_do_not_leak_throttle_slots():
    pipeline = OverlordPipeline()
    for _ in range(5):
        result = pipeline.run_incident(events(), stop_after="S3")
    assert result.error is None


def test_corrupt_pending_file_is_preserved(tmp_path):
    path = tmp_path / "pending.json"
    path.write_text("{bad")
    assert PendingStore(path).all() == []
    assert list(tmp_path.glob("pending.json.corrupt-*"))


def test_claim_gives_a_decision_to_one_caller_only(tmp_path):
    store = PendingStore(tmp_path / "pending.json")
    store._items["d"] = {"decision": {}}
    assert store.claim("d") is not None
    assert store.claim("d") is None


def test_api_refuses_requests_without_configured_token(client, monkeypatch):
    monkeypatch.delenv("OVERLORD_ALLOW_UNAUTHENTICATED", raising=False)
    monkeypatch.delenv("OVERLORD_API_TOKEN", raising=False)
    assert client.get("/pipeline/pending").status_code == 503
    assert client.get("/health").status_code == 200


def test_default_requires_two_independent_sources(monkeypatch):
    monkeypatch.delenv("OVERLORD_MIN_INDEPENDENT_SOURCES", raising=False)
    assert OverlordPipeline().min_independent_sources == 2
