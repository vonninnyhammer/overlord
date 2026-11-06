"""Hypothesis tier floor, expiry of unapproved Tier 1 decisions, and safe cancel."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from overlord.gates import assign_tier
from overlord.pending import PendingStore
from overlord.pipeline import OverlordPipeline


def events(n=3, tag="authentication", source="wazuh"):
    return [
        {"message": f"evt {i}", "source": source, "normalized_tags": [tag], "confidence": 0.9}
        for i in range(n)
    ]


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from overlord import api

    monkeypatch.setattr(api, "_PENDING", PendingStore(tmp_path / "pending.json"))
    monkeypatch.delenv("OVERLORD_API_TOKEN", raising=False)
    monkeypatch.delenv("OVERLORD_ALLOW_INLINE_APPROVAL", raising=False)
    return TestClient(api.app), api


@pytest.mark.parametrize(
    "hypothesis, asset_class, tier",
    [
        ("credential_access", "endpoint_workstation", 1),
        ("exfiltration", "production_server", 1),
        ("command_and_control", "endpoint_workstation", 0),
        ("credential_access", "perimeter_firewall_ip", 0),  # no Tier 1 there: refused, not silently Tier 0
    ],
)
def test_hypothesis_sets_minimum_tier(hypothesis, asset_class, tier):
    a = assign_tier(0, asset_class, hypothesis=hypothesis)
    if asset_class == "perimeter_firewall_ip":
        assert not a.permitted
    else:
        assert a.permitted and a.resolved_tier == tier
    assert a.requested_tier == 0


def test_caller_can_still_ask_for_a_higher_tier():
    assert assign_tier(2, "production_server", hypothesis="command_and_control").resolved_tier == 2


def test_tier0_request_for_credential_attack_waits_for_approval():
    result = OverlordPipeline().run_incident(events(), requested_tier=0, asset_class="endpoint_workstation")
    assert result.tier.resolved_tier == 1
    assert (result.blocked_at, result.error) == ("S7", "awaiting_approval")
    assert not result.applied


def test_tier0_still_autonomous_for_c2():
    result = OverlordPipeline().run_incident(
        events(tag="network_connection"), requested_tier=0, asset_class="endpoint_workstation"
    )
    assert result.tier.resolved_tier == 0 and result.applied


def test_unapproved_tier1_is_expired_and_cleared(client):
    http, api = client
    r = http.post("/pipeline/run", json={"telemetry": events(), "requested_tier": 1}).json()
    decision_id = r["summary"]["decision_id"]
    assert api._PENDING.get(decision_id) is not None
    # Age the parked decision past its 60 s window.
    item = api._PENDING.get(decision_id)
    old = datetime.now(timezone.utc) - timedelta(seconds=120)
    item["decision"]["created_at"] = old.isoformat()
    listing = http.get("/pipeline/pending").json()
    assert decision_id in listing["expired"]
    assert all(p["decision_id"] != decision_id for p in listing["pending"])


def test_fresh_tier1_is_not_expired(client):
    http, api = client
    r = http.post("/pipeline/run", json={"telemetry": events(), "requested_tier": 1}).json()
    listing = http.get("/pipeline/pending").json()
    assert listing["expired"] == []
    assert [p["decision_id"] for p in listing["pending"]] == [r["summary"]["decision_id"]]
    assert listing["pending"][0]["asset_class"] == "endpoint_workstation"


def test_failed_cancel_keeps_the_decision(client, monkeypatch):
    http, api = client
    r = http.post("/pipeline/run", json={"telemetry": events(), "requested_tier": 1}).json()
    decision_id = r["summary"]["decision_id"]

    def boom(*args, **kwargs):
        raise RuntimeError("ledger down")

    monkeypatch.setattr(OverlordPipeline, "resume", boom)
    with pytest.raises(RuntimeError):
        http.post(f"/pipeline/cancel/{decision_id}")
    assert api._PENDING.get(decision_id) is not None


def test_resumed_result_keeps_asset_class(client):
    http, api = client
    r = http.post("/pipeline/run", json={"telemetry": events(), "requested_tier": 1}).json()
    out = http.post(f"/pipeline/approve/{r['summary']['decision_id']}").json()
    assert out["result"]["tier"]["asset_class"] == "endpoint_workstation"
    assert out["summary"]["status"] == "applied"


# --- shared throttle, circuit breaker, triangulation, generic sensor

from overlord.models import ConclusionSubmission, Hypothesis  # noqa: E402
from overlord.pipeline import DefaultAnalyst  # noqa: E402
from overlord.runtime import RuntimeState  # noqa: E402


def test_throttle_is_shared_between_pipelines():
    runtime = RuntimeState()
    for _ in range(3):
        assert runtime.acquire("hermes", 3) is not None
    result = OverlordPipeline(runtime=runtime).run_incident(events())
    assert (result.blocked_at, result.error) == ("S3", "throttled")


def test_api_pipelines_share_one_runtime():
    from overlord import api
    assert api._pipeline().runtime is api._pipeline().runtime is api._RUNTIME


def test_circuit_breaker_freezes_tier1_after_five_runs():
    now = [datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)]
    runtime = RuntimeState()
    p = OverlordPipeline(runtime=runtime, clock=lambda: now[0], executor=None)
    for i in range(5):
        r = p.run_incident(events(tag="authentication"), requested_tier=1,
                           asset_class="production_server", approve=True)
        assert r.applied, r.error
        now[0] += timedelta(seconds=10)
    assert runtime.tier1_frozen(now[0])
    # While frozen, Tier 1 on a server is raised to Tier 2 (needs a named authorizer) ...
    r = p.run_incident(events(), requested_tier=1, asset_class="production_server", approve=True)
    assert r.tier.resolved_tier == 2 and r.error == "authorization_required"
    # ... and a workstation, which has no Tier 2, is refused.
    r = p.run_incident(events(), requested_tier=1, asset_class="endpoint_workstation", approve=True)
    assert (r.blocked_at, r.error) == ("S6", "circuit_breaker_open")
    # After the 15-minute freeze, Tier 1 works again.
    now[0] += timedelta(seconds=901)
    r = p.run_incident(events(), requested_tier=1, asset_class="production_server", approve=True)
    assert r.applied


def test_breaker_counts_only_runs_inside_the_window():
    now = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)
    runtime = RuntimeState()
    for i in range(10):
        assert not runtime.record_tier1_run(now + timedelta(seconds=100 * i))
    assert not runtime.tier1_frozen(now + timedelta(seconds=1000))


def test_disagreeing_conclusions_do_not_triangulate():
    class Fickle(DefaultAnalyst):
        hyps = iter([Hypothesis.CREDENTIAL_ACCESS, Hypothesis.CREDENTIAL_ACCESS, Hypothesis.DISCOVERY])

        def analyse(self, request, facts):
            c = super().analyse(request, facts)
            return c.model_copy(update={"hypothesis": next(self.hyps)})

    r = OverlordPipeline(analyst=Fickle()).run_incident(events(), requested_tier=1)
    assert (r.blocked_at, r.error) == ("S5", "need_at_least_3_conclusions_for_justification")


def test_agreeing_conclusions_from_three_facts_triangulate():
    r = OverlordPipeline().run_incident(events(), requested_tier=1)
    assert r.blocked_at == "S7" and len(set(r.triggers.values())) == 3


def test_generic_sensor_ignores_caller_fact_id_and_caps_confidence():
    same = [{"message": "evt", "source": "wazuh", "normalized_tags": ["authentication"],
             "fact_id": str(__import__("uuid").uuid4()), "confidence": 1.0, "created_by": "me"} for _ in range(3)]
    r = OverlordPipeline().run_incident(same, stop_after="S1")
    assert len(r.facts) == 1  # three replays with made-up ids still collapse to one fact
    fact = next(iter(r.facts.values()))
    assert fact.confidence == 0.9 and fact.created_by == "s1_ingest"
