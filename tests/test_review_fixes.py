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
