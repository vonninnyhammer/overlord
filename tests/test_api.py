from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from overlord.api import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_schema_listing_and_lookup():
    listing = client.get("/schemas")
    assert "observed_fact" in listing.json()["schemas"]
    schema = client.get("/schemas/decision")
    assert schema.status_code == 200
    assert schema.json()["properties"]
    assert client.get("/schemas/missing").status_code == 404


def test_sanitize_endpoint():
    response = client.post("/sanitize", json={"text": "from 10.0.1.22"})
    assert response.status_code == 200
    assert response.json()["text"] == "from [REDACTED-ADDR]"
    assert response.json()["redactions"] == 1


def test_tier_endpoint_upgrades_medical_workstation():
    response = client.post(
        "/gates/tier",
        json={"requested_tier": 1, "asset_class": "medical_workstation"},
    )
    body = response.json()
    assert body["permitted"] is True
    assert body["resolved_tier"] == 2
    assert body["requires_human_authorization"] is True


def test_triangulation_endpoint_blocks_two_conclusions():
    response = client.post(
        "/gates/triangulation", json={"justification": ["c1", "c2"]}
    )
    body = response.json()
    assert body["ok"] is False
    assert body["error"] == "need_at_least_3_conclusions_for_justification"


def test_min_support_endpoint():
    payload = {
        "hypothesis": "discovery",
        "supporting_facts": ["f1", "f2"],
        "facts_by_id": {
            "f1": {"confidence": 0.9, "expires_at": None},
            "f2": {"confidence": 0.8, "expires_at": None},
        },
    }
    response = client.post("/gates/min-support", json=payload)
    assert response.json()["accepted"] is True
    assert response.json()["n_support"] == 2


def test_window_audit_endpoint():
    response = client.post(
        "/gates/window-audit",
        json={
            "evidence_summary": "x" * 100,
            "supporting_facts": ["f1", "f2", "f3"],
            "model_context_window": 8192,
        },
    )
    assert response.json()["passed"] is True


def test_validate_conclusion_accepts_permitted_payload():
    payload = {
        "conclusion_id": str(uuid4()),
        "confidence": 0.8,
        "hypothesis": "lateral_movement",
        "supporting_facts": [str(uuid4())],
        "evidence_summary": "SMB fan-out to three hosts",
    }
    response = client.post("/validate/conclusion", json=payload)
    assert response.status_code == 200
    assert response.json()["valid"] is True


def test_validate_conclusion_rejects_smuggled_field():
    payload = {
        "conclusion_id": str(uuid4()),
        "confidence": 0.8,
        "hypothesis": "lateral_movement",
        "supporting_facts": [],
        "evidence_summary": "ok",
        "smuggled": "x",
    }
    response = client.post("/validate/conclusion", json=payload)
    assert response.status_code == 422


def test_pending_decision_can_be_approved(tmp_path, monkeypatch):
    import overlord.api as api_module
    from overlord.pending import PendingStore

    monkeypatch.setattr(api_module, "_PENDING", PendingStore(tmp_path / "pending.json"))
    telemetry = [
        {"message": f"m{i}", "normalized_tags": ["lateral_move"]} for i in range(3)
    ]
    run = client.post(
        "/pipeline/run",
        json={
            "telemetry": telemetry,
            "requested_tier": 1,
            "asset_class": "endpoint_workstation",
        },
    ).json()
    assert run["summary"]["error"] == "awaiting_approval"
    decision_id = run["summary"]["decision_id"]

    pending = client.get("/pipeline/pending").json()["pending"]
    assert [item["decision_id"] for item in pending] == [decision_id]

    approved = client.post(f"/pipeline/approve/{decision_id}").json()
    assert approved["summary"]["status"] == "applied"
    assert approved["summary"]["pairing_balanced"] is True
    assert client.get("/pipeline/pending").json()["pending"] == []


def test_pending_decision_can_be_cancelled(tmp_path, monkeypatch):
    import overlord.api as api_module
    from overlord.pending import PendingStore

    monkeypatch.setattr(api_module, "_PENDING", PendingStore(tmp_path / "pending.json"))
    telemetry = [
        {"message": f"m{i}", "normalized_tags": ["lateral_move"]} for i in range(3)
    ]
    run = client.post(
        "/pipeline/run",
        json={
            "telemetry": telemetry,
            "requested_tier": 1,
            "asset_class": "endpoint_workstation",
        },
    ).json()
    decision_id = run["summary"]["decision_id"]

    cancelled = client.post(f"/pipeline/cancel/{decision_id}").json()
    assert cancelled["summary"]["status"] == "rolled_back"
    assert cancelled["summary"]["outcome"] == "escalated"
    assert client.post(f"/pipeline/approve/{decision_id}").status_code == 404
