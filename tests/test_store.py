from __future__ import annotations

import math
from datetime import datetime, timezone

from overlord.pipeline import OverlordPipeline
from overlord.store import HashingEmbedder, Ledger, OverlordStore

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


def telemetry(count: int, tag: str = "lateral_move") -> list[dict]:
    return [
        {
            "source": "wazuh",
            "message": f"alert {index} {tag}",
            "normalized_tags": [tag],
            "host_id": "host-42",
        }
        for index in range(count)
    ]


def test_ledger_put_get_search_and_stats(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    ledger.put("fact", "f1", {"fact_id": "f1", "note": "lateral movement"})
    ledger.put("fact", "f2", {"fact_id": "f2", "note": "authentication"})

    assert ledger.get("fact", "f1")["note"] == "lateral movement"
    assert ledger.get("fact", "missing") is None
    assert ledger.stats() == {"fact": 2}
    hits = ledger.search_text("lateral")
    assert [hit["id"] for hit in hits] == ["f1"]
    ledger.close()


def test_hashing_embedder_is_deterministic_and_normalized():
    embedder = HashingEmbedder()
    first = embedder.embed("lateral movement host-42")
    second = embedder.embed("lateral movement host-42")
    assert first == second
    assert len(first) == embedder.dimensions
    assert math.isclose(math.sqrt(sum(v * v for v in first)), 1.0, rel_tol=1e-6)


def test_store_pipeline_persists_all_layers(tmp_path):
    store = OverlordStore(tmp_path / "ledger.db")
    pipeline = OverlordPipeline(store=store)
    result = pipeline.run_incident(
        telemetry(3),
        requested_tier=1,
        asset_class="endpoint_workstation",
        approve=True,
    )

    assert result.decision.status.value == "applied"
    stats = store.stats()["ledger"]
    assert stats == {"fact": 3, "conclusion": 3, "decision": 1}
    hits = store.search("lateral_movement")
    assert hits["backend"] == "ledger"
    assert hits["hits"]
    assert store.get("decision", str(result.decision.decision_id))["status"] == "applied"
    store.close()
