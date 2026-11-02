from __future__ import annotations

import base64
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from overlord.models import (
    Conclusion,
    ConclusionSubmission,
    Decision,
    Fact,
    get_schema,
)

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


def encoded(data: bytes = b"hello") -> str:
    return base64.b64encode(data).decode()


def fact_kwargs(**overrides):
    kwargs = {
        "fact_id": str(uuid4()),
        "source": "wazuh",
        "timestamp": NOW,
        "raw_payload": encoded(),
        "normalized_tags": ["authentication"],
        "confidence": 0.9,
        "provenance": {
            "collector_id": "collector-1",
            "host_id": "host-42",
            "sensor_uid": "sensor-1",
        },
        "expires_at": None,
        "created_by": "wazuh-agent",
        "tokens_used": 0,
    }
    kwargs.update(overrides)
    return kwargs


def test_fact_accepts_valid_payload():
    fact = Fact(**fact_kwargs())
    assert fact.confidence == 0.9
    assert fact.provenance.host_id == "host-42"


def test_fact_rejects_confidence_out_of_range():
    with pytest.raises(ValidationError):
        Fact(**fact_kwargs(confidence=1.5))


def test_fact_rejects_too_many_tags():
    with pytest.raises(ValidationError):
        Fact(
            **fact_kwargs(
                normalized_tags=[
                    "authentication",
                    "process_creation",
                    "network_connection",
                    "file_access",
                ]
            )
        )


def test_fact_rejects_unknown_tag():
    with pytest.raises(ValidationError):
        Fact(**fact_kwargs(normalized_tags=["made_up_tag"]))


def test_fact_rejects_duplicate_tags():
    with pytest.raises(ValidationError):
        Fact(**fact_kwargs(normalized_tags=["authentication", "authentication"]))


def test_fact_rejects_non_base64_payload():
    with pytest.raises(ValidationError):
        Fact(**fact_kwargs(raw_payload="not base64 !!!"))


def test_fact_rejects_oversized_payload():
    with pytest.raises(ValidationError):
        Fact(**fact_kwargs(raw_payload=encoded(b"a" * 4097)))


def test_conclusion_forbids_extra_fields():
    payload = {
        "conclusion_id": str(uuid4()),
        "asserted_by": "hermes_incident_cmdr_01",
        "confidence": 0.8,
        "hypothesis": "lateral_movement",
        "supporting_facts": [str(uuid4())],
        "evidence_summary": "three hosts contacted over SMB",
        "created_at": NOW,
        "smuggled_field": "x",
    }
    with pytest.raises(ValidationError):
        Conclusion(**payload)


def test_conclusion_summary_length_capped():
    with pytest.raises(ValidationError):
        Conclusion(
            conclusion_id=str(uuid4()),
            asserted_by="agent",
            confidence=0.8,
            hypothesis="discovery",
            supporting_facts=[],
            evidence_summary="z" * 257,
            created_at=NOW,
        )


def test_submission_accepts_only_permitted_fields():
    submission = ConclusionSubmission(
        conclusion_id=str(uuid4()),
        confidence=0.8,
        hypothesis="discovery",
        supporting_facts=[str(uuid4())],
        evidence_summary="ok",
    )
    assert submission.hypothesis.value == "discovery"


def test_submission_rejects_extra_field():
    with pytest.raises(ValidationError):
        ConclusionSubmission(
            conclusion_id=str(uuid4()),
            confidence=0.8,
            hypothesis="discovery",
            supporting_facts=[],
            evidence_summary="ok",
            asserted_by="sneaky",
        )


def decision_kwargs(**overrides):
    kwargs = {
        "decision_id": str(uuid4()),
        "authorised_by": "human_analyst",
        "action_tier": 1,
        "target_asset": "host:server-42",
        "justification": [str(uuid4()) for _ in range(3)],
        "execution_window_seconds": 60,
        "status": "pending",
        "outcome": None,
        "rolled_back_by": None,
        "created_at": NOW,
        "resolved_at": None,
        "tokens_used": 0,
    }
    kwargs.update(overrides)
    return kwargs


def test_decision_tier1_requires_sixty_second_window():
    assert Decision(**decision_kwargs()).execution_window_seconds == 60


def test_decision_rejects_wrong_window_for_tier():
    with pytest.raises(ValidationError):
        Decision(**decision_kwargs(action_tier=0, execution_window_seconds=60))


def test_decision_tier2_accepts_null_window():
    decision = Decision(
        **decision_kwargs(action_tier=2, execution_window_seconds=None)
    )
    assert decision.execution_window_seconds is None


def test_schema_registry_exposes_layer_models():
    for name in (
        "observed_fact",
        "analytical_conclusion",
        "agent_conclusion_submission",
        "decision",
    ):
        schema = get_schema(name)
        assert schema["type"] == "object"
        assert "properties" in schema


def test_unknown_schema_raises():
    with pytest.raises(KeyError):
        get_schema("nope")
