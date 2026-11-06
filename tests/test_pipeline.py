from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from overlord.gates import TRIANGULATION_ERROR
from overlord.models import ConclusionSubmission, DecisionOutcome, DecisionStatus, Hypothesis
from overlord.pipeline import OverlordPipeline, summarise_incident

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


def telemetry(count: int, tag: str = "network_connection") -> list[dict]:
    return [
        {
            "source": "wazuh",
            "message": f"alert {index} {tag}",
            "normalized_tags": [tag],
            "host_id": "host-42",
        }
        for index in range(count)
    ]


class SteppingClock:
    def __init__(self, step_seconds: int = 0) -> None:
        self.current = NOW
        self.step = timedelta(seconds=step_seconds)

    def __call__(self) -> datetime:
        value = self.current
        self.current = self.current + self.step
        return value


class IpAnalyst:
    def analyse(self, request, facts):
        return ConclusionSubmission(
            conclusion_id=uuid4(),
            confidence=0.9,
            hypothesis=Hypothesis.COMMAND_AND_CONTROL,
            supporting_facts=[fact.fact_id for fact in facts],
            evidence_summary="suspicious login from 10.0.1.20 to host-42",
        )


def test_happy_path_runs_all_stages_and_balances_events():
    pipeline = OverlordPipeline(clock=SteppingClock())
    result = pipeline.run_incident(
        telemetry(3),
        requested_tier=1,
        asset_class="endpoint_workstation",
        approve=True,
    )

    assert result.blocked_at is None
    assert result.tier.resolved_tier == 1
    assert result.decision.status == DecisionStatus.APPLIED
    assert result.outcome == DecisionOutcome.SUCCESS
    assert len(result.conclusions) == 3
    summary = summarise_incident(result)
    assert summary["stages_completed"] == [f"S{i}" for i in range(1, 10)]
    assert summary["pairing_balanced"] is True
    assert summary["status"] == "applied"


def test_tier0_autonomous_needs_no_approval():
    pipeline = OverlordPipeline(clock=SteppingClock())
    result = pipeline.run_incident(
        telemetry(3),
        requested_tier=0,
        asset_class="perimeter_firewall_ip",
    )

    assert result.blocked_at is None
    assert result.tier.resolved_tier == 0
    assert result.decision.execution_window_seconds == 0
    assert result.decision.status == DecisionStatus.APPLIED


def test_tier0_is_upgraded_on_domain_controller():
    pipeline = OverlordPipeline(clock=SteppingClock())
    result = pipeline.run_incident(
        telemetry(3),
        requested_tier=0,
        asset_class="domain_controller",
        approve=True,
    )

    assert result.tier.reason == "auto_upgraded_tier0_to_tier1"
    assert result.tier.resolved_tier == 1
    assert result.decision.execution_window_seconds == 60


def test_tier2_requires_written_authorization():
    blocked = OverlordPipeline(clock=SteppingClock()).run_incident(
        telemetry(3),
        requested_tier=1,
        asset_class="medical_workstation",
        approve=True,
    )
    assert blocked.tier.resolved_tier == 2
    assert blocked.blocked_at == "S7"
    assert blocked.error == "authorization_required"

    allowed = OverlordPipeline(
        clock=SteppingClock(), authorizer=lambda token: "clinician"
    ).run_incident(
        telemetry(3),
        requested_tier=1,
        asset_class="medical_workstation",
        authorization="approved by on-call clinician",
    )
    assert allowed.blocked_at is None
    assert allowed.tier.resolved_tier == 2
    assert allowed.decision.status == DecisionStatus.APPLIED


def test_cancel_stops_before_execution():
    pipeline = OverlordPipeline(clock=SteppingClock())
    result = pipeline.run_incident(
        telemetry(3),
        requested_tier=1,
        asset_class="endpoint_workstation",
        approve=False,
    )

    assert result.blocked_at == "S7"
    assert result.error == "cancelled"
    assert result.decision.status == DecisionStatus.ROLLED_BACK
    assert result.outcome == DecisionOutcome.ESCALATED
    stages = {event["metadata"]["stage"] for event in result.events}
    assert "S8" not in stages
    assert "S9" not in stages


def test_tier1_window_expiry_blocks_execution():
    pipeline = OverlordPipeline(clock=SteppingClock(step_seconds=61))
    result = pipeline.run_incident(
        telemetry(3),
        requested_tier=1,
        asset_class="endpoint_workstation",
        approve=True,
    )

    assert result.blocked_at == "S7"
    assert result.error == "window_expired"
    assert result.decision.status == DecisionStatus.FAILED


def test_insufficient_conclusions_block_triangulation():
    pipeline = OverlordPipeline(clock=SteppingClock())
    result = pipeline.run_incident(
        telemetry(2),
        requested_tier=1,
        asset_class="endpoint_workstation",
        approve=True,
    )

    assert result.blocked_at == "S5"
    assert result.error == TRIANGULATION_ERROR
    assert len(result.conclusions) == 2


def test_under_supported_conclusion_is_blocked():
    pipeline = OverlordPipeline(clock=SteppingClock())
    result = pipeline.run_incident(
        telemetry(1, tag="lateral_move"),
        requested_tier=1,
        asset_class="endpoint_workstation",
        approve=True,
    )

    assert result.blocked_at == "S4"
    assert result.error == "under_supported"


def test_dispatch_throttle_blocks_before_agent():
    pipeline = OverlordPipeline(clock=SteppingClock(), max_concurrent_requests=0)
    result = pipeline.run_incident(telemetry(3), approve=True)

    assert result.blocked_at == "S3"
    assert result.error == "throttled"


def test_evidence_summary_is_sanitized_before_storage():
    pipeline = OverlordPipeline(clock=SteppingClock(), analyst=IpAnalyst())
    result = pipeline.run_incident(
        telemetry(3),
        requested_tier=1,
        asset_class="endpoint_workstation",
        approve=True,
    )

    conclusion = next(iter(result.conclusions.values()))
    assert "10.0.1.20" not in conclusion.evidence_summary
    assert "[REDACTED-ADDR]" in conclusion.evidence_summary


def test_event_log_is_written_and_pairing_balanced(tmp_path):
    log_path = tmp_path / "events.jsonl"
    pipeline = OverlordPipeline(clock=SteppingClock(), event_log=log_path)
    result = pipeline.run_incident(
        telemetry(3),
        requested_tier=1,
        asset_class="endpoint_workstation",
        approve=True,
    )

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == len(result.events)
    events = [json.loads(line) for line in lines]
    assert any(event["type"] == "task.request" for event in events)
    assert any(event["type"] == "task.reply" for event in events)
    assert all(UUID(event["event_id"]) for event in events)


def test_stop_after_limits_stage_execution():
    pipeline = OverlordPipeline(clock=SteppingClock())
    result = pipeline.run_incident(telemetry(3), stop_after="S2")

    assert result.blocked_at is None
    assert len(result.facts) == 3
    assert result.conclusions == {}
    assert result.tier is None
    stages = {event["metadata"]["stage"] for event in result.events}
    assert stages == {"S1", "S2"}


def parked_decision() -> dict:
    pipeline = OverlordPipeline(clock=SteppingClock())
    result = pipeline.run_incident(
        telemetry(3, tag="lateral_move"),
        requested_tier=1,
        asset_class="endpoint_workstation",
    )
    assert result.error == "awaiting_approval"
    return {
        "incident_id": result.incident_id,
        "decision": result.decision.model_dump(mode="json"),
        "events": result.events,
    }


def test_resume_approval_completes_execution():
    pipeline = OverlordPipeline(clock=SteppingClock())
    result = pipeline.resume(parked_decision(), approve=True)

    assert result.blocked_at is None
    assert result.decision.status == DecisionStatus.APPLIED
    assert result.outcome == DecisionOutcome.SUCCESS
    stages = {event["metadata"]["stage"] for event in result.events}
    assert {"S8", "S9"} <= stages


def test_resume_cancel_rolls_back():
    pipeline = OverlordPipeline(clock=SteppingClock())
    result = pipeline.resume(parked_decision(), approve=False)

    assert result.blocked_at == "S7"
    assert result.error == "cancelled"
    assert result.decision.status == DecisionStatus.ROLLED_BACK
    assert result.outcome == DecisionOutcome.ESCALATED


def test_resume_after_window_expiry_fails():
    clock = SteppingClock()
    clock.current = NOW + timedelta(seconds=61)
    pipeline = OverlordPipeline(clock=clock)
    result = pipeline.resume(parked_decision(), approve=True)

    assert result.blocked_at == "S7"
    assert result.error == "window_expired"
    assert result.decision.status == DecisionStatus.FAILED


def test_resume_tier2_requires_authorization():
    pipeline = OverlordPipeline(clock=SteppingClock(), authorizer=lambda token: "clinician")
    result = pipeline.run_incident(
        telemetry(3, tag="lateral_move"),
        requested_tier=1,
        asset_class="medical_workstation",
    )
    assert result.error == "authorization_required"
    parked = {
        "incident_id": result.incident_id,
        "decision": result.decision.model_dump(mode="json"),
        "events": result.events,
    }

    blocked = pipeline.resume(parked, approve=True)
    assert blocked.error == "authorization_required"
    allowed = pipeline.resume(parked, approve=True, authorization="clinician approved")
    assert allowed.blocked_at is None
    assert allowed.decision.status == DecisionStatus.APPLIED
