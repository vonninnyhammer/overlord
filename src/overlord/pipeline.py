from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence
from uuid import UUID, uuid4

from pydantic import ValidationError

from .events import EventStatus, EventType, build_event, pair_requests_and_replies
from .gates import (
    CompressionResult,
    TierAssignment,
    WindowAudit,
    assign_tier,
    audit_window,
    compress_evidence,
    evaluate_min_support,
    evaluate_triangulation,
)
from .intel import IntelEnrichment, IntelLedger
from .models import (
    MAX_EVIDENCE_SUMMARY_CHARS,
    AuthorisedBy,
    ConclusionSubmission,
    Decision,
    DecisionOutcome,
    DecisionStatus,
    Fact,
    Hypothesis,
    Provenance,
    Source,
    validate_agent_output,
)
from .policy import EXECUTION_WINDOW_SECONDS, Tier
from .sanitize import sanitize_telemetry
from .sensors import sensor_factory
from .store import OverlordStore

STAGES: tuple[str, ...] = tuple(f"S{i}" for i in range(1, 10))

TAG_HYPOTHESIS: dict[str, Hypothesis] = {
    "authentication": Hypothesis.CREDENTIAL_ACCESS,
    "suspicious_login": Hypothesis.CREDENTIAL_ACCESS,
    "process_creation": Hypothesis.COMMAND_AND_CONTROL,
    "network_connection": Hypothesis.COMMAND_AND_CONTROL,
    "file_access": Hypothesis.COLLECTION,
    "registry_modification": Hypothesis.PERSISTENCE,
    "privilege_escalation": Hypothesis.DEFENSE_EVASION,
    "lateral_move": Hypothesis.LATERAL_MOVEMENT,
    "data_exfiltration": Hypothesis.EXFILTRATION,
}

TAG_TO_ATTCK: dict[str, str] = {
    "authentication": "T1078",
    "suspicious_login": "T1110",
    "process_creation": "T1059",
    "network_connection": "T1071",
    "file_access": "T1005",
    "registry_modification": "T1547",
    "privilege_escalation": "T1068",
    "lateral_move": "T1021",
    "data_exfiltration": "T1041",
}


class Sensor(Protocol):
    def normalize(self, raw: Mapping[str, Any], now: datetime) -> Fact: ...


class Enrichment(Protocol):
    def enrich(self, fact: Fact) -> dict[str, Any]: ...


class Analyst(Protocol):
    def analyse(
        self,
        request: Mapping[str, Any],
        facts: Sequence[Fact],
    ) -> ConclusionSubmission: ...


class Executor(Protocol):
    def execute(self, decision: Decision) -> DecisionOutcome: ...


class DefaultSensor:
    def normalize(self, raw: Mapping[str, Any], now: datetime) -> Fact:
        text = str(raw.get("message", ""))
        payload = base64.b64encode(text.encode("utf-8", "replace")[:3000]).decode("ascii")
        return Fact(
            fact_id=raw.get("fact_id") or uuid4(),
            source=Source(str(raw.get("source", Source.WAZUH.value))),
            timestamp=now,
            raw_payload=payload,
            normalized_tags=list(raw.get("normalized_tags") or ["process_creation"]),
            confidence=float(raw.get("confidence", 0.9)),
            provenance=Provenance(
                collector_id=str(raw.get("collector_id", "sensor-local")),
                host_id=str(raw.get("host_id", "host-unknown")),
                sensor_uid=str(raw.get("sensor_uid", "sensor-local")),
            ),
            created_by=str(raw.get("created_by", "s1_ingest")),
        )


class DefaultEnrichment:
    def enrich(self, fact: Fact) -> dict[str, Any]:
        techniques = sorted(
            {TAG_TO_ATTCK[tag] for tag in fact.normalized_tags if tag in TAG_TO_ATTCK}
        )
        return {
            "attck_techniques": techniques,
            "asset_node_candidates": [fact.provenance.host_id],
            "time_since_first_seen_seconds": 0,
        }


class DefaultAnalyst:
    def analyse(
        self,
        request: Mapping[str, Any],
        facts: Sequence[Fact],
    ) -> ConclusionSubmission:
        tags = [tag for fact in facts for tag in fact.normalized_tags]
        hypothesis = TAG_HYPOTHESIS.get(tags[0], Hypothesis.DISCOVERY) if tags else Hypothesis.DISCOVERY
        supporting = sorted({str(fact.fact_id) for fact in facts})
        summary = sanitize_telemetry(
            f"{hypothesis.value} observed across {len(supporting)} correlated facts"
            f" from {', '.join(sorted({tag for tag in tags}))}"
        ).text
        return ConclusionSubmission(
            conclusion_id=uuid4(),
            confidence=0.85,
            hypothesis=hypothesis,
            supporting_facts=[UUID(fact_id) for fact_id in supporting],
            evidence_summary=summary[:MAX_EVIDENCE_SUMMARY_CHARS],
        )


class DefaultExecutor:
    def execute(self, decision: Decision) -> DecisionOutcome:
        if decision.action_tier == Tier.AUTONOMOUS:
            return DecisionOutcome.SUCCESS
        if decision.target_asset == "host-unreachable":
            return DecisionOutcome.PARTIAL_FAILURE
        return DecisionOutcome.SUCCESS


@dataclass
class IncidentResult:
    incident_id: str
    facts: dict[str, Fact] = field(default_factory=dict)
    enrichment: dict[str, dict[str, Any]] = field(default_factory=dict)
    conclusions: dict[str, ConclusionSubmission] = field(default_factory=dict)
    audits: dict[str, WindowAudit] = field(default_factory=dict)
    compressions: dict[str, CompressionResult] = field(default_factory=dict)
    tier: TierAssignment | None = None
    decision: Decision | None = None
    outcome: DecisionOutcome | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    blocked_at: str | None = None
    error: str | None = None

    @property
    def applied(self) -> bool:
        return self.decision is not None and self.decision.status == DecisionStatus.APPLIED

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "facts": {k: v.model_dump(mode="json") for k, v in self.facts.items()},
            "enrichment": self.enrichment,
            "conclusions": {
                k: v.model_dump(mode="json") for k, v in self.conclusions.items()
            },
            "audits": {k: v.__dict__ for k, v in self.audits.items()},
            "compressions": {k: v.__dict__ for k, v in self.compressions.items()},
            "tier": self.tier.__dict__ if self.tier else None,
            "decision": self.decision.model_dump(mode="json") if self.decision else None,
            "outcome": self.outcome.value if self.outcome else None,
            "events": self.events,
            "blocked_at": self.blocked_at,
            "error": self.error,
        }


class OverlordPipeline:
    def __init__(
        self,
        sensor: Sensor | None = None,
        auto_sensors: bool = False,
        enrichment: Enrichment | None = None,
        analyst: Analyst | None = None,
        executor: Executor | None = None,
        event_log: str | Path | None = None,
        clock: Callable[[], datetime] | None = None,
        model_context_window: int = 8192,
        max_concurrent_requests: int = 3,
        requesting_agent: str = "hermes",
        store: OverlordStore | None = None,
    ) -> None:
        self._default_sensor = DefaultSensor()
        self.sensor = sensor or self._default_sensor
        self.auto_sensors = auto_sensors
        self.enrichment = enrichment or self._default_enrichment()
        self.analyst = analyst or DefaultAnalyst()
        self.executor = executor or DefaultExecutor()
        self.event_log = Path(event_log) if event_log else None
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.model_context_window = model_context_window
        self.max_concurrent_requests = max_concurrent_requests
        self.requesting_agent = requesting_agent
        self.store = store
        self._in_flight: dict[str, int] = {}

    @staticmethod
    def _default_enrichment() -> Enrichment:
        intel_db = os.environ.get("OVERLORD_INTEL_DB")
        if intel_db and Path(intel_db).exists():
            return IntelEnrichment(IntelLedger(intel_db), DefaultEnrichment())
        return DefaultEnrichment()

    def _persist(self, method: str, payload: dict[str, Any]) -> None:
        if self.store is None:
            return
        try:
            getattr(self.store, method)(payload)
        except Exception:
            return

    def _now(self) -> datetime:
        return self.clock()

    def _emit(
        self,
        result: IncidentResult,
        stage: str,
        event_type: str,
        status: EventStatus,
        body: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        correlation_id: str | None = None,
        from_agent: str = "n8n",
    ) -> dict[str, Any]:
        meta = {"stage": stage, "incident_id": result.incident_id}
        meta.update(dict(metadata or {}))
        event = build_event(
            event_type=event_type,
            stream=f"overlord/{result.incident_id}",
            room=stage.lower(),
            from_agent=from_agent,
            to_agent=("agent" if event_type == EventType.TASK_REQUEST.value else None),
            correlation_id=correlation_id,
            status=status,
            body=body,
            metadata=meta,
        )
        result.events.append(event)
        if self.event_log is not None:
            self.event_log.parent.mkdir(parents=True, exist_ok=True)
            with self.event_log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True) + "\n")
        return event

    def _block(self, result: IncidentResult, stage: str, error: str) -> IncidentResult:
        result.blocked_at = stage
        result.error = error
        self._emit(result, stage, "pipeline.stage", EventStatus.BLOCKED, body=error)
        return result

    def run_incident(
        self,
        telemetry: Sequence[Mapping[str, Any]],
        requested_tier: int = 1,
        asset_class: str = "endpoint_workstation",
        target_asset: str = "host-42",
        approve: bool | None = None,
        authorization: str | None = None,
        incident_id: str | None = None,
        stop_after: str | None = None,
    ) -> IncidentResult:
        result = IncidentResult(incident_id=incident_id or f"inc-{uuid4().hex[:12]}")
        limit = STAGES.index(stop_after) + 1 if stop_after in STAGES else len(STAGES)

        self._s1_ingest(result, telemetry)
        self._s2_enrichment(result)
        if limit <= 2:
            return result
        for fact_id in sorted(result.facts):
            correlation = self._s3_dispatch(result, fact_id)
            if result.blocked_at or limit <= 3:
                return result
            self._s4_analysis(result, correlation, fact_id)
            if result.blocked_at or limit <= 4:
                return result
        self._s5_justification(result)
        if result.blocked_at or limit <= 5:
            return result
        self._s6_tier(result, requested_tier, asset_class)
        if result.blocked_at or limit <= 6:
            return result
        self._s7_approval(result, target_asset, approve, authorization)
        if result.blocked_at or limit <= 7:
            return result
        self._s8_execute(result)
        if limit <= 8:
            return result
        self._s9_record(result)
        return result

    def _s1_ingest(
        self, result: IncidentResult, telemetry: Sequence[Mapping[str, Any]]
    ) -> None:
        now = self._now()
        for raw in telemetry:
            sensor = self.sensor
            if self.auto_sensors and sensor is self._default_sensor:
                sensor = sensor_factory(str(raw.get("source", "")))
            fact = sensor.normalize(raw, now)
            result.facts[str(fact.fact_id)] = fact
            self._persist("record_fact", fact.model_dump(mode="json"))
        self._emit(
            result,
            "S1",
            "pipeline.stage",
            EventStatus.READY,
            body=f"ingested {len(result.facts)} facts",
            metadata={"fact_ids": sorted(result.facts)},
        )

    def _s2_enrichment(self, result: IncidentResult) -> None:
        for fact_id, fact in result.facts.items():
            result.enrichment[fact_id] = self.enrichment.enrich(fact)
        self._emit(
            result,
            "S2",
            "pipeline.stage",
            EventStatus.READY,
            body=f"enriched {len(result.enrichment)} facts",
        )

    def _s3_dispatch(self, result: IncidentResult, trigger_fact_id: str) -> str:
        agent = self.requesting_agent
        in_flight = self._in_flight.get(agent, 0)
        if in_flight >= self.max_concurrent_requests:
            self._block(result, "S3", "throttled")
            return ""
        self._in_flight[agent] = in_flight + 1
        correlation = f"{result.incident_id}-{uuid4().hex[:8]}"
        self._emit(
            result,
            "S3",
            EventType.TASK_REQUEST.value,
            EventStatus.OPEN,
            body=f"dispatch to {agent}",
            metadata={
                "agent": agent,
                "in_flight": in_flight + 1,
                "trigger_fact_id": trigger_fact_id,
            },
            correlation_id=correlation,
            from_agent=agent,
        )
        return correlation

    def _s4_analysis(
        self, result: IncidentResult, correlation: str, trigger_fact_id: str
    ) -> None:
        agent = self.requesting_agent
        try:
            facts = [result.facts[fact_id] for fact_id in sorted(result.facts)]
            request = {
                "incident_id": result.incident_id,
                "trigger_fact_id": trigger_fact_id,
                "facts": [fact.model_dump(mode="json") for fact in facts],
                "enrichment": [result.enrichment[str(fact.fact_id)] for fact in facts],
            }
            produced = self.analyst.analyse(request, facts)
            submitted = validate_agent_output(produced.model_dump(mode="json"))

            sanitized = sanitize_telemetry(submitted.evidence_summary).text
            submission = submitted.model_copy(
                update={"evidence_summary": sanitized[:MAX_EVIDENCE_SUMMARY_CHARS]}
            )

            audit = audit_window(
                submission.evidence_summary,
                [str(fid) for fid in submission.supporting_facts],
                self.model_context_window,
            )
            result.audits[str(submission.conclusion_id)] = audit
            if not audit.passed:
                self._emit(
                    result,
                    "S4",
                    EventType.TASK_REPLY.value,
                    EventStatus.FAILED,
                    body="context_exceeded",
                    correlation_id=correlation,
                    from_agent=agent,
                )
                self._block(result, "S4", "context_exceeded")
                return
            if audit.near_limit:
                compression = compress_evidence(
                    submission.evidence_summary,
                    sorted({tag for fact in facts for tag in fact.normalized_tags}),
                    max(0, audit.evidence_tokens - audit.usable_context),
                )
                result.compressions[str(submission.conclusion_id)] = compression
                submission = submission.model_copy(
                    update={"evidence_summary": compression.evidence_summary}
                )

            support = evaluate_min_support(
                submission.hypothesis.value,
                [str(fid) for fid in submission.supporting_facts],
                {fact_id: fact.model_dump(mode="json") for fact_id, fact in result.facts.items()},
                self._now(),
            )
            if not support.accepted:
                self._emit(
                    result,
                    "S4",
                    EventType.TASK_REPLY.value,
                    EventStatus.FAILED,
                    body="under_supported",
                    correlation_id=correlation,
                    from_agent=agent,
                )
                self._block(result, "S4", "under_supported")
                return

            result.conclusions[str(submission.conclusion_id)] = submission
            self._persist("record_conclusion", submission.model_dump(mode="json"))
            self._emit(
                result,
                "S4",
                EventType.TASK_REPLY.value,
                EventStatus.READY,
                body=f"conclusion {submission.conclusion_id} accepted",
                metadata={
                    "conclusion_id": str(submission.conclusion_id),
                    "n_support": support.n_support,
                    "threshold": support.threshold,
                },
                correlation_id=correlation,
                from_agent=agent,
            )
        finally:
            self._in_flight[agent] = max(0, self._in_flight.get(agent, 1) - 1)

    def _s5_justification(self, result: IncidentResult) -> None:
        justification = sorted(result.conclusions)
        gate = evaluate_triangulation(justification)
        if not gate.ok:
            self._emit(
                result,
                "S5",
                "pipeline.stage",
                EventStatus.FAILED,
                body=gate.error,
                metadata={"distinct_count": gate.distinct_count},
            )
            self._block(result, "S5", gate.error or "triangulation_failed")
            return
        self._emit(
            result,
            "S5",
            "pipeline.stage",
            EventStatus.READY,
            body="justification_set complete",
            metadata={"conclusion_ids": justification},
        )

    def _s6_tier(
        self, result: IncidentResult, requested_tier: int, asset_class: str
    ) -> None:
        assignment = assign_tier(requested_tier, asset_class)
        result.tier = assignment
        if not assignment.permitted:
            self._emit(
                result,
                "S6",
                "pipeline.stage",
                EventStatus.FAILED,
                body=assignment.reason,
                metadata={"asset_class": asset_class, "requested_tier": requested_tier},
            )
            self._block(result, "S6", assignment.reason)
            return
        self._emit(
            result,
            "S6",
            "pipeline.stage",
            EventStatus.READY,
            body=assignment.reason,
            metadata={
                "resolved_tier": assignment.resolved_tier,
                "execution_window_seconds": assignment.execution_window_seconds,
            },
        )

    def _build_decision(self, result: IncidentResult, target_asset: str) -> Decision:
        assert result.tier is not None
        tier = result.tier.resolved_tier
        authorised = {
            Tier.AUTONOMOUS: AuthorisedBy.POLICY_ENGINE,
            Tier.CANCELLABLE: AuthorisedBy.TIER_1_AGENT,
            Tier.HUMAN: AuthorisedBy.TIER_2_AUTHORIZER,
        }[Tier(tier)]
        return Decision(
            decision_id=uuid4(),
            authorised_by=authorised,
            action_tier=tier,
            target_asset=target_asset,
            justification=[UUID(cid) for cid in sorted(result.conclusions)],
            execution_window_seconds=EXECUTION_WINDOW_SECONDS[tier],
            status=DecisionStatus.APPLIED if tier == Tier.AUTONOMOUS else DecisionStatus.PENDING,
            created_at=self._now(),
        )

    def _s7_approval(
        self,
        result: IncidentResult,
        target_asset: str,
        approve: bool | None,
        authorization: str | None,
    ) -> None:
        assert result.tier is not None
        tier = result.tier.resolved_tier
        decision = self._build_decision(result, target_asset)

        if tier == Tier.AUTONOMOUS:
            result.decision = decision
            self._emit(
                result,
                "S7",
                "pipeline.stage",
                EventStatus.APPLIED,
                body="tier0 autonomous",
            )
            return

        if tier == Tier.CANCELLABLE:
            if approve is False:
                decision = decision.model_copy(
                    update={
                        "status": DecisionStatus.ROLLED_BACK,
                        "outcome": DecisionOutcome.ESCALATED,
                        "resolved_at": self._now(),
                    }
                )
                result.decision = decision
                result.outcome = DecisionOutcome.ESCALATED
                result.blocked_at = "S7"
                result.error = "cancelled"
                self._emit(result, "S7", "pipeline.stage", EventStatus.SUPERSEDED, body="cancelled")
                return
            if approve is None:
                result.decision = decision
                self._block(result, "S7", "awaiting_approval")
                return
            elapsed = (self._now() - decision.created_at).total_seconds()
            if elapsed > float(EXECUTION_WINDOW_SECONDS[Tier.CANCELLABLE]):
                decision = decision.model_copy(
                    update={
                        "status": DecisionStatus.FAILED,
                        "outcome": DecisionOutcome.ESCALATED,
                        "resolved_at": self._now(),
                    }
                )
                result.decision = decision
                result.outcome = DecisionOutcome.ESCALATED
                self._block(result, "S7", "window_expired")
                return
            result.decision = decision
            self._emit(result, "S7", "pipeline.stage", EventStatus.APPLIED, body="tier1 approved")
            return

        if not authorization:
            result.decision = decision
            self._block(result, "S7", "authorization_required")
            return
        decision = decision.model_copy(
            update={"status": DecisionStatus.APPLIED, "created_at": self._now()}
        )
        result.decision = decision
        self._emit(
            result,
            "S7",
            "pipeline.stage",
            EventStatus.APPLIED,
            body="tier2 authorized",
        )

    def resume(
        self,
        parked: Mapping[str, Any],
        approve: bool,
        authorization: str | None = None,
    ) -> IncidentResult:
        result = IncidentResult(
            incident_id=str(parked["incident_id"]),
            events=list(parked.get("events") or []),
        )
        decision = Decision.model_validate(parked["decision"])
        result.decision = decision
        tier = decision.action_tier
        result.tier = TierAssignment(
            requested_tier=tier,
            resolved_tier=tier,
            asset_class=decision.target_asset,
            permitted=True,
            execution_window_seconds=decision.execution_window_seconds,
            requires_cancel_window=tier == Tier.CANCELLABLE,
            requires_human_authorization=tier == Tier.HUMAN,
            reason="resumed",
        )

        if not approve:
            decision = decision.model_copy(
                update={
                    "status": DecisionStatus.ROLLED_BACK,
                    "outcome": DecisionOutcome.ESCALATED,
                    "resolved_at": self._now(),
                }
            )
            result.decision = decision
            result.outcome = DecisionOutcome.ESCALATED
            result.blocked_at = "S7"
            result.error = "cancelled"
            self._emit(result, "S7", "pipeline.stage", EventStatus.SUPERSEDED, body="cancelled")
            return result

        if tier == Tier.HUMAN and not authorization:
            result.blocked_at = "S7"
            result.error = "authorization_required"
            self._emit(
                result,
                "S7",
                "pipeline.stage",
                EventStatus.BLOCKED,
                body="authorization_required",
            )
            return result

        if tier == Tier.CANCELLABLE:
            elapsed = (self._now() - decision.created_at).total_seconds()
            if elapsed > float(EXECUTION_WINDOW_SECONDS[Tier.CANCELLABLE]):
                decision = decision.model_copy(
                    update={
                        "status": DecisionStatus.FAILED,
                        "outcome": DecisionOutcome.ESCALATED,
                        "resolved_at": self._now(),
                    }
                )
                result.decision = decision
                result.outcome = DecisionOutcome.ESCALATED
                result.blocked_at = "S7"
                result.error = "window_expired"
                self._emit(
                    result,
                    "S7",
                    "pipeline.stage",
                    EventStatus.FAILED,
                    body="window_expired",
                )
                return result

        self._emit(result, "S7", "pipeline.stage", EventStatus.APPLIED, body="resumed approval")
        self._s8_execute(result)
        self._s9_record(result)
        return result

    def _s8_execute(self, result: IncidentResult) -> None:
        assert result.decision is not None
        decision = result.decision
        if decision.action_tier == Tier.AUTONOMOUS:
            outcome = DecisionOutcome.SUCCESS
        else:
            outcome = self.executor.execute(decision)
        result.outcome = outcome
        status = (
            DecisionStatus.APPLIED
            if outcome in (DecisionOutcome.SUCCESS, DecisionOutcome.PARTIAL_FAILURE)
            else DecisionStatus.FAILED
        )
        if outcome == DecisionOutcome.COLLATERAL_DAMAGE:
            status = DecisionStatus.ROLLED_BACK
        result.decision = decision.model_copy(
            update={"status": status, "outcome": outcome, "resolved_at": self._now()}
        )
        self._emit(
            result,
            "S8",
            "pipeline.stage",
            EventStatus.APPLIED if status == DecisionStatus.APPLIED else EventStatus.FAILED,
            body=outcome.value,
            metadata={"action_tier": decision.action_tier},
        )

    def _s9_record(self, result: IncidentResult) -> None:
        assert result.decision is not None
        self._persist("record_decision", result.decision.model_dump(mode="json"))
        self._emit(
            result,
            "S9",
            "pipeline.stage",
            EventStatus.APPLIED,
            body=f"decision {result.decision.decision_id} recorded",
            metadata={
                "decision_id": str(result.decision.decision_id),
                "outcome": result.outcome.value if result.outcome else None,
            },
        )


def summarise_incident(result: IncidentResult) -> dict[str, Any]:
    pairing = pair_requests_and_replies(result.events)
    return {
        "incident_id": result.incident_id,
        "stages_completed": sorted({e["metadata"]["stage"] for e in result.events}),
        "n_facts": len(result.facts),
        "n_conclusions": len(result.conclusions),
        "tier": result.tier.resolved_tier if result.tier else None,
        "decision_id": str(result.decision.decision_id) if result.decision else None,
        "status": result.decision.status.value if result.decision else None,
        "outcome": result.outcome.value if result.outcome else None,
        "blocked_at": result.blocked_at,
        "error": result.error,
        "pairing_balanced": pairing["balanced"],
    }
