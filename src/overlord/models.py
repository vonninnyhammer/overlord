from __future__ import annotations

import base64
import binascii
from datetime import datetime
from enum import Enum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

PERMITTED_TAGS = frozenset(
    {
        "authentication",
        "process_creation",
        "network_connection",
        "file_access",
        "registry_modification",
        "suspicious_login",
        "privilege_escalation",
        "lateral_move",
        "data_exfiltration",
    }
)
MAX_RAW_PAYLOAD_BYTES = 4096
MAX_EVIDENCE_SUMMARY_CHARS = 256


class Source(str, Enum):
    WAZUH = "wazuh"
    FALCO = "falco"
    VELOCIRAPTOR = "velociraptor"
    ZEEK = "zeek"
    SURICATA = "suricata"
    HUMAN = "human"


class Hypothesis(str, Enum):
    INITIAL_ACCESS = "initial_access"
    CREDENTIAL_THEFT = "credential_theft"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class AuthorisedBy(str, Enum):
    HUMAN_ANALYST = "human_analyst"
    POLICY_ENGINE = "policy_engine"
    TIER_0_AGENT = "tier_0_agent"
    TIER_1_AGENT = "tier_1_agent"
    TIER_2_AUTHORIZER = "tier_2_authorizer"


class DecisionStatus(str, Enum):
    PENDING = "pending"
    APPLIED = "applied"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"
    SUPERSEDED = "superseded"


class DecisionOutcome(str, Enum):
    SUCCESS = "success"
    PARTIAL_FAILURE = "partial_failure"
    COLLATERAL_DAMAGE = "collateral_damage"
    ESCALATED = "escalated"


class Provenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    collector_id: str
    host_id: str
    sensor_uid: str
    agent_version: str | None = None
    kernel_module: str | None = None


class Fact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fact_id: UUID
    source: Source
    timestamp: datetime
    raw_payload: str
    normalized_tags: list[str] = Field(min_length=1, max_length=3)
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: Provenance
    expires_at: datetime | None = None
    created_by: str
    tokens_used: int = Field(ge=0, default=0)

    @field_validator("raw_payload")
    @classmethod
    def _validate_payload(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("raw_payload must be valid base64") from exc
        if len(decoded) > MAX_RAW_PAYLOAD_BYTES:
            raise ValueError(
                f"raw_payload exceeds {MAX_RAW_PAYLOAD_BYTES} bytes"
            )
        return value

    @field_validator("normalized_tags")
    @classmethod
    def _validate_tags(cls, value: list[str]) -> list[str]:
        unknown = [tag for tag in value if tag not in PERMITTED_TAGS]
        if unknown:
            raise ValueError(f"unknown normalized_tags: {unknown}")
        if len(set(value)) != len(value):
            raise ValueError("normalized_tags must be distinct")
        return value


class Conclusion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    conclusion_id: UUID
    asserted_by: str
    confidence: float = Field(ge=0.0, le=1.0)
    hypothesis: Hypothesis
    supporting_facts: list[UUID]
    contradicting_facts: list[UUID] = Field(default_factory=list)
    evidence_summary: str = Field(max_length=MAX_EVIDENCE_SUMMARY_CHARS)
    agent_metadata: dict[str, Any] = Field(default_factory=dict)
    expires_at: datetime | None = None
    created_at: datetime
    justification_required_for: list[UUID] = Field(default_factory=list)
    tokens_used: int = Field(ge=0, default=0)


class ConclusionSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")

    conclusion_id: UUID
    confidence: float = Field(ge=0.0, le=1.0)
    hypothesis: Hypothesis
    supporting_facts: list[UUID]
    contradicting_facts: list[UUID] = Field(default_factory=list)
    evidence_summary: str = Field(max_length=MAX_EVIDENCE_SUMMARY_CHARS)


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_id: UUID
    authorised_by: AuthorisedBy
    action_tier: Literal[0, 1, 2]
    target_asset: str
    justification: list[UUID]
    execution_window_seconds: int | None = None
    status: DecisionStatus
    outcome: DecisionOutcome | None = None
    rolled_back_by: str | None = None
    created_at: datetime
    resolved_at: datetime | None = None
    tokens_used: int = Field(ge=0, default=0)

    @model_validator(mode="after")
    def _validate_window(self) -> "Decision":
        expected = {0: 0, 1: 60, 2: None}[self.action_tier]
        if self.execution_window_seconds != expected:
            raise ValueError(
                f"action_tier {self.action_tier} requires "
                f"execution_window_seconds={expected!r}"
            )
        return self


SCHEMAS: dict[str, dict[str, Any]] = {
    "observed_fact": Fact.model_json_schema(),
    "analytical_conclusion": Conclusion.model_json_schema(),
    "agent_conclusion_submission": ConclusionSubmission.model_json_schema(),
    "decision": Decision.model_json_schema(),
}


def get_schema(name: str) -> dict[str, Any]:
    try:
        return SCHEMAS[name]
    except KeyError as exc:
        raise KeyError(f"unknown schema {name!r}") from exc


def validate_agent_output(payload: Any) -> ConclusionSubmission:
    return ConclusionSubmission.model_validate(payload)
