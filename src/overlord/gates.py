from __future__ import annotations

import math
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from .models import MAX_EVIDENCE_SUMMARY_CHARS
from .policy import (
    ASSET_CLASS_POLICY,
    DEFAULT_MIN_SUPPORT,
    EXECUTION_WINDOW_SECONDS,
    HYPOTHESIS_MIN_TIER,
    MIN_SUPPORT_DEFAULTS,
    PROTECTED_ASSET_CLASSES,
    Tier,
)

MIN_FACT_CONFIDENCE = 0.7
TRIANGULATION_MINIMUM = 3
TRIANGULATION_ERROR = "need_at_least_3_conclusions_for_justification"
UUID_TOKEN_ESTIMATE = 8
HYPOTHESIS_TOKEN_ESTIMATE = 4
CONFIDENCE_TOKEN_ESTIMATE = 2
REASONING_RESERVE_RATIO = 0.25
COMPRESSION_TRIGGER_RATIO = 0.10
MIN_COMPRESSED_SUMMARY_CHARS = 64

IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


def min_support_for(hypothesis: str) -> int:
    key = getattr(hypothesis, "value", hypothesis)
    return MIN_SUPPORT_DEFAULTS.get(str(key), DEFAULT_MIN_SUPPORT)


@dataclass(frozen=True)
class MinSupportResult:
    accepted: bool
    n_support: int
    threshold: int
    accepted_fact_ids: tuple[str, ...]
    rejected: tuple[tuple[str, str], ...]

    @property
    def reason(self) -> str | None:
        return None if self.accepted else "under_supported"


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _parse_time(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def evaluate_min_support(
    hypothesis: str,
    supporting_facts: Sequence[str],
    facts_by_id: Mapping[str, Any],
    now: datetime | None = None,
) -> MinSupportResult:
    reference = now or datetime.now(timezone.utc)
    threshold = min_support_for(hypothesis)
    accepted: list[str] = []
    rejected: list[tuple[str, str]] = []
    seen: set[str] = set()

    for fact_id in supporting_facts:
        key = str(fact_id)
        if key in seen:
            rejected.append((key, "duplicate"))
            continue
        seen.add(key)

        fact = facts_by_id.get(key)
        if fact is None:
            rejected.append((key, "missing"))
            continue
        if float(_get(fact, "confidence", 0.0)) < MIN_FACT_CONFIDENCE:
            rejected.append((key, "low_confidence"))
            continue
        expires_at = _parse_time(_get(fact, "expires_at"))
        if expires_at is not None and expires_at <= reference:
            rejected.append((key, "expired"))
            continue
        accepted.append(key)

    return MinSupportResult(
        accepted=len(accepted) >= threshold,
        n_support=len(accepted),
        threshold=threshold,
        accepted_fact_ids=tuple(accepted),
        rejected=tuple(rejected),
    )


@dataclass(frozen=True)
class TriangulationResult:
    ok: bool
    distinct_count: int
    minimum: int
    error: str | None


def evaluate_triangulation(justification: Iterable[str]) -> TriangulationResult:
    distinct = {str(c) for c in justification if c}
    count = len(distinct)
    if count < TRIANGULATION_MINIMUM:
        return TriangulationResult(False, count, TRIANGULATION_MINIMUM, TRIANGULATION_ERROR)
    return TriangulationResult(True, count, TRIANGULATION_MINIMUM, None)


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return max(1, math.ceil(len(text) / 4))


@dataclass(frozen=True)
class WindowAudit:
    evidence_tokens: int
    allowed_context: int
    reserved_for_reasoning: int
    usable_context: int
    remaining: int
    passed: bool
    near_limit: bool


def audit_window(
    evidence_summary: str,
    supporting_facts: Sequence[str],
    model_context_window: int,
    token_count: Any = None,
) -> WindowAudit:
    counter = token_count or estimate_tokens
    evidence_tokens = (
        counter(evidence_summary)
        + UUID_TOKEN_ESTIMATE * len({str(f) for f in supporting_facts})
        + HYPOTHESIS_TOKEN_ESTIMATE
        + CONFIDENCE_TOKEN_ESTIMATE
    )
    reserved = int(model_context_window * REASONING_RESERVE_RATIO)
    usable = model_context_window - reserved
    remaining = usable - evidence_tokens
    passed = remaining >= 0
    near_limit = passed and remaining <= COMPRESSION_TRIGGER_RATIO * usable
    return WindowAudit(
        evidence_tokens=evidence_tokens,
        allowed_context=model_context_window,
        reserved_for_reasoning=reserved,
        usable_context=usable,
        remaining=remaining,
        passed=passed,
        near_limit=near_limit,
    )


@dataclass(frozen=True)
class CompressionResult:
    evidence_summary: str
    tag_counts: tuple[tuple[str, int], ...]
    applied: tuple[str, ...]


def compress_evidence(
    evidence_summary: str,
    tags: Sequence[str] = (),
    delta_tokens: int = 0,
) -> CompressionResult:
    applied: list[str] = []

    aggregated = IPV4_RE.sub(lambda m: f"{m.group(1)}.0.0.0", evidence_summary)
    if aggregated != evidence_summary:
        applied.append("ip_aggregation")

    counts: dict[str, int] = {}
    for tag in tags:
        counts[tag] = counts.get(tag, 0) + 1
    tag_counts = tuple(sorted(counts.items()))
    if len(tag_counts) != len(tags):
        applied.append("tag_consolidation")

    limit = max(MAX_EVIDENCE_SUMMARY_CHARS - delta_tokens, MIN_COMPRESSED_SUMMARY_CHARS)
    summary = aggregated
    if len(summary) > limit:
        summary = summary[:limit]
        applied.append("summary_truncation")

    return CompressionResult(summary, tag_counts, tuple(applied))


@dataclass(frozen=True)
class TierAssignment:
    requested_tier: int
    resolved_tier: int
    asset_class: str
    permitted: bool
    execution_window_seconds: int | None
    requires_cancel_window: bool
    requires_human_authorization: bool
    reason: str


def _assignment(
    requested: int,
    resolved: int,
    asset_class: str,
    permitted: bool,
    reason: str,
) -> TierAssignment:
    return TierAssignment(
        requested_tier=requested,
        resolved_tier=resolved,
        asset_class=asset_class,
        permitted=permitted,
        execution_window_seconds=EXECUTION_WINDOW_SECONDS.get(resolved),
        requires_cancel_window=resolved == Tier.CANCELLABLE,
        requires_human_authorization=resolved == Tier.HUMAN,
        reason=reason,
    )


def assign_tier(
    requested_tier: int,
    asset_class: str,
    tier0_action_permitted: bool = True,
    hypothesis: str | None = None,
) -> TierAssignment:
    requested = int(requested_tier)
    floor = HYPOTHESIS_MIN_TIER.get(str(getattr(hypothesis, "value", hypothesis)), 0) if hypothesis else 0
    if requested in EXECUTION_WINDOW_SECONDS and requested < floor:
        raised = assign_tier(floor, asset_class, tier0_action_permitted)
        return replace(raised, requested_tier=requested,
                       reason=f"raised_to_tier{floor}_for_{getattr(hypothesis, 'value', hypothesis)}:{raised.reason}")
    policy = ASSET_CLASS_POLICY.get(asset_class)
    if policy is None:
        return _assignment(requested, requested, asset_class, False, "unknown_asset_class")
    if requested not in EXECUTION_WINDOW_SECONDS:
        return _assignment(requested, requested, asset_class, False, "invalid_tier")

    if requested == Tier.AUTONOMOUS:
        if policy.tier0_allowed and tier0_action_permitted:
            return _assignment(0, 0, asset_class, True, "tier0_eligible")
        if policy.tier1_allowed:
            return _assignment(0, 1, asset_class, True, "auto_upgraded_tier0_to_tier1")
        if policy.tier2_allowed:
            return _assignment(0, 2, asset_class, True, "auto_upgraded_tier0_to_tier2")
        return _assignment(0, 0, asset_class, False, "eligibility_violation")

    if requested == Tier.CANCELLABLE:
        if policy.tier1_allowed:
            return _assignment(1, 1, asset_class, True, "tier1_eligible")
        if policy.tier2_allowed:
            return _assignment(1, 2, asset_class, True, "auto_upgraded_tier1_to_tier2")
        return _assignment(1, 1, asset_class, False, "eligibility_violation")

    if policy.tier2_allowed:
        return _assignment(2, 2, asset_class, True, "tier2_eligible")
    return _assignment(2, 2, asset_class, False, "eligibility_violation")


def is_protected(asset_class: str) -> bool:
    return asset_class in PROTECTED_ASSET_CLASSES
