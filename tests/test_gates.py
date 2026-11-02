from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from overlord.gates import (
    TRIANGULATION_ERROR,
    assign_tier,
    audit_window,
    compress_evidence,
    evaluate_min_support,
    evaluate_triangulation,
    min_support_for,
)

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


def facts() -> dict[str, dict]:
    return {
        "f1": {"confidence": 0.90, "expires_at": None},
        "f2": {"confidence": 0.80, "expires_at": None},
        "f3": {"confidence": 0.75, "expires_at": None},
        "low": {"confidence": 0.50, "expires_at": None},
        "expired": {
            "confidence": 0.95,
            "expires_at": (NOW - timedelta(hours=1)).isoformat(),
        },
        "future": {
            "confidence": 0.72,
            "expires_at": (NOW + timedelta(hours=1)).isoformat(),
        },
    }


def test_min_support_accepts_three_independent_facts():
    result = evaluate_min_support("initial_access", ["f1", "f2", "f3"], facts(), NOW)
    assert result.accepted is True
    assert result.n_support == 3
    assert result.threshold == 3
    assert result.rejected == ()


def test_min_support_rejects_low_confidence():
    result = evaluate_min_support("initial_access", ["f1", "f2", "low"], facts(), NOW)
    assert result.accepted is False
    assert result.n_support == 2
    assert ("low", "low_confidence") in result.rejected
    assert result.reason == "under_supported"


def test_min_support_deduplicates_supporting_facts():
    result = evaluate_min_support(
        "initial_access", ["f1", "f1", "f2", "f3"], facts(), NOW
    )
    assert result.accepted is True
    assert result.n_support == 3
    assert ("f1", "duplicate") in result.rejected


def test_min_support_flags_missing_fact():
    result = evaluate_min_support("initial_access", ["f1", "f2", "ghost"], facts(), NOW)
    assert result.n_support == 2
    assert ("ghost", "missing") in result.rejected


def test_min_support_ignores_expired_and_accepts_future_expiry():
    result = evaluate_min_support(
        "initial_access", ["f1", "expired", "future"], facts(), NOW
    )
    assert result.n_support == 2
    assert ("expired", "expired") in result.rejected


def test_discovery_threshold_is_two():
    assert min_support_for("discovery") == 2
    result = evaluate_min_support("discovery", ["f1", "f2"], facts(), NOW)
    assert result.accepted is True


def test_unknown_hypothesis_defaults_to_three():
    assert min_support_for("brand_new_tactic") == 3


def test_triangulation_blocks_under_three():
    result = evaluate_triangulation(["c1", "c2"])
    assert result.ok is False
    assert result.error == TRIANGULATION_ERROR
    assert TRIANGULATION_ERROR == "need_at_least_3_conclusions_for_justification"


def test_triangulation_counts_distinct_ids_only():
    result = evaluate_triangulation(["c1", "c1", "c2", "c2", "c3"])
    assert result.ok is True
    assert result.distinct_count == 3


def test_triangulation_empty_is_blocked():
    result = evaluate_triangulation([])
    assert result.ok is False
    assert result.distinct_count == 0


def test_window_audit_passes_with_room():
    audit = audit_window("x" * 100, ["f1", "f2", "f3"], 8192)
    assert audit.evidence_tokens == 55
    assert audit.reserved_for_reasoning == 2048
    assert audit.usable_context == 6144
    assert audit.remaining == 6089
    assert audit.passed is True
    assert audit.near_limit is False


def test_window_audit_fails_when_evidence_exceeds_usable_context():
    audit = audit_window("x" * 400, ["f1", "f2", "f3"], 150)
    assert audit.evidence_tokens == 130
    assert audit.remaining == -17
    assert audit.passed is False


def test_window_audit_flags_near_limit():
    audit = audit_window("x" * 400, ["f1", "f2", "f3"], 175)
    assert audit.passed is True
    assert audit.remaining == 2
    assert audit.near_limit is True


def test_window_audit_deduplicates_uuid_token_cost():
    audit = audit_window("", ["f1", "f1", "f1"], 8192)
    assert audit.evidence_tokens == 14


@pytest.mark.parametrize(
    "asset_class,requested,permitted,resolved",
    [
        ("perimeter_firewall_ip", 0, True, 0),
        ("perimeter_firewall_ip", 1, False, 1),
        ("endpoint_workstation", 0, True, 0),
        ("endpoint_workstation", 2, False, 2),
        ("production_server", 0, True, 0),
        ("production_server", 1, True, 1),
        ("production_server", 2, True, 2),
        ("domain_controller", 0, True, 1),
        ("domain_controller", 1, True, 1),
        ("domain_controller", 2, True, 2),
        ("hypervisor", 0, True, 1),
        ("medical_workstation", 0, True, 2),
        ("medical_workstation", 1, True, 2),
        ("medical_workstation", 2, True, 2),
    ],
)
def test_tier_matrix(asset_class, requested, permitted, resolved):
    result = assign_tier(requested, asset_class)
    assert result.permitted is permitted
    assert result.resolved_tier == resolved


def test_tier_upgrades_tier0_when_action_not_permitted():
    result = assign_tier(0, "production_server", tier0_action_permitted=False)
    assert result.permitted is True
    assert result.resolved_tier == 1
    assert result.reason == "auto_upgraded_tier0_to_tier1"


def test_tier_windows_follow_tier():
    assert assign_tier(0, "endpoint_workstation").execution_window_seconds == 0
    assert assign_tier(1, "production_server").execution_window_seconds == 60
    assert assign_tier(2, "domain_controller").execution_window_seconds is None
    assert assign_tier(1, "production_server").requires_cancel_window is True
    assert assign_tier(2, "domain_controller").requires_human_authorization is True


def test_tier_rejects_unknown_asset_class_and_invalid_tier():
    assert assign_tier(1, "toaster").permitted is False
    assert assign_tier(1, "toaster").reason == "unknown_asset_class"
    assert assign_tier(7, "production_server").permitted is False
    assert assign_tier(7, "production_server").reason == "invalid_tier"


def test_compress_aggregates_ip_and_consolidates_tags():
    result = compress_evidence(
        "Block 10.0.1.20 and 192.168.5.5", ["auth", "auth", "network"]
    )
    assert result.evidence_summary == "Block 10.0.0.0 and 192.0.0.0"
    assert result.tag_counts == (("auth", 2), ("network", 1))
    assert "ip_aggregation" in result.applied
    assert "tag_consolidation" in result.applied


def test_compress_truncates_to_delta_budget():
    result = compress_evidence("y" * 300, delta_tokens=100)
    assert len(result.evidence_summary) == 156
    assert "summary_truncation" in result.applied


def test_compress_never_truncates_below_floor():
    result = compress_evidence("z" * 300, delta_tokens=10_000)
    assert len(result.evidence_summary) == 64
