#!/usr/bin/env python3
"""Generate golden Overlord evaluation scenarios.

The JSON files under scenarios/ are build artifacts. Edit this generator and
re-run it; never edit the generated scenarios directly.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "scenarios"
NOW = "2026-11-03T00:00:00+00:00"
STAGES = [f"S{i}" for i in range(1, 10)]


def normalized(
    tags: list[str],
    count: int = 3,
    *,
    confidence: float = 0.9,
    host: str = "host-42",
) -> list[dict[str, Any]]:
    return [
        {
            "source": "wazuh",
            "message": f"alert {index} {' '.join(tags)}",
            "normalized_tags": list(tags),
            "host_id": host,
            "confidence": confidence,
        }
        for index in range(count)
    ]


def wazuh_raw(rule_id: str, level: int, count: int, description: str) -> list[dict[str, Any]]:
    return [
        {
            "source": "wazuh",
            "id": f"wazuh-{rule_id}-{index}",
            "@timestamp": NOW,
            "agent": {"id": "001", "name": "host-42"},
            "rule": {"id": rule_id, "description": description},
            "level": level,
            "location": "/var/log/auth.log",
        }
        for index in range(count)
    ]


def falco_raw(count: int) -> list[dict[str, Any]]:
    return [
        {
            "source": "falco",
            "time": NOW,
            "rule": "Terminal shell in container",
            "priority": "Critical",
            "output": f"shell spawned in container {index}",
            "output_fields": {"hostname": "host-42", "container.id": "abc123"},
        }
        for index in range(count)
    ]


def zeek_raw(path: str, count: int) -> list[dict[str, Any]]:
    return [
        {
            "source": "zeek",
            "_path": path,
            "uid": f"C{index}",
            "ts": 1793664000.0,
            "id.orig_h": "10.0.1.20",
            "id.resp_h": "10.0.0.5",
        }
        for index in range(count)
    ]


def applied(tier: int, *, n: int = 3) -> dict[str, Any]:
    return {
        "blocked_at": None,
        "error": None,
        "tier": tier,
        "decision_status": "applied",
        "outcome": "success",
        "n_conclusions": n,
        "stages": STAGES,
    }


def blocked(
    stage: str,
    error: str,
    *,
    tier: int | None,
    n: int,
    decision_status: str | None,
    outcome: str | None,
) -> dict[str, Any]:
    return {
        "blocked_at": stage,
        "error": error,
        "tier": tier,
        "decision_status": decision_status,
        "outcome": outcome,
        "n_conclusions": n,
        "stages": STAGES[: int(stage[1:])],
    }


SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "credential-access-auth",
        "name": "Authentication event maps to credential access",
        "description": "Three high-confidence authentication facts should reach a credential-access conclusion.",
        "telemetry": normalized(["authentication"]),
        "techniques": ["T1078"],
        "hypotheses": ["credential_access"],
        "pipeline": {"requested_tier": 1, "approve": True},
        "expect": applied(1),
    },
    {
        "id": "credential-access-bruteforce",
        "name": "Suspicious login maps to brute force",
        "description": "Suspicious-login telemetry should enrich to T1110 while keeping credential access as the hypothesis.",
        "telemetry": normalized(["suspicious_login"]),
        "techniques": ["T1110"],
        "hypotheses": ["credential_access"],
        "pipeline": {"requested_tier": 1, "approve": True},
        "expect": applied(1),
    },
    {
        "id": "command-and-control-process",
        "name": "Process creation maps to command and control",
        "description": "Process-creation telemetry should enrich to T1059 and produce a C2 conclusion.",
        "telemetry": normalized(["process_creation"]),
        "techniques": ["T1059"],
        "hypotheses": ["command_and_control"],
        "pipeline": {"requested_tier": 1, "approve": True},
        "expect": applied(1),
    },
    {
        "id": "command-and-control-network",
        "name": "Network connection maps to application-layer C2",
        "description": "Network-connection telemetry should enrich to T1071.",
        "telemetry": normalized(["network_connection"]),
        "techniques": ["T1071"],
        "hypotheses": ["command_and_control"],
        "pipeline": {"requested_tier": 1, "approve": True},
        "expect": applied(1),
    },
    {
        "id": "collection-file-access",
        "name": "File access maps to collection",
        "description": "File-access telemetry should enrich to T1005 and meet the collection support threshold.",
        "telemetry": normalized(["file_access"]),
        "techniques": ["T1005"],
        "hypotheses": ["collection"],
        "pipeline": {"requested_tier": 1, "approve": True},
        "expect": applied(1),
    },
    {
        "id": "persistence-registry",
        "name": "Registry modification maps to persistence",
        "description": "Registry-modification telemetry should enrich to T1547.",
        "telemetry": normalized(["registry_modification"]),
        "techniques": ["T1547"],
        "hypotheses": ["persistence"],
        "pipeline": {"requested_tier": 1, "approve": True},
        "expect": applied(1),
    },
    {
        "id": "privilege-escalation",
        "name": "Privilege escalation maps to defense evasion",
        "description": "Privilege-escalation telemetry should enrich to T1068.",
        "telemetry": normalized(["privilege_escalation"]),
        "techniques": ["T1068"],
        "hypotheses": ["defense_evasion"],
        "pipeline": {"requested_tier": 1, "approve": True},
        "expect": applied(1),
    },
    {
        "id": "lateral-movement",
        "name": "Lateral move maps to remote services",
        "description": "Lateral-move telemetry should enrich to T1021.",
        "telemetry": normalized(["lateral_move"]),
        "techniques": ["T1021"],
        "hypotheses": ["lateral_movement"],
        "pipeline": {"requested_tier": 1, "approve": True},
        "expect": applied(1),
    },
    {
        "id": "exfiltration",
        "name": "Exfiltration telemetry maps to exfil over C2",
        "description": "Data-exfiltration telemetry should enrich to T1041.",
        "telemetry": normalized(["data_exfiltration"]),
        "techniques": ["T1041"],
        "hypotheses": ["exfiltration"],
        "pipeline": {"requested_tier": 1, "approve": True},
        "expect": applied(1),
    },
    {
        "id": "tier0-autonomous",
        "name": "Tier 0 executes autonomously on a perimeter IP",
        "description": "A perimeter firewall IP permits tier 0 with no approval.",
        "telemetry": normalized(["network_connection"]),
        "techniques": ["T1071"],
        "hypotheses": ["command_and_control"],
        "pipeline": {
            "requested_tier": 0,
            "asset_class": "perimeter_firewall_ip",
        },
        "expect": applied(0),
    },
    {
        "id": "tier1-awaiting-approval",
        "name": "Tier 1 parks until a human approves",
        "description": "Detection succeeds, but the pipeline must block at S7 awaiting approval.",
        "telemetry": normalized(["authentication"]),
        "techniques": ["T1078"],
        "hypotheses": ["credential_access"],
        "pipeline": {"requested_tier": 1, "approve": None},
        "expect": blocked(
            "S7",
            "awaiting_approval",
            tier=1,
            n=3,
            decision_status="pending",
            outcome=None,
        ),
    },
    {
        "id": "tier2-authorization-missing",
        "name": "Tier 2 requires written authorization",
        "description": "A medical workstation upgrades tier 1 to tier 2 and blocks without authorization.",
        "telemetry": normalized(["authentication"]),
        "techniques": ["T1078"],
        "hypotheses": ["credential_access"],
        "pipeline": {
            "requested_tier": 1,
            "asset_class": "medical_workstation",
            "approve": True,
        },
        "expect": blocked(
            "S7",
            "authorization_required",
            tier=2,
            n=3,
            decision_status="pending",
            outcome=None,
        ),
    },
    {
        "id": "tier2-authorized",
        "name": "Tier 2 executes with written authorization",
        "description": "The same medical-workstation flow completes when authorization is supplied.",
        "telemetry": normalized(["authentication"]),
        "techniques": ["T1078"],
        "hypotheses": ["credential_access"],
        "pipeline": {
            "requested_tier": 1,
            "asset_class": "medical_workstation",
            "approve": True,
            "authorization": "approved by on-call clinician",
        },
        "expect": applied(2),
    },
    {
        "id": "tier1-cancelled",
        "name": "Tier 1 cancellation rolls back",
        "description": "An explicit rejection must stop before execution and mark the decision rolled back.",
        "telemetry": normalized(["authentication"]),
        "techniques": ["T1078"],
        "hypotheses": ["credential_access"],
        "pipeline": {"requested_tier": 1, "approve": False},
        "expect": blocked(
            "S7",
            "cancelled",
            tier=1,
            n=3,
            decision_status="rolled_back",
            outcome="escalated",
        ),
    },
    {
        "id": "tier1-window-expired",
        "name": "Tier 1 execution window expires",
        "description": "A slow approval path must fail closed when the 60-second window elapses.",
        "telemetry": normalized(["authentication"]),
        "techniques": ["T1078"],
        "hypotheses": ["credential_access"],
        "pipeline": {
            "requested_tier": 1,
            "approve": True,
            "clock_step_seconds": 61,
        },
        "expect": blocked(
            "S7",
            "window_expired",
            tier=1,
            n=3,
            decision_status="failed",
            outcome="escalated",
        ),
    },
    {
        "id": "under-supported-single-fact",
        "name": "One fact cannot support a conclusion",
        "description": "The min-support gate must reject a single authentication fact at S4.",
        "telemetry": normalized(["authentication"], count=1),
        "techniques": [],
        "hypotheses": [],
        "pipeline": {"requested_tier": 1, "approve": True},
        "expect": blocked(
            "S4",
            "under_supported",
            tier=None,
            n=0,
            decision_status=None,
            outcome=None,
        ),
    },
    {
        "id": "context-exceeded",
        "name": "Tiny context window fails the audit",
        "description": "Evidence plus UUID overhead must exceed a 32-token window and block at S4.",
        "telemetry": normalized(["process_creation"]),
        "techniques": [],
        "hypotheses": [],
        "pipeline": {
            "requested_tier": 1,
            "approve": True,
            "model_context_window": 32,
        },
        "expect": blocked(
            "S4",
            "context_exceeded",
            tier=None,
            n=0,
            decision_status=None,
            outcome=None,
        ),
    },
    {
        "id": "adapter-wazuh-raw",
        "name": "Wazuh adapter normalizes a suspicious-login rule",
        "description": "Raw Wazuh rule 5711 should yield both T1078 and T1110 through the real adapter.",
        "telemetry": wazuh_raw("5711", 12, 3, "Multiple failed logins followed by success"),
        "techniques": ["T1078", "T1110"],
        "hypotheses": ["credential_access"],
        "pipeline": {
            "requested_tier": 1,
            "approve": True,
            "auto_sensors": True,
        },
        "expect": applied(1),
    },
    {
        "id": "adapter-falco-raw",
        "name": "Falco adapter normalizes a shell-spawn alert",
        "description": "A critical Falco shell alert should become process creation and T1059.",
        "telemetry": falco_raw(3),
        "techniques": ["T1059"],
        "hypotheses": ["command_and_control"],
        "pipeline": {
            "requested_tier": 1,
            "approve": True,
            "auto_sensors": True,
        },
        "expect": applied(1),
    },
    {
        "id": "adapter-zeek-notice",
        "name": "Zeek notice maps to process creation",
        "description": "Zeek notices carry 0.8 confidence and map to process creation in this adapter.",
        "telemetry": zeek_raw("notice", 3),
        "techniques": ["T1059"],
        "hypotheses": ["command_and_control"],
        "pipeline": {
            "requested_tier": 1,
            "approve": True,
            "auto_sensors": True,
        },
        "expect": applied(1),
    },
    {
        "id": "adapter-zeek-low-confidence",
        "name": "Zeek conn records fail min support",
        "description": "Zeek conn records carry 0.6 confidence, below the 0.7 floor, so S4 must block.",
        "telemetry": zeek_raw("conn", 3),
        "techniques": [],
        "hypotheses": [],
        "pipeline": {
            "requested_tier": 1,
            "approve": True,
            "auto_sensors": True,
        },
        "expect": blocked(
            "S4",
            "under_supported",
            tier=None,
            n=0,
            decision_status=None,
            outcome=None,
        ),
    },
]


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for stale in OUTPUT.glob("*.json"):
        stale.unlink()

    seen: set[str] = set()
    for scenario in SCENARIOS:
        scenario_id = scenario["id"]
        if scenario_id in seen:
            raise SystemExit(f"duplicate scenario id: {scenario_id}")
        seen.add(scenario_id)
        document = {
            "id": scenario_id,
            "name": scenario["name"],
            "description": scenario["description"],
            "now": NOW,
            "techniques": scenario["techniques"],
            "hypotheses": scenario["hypotheses"],
            "pipeline": scenario["pipeline"],
            "telemetry": scenario["telemetry"],
            "expect": scenario["expect"],
        }
        target = OUTPUT / f"{scenario_id}.json"
        target.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(f"wrote {len(SCENARIOS)} scenarios to {OUTPUT}")


if __name__ == "__main__":
    main()
