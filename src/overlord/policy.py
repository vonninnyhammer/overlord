from __future__ import annotations

from enum import IntEnum
from typing import NamedTuple

MIN_SUPPORT_DEFAULTS: dict[str, int] = {
    "initial_access": 3,
    "credential_theft": 3,
    "lateral_movement": 3,
    "persistence": 3,
    "defense_evasion": 3,
    "credential_access": 3,
    "discovery": 2,
    "collection": 2,
    "command_and_control": 2,
    "exfiltration": 3,
    "impact": 3,
}
DEFAULT_MIN_SUPPORT = 3

# The lowest tier a hypothesis may run at. A caller can ask for a higher tier, never a lower one,
# so an attack on credentials, persistence or data always waits for at least a Tier 1 approval.
HYPOTHESIS_MIN_TIER: dict[str, int] = {
    "initial_access": 1,
    "credential_theft": 1,
    "credential_access": 1,
    "lateral_movement": 1,
    "persistence": 1,
    "defense_evasion": 1,
    "exfiltration": 1,
    "impact": 1,
    "discovery": 0,
    "collection": 0,
    "command_and_control": 0,
}


class Tier(IntEnum):
    AUTONOMOUS = 0
    CANCELLABLE = 1
    HUMAN = 2


class AssetPolicy(NamedTuple):
    tier0_allowed: bool
    tier1_allowed: bool
    tier2_allowed: bool


ASSET_CLASS_POLICY: dict[str, AssetPolicy] = {
    "perimeter_firewall_ip": AssetPolicy(True, False, False),
    "endpoint_workstation": AssetPolicy(True, True, False),
    "production_server": AssetPolicy(True, True, True),
    "domain_controller": AssetPolicy(False, True, True),
    "hypervisor": AssetPolicy(False, True, True),
    "medical_workstation": AssetPolicy(False, False, True),
}

PROTECTED_ASSET_CLASSES = frozenset(
    {"domain_controller", "hypervisor", "medical_workstation"}
)

EXECUTION_WINDOW_SECONDS: dict[int, int | None] = {0: 0, 1: 60, 2: None}

CIRCUIT_BREAKER_TIER1_THRESHOLD = 5
CIRCUIT_BREAKER_TIER1_WINDOW_SECONDS = 300
BREAK_GLASS_TIER1_FREEZE_SECONDS = 900
