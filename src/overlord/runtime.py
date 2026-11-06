"""State that must be shared by every pipeline in one process.

The HTTP API builds a new OverlordPipeline per request, so counters kept on the pipeline
reset each time. The throttle and the Tier 1 circuit breaker live here instead.
"""
from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timedelta

from .policy import (
    BREAK_GLASS_TIER1_FREEZE_SECONDS,
    CIRCUIT_BREAKER_TIER1_THRESHOLD,
    CIRCUIT_BREAKER_TIER1_WINDOW_SECONDS,
)


class RuntimeState:
    def __init__(
        self,
        tier1_threshold: int = CIRCUIT_BREAKER_TIER1_THRESHOLD,
        tier1_window_seconds: int = CIRCUIT_BREAKER_TIER1_WINDOW_SECONDS,
        freeze_seconds: int = BREAK_GLASS_TIER1_FREEZE_SECONDS,
    ) -> None:
        self._lock = threading.Lock()
        self._in_flight: dict[str, int] = {}
        self._tier1_runs: deque[datetime] = deque()
        self._frozen_until: datetime | None = None
        self.tier1_threshold = tier1_threshold
        self.tier1_window = timedelta(seconds=tier1_window_seconds)
        self.freeze = timedelta(seconds=freeze_seconds)

    # --- throttle: how many analyst requests each agent has open
    def acquire(self, agent: str, limit: int) -> int | None:
        """Take a slot for agent; returns the new count, or None if it is at the limit."""
        with self._lock:
            current = self._in_flight.get(agent, 0)
            if current >= limit:
                return None
            self._in_flight[agent] = current + 1
            return current + 1

    def release(self, agent: str) -> None:
        with self._lock:
            self._in_flight[agent] = max(0, self._in_flight.get(agent, 0) - 1)

    def in_flight(self, agent: str) -> int:
        with self._lock:
            return self._in_flight.get(agent, 0)

    # --- circuit breaker: too many Tier 1 actions in a short time freezes Tier 1
    def record_tier1_run(self, now: datetime) -> bool:
        """Count an executed Tier 1 action. Returns True if this run tripped the breaker."""
        with self._lock:
            self._tier1_runs.append(now)
            while self._tier1_runs and now - self._tier1_runs[0] > self.tier1_window:
                self._tier1_runs.popleft()
            if len(self._tier1_runs) >= self.tier1_threshold and not self._is_frozen(now):
                self._frozen_until = now + self.freeze
                self._tier1_runs.clear()
                return True
            return False

    def tier1_frozen(self, now: datetime) -> bool:
        with self._lock:
            return self._is_frozen(now)

    def frozen_until(self) -> datetime | None:
        with self._lock:
            return self._frozen_until

    def _is_frozen(self, now: datetime) -> bool:
        return self._frozen_until is not None and now < self._frozen_until
