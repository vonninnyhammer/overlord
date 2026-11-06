from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any


log = logging.getLogger(__name__)


class PendingStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._items: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            loaded = None
        if isinstance(loaded, dict):
            self._items = loaded
            return
        # Keep the evidence: an unreadable file may hold approvals someone is waiting on.
        quarantine = self.path.with_name(f"{self.path.name}.corrupt-{int(time.time())}")
        self.path.replace(quarantine)
        log.error("pending store unreadable; moved to %s", quarantine)

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._items, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

    def park(self, result: Any) -> str:
        decision_id = str(result.decision.decision_id)
        with self._lock:
            self._items[decision_id] = {
                "incident_id": result.incident_id,
                "decision": result.decision.model_dump(mode="json"),
                "asset_class": result.tier.asset_class if result.tier else None,
                "events": result.events,
            }
            self._save()
        return decision_id

    def claim(self, decision_id: str) -> dict[str, Any] | None:
        """Atomically take a decision so two concurrent approvals cannot both execute it."""
        with self._lock:
            item = self._items.pop(decision_id, None)
            if item is not None:
                self._save()
            return item

    def restore(self, decision_id: str, item: dict[str, Any]) -> None:
        with self._lock:
            self._items[decision_id] = item
            self._save()

    def get(self, decision_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._items.get(decision_id)

    def remove(self, decision_id: str) -> None:
        with self._lock:
            if self._items.pop(decision_id, None) is not None:
                self._save()

    def all(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {"decision_id": decision_id, **item}
                for decision_id, item in sorted(self._items.items())
            ]
