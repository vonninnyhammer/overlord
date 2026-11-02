from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class PendingStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._items: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            loaded = {}
        if isinstance(loaded, dict):
            self._items = loaded

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._items, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

    def park(self, result: Any) -> str:
        decision_id = str(result.decision.decision_id)
        self._items[decision_id] = {
            "incident_id": result.incident_id,
            "decision": result.decision.model_dump(mode="json"),
            "events": result.events,
        }
        self._save()
        return decision_id

    def get(self, decision_id: str) -> dict[str, Any] | None:
        return self._items.get(decision_id)

    def remove(self, decision_id: str) -> None:
        if self._items.pop(decision_id, None) is not None:
            self._save()

    def all(self) -> list[dict[str, Any]]:
        return [
            {"decision_id": decision_id, **item}
            for decision_id, item in sorted(self._items.items())
        ]
