from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

import httpx

TOKEN_RE = re.compile(r"[a-z0-9_]+")
HASH_DIMENSIONS = 256
DEFAULT_COLLECTION = "overlord_records"


class Embedder(Protocol):
    dimensions: int

    def embed(self, text: str) -> list[float]: ...


class HashingEmbedder:
    dimensions = HASH_DIMENSIONS

    def embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dimensions
        for token in TOKEN_RE.findall(text.lower()):
            digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
            index = int.from_bytes(digest[:4], "big") % self.dimensions
            sign = 1.0 if digest[4] & 1 else -1.0
            vector[index] += sign
        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0.0:
            return vector
        return [value / norm for value in vector]


class OllamaEmbedder:
    def __init__(
        self,
        model: str = "nomic-embed-text",
        url: str = "http://127.0.0.1:11434",
        dimensions: int = 768,
        timeout: float = 10.0,
    ) -> None:
        self.model = model
        self.url = url.rstrip("/")
        self.dimensions = dimensions
        self.timeout = timeout

    def embed(self, text: str) -> list[float]:
        response = httpx.post(
            f"{self.url}/api/embed",
            json={"model": self.model, "input": text},
            timeout=self.timeout,
        )
        response.raise_for_status()
        embeddings = response.json().get("embeddings") or []
        if not embeddings:
            raise ValueError("ollama returned no embeddings")
        vector = embeddings[0]
        self.dimensions = len(vector)
        return vector


class Ledger:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(str(self.path), check_same_thread=False)
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS records (
                kind TEXT NOT NULL,
                id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (kind, id)
            )
            """
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_records_kind ON records(kind)"
        )
        self._connection.commit()

    def put(self, kind: str, record_id: str, payload: dict[str, Any]) -> None:
        created_at = str(payload.get("created_at") or payload.get("timestamp") or "")
        if not created_at:
            created_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._connection.execute(
                "INSERT OR REPLACE INTO records (kind, id, created_at, payload)"
                " VALUES (?, ?, ?, ?)",
                (kind, record_id, created_at, json.dumps(payload, sort_keys=True)),
            )
            self._connection.commit()

    def get(self, kind: str, record_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT payload FROM records WHERE kind = ? AND id = ?",
                (kind, record_id),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def search_text(
        self, query: str, kind: str | None = None, limit: int = 10
    ) -> list[dict[str, Any]]:
        pattern = f"%{query}%"
        with self._lock:
            if kind:
                rows = self._connection.execute(
                    "SELECT kind, id, payload FROM records"
                    " WHERE kind = ? AND payload LIKE ?"
                    " ORDER BY created_at DESC LIMIT ?",
                    (kind, pattern, limit),
                ).fetchall()
            else:
                rows = self._connection.execute(
                    "SELECT kind, id, payload FROM records WHERE payload LIKE ?"
                    " ORDER BY created_at DESC LIMIT ?",
                    (pattern, limit),
                ).fetchall()
        return [
            {"kind": row[0], "id": row[1], "record": json.loads(row[2])} for row in rows
        ]

    def stats(self) -> dict[str, int]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT kind, COUNT(*) FROM records GROUP BY kind"
            ).fetchall()
        return {kind: count for kind, count in rows}

    def close(self) -> None:
        with self._lock:
            self._connection.close()


class QdrantIndex:
    def __init__(
        self,
        url: str = "http://127.0.0.1:6350",
        collection: str = DEFAULT_COLLECTION,
        embedder: Embedder | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.url = url.rstrip("/")
        self.collection = collection
        self.embedder = embedder or OllamaEmbedder()
        self.timeout = timeout
        self._ready = False

    def _client(self) -> httpx.Client:
        return httpx.Client(base_url=self.url, timeout=self.timeout)

    def ensure(self) -> bool:
        if self._ready:
            return True
        try:
            with self._client() as client:
                existing = client.get(f"/collections/{self.collection}")
                if existing.status_code == 404:
                    created = client.put(
                        f"/collections/{self.collection}",
                        json={
                            "vectors": {
                                "size": self.embedder.dimensions,
                                "distance": "Cosine",
                            }
                        },
                    )
                    created.raise_for_status()
                else:
                    existing.raise_for_status()
            self._ready = True
        except (httpx.HTTPError, ValueError):
            self._ready = False
        return self._ready

    def upsert(
        self, record_id: str, text: str, payload: dict[str, Any]
    ) -> bool:
        if not self.ensure():
            return False
        try:
            vector = self.embedder.embed(text)
            with self._client() as client:
                response = client.put(
                    f"/collections/{self.collection}/points",
                    json={
                        "points": [
                            {
                                "id": record_id,
                                "vector": vector,
                                "payload": payload,
                            }
                        ]
                    },
                )
                response.raise_for_status()
            return True
        except (httpx.HTTPError, ValueError):
            return False

    def search(
        self, text: str, limit: int = 10, kind: str | None = None
    ) -> list[dict[str, Any]]:
        if not self.ensure():
            return []
        try:
            vector = self.embedder.embed(text)
            body: dict[str, Any] = {
                "vector": vector,
                "limit": limit,
                "with_payload": True,
            }
            if kind:
                body["filter"] = {
                    "must": [{"key": "kind", "match": {"value": kind}}]
                }
            with self._client() as client:
                response = client.post(
                    f"/collections/{self.collection}/points/search", json=body
                )
                response.raise_for_status()
            return response.json().get("result", [])
        except (httpx.HTTPError, ValueError):
            return []

    def stats(self) -> dict[str, Any]:
        if not self.ensure():
            return {"available": False}
        try:
            with self._client() as client:
                response = client.get(f"/collections/{self.collection}")
                response.raise_for_status()
            return {"available": True, **response.json().get("result", {})}
        except (httpx.HTTPError, ValueError):
            return {"available": False}


class OverlordStore:
    def __init__(
        self,
        ledger_path: str | Path,
        vector: QdrantIndex | None = None,
    ) -> None:
        self.ledger = Ledger(ledger_path)
        self.vector = vector

    def record_fact(self, fact: dict[str, Any]) -> None:
        fact_id = str(fact["fact_id"])
        self.ledger.put("fact", fact_id, fact)
        if self.vector:
            text = " ".join(
                [
                    str(fact.get("source", "")),
                    " ".join(fact.get("normalized_tags") or []),
                    str(fact.get("provenance", {}).get("host_id", "")),
                ]
            )
            self.vector.upsert(
                fact_id,
                text,
                {"kind": "fact", "fact_id": fact_id},
            )

    def record_conclusion(self, conclusion: dict[str, Any]) -> None:
        conclusion_id = str(conclusion["conclusion_id"])
        self.ledger.put("conclusion", conclusion_id, conclusion)
        if self.vector:
            text = " ".join(
                [
                    str(conclusion.get("hypothesis", "")),
                    str(conclusion.get("evidence_summary", "")),
                    " ".join(conclusion.get("supporting_facts") or []),
                ]
            )
            self.vector.upsert(
                conclusion_id,
                text,
                {"kind": "conclusion", "conclusion_id": conclusion_id},
            )

    def record_decision(self, decision: dict[str, Any]) -> None:
        decision_id = str(decision["decision_id"])
        self.ledger.put("decision", decision_id, decision)
        if self.vector:
            text = " ".join(
                [
                    str(decision.get("target_asset", "")),
                    str(decision.get("status", "")),
                    str(decision.get("outcome", "")),
                    " ".join(decision.get("justification") or []),
                ]
            )
            self.vector.upsert(
                decision_id,
                text,
                {"kind": "decision", "decision_id": decision_id},
            )

    def search(
        self, query: str, kind: str | None = None, limit: int = 10
    ) -> dict[str, Any]:
        if self.vector:
            hits = self.vector.search(query, limit=limit, kind=kind)
            if hits:
                return {"backend": "qdrant", "hits": hits}
        return {
            "backend": "ledger",
            "hits": self.ledger.search_text(query, kind=kind, limit=limit),
        }

    def get(self, kind: str, record_id: str) -> dict[str, Any] | None:
        return self.ledger.get(kind, record_id)

    def stats(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"ledger": self.ledger.stats()}
        if self.vector:
            payload["vector"] = self.vector.stats()
        return payload

    def close(self) -> None:
        self.ledger.close()
