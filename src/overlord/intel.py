from __future__ import annotations

import base64
import binascii
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{3,}")
STOPWORDS = frozenset(
    {
        "that",
        "this",
        "with",
        "from",
        "have",
        "been",
        "were",
        "which",
        "their",
        "there",
        "would",
        "could",
        "about",
        "after",
        "into",
        "than",
        "then",
        "when",
        "where",
    }
)


def _payload_text(fact: Any) -> str:
    payload = getattr(fact, "raw_payload", "")
    if not payload:
        return ""
    try:
        return base64.b64decode(payload, validate=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return ""


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    keys = row.keys()
    return {
        "source": row["source"],
        "id": row["external_id"],
        "title": row["title"],
        "url": row["url"],
        "published": row["published"],
        "severity": row["severity"],
        "cvss": row["cvss"],
        "vendor": row["vendor"] if "vendor" in keys else None,
        "product": row["product"] if "product" in keys else None,
        "exploit_available": bool(row["exploit_available"])
        if "exploit_available" in keys
        else False,
        "kev": bool(row["kev"]),
        "score": row["score"],
        "cves": [c for c in (row["cve_ids"] or "").split(",") if c],
        "techniques": [t for t in (row["techniques"] or "").split(",") if t],
        "iocs": [i for i in (row["iocs"] or "").split(",") if i],
    }


class IntelLedger:
    """Read-only view of the threat-intel collector's SQLite ledger."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def available(self) -> bool:
        return self.path.exists()

    def _connect(self) -> sqlite3.Connection | None:
        if not self.path.exists():
            return None
        try:
            connection = sqlite3.connect(
                f"file:{self.path}?mode=ro", uri=True, check_same_thread=False
            )
        except sqlite3.Error:
            return None
        connection.row_factory = sqlite3.Row
        return connection

    def match(
        self,
        *,
        cves: Iterable[str] = (),
        techniques: Iterable[str] = (),
        iocs: Iterable[str] = (),
        text: str = "",
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[str] = []
        for cve in sorted({c.upper() for c in cves if c}):
            clauses.append("cve_ids LIKE ?")
            params.append(f"%{cve}%")
        for technique in sorted({t.upper() for t in techniques if t}):
            clauses.append("techniques LIKE ?")
            params.append(f"%{technique}%")
        for ioc in sorted({i for i in iocs if i}):
            clauses.append("iocs LIKE ?")
            params.append(f"%{ioc}%")
        for token in self._terms(text):
            clauses.append("(title LIKE ? OR summary LIKE ?)")
            params.extend([f"%{token}%", f"%{token}%"])
        if not clauses:
            return []

        query = (
            "SELECT * FROM findings WHERE reference = 0 AND ("
            + " OR ".join(clauses)
            + ") ORDER BY score DESC, COALESCE(published, first_seen) DESC LIMIT ?"
        )
        params.append(str(limit))
        connection = self._connect()
        if connection is None:
            return []
        try:
            rows = connection.execute(query, params).fetchall()
        except sqlite3.OperationalError:
            return []
        finally:
            connection.close()
        return [_row_to_dict(row) for row in rows]

    def _terms(self, text: str) -> list[str]:
        seen: list[str] = []
        for token in TOKEN_RE.findall(text):
            lowered = token.lower()
            if lowered in STOPWORDS or lowered in seen:
                continue
            seen.append(lowered)
            if len(seen) == 5:
                break
        return seen


class IntelEnrichment:
    """Attach matching threat-intelligence context to a fact."""

    def __init__(self, ledger: IntelLedger, base: Any | None = None) -> None:
        self.ledger = ledger
        self.base = base

    def enrich(self, fact: Any) -> dict[str, Any]:
        context: dict[str, Any] = {}
        if self.base is not None:
            context.update(self.base.enrich(fact))

        text = _payload_text(fact)
        cves = sorted({m.upper() for m in CVE_RE.findall(text)})
        techniques = sorted({m.upper() for m in TECHNIQUE_RE.findall(text)})
        techniques = sorted(
            set(techniques) | set(context.get("attck_techniques") or [])
        )
        context["threat_intel"] = self.ledger.match(
            cves=cves, techniques=techniques, text=text, limit=5
        )
        return context
