import base64
import sqlite3
from datetime import datetime, timezone
from uuid import uuid4

from overlord.intel import IntelEnrichment, IntelLedger
from overlord.models import Fact, Provenance, Source
from overlord.pipeline import DefaultEnrichment

SCHEMA = """
CREATE TABLE findings (
    content_hash TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    source_name TEXT NOT NULL,
    external_id TEXT NOT NULL,
    title TEXT NOT NULL,
    url TEXT,
    summary TEXT,
    published TEXT,
    modified TEXT,
    severity TEXT,
    cvss REAL,
    vendor TEXT,
    product TEXT,
    exploit_available INTEGER NOT NULL DEFAULT 0,
    cve_ids TEXT,
    cwe_ids TEXT,
    techniques TEXT,
    iocs TEXT,
    kev INTEGER NOT NULL DEFAULT 0,
    reference INTEGER NOT NULL DEFAULT 0,
    weight REAL NOT NULL DEFAULT 0.5,
    score REAL NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
)
"""


def ledger(tmp_path):
    path = tmp_path / "intel.db"
    connection = sqlite3.connect(path)
    connection.execute(SCHEMA)
    connection.execute(
        "INSERT INTO findings (content_hash, source, source_name, external_id,"
        " title, url, summary, published, severity, vendor, product,"
        " exploit_available, cve_ids, techniques, iocs, kev, reference, score,"
        " first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "abc",
            "cisa_kev",
            "KEV",
            "CVE-2026-0001",
            "Ivanti Connect Secure authentication bypass",
            "https://example.test/kev",
            "Exploited in the wild via T1190.",
            "2026-11-01",
            "KEV",
            "Ivanti",
            "Connect Secure",
            1,
            "CVE-2026-0001",
            "T1190",
            "198.51.100.7",
            1,
            0,
            0.96,
            "2026-11-01T00:00:00+00:00",
            "2026-11-01T00:00:00+00:00",
        ),
    )
    connection.commit()
    connection.close()
    return path


def fact(message: str, tags: list[str]) -> Fact:
    return Fact(
        fact_id=uuid4(),
        source=Source.WAZUH,
        timestamp=datetime(2026, 11, 3, tzinfo=timezone.utc),
        raw_payload=base64.b64encode(message.encode()).decode(),
        normalized_tags=tags,
        confidence=0.9,
        provenance=Provenance(
            collector_id="test", host_id="host-1", sensor_uid="sensor-1"
        ),
        created_by="test",
    )


def test_matches_by_cve_and_technique(tmp_path):
    intel = IntelLedger(ledger(tmp_path))
    by_cve = intel.match(cves=["CVE-2026-0001"])
    assert len(by_cve) == 1
    assert by_cve[0]["vendor"] == "Ivanti"
    assert by_cve[0]["product"] == "Connect Secure"
    assert by_cve[0]["exploit_available"] is True

    by_technique = intel.match(techniques=["T1190"])
    assert len(by_technique) == 1


def test_enrichment_attaches_threat_intel(tmp_path):
    enrichment = IntelEnrichment(IntelLedger(ledger(tmp_path)), DefaultEnrichment())
    enriched = enrichment.enrich(
        fact("Observed exploitation of CVE-2026-0001 via T1190", ["authentication"])
    )
    assert "T1078" in enriched["attck_techniques"]
    assert len(enriched["threat_intel"]) == 1
    assert enriched["threat_intel"][0]["id"] == "CVE-2026-0001"


def test_missing_ledger_returns_no_matches(tmp_path):
    intel = IntelLedger(tmp_path / "missing.db")
    assert intel.match(cves=["CVE-2026-0001"]) == []
