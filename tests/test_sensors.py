import base64
import json
from datetime import datetime, timezone

from overlord.adapters.falco import FalcoAdapter
from overlord.adapters.wazuh import WazuhAdapter
from overlord.adapters.zeek import ZeekAdapter
from overlord.models import MAX_RAW_PAYLOAD_BYTES, Source
from overlord.pipeline import OverlordPipeline
from overlord.sensors import FallbackSensor, sensor_factory

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


def wazuh_alert(**overrides):
    alert = {
        "@timestamp": "2026-11-01T11:58:03.120Z",
        "id": "1698843483.4417",
        "level": 9,
        "location": "/var/log/auth.log",
        "agent": {"id": "001", "name": "web-01"},
        "rule": {"id": "5711", "description": "sshd: brute force"},
    }
    alert.update(overrides)
    return alert


def test_wazuh_normalizes_to_fact():
    fact = WazuhAdapter().normalize(wazuh_alert(), NOW)
    assert fact.source == Source.WAZUH
    assert fact.normalized_tags == ["authentication", "suspicious_login"]
    assert fact.provenance.host_id == "web-01"
    assert fact.provenance.sensor_uid == "001"
    assert fact.confidence == 9 / 15
    assert json.loads(base64.b64decode(fact.raw_payload))["rule"]["id"] == "5711"


def test_wazuh_id_is_deterministic():
    first = WazuhAdapter().normalize(wazuh_alert(), NOW)
    second = WazuhAdapter().normalize(wazuh_alert(), NOW)
    assert first.fact_id == second.fact_id


def test_wazuh_unknown_rule_uses_default_tag():
    fact = WazuhAdapter().normalize(wazuh_alert(rule={"id": "999999"}), NOW)
    assert fact.normalized_tags == ["process_creation"]


def test_wazuh_bad_timestamp_falls_back_to_now():
    fact = WazuhAdapter().normalize(wazuh_alert(**{"@timestamp": "not-a-time"}), NOW)
    assert fact.timestamp == NOW


def test_wazuh_oversized_payload_is_capped_and_valid():
    fact = WazuhAdapter().normalize(wazuh_alert(payload="x" * 10_000), NOW)
    decoded = base64.b64decode(fact.raw_payload, validate=True)
    assert len(decoded) <= MAX_RAW_PAYLOAD_BYTES


def test_falco_normalizes_priority_and_host():
    raw = {
        "time": "2026-11-01T11:59:00.000Z",
        "rule": "Terminal shell in container",
        "priority": "Critical",
        "output": "A shell was spawned",
        "output_fields": {"k8s.pod.name": "api-7d9", "container.id": "abc123"},
    }
    fact = FalcoAdapter().normalize(raw, NOW)
    assert fact.source == Source.FALCO
    assert fact.normalized_tags == ["process_creation"]
    assert fact.provenance.host_id == "api-7d9"
    assert fact.confidence == 0.9


def test_zeek_maps_path_and_timestamp():
    raw = {"_path": "dns", "ts": 1762084740.5, "uid": "C1x", "id.orig_h": "10.0.0.5"}
    fact = ZeekAdapter().normalize(raw, NOW)
    assert fact.source == Source.ZEEK
    assert fact.normalized_tags == ["network_connection"]
    assert fact.provenance.host_id == "10.0.0.5"
    assert fact.timestamp.year == 2025


def test_fallback_sensor_handles_unknown_source():
    fact = FallbackSensor().normalize({"source": "mystery", "message": "hello"}, NOW)
    assert fact.source == Source.HUMAN
    assert fact.normalized_tags == ["process_creation"]


def test_sensor_factory_selects_adapter():
    assert isinstance(sensor_factory("wazuh"), WazuhAdapter)
    assert isinstance(sensor_factory("FALCO"), FalcoAdapter)
    assert isinstance(sensor_factory("zeek"), ZeekAdapter)
    assert isinstance(sensor_factory("other"), FallbackSensor)


def test_pipeline_auto_sensors_uses_source_adapter():
    pipeline = OverlordPipeline(auto_sensors=True)
    result = pipeline.run_incident([wazuh_alert(source="wazuh")], stop_after="S1")
    fact = next(iter(result.facts.values()))
    assert fact.source == Source.WAZUH
    assert fact.normalized_tags == ["authentication", "suspicious_login"]
    assert fact.provenance.host_id == "web-01"


def test_pipeline_without_auto_sensors_keeps_default_sensor():
    pipeline = OverlordPipeline()
    raw = {
        "source": "wazuh",
        "message": "generic telemetry",
        "normalized_tags": ["process_creation"],
    }
    result = pipeline.run_incident([raw], stop_after="S1")
    fact = next(iter(result.facts.values()))
    assert fact.normalized_tags == ["process_creation"]
    assert fact.provenance.host_id == "host-unknown"


def test_api_pipeline_auto_sensors():
    from fastapi.testclient import TestClient

    from overlord.api import app

    client = TestClient(app)
    response = client.post(
        "/pipeline/run",
        json={
            "telemetry": [wazuh_alert(source="wazuh")],
            "stop_after": "S1",
            "auto_sensors": True,
        },
    )
    assert response.status_code == 200
    assert "web-01" in response.text
