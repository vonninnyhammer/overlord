"""Tests for the operational tools: workflow generator, journal shipper, workflow installer."""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from overlord.pipeline import OverlordPipeline

TOOLS = Path(__file__).resolve().parents[1] / "tools"


def _load(name: str):
    if str(TOOLS) not in sys.path:
        sys.path.insert(0, str(TOOLS))
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build = _load("build_workflows")
shipper = _load("journal_shipper")
installer = _load("install_workflows")


# --------------------------------------------------------------------------- workflows

@pytest.mark.parametrize("filename", sorted(build.BUILDERS))
def test_generated_workflow_is_committed_and_current(filename):
    path = TOOLS.parent / "workflows" / filename
    assert path.read_text() == build.render(build.BUILDERS[filename])


@pytest.mark.parametrize("builder", list(build.BUILDERS.values()))
def test_workflow_connections_reference_real_nodes(builder):
    wf = builder()
    names = {n["name"] for n in wf["nodes"]}
    assert len(names) == len(wf["nodes"])
    for src, conn in wf["connections"].items():
        assert src in names
        for output in conn["main"]:
            for link in output:
                assert link["node"] in names


@pytest.mark.parametrize("builder", list(build.BUILDERS.values()))
def test_workflow_carries_no_private_values(builder):
    text = json.dumps(builder())
    assert "id" not in builder()  # n8n workflow IDs are private; the installer assigns them
    # Only loopback addresses; tailnet IPs, topics and tokens come from $env.
    for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
        assert ip == "127.0.0.1"
    assert "Bearer " not in text.replace("Bearer {{ $env.OVERLORD_API_TOKEN }}", "")


def test_alert_nodes_never_fail_the_workflow():
    for builder in (build.watcher, build.errors):
        node = next(n for n in builder()["nodes"] if n["name"] == "Send ntfy")
        assert node["onError"] == "continueRegularOutput"
        assert "$env.OVERLORD_NTFY_URL" in node["parameters"]["url"]


def test_watcher_does_not_log_every_poll():
    settings = build.watcher()["settings"]
    assert settings["saveDataSuccessExecution"] == "none"


# --------------------------------------------------------------------------- shipper

def _entry(ident: str, message, stamp: str = "1762950000000000") -> dict:
    return {"SYSLOG_IDENTIFIER": ident, "MESSAGE": message, "__REALTIME_TIMESTAMP": stamp}


@pytest.mark.parametrize("ident,message,tags", [
    ("sshd", "Failed password for invalid user admin from 203.0.113.9 port 4242 ssh2",
     ["suspicious_login"]),
    ("sshd", "Invalid user oracle from 203.0.113.9 port 4242", ["suspicious_login"]),
    ("sshd", "Accepted publickey for root from 203.0.113.9 port 4242 ssh2",
     ["suspicious_login", "authentication"]),
    ("sudo", "  mallory : user NOT in sudoers ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
     ["privilege_escalation"]),
    ("sudo", "  alice : 3 incorrect password attempts ; TTY=pts/1", ["suspicious_login"]),
    ("su", "FAILED SU (to root) alice on pts/2", ["suspicious_login"]),
])
def test_shipper_ships_security_relevant_events(ident, message, tags):
    event = shipper.classify(_entry(ident, message))
    assert event["normalized_tags"] == tags
    assert 0.7 <= event["confidence"] <= 0.9
    assert event["timestamp"] == datetime.fromtimestamp(1762950000, tz=timezone.utc).isoformat()
    assert event["message"].startswith(f"{ident}: ")


@pytest.mark.parametrize("ident,message", [
    ("sshd", "Accepted publickey for alice from 192.0.2.10 port 50000 ssh2"),
    ("sudo", "  alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"),
    ("sshd", "Received disconnect from 203.0.113.9 port 4242:11: Bye"),
    ("cron", "Failed password for root"),
    ("sshd", [70, 97, 105, 108]),  # non-UTF-8 message arrives as a byte array
])
def test_shipper_skips_routine_and_unreadable_events(ident, message):
    assert shipper.classify(_entry(ident, message)) is None


def test_shipper_retries_then_drops(monkeypatch):
    calls = []
    monkeypatch.setattr(shipper, "post", lambda url, host, events: calls.append(len(events)) or "retry")
    s = shipper.Shipper("http://x", "workstation", window=0)
    s.add({"message": "a"})
    for _ in range(shipper.MAX_ATTEMPTS):
        s.next_try = 0
        s.flush()
    assert len(calls) == shipper.MAX_ATTEMPTS
    assert not s.buffer


def test_shipper_drops_rejected_batch_without_retry(monkeypatch):
    monkeypatch.setattr(shipper, "post", lambda url, host, events: "rejected")
    s = shipper.Shipper("http://x", "workstation", window=0)
    s.add({"message": "a"})
    s.flush()
    assert not s.buffer and s.attempts == 0


def test_journald_events_reach_the_core_but_one_source_cannot_trigger_a_response():
    """A journald-only batch is analysed, then held by the two-source rule."""
    events = [shipper.classify(_entry("sshd", f"Failed password for root from 203.0.113.9 port {p} ssh2",
                                      str(1762950000000000 + p)))
              for p in (1, 2, 3)]
    telemetry = [{**e, "source": "journald", "host_id": "workstation", "sensor_uid": "journald:workstation",
                  "collector_id": "journal-shipper"} for e in events]
    result = OverlordPipeline(min_independent_sources=2).run_incident(
        telemetry, requested_tier=0, target_asset="workstation")
    assert {f.source.value for f in result.facts.values()} == {"journald"}
    assert result.blocked_at == "S5"
    assert result.error == "insufficient_independent_sources"


# --------------------------------------------------------------------------- installer

def _repo():
    return {wf["name"]: wf for wf in (b() for b in build.BUILDERS.values())} | {
        "Overlord — Full": {"name": "Overlord — Full", "nodes": [], "connections": {},
                                 "settings": {}}}


def test_installer_reuses_ids_and_wires_error_workflow():
    existing = [
        {"id": "FULLID0000000001", "name": "Overlord — Full", "active": True},
        {"id": "OTHER00000000001", "name": "Someone else's workflow", "active": True},
    ]
    merged, publish, notes = installer.plan(existing, _repo())
    assert merged["Overlord — Full"]["id"] == "FULLID0000000001"
    errors_id = merged[build.ERRORS_NAME]["id"]
    assert re.fullmatch(r"[A-Za-z0-9]{16}", errors_id)
    for name, wf in merged.items():
        if name != build.ERRORS_NAME:
            assert wf["settings"]["errorWorkflow"] == errors_id
    assert "errorWorkflow" not in merged[build.ERRORS_NAME]["settings"]
    assert set(publish) == {merged[n]["id"] for n in
                            ("Overlord — Full", build.ERRORS_NAME, build.INTAKE_NAME, build.WATCHER_NAME)}
    assert any("Someone else's workflow" in n for n in notes)


def test_installer_keeps_unpublished_workflows_unpublished():
    existing = [{"id": "FULLID0000000001", "name": "Overlord — Full", "active": False}]
    merged, publish, _ = installer.plan(existing, _repo())
    assert "FULLID0000000001" not in publish


def test_installer_refuses_duplicate_names():
    existing = [{"id": "A" * 16, "name": "Overlord — Full"}, {"id": "B" * 16, "name": "Overlord — Full"}]
    with pytest.raises(SystemExit):
        installer.plan(existing, _repo())
