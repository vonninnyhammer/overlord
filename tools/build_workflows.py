#!/usr/bin/env python3
"""Generate the operational n8n workflows: telemetry intake, approval watcher, error alerts.

The JSON written to workflows/ is public: it carries no IDs, addresses, topics or tokens.
Everything private comes from n8n's environment at run time:

  OVERLORD_API_TOKEN    bearer token for the Overlord core
  OVERLORD_NTFY_URL     ntfy server base URL (e.g. http://<node tailnet ip>:2586)
  OVERLORD_NTFY_TOPIC   ntfy topic the phone subscribes to

Run:  python tools/build_workflows.py          (writes workflows/*.json)
      python tools/build_workflows.py --check  (exit 1 if the files are stale)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "workflows"
CORE = "http://127.0.0.1:8790"
AUTH_HEADER = {
    "parameters": [{"name": "Authorization", "value": "=Bearer {{ $env.OVERLORD_API_TOKEN }}"}]
}

INTAKE_NAME = "Overlord — Telemetry Intake"
WATCHER_NAME = "Overlord — Approval Watcher"
ERRORS_NAME = "Overlord — Error Alerts"


def _id(workflow: str, node: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"overlord-workflow:{workflow}:{node}"))


def _node(workflow: str, name: str, ntype: str, version: float, x: int, y: int = 0,
          params: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    node = {
        "parameters": params or {},
        "id": _id(workflow, name),
        "name": name,
        "type": f"n8n-nodes-base.{ntype}",
        "typeVersion": version,
        "position": [x, y],
    }
    node.update(extra)
    return node


def _links(*chains: tuple[str, ...], branches: dict[str, list[str]] | None = None) -> dict[str, Any]:
    """Connections for straight chains, plus multi-output nodes given as {node: [out0, out1]}."""
    conns: dict[str, Any] = {}
    for chain in chains:
        for src, dst in zip(chain, chain[1:]):
            conns[src] = {"main": [[{"node": dst, "type": "main", "index": 0}]]}
    for src, outs in (branches or {}).items():
        conns[src] = {"main": [[{"node": dst, "type": "main", "index": 0}] for dst in outs]}
    return conns


def _workflow(name: str, nodes: list[dict[str, Any]], connections: dict[str, Any],
              **settings: Any) -> dict[str, Any]:
    return {
        "name": name,
        "nodes": nodes,
        "connections": connections,
        "active": False,
        "settings": {"executionOrder": "v1", **settings},
        "pinData": {},
        "meta": {"templateCredsSetupCompleted": True},
        "tags": [],
    }


def _ntfy_node(wf: str, x: int, y: int = 0) -> dict[str, Any]:
    """Publish {title, message, priority, tags} items to ntfy; never fail the workflow over it."""
    body = (
        "={{ JSON.stringify({ topic: $env.OVERLORD_NTFY_TOPIC, title: $json.title, "
        "message: $json.message, priority: $json.priority, tags: $json.tags }) }}"
    )
    return _node(wf, "Send ntfy", "httpRequest", 4.2, x, y, {
        "method": "POST",
        "url": "={{ $env.OVERLORD_NTFY_URL }}",
        "sendBody": True,
        "specifyBody": "json",
        "jsonBody": body,
        "options": {"timeout": 5000},
    }, onError="continueRegularOutput")


# --------------------------------------------------------------------------- intake

INTAKE_VALIDATE = r"""const body = $json.body || {};
const host = String(body.host || '').toLowerCase();
if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(host)) {
  return [{ json: { error: 'invalid_host' } }];
}
const TAGS = new Set(['authentication', 'suspicious_login', 'privilege_escalation']);
const events = Array.isArray(body.events) ? body.events.slice(0, 200) : [];
const telemetry = [];
for (const e of events) {
  if (!e || typeof e !== 'object') continue;
  const tags = (Array.isArray(e.normalized_tags) ? e.normalized_tags : []).filter(t => TAGS.has(t));
  if (!tags.length) continue;
  const conf = Number(e.confidence);
  telemetry.push({
    source: 'journald',
    message: String(e.message || '').slice(0, 2000),
    timestamp: e.timestamp ? String(e.timestamp) : undefined,
    normalized_tags: tags,
    confidence: Number.isFinite(conf) ? Math.min(Math.max(conf, 0), 0.9) : 0.5,
    host_id: host,
    sensor_uid: 'journald:' + host,
    collector_id: 'journal-shipper',
  });
}
if (!telemetry.length) {
  return [{ json: { error: 'no_events' } }];
}
// Tier 0 requested: the hypothesis floor raises it where the policy says so.
return [{ json: { error: '', payload: {
  telemetry, requested_tier: 0, target_asset: host, auto_sensors: false,
} } }];"""

INTAKE_SUMMARY = r"""const s = $json.summary || {};
return [{ json: { ok: true, summary: s } }];"""


def intake() -> dict[str, Any]:
    wf = "intake"
    nodes = [
        _node(wf, "Webhook", "webhook", 2, 0, params={
            "httpMethod": "POST", "path": "overlord/intake",
            "responseMode": "responseNode", "options": {},
        }, webhookId=_id(wf, "webhook-id")),
        _node(wf, "Validate Batch", "code", 2, 220, params={
            "mode": "runOnceForAllItems", "jsCode": INTAKE_VALIDATE}),
        _node(wf, "Rejected", "if", 2.2, 440, params={
            "conditions": {
                "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "loose", "version": 2},
                "conditions": [{
                    "id": _id(wf, "rejected-cond"),
                    "leftValue": "={{ $json.error }}", "rightValue": "",
                    "operator": {"type": "string", "operation": "notEmpty"},
                }],
                "combinator": "and",
            },
            "options": {},
        }),
        _node(wf, "Run Pipeline", "httpRequest", 4.2, 660, -100, {
            "method": "POST",
            "url": f"{CORE}/pipeline/run",
            "sendBody": True, "specifyBody": "json",
            "jsonBody": "={{ JSON.stringify($json.payload) }}",
            "sendHeaders": True, "headerParameters": AUTH_HEADER,
            "options": {"timeout": 30000},
        }),
        _node(wf, "Summarise", "code", 2, 880, -100, {
            "mode": "runOnceForAllItems", "jsCode": INTAKE_SUMMARY}),
        _node(wf, "Respond", "respondToWebhook", 1.1, 1100, params={
            "respondWith": "json", "responseBody": "={{ $json }}", "options": {}}),
    ]
    conns = _links(("Webhook", "Validate Batch", "Rejected"),
                   ("Run Pipeline", "Summarise", "Respond"),
                   branches={"Rejected": ["Respond", "Run Pipeline"]})
    return _workflow(INTAKE_NAME, nodes, conns)


# --------------------------------------------------------------------------- watcher

WATCHER_NOTICES = r"""const state = $getWorkflowStaticData('global');
const seen = state.seen || {};
const now = Date.now();
const res = $input.first().json || {};
const out = [];

// Overlord unreachable: alert once on the transition, not every 10 seconds.
if (!Array.isArray(res.pending)) {
  if (!state.down) {
    state.down = true;
    out.push({ json: { title: 'Overlord unreachable', priority: 4, tags: ['warning'],
      message: 'The approval watcher cannot read /pipeline/pending. Pending approvals will not be announced.' } });
  }
  return out;
}
if (state.down) {
  state.down = false;
  out.push({ json: { title: 'Overlord reachable again', priority: 3, tags: ['white_check_mark'],
    message: 'The approval watcher can read the queue again.' } });
}

for (const item of res.pending) {
  const id = String(item.decision_id || '');
  if (!id || seen[id]) continue;
  seen[id] = now;
  const d = item.decision || {};
  const win = d.execution_window_seconds;
  out.push({ json: {
    title: `Overlord: Tier ${d.action_tier} approval needed`,
    priority: d.action_tier === 1 ? 5 : 4,
    tags: ['rotating_light'],
    message: [
      `Asset: ${d.target_asset} (${item.asset_class || 'unknown class'})`,
      win ? `Expires ${win}s after ${d.created_at}` : 'No time limit (Tier 2 needs an authorizer)',
      `Decision: ${id}`,
      'Decide on the laptop: tools/decide.py approve|cancel <decision>',
    ].join('\n'),
  } });
}
for (const id of (res.expired || [])) {
  out.push({ json: { title: 'Overlord: approval expired', priority: 3, tags: ['hourglass'],
    message: `Decision ${id} was not approved in time; it was expired and recorded.` } });
}
for (const [id, t] of Object.entries(seen)) {
  if (now - t > 86400000) delete seen[id];
}
state.seen = seen;
return out;"""


def watcher() -> dict[str, Any]:
    wf = "watcher"
    nodes = [
        _node(wf, "Every 10 Seconds", "scheduleTrigger", 1.2, 0, params={
            "rule": {"interval": [{"field": "seconds", "secondsInterval": 10}]}}),
        _node(wf, "Read Queue", "httpRequest", 4.2, 220, params={
            "method": "GET",
            "url": f"{CORE}/pipeline/pending",
            "sendHeaders": True, "headerParameters": AUTH_HEADER,
            "options": {"timeout": 5000},
        }, onError="continueRegularOutput"),
        _node(wf, "New Notices", "code", 2, 440, params={
            "mode": "runOnceForAllItems", "jsCode": WATCHER_NOTICES}),
        _ntfy_node(wf, 660),
    ]
    conns = _links(("Every 10 Seconds", "Read Queue", "New Notices", "Send ntfy"))
    # Polling every 10 s would fill the execution log; keep failures only.
    return _workflow(WATCHER_NAME, nodes, conns,
                     saveDataSuccessExecution="none", saveManualExecutions=False)


# --------------------------------------------------------------------------- errors

ERROR_FORMAT = r"""const state = $getWorkflowStaticData('global');
const last = state.last || {};
const now = Date.now();
const wf = ($json.workflow && $json.workflow.name) || 'unknown workflow';
const ex = $json.execution || {};
const err = (ex.error && ex.error.message) || 'unknown error';
// At most one alert per workflow every 5 minutes.
if (last[wf] && now - last[wf] < 300000) return [];
last[wf] = now;
state.last = last;
return [{ json: {
  title: `n8n failure: ${wf}`,
  priority: 4,
  tags: ['x'],
  message: [`Node: ${ex.lastNodeExecuted || 'unknown'}`, `Error: ${String(err).slice(0, 300)}`,
            ex.id ? `Execution: ${ex.id}` : ''].filter(Boolean).join('\n'),
} }];"""


def errors() -> dict[str, Any]:
    wf = "errors"
    nodes = [
        _node(wf, "Error Trigger", "errorTrigger", 1, 0),
        _node(wf, "Format Alert", "code", 2, 220, params={
            "mode": "runOnceForAllItems", "jsCode": ERROR_FORMAT}),
        _ntfy_node(wf, 440),
    ]
    return _workflow(ERRORS_NAME, nodes, _links(("Error Trigger", "Format Alert", "Send ntfy")))


BUILDERS = {
    "overlord-intake.json": intake,
    "overlord-approval-watcher.json": watcher,
    "overlord-error-alerts.json": errors,
}


def render(builder) -> str:
    return json.dumps(builder(), indent=2, ensure_ascii=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if generated files are stale")
    args = parser.parse_args(argv)
    stale = []
    for filename, builder in BUILDERS.items():
        path = OUT_DIR / filename
        text = render(builder)
        if args.check:
            if not path.exists() or path.read_text() != text:
                stale.append(filename)
        else:
            path.write_text(text)
            print(f"wrote {path.relative_to(ROOT)}")
    if stale:
        print("stale: " + ", ".join(stale), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
