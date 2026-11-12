#!/usr/bin/env python3
"""List, approve or cancel parked Overlord decisions from the laptop.

  python3 tools/decide.py list
  python3 tools/decide.py approve <decision_id>
  python3 tools/decide.py approve <decision_id> --tier2     # sends the Tier 2 authorization
  python3 tools/decide.py cancel  <decision_id>

Reads the API token from ~/.config/overlord/overlord.env and never prints it.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

CONFIG = Path.home() / ".config/overlord"
CORE = "http://127.0.0.1:8790"


def _token() -> str:
    for line in (CONFIG / "overlord.env").read_text().splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "OVERLORD_API_TOKEN":
            return value.strip().strip('"').strip("'")
    raise SystemExit("OVERLORD_API_TOKEN not found in ~/.config/overlord/overlord.env")


def _call(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(CORE + path, data=data, method=method, headers={
        "Authorization": f"Bearer {_token()}", "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}")
        except json.JSONDecodeError:
            return exc.code, {}
    except urllib.error.URLError as exc:
        raise SystemExit(f"Overlord is not reachable at {CORE}: {exc.reason}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    for name in ("approve", "cancel"):
        p = sub.add_parser(name)
        p.add_argument("decision_id")
        if name == "approve":
            p.add_argument("--tier2", action="store_true",
                           help="send the Tier 2 authorization from ~/.config/overlord/tier2-token")
    args = parser.parse_args(argv)

    if args.cmd == "list":
        status, reply = _call("GET", "/pipeline/pending")
        if status != 200:
            print(f"error {status}: {reply.get('detail', reply)}", file=sys.stderr)
            return 1
        for item in reply.get("pending", []):
            d = item.get("decision", {})
            window = d.get("execution_window_seconds")
            print(f"{item['decision_id']}  tier {d.get('action_tier')}  {d.get('target_asset')}"
                  f"  created {d.get('created_at')}  window {window if window else 'none'}")
        for decision_id in reply.get("expired", []):
            print(f"{decision_id}  expired just now")
        if not reply.get("pending") and not reply.get("expired"):
            print("no pending decisions")
        return 0

    body = None
    if args.cmd == "approve" and args.tier2:
        body = {"authorization": (CONFIG / "tier2-token").read_text().strip()}
    status, reply = _call("POST", f"/pipeline/{args.cmd}/{args.decision_id}", body)
    if status != 200:
        print(f"error {status}: {reply.get('detail', reply)}", file=sys.stderr)
        return 1
    summary = reply.get("summary", {})
    print(json.dumps(summary, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
