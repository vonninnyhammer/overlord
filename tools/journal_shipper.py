#!/usr/bin/env python3
"""Follow the local journal for sshd/sudo/su auth events and ship them to Overlord's n8n intake.

Standard library only, so it runs on any of the machines with system python3.
Needs read access to the system journal (member of `adm` or `systemd-journal`).

  python3 tools/journal_shipper.py                  # follow and ship
  python3 tools/journal_shipper.py --dry-run        # print batches instead of posting

Only events that matter are shipped (failed logins, root logins, sudo/su failures,
non-sudoers); routine successful logins and sudo commands are not.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import selectors
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_URL = "http://127.0.0.1:5678/webhook/overlord/intake"
IDENTIFIERS = ("sshd", "sudo", "su")
MAX_BUFFER = 500
MAX_BATCH = 100
MAX_ATTEMPTS = 5

log = logging.getLogger("journal-shipper")

# (identifier, pattern, tags, confidence). First match wins.
RULES: list[tuple[str, re.Pattern[str], list[str], float]] = [
    ("sshd", re.compile(r"^(Failed (password|publickey)|Invalid user|maximum authentication attempts)"),
     ["suspicious_login"], 0.8),
    ("sshd", re.compile(r"^Accepted \S+ for root\b"), ["suspicious_login", "authentication"], 0.75),
    ("sudo", re.compile(r"user NOT in sudoers"), ["privilege_escalation"], 0.85),
    ("sudo", re.compile(r"incorrect password attempts?|authentication failure"), ["suspicious_login"], 0.75),
    ("su", re.compile(r"^FAILED SU|authentication failure"), ["suspicious_login"], 0.75),
]


def classify(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Turn one `journalctl -o json` entry into an intake event, or None to skip it."""
    ident = str(entry.get("SYSLOG_IDENTIFIER") or "")
    message = entry.get("MESSAGE")
    if not isinstance(message, str):  # journald gives byte arrays for non-UTF-8 text
        return None
    for rule_ident, pattern, tags, confidence in RULES:
        if ident == rule_ident and pattern.search(message):
            event: dict[str, Any] = {
                "message": f"{ident}: {message}"[:2000],
                "normalized_tags": list(tags),
                "confidence": confidence,
            }
            stamp = entry.get("__REALTIME_TIMESTAMP")
            if stamp and str(stamp).isdigit():
                event["timestamp"] = datetime.fromtimestamp(
                    int(stamp) / 1_000_000, tz=timezone.utc).isoformat()
            return event
    return None


def post(url: str, host: str, events: list[dict[str, Any]], timeout: float = 30) -> str:
    """Return 'ok', 'rejected' (do not retry) or 'retry'."""
    body = json.dumps({"host": host, "events": events}).encode()
    req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            reply = json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return "rejected" if 400 <= exc.code < 500 else "retry"
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return "retry"
    if isinstance(reply, dict) and reply.get("error"):
        log.warning("intake rejected batch: %s", reply["error"])
        return "rejected"
    return "ok"


class Shipper:
    def __init__(self, url: str, host: str, window: float, dry_run: bool = False) -> None:
        self.url, self.host, self.window, self.dry_run = url, host, window, dry_run
        self.buffer: deque[dict[str, Any]] = deque(maxlen=MAX_BUFFER)
        self.first_at: float | None = None
        self.attempts = 0
        self.next_try = 0.0

    def add(self, event: dict[str, Any]) -> None:
        if len(self.buffer) == self.buffer.maxlen:
            log.warning("buffer full; dropping oldest event")
        self.buffer.append(event)
        if self.first_at is None:
            self.first_at = time.monotonic()

    def due(self) -> bool:
        now = time.monotonic()
        return (bool(self.buffer) and self.first_at is not None and now >= self.next_try
                and (now - self.first_at >= self.window or len(self.buffer) >= MAX_BATCH))

    def flush(self) -> None:
        batch = [self.buffer[i] for i in range(min(MAX_BATCH, len(self.buffer)))]
        if self.dry_run:
            print(json.dumps({"host": self.host, "events": batch}, indent=2), flush=True)
            status = "ok"
        else:
            status = post(self.url, self.host, batch)
        if status == "retry":
            self.attempts += 1
            if self.attempts < MAX_ATTEMPTS:
                self.next_try = time.monotonic() + min(300, 10 * 2 ** self.attempts)
                log.warning("intake unreachable; retry %d in %.0fs", self.attempts,
                            self.next_try - time.monotonic())
                return
            log.error("dropping %d events after %d attempts", len(batch), self.attempts)
        elif status == "rejected":
            log.warning("dropping %d rejected events", len(batch))
        else:
            log.info("shipped %d events", len(batch))
        for _ in batch:
            self.buffer.popleft()
        self.attempts, self.next_try = 0, 0.0
        self.first_at = time.monotonic() if self.buffer else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--host", default=socket.gethostname().split(".")[0].lower())
    parser.add_argument("--window", type=float, default=30.0,
                        help="seconds to gather related events into one batch")
    parser.add_argument("--cursor-file", type=Path,
                        default=Path.home() / ".local/state/overlord-shipper/cursor")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    shipper = Shipper(args.url, args.host, args.window, args.dry_run)
    args.cursor_file.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["journalctl", "-f", "-o", "json", "-n", "0", f"--cursor-file={args.cursor_file}"]
    for ident in IDENTIFIERS:
        cmd += ["-t", ident]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    assert proc.stdout is not None
    fd = proc.stdout.fileno()
    sel = selectors.DefaultSelector()
    sel.register(fd, selectors.EVENT_READ)
    pending = b""
    log.info("following %s as host %s", ", ".join(IDENTIFIERS), args.host)
    try:
        while True:
            # Raw reads with a timeout, so a quiet journal still lets batches flush.
            if sel.select(timeout=2):
                chunk = os.read(fd, 65536)
                if not chunk:
                    log.error("journalctl exited")
                    return 1
                pending += chunk
                *lines, pending = pending.split(b"\n")
                for line in lines:
                    try:
                        event = classify(json.loads(line))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        event = None
                    if event:
                        shipper.add(event)
            if shipper.due():
                shipper.flush()
    except KeyboardInterrupt:
        return 0
    finally:
        proc.terminate()  # lets journalctl write the cursor file
        proc.wait(timeout=5)


if __name__ == "__main__":
    sys.exit(main())
