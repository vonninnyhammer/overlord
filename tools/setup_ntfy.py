#!/usr/bin/env python3
"""Install a tailnet-only ntfy server on a remote node and point Overlord's n8n at it.

  python3 tools/setup_ntfy.py                 --host <ssh alias>   # installs there, port 2586
  python3 tools/setup_ntfy.py --host <ssh alias> --test-only

ntfy runs as a systemd *user* service on the node (no sudo), listening only on the
node's Tailscale IPv4 address. The topic is random and is written to
~/.config/overlord/n8n.env as OVERLORD_NTFY_TOPIC; it is not printed.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import urllib.request
from pathlib import Path

VERSION = "2.11.0"
PORT = 2586
ENV_FILE = Path.home() / ".config/overlord/n8n.env"

REMOTE = r"""set -euo pipefail
V=__VERSION__
PORT=__PORT__
IP=$(tailscale ip -4 | head -1)
[ -n "$IP" ] || { echo "no tailscale IPv4 on this node" >&2; exit 1; }
mkdir -p ~/.local/bin ~/.config/ntfy ~/.cache/ntfy ~/.config/systemd/user
if ! [ -x ~/.local/bin/ntfy ] || ! ~/.local/bin/ntfy --help 2>&1 | grep -q serve; then
  tmp=$(mktemp -d)
  base=https://github.com/binwiederhier/ntfy/releases/download/v$V
  curl -fsSL -o "$tmp/ntfy_${V}_linux_amd64.tar.gz" "$base/ntfy_${V}_linux_amd64.tar.gz"
  curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt"
  (cd "$tmp" && grep " ntfy_${V}_linux_amd64.tar.gz\$" checksums.txt | sha256sum -c -)
  tar -xzf "$tmp/ntfy_${V}_linux_amd64.tar.gz" -C "$tmp"
  install -m 755 "$tmp/ntfy_${V}_linux_amd64/ntfy" ~/.local/bin/ntfy
  rm -rf "$tmp"
fi
cat > ~/.config/ntfy/server.yml <<EOF
base-url: "http://$IP:$PORT"
listen-http: "$IP:$PORT"
cache-file: "$HOME/.cache/ntfy/cache.db"
cache-duration: "24h"
EOF
cat > ~/.config/systemd/user/ntfy.service <<EOF
[Unit]
Description=ntfy push server (tailnet only)
After=network-online.target

[Service]
ExecStart=%h/.local/bin/ntfy serve --config %h/.config/ntfy/server.yml
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable ntfy >/dev/null 2>&1
systemctl --user restart ntfy
sleep 2
systemctl --user is-active --quiet ntfy || { journalctl --user -u ntfy -n 20 --no-pager >&2; exit 1; }
echo "NTFY_URL=http://$IP:$PORT"
"""


def set_env(path: Path, values: dict[str, str]) -> None:
    lines = path.read_text().splitlines() if path.exists() else []
    kept = [line for line in lines if line.partition("=")[0].strip() not in values]
    kept += [f"{k}={v}" for k, v in values.items()]
    path.write_text("\n".join(kept) + "\n")
    os.chmod(path, 0o600)


def read_env(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text().splitlines():
        key, sep, value = line.partition("=")
        if sep:
            out[key.strip()] = value.strip()
    return out


def publish(url: str, topic: str, title: str, message: str) -> None:
    body = json.dumps({"topic": topic, "title": title, "message": message, "priority": 3,
                       "tags": ["white_check_mark"]}).encode()
    req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", required=True, help="ssh alias of the node to run ntfy on")
    parser.add_argument("--test-only", action="store_true", help="just send a test notification")
    args = parser.parse_args(argv)

    if not args.test_only:
        script = REMOTE.replace("__VERSION__", VERSION).replace("__PORT__", str(PORT))
        proc = subprocess.run(["ssh", "-o", "BatchMode=yes", args.host, "bash -s"],
                              input=script, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            print(proc.stderr[-3000:], file=sys.stderr)
            return 1
        url = next(line.split("=", 1)[1] for line in proc.stdout.splitlines()
                   if line.startswith("NTFY_URL="))
        current = read_env(ENV_FILE)
        topic = current.get("OVERLORD_NTFY_TOPIC") or f"overlord-{secrets.token_hex(12)}"
        set_env(ENV_FILE, {"OVERLORD_NTFY_URL": url, "OVERLORD_NTFY_TOPIC": topic})
        print(f"ntfy running on {args.host} at {url}")
        print(f"wrote OVERLORD_NTFY_URL and OVERLORD_NTFY_TOPIC to {ENV_FILE}")

    env = read_env(ENV_FILE)
    publish(env["OVERLORD_NTFY_URL"], env["OVERLORD_NTFY_TOPIC"], "Overlord alerts connected",
            "Test notification from tools/setup_ntfy.py.")
    print("test notification sent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
