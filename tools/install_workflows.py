#!/usr/bin/env python3
"""Import workflows/*.json into the live n8n, keeping existing IDs and wiring error alerts.

  python3 tools/install_workflows.py            # dry run: show what would happen
  python3 tools/install_workflows.py --apply    # back up, stop n8n, import, publish, start

What --apply does:
  1. backs up every n8n workflow to /data2/edi-dco/backup/n8n-workflows-<time>/
  2. stops overlord-n8n (the CLI import needs n8n stopped)
  3. matches repo workflows to n8n by name, reusing the n8n ID (new ones get a new ID)
  4. sets settings.errorWorkflow on every workflow to "Overlord - Error Alerts"
  5. imports, then publishes whatever was published before plus the new operational ones
  6. starts overlord-n8n again

The repo JSON carries no IDs (the repo is public); the ID-bearing copies are written
to a private temporary folder and removed afterwards.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shlex
import shutil
import string
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from build_workflows import ERRORS_NAME, INTAKE_NAME, WATCHER_NAME  # noqa: E402

DATA = Path("/data2/edi-dco")
BACKUPS = DATA / "backup"
SERVICE = "overlord-n8n"
N8N = "/usr/local/bin/n8n"
ALWAYS_PUBLISH = {ERRORS_NAME, INTAKE_NAME, WATCHER_NAME}
NTFY_KEYS = ("OVERLORD_NTFY_URL", "OVERLORD_NTFY_TOPIC")


def n8n_env() -> dict[str, str]:
    """The service's Environment= settings, so the CLI uses the same data folder."""
    out = subprocess.run(["systemctl", "--user", "show", SERVICE, "-p", "Environment", "--value"],
                         capture_output=True, text=True, check=True).stdout
    env = dict(os.environ)
    for pair in shlex.split(out):
        key, _, value = pair.partition("=")
        env[key] = value
    return env


def n8n(env: dict[str, str], *args: str) -> str:
    proc = subprocess.run([N8N, *args], env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"n8n {' '.join(args)} failed:\n{proc.stdout[-2000:]}{proc.stderr[-2000:]}")
    return proc.stdout


def new_id() -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(16))


def is_published(workflow: dict) -> bool:
    return bool(workflow.get("active") or workflow.get("activeVersionId"))


def plan(existing: list[dict], repo: dict[str, dict]) -> tuple[dict[str, dict], list[str], list[str]]:
    """Return (workflows with ids and error wiring, ids to publish, notes)."""
    by_name = {w["name"]: w for w in existing}
    dupes = {w["name"] for w in existing if sum(x["name"] == w["name"] for x in existing) > 1}
    if dupes & set(repo):
        raise SystemExit(f"n8n has duplicate names, refusing to guess: {sorted(dupes & set(repo))}")
    out: dict[str, dict] = {}
    notes: list[str] = []
    for name, workflow in repo.items():
        wf = json.loads(json.dumps(workflow))
        if name in by_name:
            wf["id"] = by_name[name]["id"]
            notes.append(f"update  {wf['id']}  {name}")
        else:
            wf["id"] = new_id()
            notes.append(f"create  {wf['id']}  {name}")
        out[name] = wf
    errors_id = out[ERRORS_NAME]["id"]
    for name, wf in out.items():
        if name != ERRORS_NAME:
            wf.setdefault("settings", {})["errorWorkflow"] = errors_id
    publish = sorted({out[n]["id"] for n in out if n in ALWAYS_PUBLISH
                      or (n in by_name and is_published(by_name[n]))})
    unmanaged = sorted(set(by_name) - set(repo))
    if unmanaged:
        notes.append("left alone (not in repo): " + ", ".join(unmanaged))
    return out, publish, notes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)

    if not os.path.ismount(DATA):
        raise SystemExit(f"{DATA} is not mounted; unlock edi-dco.luks first")
    env_file = Path.home() / ".config/overlord/n8n.env"
    keys = {line.partition("=")[0].strip() for line in env_file.read_text().splitlines()}
    missing = [k for k in NTFY_KEYS if k not in keys]
    if missing:
        print(f"warning: {env_file} lacks {', '.join(missing)}; alerts will not be delivered "
              "(run tools/setup_ntfy.py)", file=sys.stderr)

    repo = {}
    for path in sorted((ROOT / "workflows").glob("*.json")):
        wf = json.loads(path.read_text())
        repo[wf["name"]] = wf

    env = n8n_env()
    was_running = subprocess.run(["systemctl", "--user", "is-active", "--quiet", SERVICE]).returncode == 0
    work = Path(tempfile.mkdtemp(prefix="overlord-n8n-", dir=DATA))
    os.chmod(work, 0o700)
    try:
        if args.apply and was_running:
            subprocess.run(["systemctl", "--user", "stop", SERVICE], check=True)
        n8n(env, "export:workflow", "--all", f"--output={work / 'existing.json'}")
        existing = json.loads((work / "existing.json").read_text() or "[]")
        merged, publish, notes = plan(existing, repo)
        print("\n".join(notes))
        print(f"publish {len(publish)} workflow(s)")
        if not args.apply:
            print("dry run: nothing changed (use --apply)")
            return 0

        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = BACKUPS / f"n8n-workflows-{stamp}"
        backup.mkdir(parents=True)
        n8n(env, "export:workflow", "--backup", f"--output={backup}")
        print(f"backup  {backup}")

        staged = work / "import"
        staged.mkdir()
        for wf in merged.values():
            (staged / f"{wf['id']}.json").write_text(json.dumps(wf))
        n8n(env, "import:workflow", "--separate", f"--input={staged}")
        for wid in publish:
            n8n(env, "publish:workflow", f"--id={wid}")
        print("imported and published")
    finally:
        shutil.rmtree(work, ignore_errors=True)
        if args.apply and was_running:
            subprocess.run(["systemctl", "--user", "start", SERVICE], check=True)
            print(f"started {SERVICE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
