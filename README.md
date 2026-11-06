# Overlord

A deterministic, policy-gated pipeline for defensive cyber operations. Overlord
takes raw telemetry in one end and produces a recorded, auditable incident —
including a human approval step when the response tier requires one. The core
is deterministic; the model-backed analyst, enrichment, executor, and sensor
stages are pluggable adapters.

The design goal is not "autonomous offense." It is a response pipeline whose
every decision can be replayed, whose context window is audited rather than
assumed, and whose higher-impact actions stop for a human.

## Design principles

- **Deterministic stages.** A fixed sequence of nine stages. No stage silently
  skips; `stop_after` exists for inspection, not for production shortcuts.
- **Audited context.** `audit_window` computes `usable_context = allowed -
  reserved`, then `remaining = usable_context - evidence_tokens`, and fails when
  `remaining < 0`. Token cost is not double-subtracted.
- **Tiered response.** The caller requests a tier; the hypothesis sets a floor
  (`HYPOTHESIS_MIN_TIER`: credential, persistence, lateral-movement, evasion,
  exfiltration and impact hypotheses are at least Tier 1), and the asset class
  decides what is allowed. Tier 0 may proceed automatically. Tier 1 needs an
  approval within 60 seconds; unapproved ones are expired and recorded the next
  time the queue is read. Tier 2 needs a named authorizer.
- **Evidence, not vibes.** A conclusion must clear a minimum-support threshold,
  and a response needs at least three conclusions that agree on one hypothesis,
  each reached from a different trigger fact (with the built-in analyst this
  means three separate facts). Identical replayed events collapse into one fact. By default a response also needs facts from two
  different sensor types (`OVERLORD_MIN_INDEPENDENT_SOURCES`, default `2`; set `1`
  to allow a single sensor).
- **Sanitised telemetry.** Addresses, hostnames, URLs, email addresses, usernames
  in paths, common secrets, and binary blobs are replaced in what the analyst
  receives. The original fact is kept for forensics. Redaction is pattern-based,
  so an unlabelled short hostname can still get through.
- **Brakes.** At most three analyst requests per agent are open at once, across
  all API requests. After five Tier 1 actions inside five minutes, Tier 1 is
  frozen for fifteen minutes: new Tier 1 requests are raised to Tier 2 where the
  asset allows it and refused where it doesn't, and parked Tier 1 approvals
  return 409. The counters live in memory, so a restart resets them.
- **Append-only trail.** Requests and replies are paired into events; the final
  decision is recorded with its provenance.

## Pipeline

| Stage | Name | Responsibility |
|-------|------|----------------|
| S1 | `ingest` | Normalise incoming telemetry and sanitise it. |
| S2 | `enrichment` | Attach asset/intel context. |
| S3 | `dispatch` | Map observations to a hypothesis and ATT&CK technique; emit the trigger fact. |
| S4 | `analysis` | Run the analyst adapter to produce a conclusion. |
| S5 | `justification` | Apply minimum-support and triangulation gates. |
| S6 | `tier` | Assign the response tier for the asset class and hypothesis. |
| S7 | `approval` | Create a pending decision and wait for a human when the tier demands it. |
| S8 | `execute` | Hand the approved action to the executor adapter. |
| S9 | `record` | Persist the fact, conclusion, and decision with provenance. |

Gates available as standalone operations: minimum support, triangulation,
window audit, tier assignment, and evidence compression.

## Sensors

The generic sensor (used unless `auto_sensors` is on) takes tags from the caller,
but derives the fact id from the event itself, caps confidence at 0.9, and sets
the author; a caller cannot use made-up ids to make one event count several times.

Three adapters normalise vendor events into the same `Fact` shape: `wazuh`,
`falco`, and `zeek`. Each produces a deterministic UUID derived from the source
event, a size-capped base64 payload, permitted tags, and provenance.

The pipeline uses its default sensor unless `auto_sensors=True`, in which case
each telemetry item is routed by its `source` field:

```python
pipeline = OverlordPipeline(auto_sensors=True)
pipeline.run_incident([{"source": "wazuh", "@timestamp": "...", "rule": {"id": "5711"}}])
```

Over HTTP, set `"auto_sensors": true` on `/pipeline/run`. Unknown or missing
sources fall back to a conservative generic sensor.

## Threat-intelligence enrichment

When `OVERLORD_INTEL_DB` points at the ledger written by the
[threat-intel-feed](https://github.com/vonninnyhammer/threat-intel-feed)
collector, enrichment attaches matching advisory context to each fact. Matching
is by CVE, ATT&CK technique, IOC, and advisory text; results are returned under
`enrichment[fact_id]["threat_intel"]`. The adapter is read-only and degrades to
the default enrichment when the ledger is absent.

## Quick start

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"

pytest -q
overlord-eval --no-write
uvicorn overlord.api:app --host 127.0.0.1 --port 8790
```

Run the pipeline directly:

```bash
curl -s -X POST http://127.0.0.1:8790/pipeline/run \
  -H 'content-type: application/json' \
  -d '{"telemetry":[{"source":"wazuh","message":"login","normalized_tags":["authentication"]}]}'
```

Inspect and resume a stopped run:

```bash
curl -s -X POST http://127.0.0.1:8790/pipeline/run \
  -H 'content-type: application/json' \
  -d '{"telemetry":[{"source":"wazuh","message":"login"}],"stop_after":"S2"}'

curl -s http://127.0.0.1:8790/pipeline/stages
```

## Evaluation harness

`overlord-eval` replays labelled telemetry scenarios through the real pipeline
and scores both detection quality and policy behaviour. Each scenario carries
the expected ATT&CK techniques and hypotheses, the pipeline inputs, and the
expected gate outcome. Runs use a fixed clock by default, so scores are
deterministic and suitable for a regression gate.

```bash
overlord-eval                       # writes reports/eval.json and reports/eval.md
overlord-eval --no-write            # summary only
overlord-eval scenarios/credential-access-auth.json --no-write
```

A scenario is a small JSON document:

```json
{
  "id": "credential-access-auth",
  "name": "Authentication event maps to credential access",
  "techniques": ["T1078"],
  "hypotheses": ["credential_access"],
  "pipeline": {"requested_tier": 1, "approve": true},
  "telemetry": [{"source": "wazuh", "message": "...", "normalized_tags": ["authentication"], "confidence": 0.9}],
  "expect": {
    "blocked_at": null,
    "error": null,
    "tier": 1,
    "decision_status": "applied",
    "outcome": "success",
    "n_conclusions": 3
  }
}
```

The report includes:

- technique and hypothesis precision, recall, and F1;
- detection pass rate (no missed or unexpected labels);
- gate, tier, and decision accuracy;
- per-technique coverage and per-scenario latency;
- explicit failure reasons for every mismatched scenario.

The command exits non-zero when any scenario fails or a configured threshold is
missed (`--min-pass-rate`, `--min-technique-recall`,
`--min-technique-precision`). `scenarios/` is generated: edit
`tools/generate_scenarios.py` and re-run it rather than editing JSON by hand.
The harness evaluates deterministic telemetry replay and policy gates; live
adversary emulation in isolated VMs is a separate layer.

## API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness. |
| GET | `/schemas` | List the output schemas. |
| GET | `/schemas/{name}` | Fetch one schema. |
| POST | `/sanitize` | Sanitise telemetry text. |
| POST | `/gates/min-support` | Evaluate minimum support. |
| POST | `/gates/triangulation` | Evaluate source triangulation. |
| POST | `/gates/window-audit` | Audit the evidence window. |
| POST | `/gates/tier` | Assign a response tier. |
| POST | `/gates/compress` | Compress evidence to a character budget. |
| GET | `/pipeline/stages` | List stages. |
| POST | `/pipeline/run` | Run the pipeline (optionally `stop_after`, `auto_sensors`). |
| GET | `/pipeline/pending` | List pending approvals. |
| POST | `/pipeline/approve/{decision_id}` | Approve and resume. |
| POST | `/pipeline/cancel/{decision_id}` | Cancel and roll back. |
| GET | `/store/stats` | Record counts. |
| GET | `/store/search` | Vector/text search over records. |
| GET | `/store/{kind}/{record_id}` | Fetch one record. |
| POST | `/validate/conclusion` | Validate an agent conclusion against its schema. |

Approval is a separate step: `/pipeline/run` rejects `approve: true` and
`authorization` unless `OVERLORD_ALLOW_INLINE_APPROVAL=1`. Tier 2 tokens are verified
against `OVERLORD_TIER2_AUTHORIZERS`, and an unset value means nobody can authorize.
The approver's name is stored on the decision. Create a digest with
`printf %s "$TOKEN" | sha256sum`.

## Record store

Persistence is opt-in (`OVERLORD_PERSIST=1`). The default store is a local
SQLite ledger for facts, conclusions, and decisions. When a Qdrant URL is
configured, records are also indexed as vectors for semantic search. The
default embedder hashes tokens locally; an Ollama embedder is available for
768-dimension embeddings.

## n8n workflows

`workflows/` contains importable n8n definitions for the full pipeline, each
individual stage, the standalone gates, and the approval console. Import them
with:

```bash
n8n import:workflow --separate --input=workflows
```

The HTTP nodes target the core API at `http://127.0.0.1:8790`; change that if
you run the core elsewhere.

## Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `OVERLORD_STATE_DIR` | `~/.local/state/overlord` | State and ledger directory. |
| `OVERLORD_PERSIST` | `0` | Set to `1` to enable the record store. |
| `OVERLORD_QDRANT_URL` | `http://127.0.0.1:6350` | Qdrant endpoint when persisting. |
| `OVERLORD_EMBED_MODEL` | `nomic-embed-text` | Ollama embedding model. |
| `OVERLORD_INTEL_DB` | unset | Threat-intel SQLite ledger for enrichment. |
| `OVERLORD_API_TOKEN` | unset | Bearer token for pipeline and store endpoints. **Unset makes them return 503.** n8n workflows read the same variable, so n8n needs it too. |
| `OVERLORD_ALLOW_UNAUTHENTICATED` | `0` | Set to `1` to run those endpoints without a token, for local development on loopback only. |
| `OVERLORD_TIER2_AUTHORIZERS` | unset | JSON mapping authorizer name to SHA-256 of their token. |
| `OVERLORD_ALLOW_INLINE_APPROVAL` | `0` | Set to `1` to allow approval inside `/pipeline/run`. |
| `OVERLORD_MIN_INDEPENDENT_SOURCES` | `2` | Distinct sensor types needed before a response. |
| `OVERLORD_ASSET_INVENTORY` | unset | JSON file mapping asset name to class. When set, a target that is missing or declared differently is blocked. |

## Status

The deterministic core, gates, pipeline, pending approvals, record store, API,
sensor adapters (Wazuh, Falco, Zeek), threat-intelligence enrichment, the
evaluation harness, tests, and n8n workflows are implemented. The analyst and
executor stages ship with simulations and remain pluggable adapters.

## License

MIT. See [LICENSE](LICENSE).
