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
- **Tiered response.** Asset class and hypothesis determine a tier. Tier 0 may
  proceed automatically; higher tiers require an explicit approval inside a
  bounded execution window.
- **Evidence, not vibes.** A conclusion must clear a minimum-support threshold
  and triangulate across independent sources before it can drive a response.
- **Sanitised telemetry.** Hostnames, addresses, and binary blobs are replaced
  before anything is handed to a model.
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
uvicorn overlord.api:app --host 127.0.0.1 --port 8790
```

Run the pipeline directly:

```bash
curl -s -X POST http://127.0.0.1:8790/pipeline/run \
  -H 'content-type: application/json' \
  -d '{"source":"sim","telemetry":[{"tag":"authentication","host":"web-01"}]}'
```

Inspect and resume a stopped run:

```bash
curl -s -X POST http://127.0.0.1:8790/pipeline/run \
  -H 'content-type: application/json' \
  -d '{"source":"sim","stop_after":"S2"}'

curl -s http://127.0.0.1:8790/pipeline/stages
```

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

## Status

The deterministic core, gates, pipeline, pending approvals, record store, API,
sensor adapters (Wazuh, Falco, Zeek), threat-intelligence enrichment, tests, and
n8n workflows are implemented. The analyst and executor stages ship with
simulations and remain pluggable adapters.

## License

MIT. See [LICENSE](LICENSE).
