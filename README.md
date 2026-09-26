# FRIDAY — AI Incident Investigation & Root-Cause Analysis Platform

FRIDAY turns raw, heterogeneous telemetry into an explainable incident story and
an evidence-grounded root-cause hypothesis, following:

**Collect → Understand → Correlate → Reconstruct → Investigate → Explain → Recommend → Verify → Learn**

## What's included

- `backend/main.py` — FastAPI service: telemetry ingestion (generic JSON, log upload, OTLP,
  real agent metrics), normalization, incident detection, correlation, RCA hypothesis
  generation, dependency graph, blast radius, "what changed", replay, copilot Q&A,
  resolution verification, and an incident memory store — all backed by SQLite.
- `backend/collectors.py` — **real** monitoring collectors: PostgreSQL, MySQL, Redis
  (each polls the live service and pushes real latency/pool/error metrics), plus
  Docker (real per-container CPU/memory via the Docker SDK, when the daemon socket
  is mounted). All are opt-in via env vars and simply no-op if unset.
- `backend/agent.py` — standalone cross-platform agent you run **on** a Windows or
  Linux machine. Collects real CPU/memory/disk/network via `psutil` and streams it
  to the backend (optionally including that host's real Docker container stats too).
- `frontend/` — a single-file React dashboard (loaded from CDN, no build step)
  covering all FRIDAY screens: Overview, Live Monitor, Incidents, RCA Investigation,
  Timeline, Dependency Graph, Blast Radius, What Changed?, Incident Replay,
  AI Copilot, Telemetry Sources, Settings.
- `sample_logs/` — example log file and OTLP JSON payload you can upload/POST to try
  the ingestion paths without the live demo.
- `docker-compose.yml` — runs backend (port 8000) + frontend (port 3000).

## Real monitoring (new)

All of these are **off by default** (the demo/simulated flow keeps working with zero
config) and turn on individually by setting an env var in `.env`:

| Feature | Env var(s) | What it does |
|---|---|---|
| Real PostgreSQL monitoring | `PG_DSN` | Connects and polls real latency, connection-pool utilization, slow queries |
| Real MySQL monitoring | `MYSQL_DSN` | Connects and polls real latency, `Threads_connected`/`max_connections`, slow query count |
| Real Redis monitoring | `REDIS_URL` | `PING` latency, real cache-hit %, connected clients, memory utilization |
| Real Docker monitoring (backend-side) | `DOCKER_MONITOR=1` (+ mount `/var/run/docker.sock`) | Real per-container CPU%/mem%, restarts container-down alerts |
| Real Windows/Linux host monitoring | run `backend/agent.py` on the host | Real CPU/mem/disk/network via `psutil`, works unmodified on Windows and Linux |
| Real Docker monitoring (agent-side) | `AGENT_DOCKER=1` when running `agent.py` | Same container stats, collected from the monitored host itself |
| Gemini AI RCA/Copilot | `LLM_PROVIDER=gemini`, `LLM_MODEL=gemini-1.5-flash`, `LLM_API_KEY=...` | Google Gemini answers the Copilot and incident narrative, same evidence-grounding as Anthropic/OpenAI |

All of it flows into the exact same ingestion pipeline as the demo data (`source="REAL"`
for the collectors, `source="AGENT"` for the host agent), so anomaly detection, incident
opening, RCA, dependency-graph auto-discovery, and blast radius all work on real
telemetry with no extra code.

### Running the Windows/Linux agent
```bash
cd backend
pip install -r agent_requirements.txt
# Linux/macOS
export FRIDAY_API_BASE=http://localhost:8000
export AGENT_TOKEN=changeme        # optional, must match backend's AGENT_TOKEN
python agent.py
```
```powershell
# Windows PowerShell
cd backend
pip install -r agent_requirements.txt
$env:FRIDAY_API_BASE="http://localhost:8000"
$env:AGENT_TOKEN="changeme"
python agent.py
```
Run one agent per machine you want monitored — each reports under `host:<hostname>`.

## Quick start

### Docker (recommended)
```bash
cp .env.example .env      # optional: set LLM_PROVIDER/LLM_MODEL/LLM_API_KEY
docker compose up --build
```
Open http://localhost:3000. Click **Start Live Demo (Insta)** to watch a
PostgreSQL-connection-saturation incident unfold end-to-end.

### Without Docker
```bash
# backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# frontend (any static server)
cd ../frontend
python3 -m http.server 3000
```
Open http://localhost:3000/index.html. If your backend isn't on
`localhost:8000`, set `window.FRIDAY_API_BASE` at the top of `index.html`
before the `<script type="text/babel">` block.

## Connecting an AI provider

FRIDAY works fully with **no AI key** — the copilot and RCA narrative fall
back to a rule-based, evidence-grounded engine that never invents telemetry.
For the hackathon demo, using a real LLM is recommended for more natural,
reasoned copilot answers. Set these in `.env` (or as real environment
variables if running without Docker):

```
LLM_PROVIDER=anthropic        # or "openai" for any OpenAI-compatible API
LLM_MODEL=claude-sonnet-4-6   # or e.g. gpt-4o-mini
LLM_API_KEY=sk-...
```

**Without Docker (Windows PowerShell), before starting uvicorn:**
```powershell
$env:LLM_PROVIDER="anthropic"
$env:LLM_MODEL="claude-sonnet-4-6"
$env:LLM_API_KEY="sk-ant-..."
uvicorn main:app --reload --port 8000
```

The key is only ever read server-side by the backend (`backend/main.py`'s
`llm()` function) — it is never sent to or exposed in the frontend. Once set,
`GET /api/settings` and the Settings tab show `llm_key_configured: true`, and
the Copilot tab tags each answer with a badge showing which engine produced
it ("Rule-based engine" vs "LLM: anthropic"). The copilot also carries
conversation history across turns, so follow-up questions stay in context.

## Trying the four ingestion paths

1. **Uploaded logs** — Telemetry Sources → Upload → pick `sample_logs/insta_incident.log`.
2. **Live simulated stream** — top-bar **Start Live Demo (Insta)** button.
3. **Generic HTTP ingestion**:
   ```bash
   curl -X POST localhost:8000/api/telemetry/logs -H 'Content-Type: application/json' \
     -d '[{"service":"instagram-api","severity":"ERROR","message":"HTTP 500 on GET /feed"}]'
   ```
4. **OpenTelemetry adapter**:
   ```bash
   curl -X POST localhost:8000/api/telemetry/otlp -H 'Content-Type: application/json' \
     --data @sample_logs/otlp_sample.json
   ```

## Demo flow

Open FRIDAY → Start Live Demo → watch metrics/logs/traces arrive on **Live
Monitor** → FRIDAY opens an incident once the connection pool crosses ~90% →
review **RCA Investigation** for the ranked hypotheses and evidence → check
**Dependency Graph** / **Blast Radius** / **What Changed?** → open **Incident
Replay** to scrub through failure propagation → ask the **AI Copilot** why it
suspects PostgreSQL → **Approve Action** (simulated remediation, triggers
recovery in the simulator) → **Mark Resolved & Verify Recovery** → the
incident is stored in incident memory for future similarity matching.

## How the analysis is computed (not hand-waved)

- **Blast radius** — affected requests are computed by integrating request-rate
  and error-rate telemetry sample-by-sample over the incident window (not a
  single snapshot × duration guess). Affected users use real distinct
  `request_id` values when present, falling back to a clearly-labeled
  session-density estimate otherwise. An **impact score (0-100)** blends peak
  error rate, breadth of affected services, and distinct traces touched.
- **Early warning** — uses least-squares linear regression on the last 8
  samples of each risk metric to get a slope, then combines proximity-to-threshold
  and steepness into a 0-100 risk score with an estimated time-to-threshold,
  instead of a flat "3 points in a row" check.
- **Dependency graph** — the Insta demo's known architecture is always shown,
  plus any additional edges **auto-discovered** by correlating which services
  share a `trace_id` and in what order they appear — so uploading real logs
  with trace IDs from an unfamiliar architecture will surface new edges
  (dashed, blue) rather than being forced into the fixed Insta topology.
- **AI Copilot** — when `LLM_API_KEY` is set, answers are generated by a real
  LLM call grounded in the incident's evidence JSON, with the last 8 turns of
  conversation carried forward for follow-up questions. Without a key, a
  rule-based engine answers from the same evidence — both paths refuse to
  invent facts not present in the telemetry.

## Notes on the prototype

- All remediation actions are simulated and require explicit human approval;
  FRIDAY never executes production changes.
- Simulated/demo telemetry is always labeled as such in the UI and API
  (`source: "DEMO"`), distinct from `API`, `UPLOADED`, and `OTLP` sources.
- RCA output always distinguishes supporting, missing, and conflicting
  evidence, and explicitly says "Insufficient telemetry" or "No dominant
  hypothesis" rather than forcing a confident answer.
