# KyberShield Agent Risk Monitor MVP

A lightweight local system that consumes AI agent activity events into a rule-based risk analyzer and exposes the alerts. Three components:

| Component   | Stack                | Does                                                |
| ----------- | -------------------- | --------------------------------------------------- |
| `ingest/`   | TypeScript / Express | Accepts events, stores them, exposes read endpoints |
| `analyzer/` | Python / psycopg     | Scans new events, generates alerts                  |
| Postgres    | `docker-compose.yml` | `events` + `alerts` tables (see `migrations/`)      |

The ingest service also provides the "insights" read endpoints (Task 3) — one Express app, ingestion and querying both are authenticated with the same bearer tokens. See [SOLUTION.md](SOLUTION.md) for why, and the rest of the design decisions and trade-offs.

## Prerequisites

- Docker Desktop
- Node.js 20+
- Python 3.12+

On Windows, if bare `python`/`py` resolves to the Microsoft Store stub or old launcher entry, be explicit about the interpreter: `py -3.12`.

## Setup

```bash
# 1. start Postgres
docker compose up -d

# 2. Node deps + schema
npm install
npm run migrate

# 3. Python deps (from repo root, so analyzer picks up the root .env)
py -3.12 -m venv .venv
.venv\Scripts\pip install -r analyzer\requirements.txt  # Windows
# source .venv/bin/activate && pip install -r analyzer/requirements.txt  # macOS/Linux

# 4. env vars — create .env in the repo root:
cat > .env <<'ENV'
DATABASE_URL=postgres://kybershield:localdev@localhost:5433/kybershield
PORT=3000
LOG_LEVEL=info
API_KEYS=fleet-1:change-me
MAX_BODY_BYTES=524288
ALLOWED_DOMAINS=api.github.com,api.openai.com,registry.npmjs.org
SENSITIVE_READ_THRESHOLD=3
SENSITIVE_READ_WINDOW_SECONDS=300
ANALYZER_BATCH_SIZE=100
ANALYZER_POLL_SECONDS=5
ENV
```

## Run

Three processes, each in their own terminal:

```bash
# ingest + insights API, http://localhost:3000
npm run dev

# risk analyzer — polls for new events every ANALYZER_POLL_SECONDS
.venv\Scripts\python -m analyzer.main
# or process whatever's pending once and exit (good for cron/manual runs):
.venv\Scripts\python -m analyzer.main --once
```

Postgres is already running from `docker compose up -d`.

## Try it

All routes except `/health` require `Authorization: Bearer <key>`. Valid keys are in `API_KEYS` in `.env` (format `client:key,client2:key2`) — the shipped default is `dev-key-please-change`.

```bash
curl localhost:3000/health

curl -i -X POST localhost:3000/v1/events \
-H 'content-type: application/json' \
-H 'authorization: Bearer dev-key-please-change' \
-d '{"event_id":"evt-1","agent_id":"agent-a","timestamp":"2026-09-03T12:00:00Z","type":"file_read","payload":{"path":"/home/user/.ssh/id_rsa"}}'

# same event_id again -> 200 duplicate, not a second row
curl -i -X POST localhost:3000/v1/events \
-H 'content-type: application/json' \
-H 'authorization: Bearer dev-key-please-change' \
-d '{"event_id":"evt-1","agent_id":"agent-a","timestamp":"2026-09-03T12:00:00Z","type":"file_read","payload":{"path":"/home/user/.ssh/id_rsa"}}'
```

Run the analyzer (`python -m analyzer.main --once`), then:

```bash
curl -H 'authorization: Bearer dev-key-please-change' localhost:3000/v1/alerts
curl -H 'authorization: Bearer dev-key-please-change' 'localhost:3000/v1/alerts?agent_id=agent-a&rule=secret_file_access'
curl -H 'authorization: Bearer dev-key-please-change' localhost:3000/v1/agents/agent-a/summary
curl -H 'authorization: Bearer dev-key-please-change' localhost:3000/v1/agents/agent-a/timeline
```

On Windows PowerShell, `curl` is aliased to `Invoke-WebRequest` and won't accept curl flags — use `curl.exe` (shipped with Windows) instead, and `` ` ``
instead of `\` for line continuation. For GETs that's enough. For the `POST` above, PowerShell's argument passing to native executables can mangle the JSON body's embedded double quotes and turn a valid request into a `400 invalid_json` (or worse). Use `Invoke-RestMethod` instead — it builds the request natively, with no native-exe quoting involved:

```powershell
$body = @{
  event_id  = "evt-1"
  agent_id  = "agent-a"
  timestamp = "2026-09-03T12:00:00Z"
  type      = "file_read"
  payload   = @{ path = "/home/user/.ssh/id_rsa" }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post -Uri "http://localhost:3000/v1/events" `
  -Headers @{ Authorization = "Bearer dev-key-please-change" } `
  -ContentType "application/json" `
  -Body $body
```

## API reference

### Ingest

- `POST /v1/events` — body is the event envelope (`event_id`, `agent_id`,
  `timestamp` ISO-8601, `type`, `payload`, optional `tags`). `201` +
  `{status:"stored"}` on a new event, `200` + `{status:"duplicate"}` if
  `event_id` was already stored, `400` on a validation failure, `413` over
  `MAX_BODY_BYTES`.

### Insights

- `GET /v1/alerts?agent_id=&rule=&since_hours=24&limit=100` — recent alerts,
  optionally filtered.
- `GET /v1/agents/:agent_id/summary?window_hours=24` — `total_alerts`,
  `max_severity`, `top_rules` for the window.
- `GET /v1/agents/:agent_id/timeline?window_hours=24&limit=200` — events and
  alerts for that agent, merged and time-sorted.

### Health

- `GET /health` — no auth, checks the DB with `SELECT 1`.

## Risk rules

In `analyzer/rules.py`:

| Rule                         | Fires on                                                                                          | Severity                    |
| ---------------------------- | ------------------------------------------------------------------------------------------------- | --------------------------- |
| `secret_file_access`         | `file_read` of a likely secret path (`.env`, `id_rsa`, `.aws/credentials`, ...)                   | medium–critical, by pattern |
| `rapid_sensitive_reads`      | ≥`SENSITIVE_READ_THRESHOLD` secret-path reads by one agent within `SENSITIVE_READ_WINDOW_SECONDS` | high                        |
| `shell_download_execute`     | shell command matching a download-then-execute pattern (`curl \| bash`, `base64 -d \| sh`, ...)   | critical                    |
| `disallowed_network_request` | `http_request` to a host not in `ALLOWED_DOMAINS`                                                 | medium (high for a raw IP)  |
| `elevated_tool_call`         | `tool_call` whose name/args suggest elevated privileges or a broad filesystem scope               | high                        |

## Testing / verification

```bash
npm run typecheck   # tsc --noEmit
npm run format:check # prettier --check .
```

No automated test suite (out of scope for the ±4h estimate), but ingest, dedup, analyzer-dedup, and insights behaviors were manually verified against the running system; see the commit history for the exact commands and results.

## Repo layout

```

ingest/src/
config.ts, db.ts, logger.ts  env config, pg pool, structured logger
auth.ts            bearer-token middleware
schemas.ts          zod event envelope
routes/events.ts       POST /v1/events
routes/alerts.ts       GET /v1/alerts
routes/agents.ts       GET /v1/agents/:id/summary, /timeline
server.ts           wiring, error handling, timeouts, shutdown
migrate.ts          applies migrations/.sql in order

analyzer/
config.py, db.py       env config, psycopg connection
rules.py           the 5 rules above
main.py            poll loop / --once, alert dedup

migrations/001_init.sql     events + alerts schema
docker-compose.yml       Postgres
```
