# KyberShield Agent Risk Monitor MVP

A small local system that ingests AI agent activity events, runs them through
a rule-based risk analyzer, and exposes the resulting alerts. Three pieces:

| Component   | Stack                | Does                                                |
| ----------- | -------------------- | --------------------------------------------------- |
| `ingest/`   | TypeScript / Express | Accepts events, stores them, exposes read endpoints |
| `analyzer/` | Python / psycopg     | Scans new events, generates alerts                  |
| Postgres    | `docker-compose.yml` | `events` + `alerts` tables (see `migrations/`)      |

The ingest service also serves the "insights" read endpoints (Task 3) — one
Express app, ingestion and querying both authenticated with the same bearer
tokens. See [SOLUTION.md](SOLUTION.md) for why, and for the rest of the
design decisions and trade-offs.

## Prerequisites

- Docker Desktop
- Node.js 20+
- Python 3.12+

On Windows, if bare `python`/`py` resolve to the Microsoft Store stub or a
stale launcher entry, use the interpreter explicitly: `py -3.12`.

## Setup

```bash
# 1. start Postgres
docker compose up -d

# 2. Node deps + schema
npm install
npm run migrate

# 3. Python deps (from repo root, so analyzer picks up the root .env)
py -3.12 -m venv .venv
.venv\Scripts\pip install -r analyzer\requirements.txt   # Windows
# source .venv/bin/activate && pip install -r analyzer/requirements.txt   # macOS/Linux

# 4. env vars — .env.example documents every var; copy it if you don't have .env yet
cp .env.example .env
```

## Run

Three processes, each in its own terminal:

```bash
# ingest + insights API, http://localhost:3000
npm run dev

# risk analyzer — polls for new events every ANALYZER_POLL_SECONDS
.venv\Scripts\python -m analyzer.main
# or process whatever's pending once and exit (good for cron/manual runs):
.venv\Scripts\python -m analyzer.main --once
```

Postgres is already up from `docker compose up -d`.

## Try it

All routes except `/health` require `Authorization: Bearer <key>`. Valid
keys live in `API_KEYS` in `.env` (format `client:key,client2:key2`) — the
shipped default is `dev-key-please-change`.

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

On Windows PowerShell, `curl` is aliased to `Invoke-WebRequest` and won't
accept curl flags — use `curl.exe` (ships with Windows) instead, and `` ` ``
for line continuation instead of `\`.

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

Implemented in `analyzer/rules.py`:

| Rule                         | Fires on                                                                                          | Severity                    |
| ---------------------------- | ------------------------------------------------------------------------------------------------- | --------------------------- |
| `secret_file_access`         | `file_read` of a likely secret path (`.env`, `id_rsa`, `.aws/credentials`, ...)                   | medium–critical, by pattern |
| `rapid_sensitive_reads`      | ≥`SENSITIVE_READ_THRESHOLD` secret-path reads by one agent within `SENSITIVE_READ_WINDOW_SECONDS` | high                        |
| `shell_download_execute`     | shell command matching a download-then-execute pattern (`curl \| bash`, `base64 -d \| sh`, ...)   | critical                    |
| `disallowed_network_request` | `http_request` to a host not in `ALLOWED_DOMAINS`                                                 | medium (high for a raw IP)  |
| `elevated_tool_call`         | `tool_call` whose name/args suggest elevated privileges or a broad filesystem scope               | high                        |

## Testing / verification

```bash
npm run typecheck     # tsc --noEmit
npm run format:check  # prettier --check .
```

There's no automated test suite (out of scope for the ±4h estimate) — the
ingest, dedup, analyzer-dedup, and insights behaviors were verified manually
against the running system; see the commit history for the exact commands
and results.

## Repo layout

```
ingest/src/
  config.ts, db.ts, logger.ts   env config, pg pool, structured logger
  auth.ts                       bearer-token middleware
  schemas.ts                    zod event envelope
  routes/events.ts              POST /v1/events
  routes/alerts.ts              GET /v1/alerts
  routes/agents.ts              GET /v1/agents/:id/summary, /timeline
  server.ts                     wiring, error handling, timeouts, shutdown
  migrate.ts                    applies migrations/*.sql in order

analyzer/
  config.py, db.py              env config, psycopg connection
  rules.py                      the 5 rules above
  main.py                       poll loop / --once, alert dedup

migrations/001_init.sql         events + alerts schema
docker-compose.yml              Postgres
```
