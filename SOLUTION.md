# KyberShield MVP — design notes

Run instructions are in [README.md](README.md); this is the why.

## Architecture

One Postgres database, two processes:

- `ingest/` (TypeScript/Express) — writes events (Task 1) and also serves
  the read endpoints for alerts/summaries/timelines (Task 3).
- `analyzer/` (Python) — reads events, writes alerts (Task 2).

Task 3 could have been a separate service or a CLI. It's bundled into `ingest`
instead: it's the same type of work (authenticated JSON over HTTP against
the same database), a separate process would mean a second auth
implementation and a second set of pool/timeout/logging plumbing for
no isolation benefit at this scale, and "a teammate could integrate this
into a dashboard" is easiest to satisfy with one well-known base URL.
If the write and read paths ever needed to scale or deploy independently,
splitting them is a small change — neither depends on the other's
internals, they only share the schema.

The analyzer is a separate process on purpose, in a different language,
per the assignment — but even ignoring that constraint, event ingestion
and risk analysis have different failure modes and load shapes (ingestion
is latency-sensitive and bursty; analysis is throughput-oriented and
fine to lag by a few seconds), which is a reasonable place to draw a
process boundary regardless of stack.

## Task 1 — Ingest service

### Envelope strict, payload permissive

`eventSchema` (`ingest/src/schemas.ts`) validates the envelope fields
(`event_id`, `agent_id`, `timestamp`, `type`, `payload`, `tags`) strictly —
`.strict()` rejects any unrecognized top-level field, so a typo or a
client sending the wrong shape fails loudly at 400 rather than being
silently accepted with the extra data dropped.

`payload` itself is `z.record(z.string(), z.unknown())` — an open bag of
JSON, not a discriminated union over the four known event types
(`file_read`, `process_start`, `network_connect`, ...). This is
deliberate, not an omission.

Why: this is a security event pipeline. The event whose shape nobody
predicted — a new agent behavior, a new attack technique, a bug in an
agent that produces a malformed-but-real event — is exactly the one
worth keeping. A validator that rejects payloads it doesn't recognize
turns "unknown" into "silently dropped," which is worse than storing it
and dealing with the analysis side later. `type` is still required and
indexed (`events_agent_time_idx`, GIN on `payload`), so unrecognized
types are fully queryable — they're just not schema-checked beyond
"this is a JSON object."

How it's applied: any envelope violation (missing field, wrong type,
unexpected key) is a 400. Any payload content, for any `type` string,
is accepted and stored as-is in the `jsonb` column. Downstream analyzers
can impose per-type schemas later, against `analyzed_at IS NULL` rows,
without the ingest path ever having discarded data.

### Idempotency

`event_id` is the primary key — every insert uses
`ON CONFLICT (event_id) DO NOTHING RETURNING event_id`. The handler tells
duplicates apart from fresh inserts by `rowCount` (1 vs 0) and reports
it back to the client as 201 `stored` vs 200 `duplicate` — the same request
replayed (retry, at-least-once delivery, crash-and-resend) never
double-counts an event, and the caller can see which case happened.
Proven against Postgres directly before any application code existed
(see commit history).

`occurred_at` (agent-reported event time) is stored separately from
`received_at` (insert time, `DEFAULT now()`), and nothing in the schema or
the insert path assumes they're close together or arrive in order —
that's what 'support events that can arrive out of order in time'
means in practice: don't derive anything from insert order. The
`(agent_id, occurred_at DESC)` index and every windowed query (Task 2's
rapid-reads rule, Task 3's timeline) key off `occurred_at`, never off
insertion order or `ingest_seq`.

### Auth

Bearer tokens are compared with `timingSafeEqual` over SHA-256 digests
of both the presented and stored key, looping over every configured key
without short-circuiting on a match. Plain `===` leaks timing information
proportional to the number of correct leading characters;
hashing first also sidesteps `timingSafeEqual`s length-mismatch throw
(a length difference is itself a signal `===` would otherwise not need
to hide by hashing).

The same middleware guards the Task 3 read endpoints — alerts and timelines
are as sensitive as the raw events they're built from, so there's no reason
for a lower bar there.

### Timeouts (the 'shouldn't hang indefinitely' requirement)

Four independent timeouts, each covering a different failure mode:

- `connectionTimeoutMillis` / `statement_timeout` (pg pool) — a stuck
  connection acquisition or a runaway query.
- `server.requestTimeout` (10s) / `server.headersTimeout` (12s) — a
  slow-loris client that opens a socket and dribbles bytes. Headers
  timeout is set above the request timeout, as Node requires.

## Task 2 — Risk analyzer

### How it runs

`analyzer/main.py` polls: fetch up to `ANALYZER_BATCH_SIZE` events where
`analyzed_at IS NULL` (oldest `ingest_seq` first, `FOR UPDATE SKIP LOCKED`)
— run every rule against each one, insert whatever alerts matched,
mark the event analyzed, commit — sleep `ANALYZER_POLL_SECONDS` and repeat.
`--once` runs a single batch and exits, for cron or a manual 'process what's
pending right now' call, without a second code path.

`FOR UPDATE SKIP LOCKED` isn't needed for a single worker — it's there
so running two analyzer processes for throughput doesn't mean they
both grab the same batch. Costs nothing when there's only one.

### Rule dedup

`alerts` has `UNIQUE (event_id, rule)`. The insert is `ON CONFLICT
(event_id, rule) DO NOTHING`, the same pattern as event dedup in Task 1.
Re-analyzing an event (a manual re-run, a rule that gets re-triggered)
recomputes the same findings but produces no duplicate rows — verified by
resetting `analyzed_at` on already-alerted events and re-running the analyzer
(see commit history).

### Error handling

Each event's rule evaluation is wrapped individually; a failure rolls
back just that event's transaction and leaves `analyzed_at` NULL so it's
picked up again next poll, while the rest of the batch still commits.
A single bad event (a rule crashing on unexpected payload shape, say)
degrades to "this one event keeps getting retried and logged" rather than
stalling every event behind it or silently dropping it.

### Rules chosen

Five, covering four of the five example categories in the brief plus a
network-allowlist rule using `ALLOWED_DOMAINS` (already provided in `.env`):

- `secret_file_access` — `file_read` against a pattern list
  (`.env`, `id_rsa`, `.aws/credentials`, `.pem`, ...), severity varies
  by pattern (private key material is `critical`, `.npmrc` is `medium`).
- `rapid_sensitive_reads` — the same secret-path check, but counted
  across a rolling `SENSITIVE_READ_WINDOW_SECONDS` window per agent;
  fires once the count hits `SENSITIVE_READ_THRESHOLD`. Repeated
  sensitive reads read as reconnaissance even when no single read looks
  unusual on its own.
- `shell_download_execute` — `shell_command` matching
  download-then-execute patterns (`curl … | bash`, `base64 -d | sh`,
  download-then-chmod). Always `critical` — this is remote code
  execution, not a judgment call.
- `disallowed_network_request` — `http_request` to a host outside
  `ALLOWED_DOMAINS`; a bare IP (which sidesteps domain-based allowlisting
  entirely) is `high`, a domain is `medium`.
- `elevated_tool_call` — `tool_call` whose name or args suggest
  elevated privileges (`sudo`, `chmod`, `admin`) or an unrestricted
  scope (`args` targeting `/`, ``, etc.).

### Known limitation: out-of-order arrivals and windowed rules

`rapid_sensitive_reads` counts events with `occurred_at` at or before
the triggering event's own timestamp — correct for that event. But if
event A (10:00:00) arrives _after_ event B (10:00:05) was already analyzed,
B's count was computed without knowing about A, and that alert isn't
retroactively corrected. For an MVP this is an accepted gap: it only
under-counts (never invents a false alert), only affects a rule with a
time window, and fixing it properly means re-triggering analysis on
every later event in an agent's window whenever a late event lands —
real complexity for a case (chronic several-second lateness during exactly
one detection window) this deployment isn't expected to hit.

## Task 3 — Insights API

- `GET /v1/alerts` filters by `agent_id`/`rule` and defaults to the
  last 24h (`since_hours`), matching the brief's example. `limit` is
  capped at 500 server-side regardless of what's requested.
- `/v1/agents/:id/summary` computes `max_severity` and `top_rules` in
  application code, not SQL — the rows for a 24h/single-agent window
  are never large enough that a manual severity-rank comparison and a
  `Map` count are worth pushing into a `CASE`-ordered SQL aggregate.
- `/v1/agents/:id/timeline` is a single `UNION ALL` over events and
  alerts, ordered and limited once — a merge done in SQL rather than
  fetching both lists and interleaving them in TypeScript.

## What's out of scope for this MVP

- No automated test suite — behavior was verified manually against the
  running system at each step (commands and results are in the commit
  history); given the ±4h estimate, hand-verification against a real
  Postgres instance bought more confidence per minute spent than
  mocking the DB for unit tests would have.
- No pagination on `/v1/alerts` beyond `limit` — a cursor would be the
  next thing added if alert volume grew past what one page covers.
- The analyzer is a single long-lived connection per process; fine at
  this scale, a connection pool is the first thing to add before
  running more than one analyzer worker.
