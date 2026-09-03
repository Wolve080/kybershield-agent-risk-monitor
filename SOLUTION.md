# Ingest service — design notes

## Envelope strict, payload permissive

`eventSchema` (`ingest/src/schemas.ts`) validates the envelope fields
(`event_id`, `agent_id`, `timestamp`, `type`, `payload`, `tags`) strictly —
`.strict()` rejects any unrecognized top-level field, so a typo or a
client sending the wrong shape fails loudly at 400 rather than being
silently accepted with the extra data dropped.

`payload` itself is `z.record(z.string(), z.unknown())` — an open bag of
JSON, not a discriminated union over the four known event types
(`file_read`, `process_start`, `network_connect`, ...). This is
deliberate, not an omission.

**Why:** this is a security event pipeline. The event whose shape nobody
predicted — a new agent behavior, a new attack technique, a bug in an
agent that produces a malformed-but-real event — is exactly the one
worth keeping. A validator that rejects payloads it doesn't recognize
turns "unknown" into "silently dropped," which is worse than storing it
and dealing with the analysis side later. `type` is still required and
indexed (`events_agent_time_idx`, GIN on `payload`), so unrecognized
types are fully queryable — they're just not schema-checked beyond
"this is a JSON object."

**How it's applied:** any envelope violation (missing field, wrong
type, unexpected key) is a 400. Any payload content, for any `type`
string, is accepted and stored as-is in the `jsonb` column. Downstream
analyzers can impose per-type schemas later, against `analyzed_at IS
NULL` rows, without the ingest path ever having discarded data.

## Idempotency

`event_id` is the primary key; every insert uses
`ON CONFLICT (event_id) DO NOTHING RETURNING event_id`. The handler
tells duplicates apart from fresh inserts by `rowCount` (1 vs 0) and
reports it back to the client as 201 `stored` vs 200 `duplicate` — the
same request replayed (retry, at-least-once delivery, crash-and-resend)
never double-counts an event, and the caller can see which case
happened. Proven against Postgres directly before any application code
existed (see commit history).

## Auth

Bearer tokens are compared with `timingSafeEqual` over SHA-256 digests
of both the presented and stored key, looping over every configured key
without short-circuiting on a match. Plain `===` leaks timing
information proportional to the number of correct leading characters;
hashing first also sidesteps `timingSafeEqual`'s length-mismatch throw
(a length difference is itself a signal `===` would otherwise not need
to hide by hashing).

## Timeouts (the "shouldn't hang indefinitely" requirement)

Four independent timeouts, each covering a different failure mode:

- `connectionTimeoutMillis` / `statement_timeout` (pg pool) — a stuck
  connection acquisition or a runaway query.
- `server.requestTimeout` (10s) / `server.headersTimeout` (12s) — a
  slow-loris client that opens a socket and dribbles bytes. Headers
  timeout is set above the request timeout, as Node requires.
