CREATE TYPE severity AS ENUM ('low', 'medium', 'high', 'critical');

CREATE TABLE events (
  event_id     text PRIMARY KEY,
  agent_id     text        NOT NULL,
  occurred_at  timestamptz NOT NULL,
  received_at  timestamptz NOT NULL DEFAULT now(),
  type         text        NOT NULL,
  payload      jsonb       NOT NULL,
  tags         text[]      NOT NULL DEFAULT '{}',
  ingest_seq   bigserial   NOT NULL,
  analyzed_at  timestamptz
);

CREATE INDEX events_agent_time_idx ON events (agent_id, occurred_at DESC);
CREATE INDEX events_time_idx       ON events (occurred_at DESC);
CREATE INDEX events_unanalyzed_idx ON events (ingest_seq) WHERE analyzed_at IS NULL;
CREATE INDEX events_payload_idx    ON events USING gin (payload);

CREATE TABLE alerts (
  alert_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id   text        NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
  agent_id   text        NOT NULL,
  rule       text        NOT NULL,
  severity   severity    NOT NULL,
  summary    text        NOT NULL,
  details    jsonb       NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (event_id, rule)
);

CREATE INDEX alerts_created_idx       ON alerts (created_at DESC);
CREATE INDEX alerts_agent_created_idx ON alerts (agent_id, created_at DESC);
CREATE INDEX alerts_rule_idx          ON alerts (rule);