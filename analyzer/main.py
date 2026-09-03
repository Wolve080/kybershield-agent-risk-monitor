from __future__ import annotations

import argparse
import logging
import time

import psycopg
from psycopg.types.json import Jsonb

from . import config
from .db import connect
from .rules import ALL_RULES, Finding

logging.basicConfig(level=config.LOG_LEVEL, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("analyzer")

# FOR UPDATE SKIP LOCKED costs nothing with a single worker and means this
# can be scaled to multiple analyzer processes later without them stepping
# on each other's batches.
FETCH_BATCH_SQL = """
    SELECT event_id, agent_id, occurred_at, type, payload, tags
    FROM events
    WHERE analyzed_at IS NULL
    ORDER BY ingest_seq
    LIMIT %s
    FOR UPDATE SKIP LOCKED
"""

INSERT_ALERT_SQL = """
    INSERT INTO alerts (event_id, agent_id, rule, severity, summary, details)
    VALUES (%s, %s, %s, %s, %s, %s)
    ON CONFLICT (event_id, rule) DO NOTHING
"""

MARK_ANALYZED_SQL = "UPDATE events SET analyzed_at = now() WHERE event_id = %s"


def process_batch(conn: psycopg.Connection) -> int:
    with conn.cursor() as cur:
        cur.execute(FETCH_BATCH_SQL, (config.ANALYZER_BATCH_SIZE,))
        events = cur.fetchall()

    for event in events:
        try:
            findings: list[Finding] = []
            for rule in ALL_RULES:
                findings.extend(rule(event, conn))

            with conn.cursor() as cur:
                for f in findings:
                    cur.execute(
                        INSERT_ALERT_SQL,
                        (
                            event["event_id"],
                            event["agent_id"],
                            f.rule,
                            f.severity,
                            f.summary,
                            Jsonb(f.details),
                        ),
                    )
                cur.execute(MARK_ANALYZED_SQL, (event["event_id"],))
            conn.commit()

            if findings:
                log.info(
                    "event %s -> %d alert(s): %s",
                    event["event_id"],
                    len(findings),
                    [f.rule for f in findings],
                )
        except Exception:
            # leave analyzed_at NULL so this event gets retried next poll,
            # rather than losing it or crashing the whole batch
            conn.rollback()
            log.exception("failed to analyze event %s, will retry", event["event_id"])

    return len(events)


def main() -> None:
    parser = argparse.ArgumentParser(description="KyberShield risk analyzer")
    parser.add_argument("--once", action="store_true", help="process a single batch and exit")
    args = parser.parse_args()

    log.info(
        "starting analyzer (batch_size=%d, poll_seconds=%d, once=%s)",
        config.ANALYZER_BATCH_SIZE,
        config.ANALYZER_POLL_SECONDS,
        args.once,
    )

    with connect() as conn:
        while True:
            n = process_batch(conn)
            if args.once:
                log.info("processed %d event(s), exiting (--once)", n)
                break
            if n == 0:
                time.sleep(config.ANALYZER_POLL_SECONDS)


if __name__ == "__main__":
    main()
