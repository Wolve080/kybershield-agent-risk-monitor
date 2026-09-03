import { Router } from 'express';
import { eventSchema } from '../schemas.js';
import { pool } from '../db.js';
import { logger } from '../logger.js';

export const eventsRouter = Router();

const INSERT_SQL = `
  INSERT INTO events (event_id, agent_id, occurred_at, type, payload, tags)
  VALUES ($1, $2, $3, $4, $5, $6)
  ON CONFLICT (event_id) DO NOTHING
  RETURNING event_id
`;

eventsRouter.post('/', async (req, res) => {
  const parsed = eventSchema.safeParse(req.body);
  if (!parsed.success) {
    // Never log the whole payload — it may contain the exact secrets this
    // product exists to detect. Log the event_id and failing fields only.
    const rawEventId = req.body?.event_id;
    logger.warn(
      {
        event_id: typeof rawEventId === 'string' ? rawEventId : undefined,
        fields: parsed.error.issues.map((issue) => issue.path.join('.')),
      },
      'event failed validation',
    );
    res.status(400).json({ error: 'invalid_event', issues: parsed.error.issues });
    return;
  }

  const { event_id, agent_id, timestamp, type, payload, tags } = parsed.data;

  try {
    const result = await pool.query(INSERT_SQL, [
      event_id,
      agent_id,
      timestamp,
      type,
      payload,
      tags ?? [],
    ]);

    if (result.rowCount === 1) {
      res.status(201).json({ status: 'stored', event_id });
    } else {
      res.status(200).json({ status: 'duplicate', event_id });
    }
  } catch (err) {
    const code = err && typeof err === 'object' && 'code' in err ? err.code : undefined;
    logger.error({ event_id, code }, 'failed to insert event');
    res.status(500).json({ error: 'internal_error' });
  }
});
