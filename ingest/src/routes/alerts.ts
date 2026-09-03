import { Router } from "express";
import { z } from "zod";
import { pool } from "../db.js";
import { logger } from "../logger.js";

export const alertsRouter = Router();

const querySchema = z.object({
  agent_id: z.string().min(1).optional(),
  rule: z.string().min(1).optional(),
  since_hours: z.coerce
    .number()
    .positive()
    .max(24 * 30)
    .optional()
    .default(24),
  limit: z.coerce.number().int().positive().max(500).optional().default(100),
});

alertsRouter.get("/", async (req, res) => {
  const parsed = querySchema.safeParse(req.query);
  if (!parsed.success) {
    res
      .status(400)
      .json({ error: "invalid_query", issues: parsed.error.issues });
    return;
  }
  const { agent_id, rule, since_hours, limit } = parsed.data;

  try {
    const result = await pool.query(
      `SELECT alert_id, event_id, agent_id, rule, severity, summary, details, created_at
       FROM alerts
       WHERE created_at >= now() - make_interval(hours => $1)
         AND ($2::text IS NULL OR agent_id = $2)
         AND ($3::text IS NULL OR rule = $3)
       ORDER BY created_at DESC
       LIMIT $4`,
      [since_hours, agent_id ?? null, rule ?? null, limit],
    );
    res.status(200).json({ alerts: result.rows });
  } catch (err) {
    logger.error({ err }, "failed to list alerts");
    res.status(500).json({ error: "internal_error" });
  }
});
