import { Router } from "express";
import type { Response } from "express";
import { z } from "zod";
import { pool } from "../db.js";
import { logger } from "../logger.js";

export const agentsRouter = Router();

const SEVERITY_RANK: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function missingAgentId(res: Response): void {
  res.status(400).json({ error: "missing_agent_id" });
}

const summaryQuerySchema = z.object({
  window_hours: z.coerce
    .number()
    .positive()
    .max(24 * 30)
    .optional()
    .default(24),
});

agentsRouter.get("/:agent_id/summary", async (req, res) => {
  const agentId = req.params["agent_id"];
  if (!agentId) {
    missingAgentId(res);
    return;
  }

  const parsed = summaryQuerySchema.safeParse(req.query);
  if (!parsed.success) {
    res
      .status(400)
      .json({ error: "invalid_query", issues: parsed.error.issues });
    return;
  }
  const { window_hours } = parsed.data;

  try {
    const [windowResult, alertsResult] = await Promise.all([
      pool.query<{ window_start: Date; window_end: Date }>(
        "SELECT now() - make_interval(hours => $1) AS window_start, now() AS window_end",
        [window_hours],
      ),
      pool.query<{ rule: string; severity: string }>(
        `SELECT rule, severity FROM alerts
         WHERE agent_id = $1 AND created_at >= now() - make_interval(hours => $2)`,
        [agentId, window_hours],
      ),
    ]);

    const ruleCounts = new Map<string, number>();
    let maxSeverity: string | null = null;
    for (const row of alertsResult.rows) {
      ruleCounts.set(row.rule, (ruleCounts.get(row.rule) ?? 0) + 1);
      if (
        !maxSeverity ||
        (SEVERITY_RANK[row.severity] ?? -1) > (SEVERITY_RANK[maxSeverity] ?? -1)
      ) {
        maxSeverity = row.severity;
      }
    }

    const topRules = [...ruleCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([rule, count]) => ({ rule, count }));

    res.status(200).json({
      agent_id: agentId,
      window_start: windowResult.rows[0]?.window_start,
      window_end: windowResult.rows[0]?.window_end,
      total_alerts: alertsResult.rowCount,
      max_severity: maxSeverity,
      top_rules: topRules,
    });
  } catch (err) {
    logger.error({ err }, "failed to build agent summary");
    res.status(500).json({ error: "internal_error" });
  }
});

const timelineQuerySchema = z.object({
  window_hours: z.coerce
    .number()
    .positive()
    .max(24 * 30)
    .optional()
    .default(24),
  limit: z.coerce.number().int().positive().max(1000).optional().default(200),
});

agentsRouter.get("/:agent_id/timeline", async (req, res) => {
  const agentId = req.params["agent_id"];
  if (!agentId) {
    missingAgentId(res);
    return;
  }

  const parsed = timelineQuerySchema.safeParse(req.query);
  if (!parsed.success) {
    res
      .status(400)
      .json({ error: "invalid_query", issues: parsed.error.issues });
    return;
  }
  const { window_hours, limit } = parsed.data;

  try {
    const result = await pool.query(
      `
      (
        SELECT occurred_at AS timestamp, 'event' AS kind, event_id AS reference_id, type AS brief
        FROM events
        WHERE agent_id = $1 AND occurred_at >= now() - make_interval(hours => $2)
      )
      UNION ALL
      (
        SELECT created_at AS timestamp, 'alert' AS kind, alert_id::text AS reference_id, summary AS brief
        FROM alerts
        WHERE agent_id = $1 AND created_at >= now() - make_interval(hours => $2)
      )
      ORDER BY timestamp DESC
      LIMIT $3
      `,
      [agentId, window_hours, limit],
    );
    res.status(200).json({ agent_id: agentId, timeline: result.rows });
  } catch (err) {
    logger.error({ err }, "failed to build agent timeline");
    res.status(500).json({ error: "internal_error" });
  }
});
