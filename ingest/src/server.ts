import express from "express";
import { pinoHttp } from "pino-http";
import { config } from "./config.js";
import { logger } from "./logger.js";
import { pool } from "./db.js";
import { requireApiKey } from "./auth.js";
import { eventsRouter } from "./routes/events.js";
import { alertsRouter } from "./routes/alerts.js";
import { agentsRouter } from "./routes/agents.js";

const app = express();
app.use(pinoHttp({ logger }));
app.use(express.json({ limit: config.maxBodyBytes }));

// no auth on health checks
app.get("/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.status(200).json({ status: "ok" });
  } catch (err) {
    logger.error({ err }, "health check failed");
    res.status(503).json({ status: "unavailable" });
  }
});

app.use("/v1/events", requireApiKey, eventsRouter);
app.use("/v1/alerts", requireApiKey, alertsRouter);
app.use("/v1/agents", requireApiKey, agentsRouter);

function bodyParserErrorType(err: unknown): unknown {
  return typeof err === "object" && err !== null && "type" in err
    ? (err as { type?: unknown }).type
    : undefined;
}

// needs all 4 params or express won't treat it as an error handler
app.use(
  (
    err: unknown,
    _req: express.Request,
    res: express.Response,
    next: express.NextFunction,
  ) => {
    if (res.headersSent) {
      next(err);
      return;
    }

    const type = bodyParserErrorType(err);
    if (type === "entity.too.large") {
      res.status(413).json({ error: "payload_too_large" });
      return;
    }
    if (type === "entity.parse.failed" || err instanceof SyntaxError) {
      logger.warn({ err }, "request body is not valid JSON");
      res.status(400).json({ error: "invalid_json" });
      return;
    }

    logger.error({ err }, "unhandled error");
    res.status(500).json({ error: "internal_error" });
  },
);

const server = app.listen(config.port, () => {
  logger.info(`listening on ${config.port}`);
});

// slowloris mitigation - don't let a client hold the connection open forever
server.requestTimeout = 10_000;
server.headersTimeout = 12_000;

function shutdown() {
  logger.info("shutting down");
  server.close(() => {
    pool
      .end()
      .then(() => process.exit(0))
      .catch((err: unknown) => {
        logger.error({ err }, "error closing pool");
        process.exit(1);
      });
  });
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
