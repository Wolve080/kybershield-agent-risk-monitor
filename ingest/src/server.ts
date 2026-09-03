import express from 'express';
import { pinoHttp } from 'pino-http';
import { config } from './config.js';
import { logger } from './logger.js';
import { pool } from './db.js';
import { requireApiKey } from './auth.js';
import { eventsRouter } from './routes/events.js';

const app = express();
app.use(pinoHttp({ logger }));
app.use(express.json({ limit: config.maxBodyBytes }));

// Unauthenticated: health checks shouldn't need credentials.
app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.status(200).json({ status: 'ok' });
  } catch (err) {
    logger.error({ err }, 'health check failed');
    res.status(503).json({ status: 'unavailable' });
  }
});

app.use('/v1/events', requireApiKey, eventsRouter);

function isPayloadTooLarge(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'type' in err &&
    (err as { type?: unknown }).type === 'entity.too.large'
  );
}

// Error middleware — must take exactly four parameters; that arity is how
// Express identifies it as an error handler rather than a normal one.
app.use((err: unknown, _req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (res.headersSent) {
    next(err);
    return;
  }

  if (isPayloadTooLarge(err)) {
    res.status(413).json({ error: 'payload_too_large' });
    return;
  }

  logger.error({ err }, 'unhandled error');
  res.status(500).json({ error: 'internal_error' });
});

const server = app.listen(config.port, () => {
  logger.info(`listening on ${config.port}`);
});

// Guards against a client opening a socket and dribbling bytes forever
// (a "slowloris" attack) rather than sending a request promptly.
server.requestTimeout = 10_000;
server.headersTimeout = 12_000;

function shutdown() {
  logger.info('shutting down');
  server.close(() => {
    pool
      .end()
      .then(() => process.exit(0))
      .catch((err: unknown) => {
        logger.error({ err }, 'error closing pool');
        process.exit(1);
      });
  });
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
