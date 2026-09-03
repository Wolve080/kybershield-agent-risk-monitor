import { createHash, timingSafeEqual } from "node:crypto";
import type { Request, Response, NextFunction } from "express";
import { config } from "./config.js";
import { logger } from "./logger.js";

const BEARER_PREFIX = "Bearer ";

function sha256(s: string): Buffer {
  return createHash("sha256").update(s).digest();
}

// hash first so both buffers are always 32 bytes (timingSafeEqual throws
// on a length mismatch) and comparison time doesn't leak key length/content
function safeEqual(a: string, b: string): boolean {
  return timingSafeEqual(sha256(a), sha256(b));
}

export function requireApiKey(req: Request, res: Response, next: NextFunction) {
  const header = req.header("authorization");
  if (!header || !header.startsWith(BEARER_PREFIX)) {
    logger.warn(
      { path: req.path },
      "missing or malformed authorization header",
    );
    res.status(401).json({ error: "unauthorized" });
    return;
  }

  const presented = header.slice(BEARER_PREFIX.length);

  // don't break early, keeps timing independent of which key matches
  let matchedClient: string | undefined;
  for (const [storedKey, clientName] of config.apiKeys) {
    if (safeEqual(presented, storedKey)) {
      matchedClient = clientName;
    }
  }

  if (!matchedClient) {
    logger.warn({ path: req.path }, "invalid api key");
    res.status(401).json({ error: "unauthorized" });
    return;
  }

  res.locals["client"] = matchedClient;
  next();
}
