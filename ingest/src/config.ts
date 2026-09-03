import dotenv from "dotenv";

dotenv.config();

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required env var: ${name}`);
  return value;
}

function parseApiKeys(raw: string): Map<string, string> {
  const keys = new Map<string, string>();
  for (const pair of raw.split(",")) {
    const [client, key] = pair.split(":");
    if (!client || !key) throw new Error(`Bad API_KEYS entry: "${pair}"`);
    keys.set(key.trim(), client.trim());
  }
  return keys;
}

export const config = {
  databaseUrl: required("DATABASE_URL"),
  port: Number(process.env["PORT"] ?? 3000),
  logLevel: process.env["LOG_LEVEL"] ?? "info",
  apiKeys: parseApiKeys(required("API_KEYS")),
  maxBodyBytes: Number(process.env["MAX_BODY_BYTES"] ?? 524_288),
};
