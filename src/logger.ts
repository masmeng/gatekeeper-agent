// Minimal structured logger. NEVER log secrets: callers must pass only
// redacted values. This module also provides a redactor for defense in depth.
const SECRET_KEYS = ["secret", "api_key", "apikey", "password", "seed", "private"];

export function redact(value: unknown): unknown {
  if (typeof value === "string") {
    // A long hex/base64-looking token is almost certainly a secret.
    if (/^[A-Za-z0-9+/=_-]{32,}$/.test(value) && !value.startsWith("0x")) {
      return "<redacted>";
    }
    return value;
  }
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const lower = k.toLowerCase();
      out[k] = SECRET_KEYS.some((s) => lower.includes(s)) ? "<redacted>" : redact(v);
    }
    return out;
  }
  return value;
}

type Level = "info" | "warn" | "error";

function log(level: Level, msg: string, fields?: Record<string, unknown>): void {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    msg,
    ...(fields ? { fields: redact(fields) } : {}),
  });
  if (level === "error") console.error(line);
  else console.log(line);
}

export const logger = {
  info: (msg: string, fields?: Record<string, unknown>) => log("info", msg, fields),
  warn: (msg: string, fields?: Record<string, unknown>) => log("warn", msg, fields),
  error: (msg: string, fields?: Record<string, unknown>) => log("error", msg, fields),
};
