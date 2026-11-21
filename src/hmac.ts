// HMAC-SHA256 helpers for the x-agent-games-signature header.
// The HMAC is computed over the RAW request/response body bytes, and verified
// BEFORE any JSON parsing. Comparison is timing-safe.
import crypto from "node:crypto";
import { HMAC_HEADER } from "./config.js";

/** Lowercase hex HMAC-SHA256 of `raw` under `secret`. */
export function signHmacSha256Hex(secret: string, raw: Buffer): string {
  return crypto.createHmac("sha256", secret).update(raw).digest("hex");
}

/**
 * Timing-safe verification of an incoming signature header.
 * Accepts a bare lowercase/uppercase hex digest, or a "sha256=<hex>" prefix.
 * Returns false for missing/empty/malformed values — never throws.
 */
export function verifyHmacSha256Hex(
  secret: string,
  raw: Buffer,
  headerValue: string | string[] | undefined,
): boolean {
  if (!secret || headerValue === undefined) return false;
  const presented = Array.isArray(headerValue) ? headerValue[0] : headerValue;
  if (!presented) return false;
  let hex = presented.trim();
  if (hex.toLowerCase().startsWith("sha256=")) hex = hex.slice("sha256=".length);
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) return false;
  const expected = signHmacSha256Hex(secret, raw);
  const a = Buffer.from(expected, "hex");
  const b = Buffer.from(hex.toLowerCase(), "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export { HMAC_HEADER };
