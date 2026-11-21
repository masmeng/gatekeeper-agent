// Configuration — all secrets come from environment variables only.
// Never hardcode a secret here. See .env.example for the full list.
import { config as loadDotenv } from "dotenv";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

loadDotenv();

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Project root. When run from source (tsx) __dirname is <root>/src; when run
 * compiled, it is <root>/dist/src. Resolve by finding the directory that
 * contains the circuits/ artifacts (falling back to package.json).
 */
function findRoot(): string {
  const candidates = [
    path.resolve(__dirname, ".."),
    path.resolve(__dirname, "..", ".."),
    process.cwd(),
  ];
  for (const c of candidates) {
    if (fs.existsSync(path.join(c, "circuits", "gatekeeper.wasm"))) return c;
  }
  for (const c of candidates) {
    if (fs.existsSync(path.join(c, "package.json"))) return c;
  }
  return candidates[0];
}
const ROOT = findRoot();

function env(name: string, fallback = ""): string {
  const v = process.env[name];
  return v === undefined || v === "" ? fallback : v;
}

function envInt(name: string, fallback: number): number {
  const raw = env(name, "");
  if (raw === "") return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n)) throw new Error(`Invalid integer for ${name}: ${raw}`);
  return n;
}

function envBool(name: string, fallback: boolean): boolean {
  const raw = env(name, "").toLowerCase();
  if (raw === "") return fallback;
  if (raw === "true" || raw === "1" || raw === "yes") return true;
  if (raw === "false" || raw === "0" || raw === "no") return false;
  throw new Error(`Invalid boolean for ${name}: ${raw}`);
}

/** Gatekeeper verification-key hash registered on zkVerify mainnet. */
export const EXPECTED_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

/** BN128 (alt_bn128) field prime, as a BigInt. */
export const FIELD_PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);

/**
 * ASSUMPTION A1 — taskId encoding (NOT specified in the /build spec).
 * The gatekeeper circuit takes `taskId` as a single BN128 field element, but the
 * platform sends `task_id` as a string (e.g. "gk_8d31_..."). This service encodes
 * it as keccak256(task_id) mod FIELD_PRIME — the standard EVM-compatible way to
 * map an arbitrary string into a field element. If the platform publishes a
 * different encoding, change TASK_ID_ENCODING here and in envelope.ts.
 * Valid values: "keccak256-mod-p".
 */
export const TASK_ID_ENCODING = env("TASK_ID_ENCODING", "keccak256-mod-p");

/**
 * ASSUMPTION A2 — HMAC signature format (NOT specified in the /build spec).
 * The platform header is `x-agent-games-signature`. This service computes
 * HMAC-SHA256 over the raw body and emits/compares a lowercase hex digest.
 * On verification it also accepts an optional "sha256=" prefix (GitHub-style).
 */
export const HMAC_HEADER = "x-agent-games-signature";

export const config = {
  /** HMAC secret from the dashboard "Rotate Secret" (REQUIRED). */
  hmacSecret: env("AGENT_GAMES_HMAC_SECRET", ""),
  /** Kurier API key from kurier.xyz dashboard (optional; see README). */
  kurierApiKey: env("KURIER_API_KEY", ""),
  /** Kurier REST base URL. Mainnet default; set to the testnet URL for testing. */
  kurierBaseUrl: env("KURIER_BASE_URL", "https://api.kurier.xyz/api/v1"),
  /**
   * When true (and a Kurier key is set) an APPROVE is only returned after the
   * Kurier job reaches Finalized. When false, a locally-verified proof is
   * enough and Kurier is used best-effort. Default: true.
   */
  requireKurierFinalized: envBool("KURIER_REQUIRE_FINALIZED", true),
  /** Max time (ms) to wait for a Kurier job to reach Finalized per request. */
  kurierFinalizeTimeoutMs: envInt("KURIER_FINALIZE_TIMEOUT_MS", 20000),
  /** Interval (ms) between Kurier job-status polls. Kurier docs use 5s. */
  kurierPollIntervalMs: envInt("KURIER_POLL_INTERVAL_MS", 5000),
  /** Hard per-request deadline (ms). The platform enforces 60s. */
  requestTimeoutMs: envInt("REQUEST_TIMEOUT_MS", 60000),
  /** Safety margin (ms) reserved for serializing + sending the response. */
  responseMarginMs: envInt("RESPONSE_MARGIN_MS", 5000),
  /** Allowed clock skew (ms) when validating issued_at / deadline_at. */
  clockSkewMs: envInt("CLOCK_SKEW_MS", 120000),

  host: env("HOST", "0.0.0.0"),
  port: envInt("PORT", 3000),

  wasmPath: env("GATEKEEPER_WASM", path.join(ROOT, "circuits", "gatekeeper.wasm")),
  zkeyPath: env("GATEKEEPER_ZKEY", path.join(ROOT, "circuits", "gatekeeper_final.zkey")),
  storePath: env("USED_PROOFS_PATH", path.join(ROOT, "data", "used-proofs.json")),
  /** Max entries kept in the used-proof store (FIFO eviction). */
  storeMaxEntries: envInt("USED_PROOFS_MAX_ENTRIES", 10000),

  /** Expected verification-key hash (lowercase compare). */
  expectedVkHash: EXPECTED_VK_HASH.toLowerCase(),

  nodeEnv: env("NODE_ENV", "development"),
};

export function assertConfig(): void {
  if (!config.hmacSecret) {
    throw new Error(
      "AGENT_GAMES_HMAC_SECRET is not set. Copy it from the Agent Games dashboard " +
        "(Rotate Secret) into your .env file. The service refuses to start without a real secret.",
    );
  }
  const normalized = config.hmacSecret.toLowerCase().replace(/[^a-z0-9]/g, "");
  const placeholders = new Set([
    "test", "testsecret", "placeholder", "changeme", "secret", "xxx",
    "123", "password", "yoursecrethere", "hmacsecret", "rotatesecret",
  ]);
  if (config.hmacSecret.length < 16 || placeholders.has(normalized)) {
    throw new Error(
      "AGENT_GAMES_HMAC_SECRET looks like a placeholder (too short or a generic value). " +
        "Use the real platform-generated secret from Rotate Secret.",
    );
  }
}
