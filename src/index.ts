// HTTP server for the Proof Gatekeeper agent.
//   POST /agent  — the registered endpoint (preflight + task envelope)
//   GET  /health — liveness probe (not part of the agent-games protocol)
// Plain node:http is used on purpose: the handler needs the RAW request body
// for HMAC verification, and a framework would only add surface area.
import fs from "node:fs";
import http from "node:http";
import { assertConfig, config } from "./config.js";
import { HMAC_HEADER, signHmacSha256Hex } from "./hmac.js";
import { logger } from "./logger.js";
import { loadVerificationKey } from "./prover.js";
import { handleAgent, type RouteResult } from "./routes.js";
import { UsedProofStore } from "./store.js";

const MAX_BODY_BYTES = 1024 * 1024; // tasks are small; 1 MiB is generous

const store = new UsedProofStore(config.storePath, config.storeMaxEntries);

function sendSigned(
  res: http.ServerResponse,
  result: RouteResult,
): void {
  const raw = Buffer.from(JSON.stringify(result.body), "utf8");
  const signature = signHmacSha256Hex(config.hmacSecret, raw);
  res.writeHead(result.status, {
    "content-type": "application/json",
    [HMAC_HEADER]: signature,
    "content-length": raw.length,
  });
  res.end(raw);
}

function readRawBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let tooLarge = false;
    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        tooLarge = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (tooLarge) reject(new Error("request body too large"));
      else resolve(Buffer.concat(chunks));
    });
    req.on("error", reject);
  });
}

async function handleRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
): Promise<void> {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  const started = Date.now();

  if (req.method === "GET" && url.pathname === "/health") {
    const raw = Buffer.from(
      JSON.stringify({ ok: true, service: "gatekeeper-agent", protocolVersion: "v1" }),
      "utf8",
    );
    res.writeHead(200, { "content-type": "application/json", "content-length": raw.length });
    res.end(raw);
    return;
  }

  if (req.method !== "POST" || url.pathname !== "/agent") {
    const raw = Buffer.from(
      JSON.stringify({ error: "not_found", hint: "POST /agent" }),
      "utf8",
    );
    res.writeHead(404, { "content-type": "application/json", "content-length": raw.length });
    res.end(raw);
    return;
  }

  let rawBody: Buffer;
  try {
    rawBody = await readRawBody(req);
  } catch {
    sendSigned(res, { status: 413, body: { error: "request_too_large" } });
    return;
  }

  // Hard deadline: the platform enforces 60s. Race the handler against it
  // and fail closed (REJECT) if the pipeline overruns. The handler only
  // returns a value, so exactly one response is ever sent.
  const deadlineMs = started + config.requestTimeoutMs;
  const work = handleAgent(rawBody, req.headers, { store, deadlineMs });
  const timeout = new Promise<RouteResult>((resolve) => {
    setTimeout(
      () => resolve({ status: 200, body: { decision: "REJECT", reason_code: "TIMEOUT" } }),
      config.requestTimeoutMs,
    );
  });
  let result: RouteResult;
  try {
    result = await Promise.race([work, timeout]);
  } catch (err) {
    logger.error("handler error", {
      error: err instanceof Error ? err.message : String(err),
    });
    result = { status: 200, body: { decision: "REJECT", reason_code: "INTERNAL_ERROR" } };
  }
  logger.info("request handled", {
    status: result.status,
    ms: Date.now() - started,
    decision: (result.body as { decision?: string }).decision ?? "-",
  });
  sendSigned(res, result);
}

async function main(): Promise<void> {
  assertConfig();

  for (const p of [config.wasmPath, config.zkeyPath]) {
    if (!fs.existsSync(p)) {
      throw new Error(`Circuit artifact missing: ${p}`);
    }
  }
  // Warm the verification-key cache so the first task is not slowed down.
  await loadVerificationKey();
  store.load();
  logger.info("used-proof store loaded", { entries: store.size() });

  const server = http.createServer((req, res) => {
    handleRequest(req, res).catch((err) => {
      logger.error("unhandled request error", {
        error: err instanceof Error ? err.message : String(err),
      });
      if (!res.headersSent) {
        sendSigned(res, {
          status: 200,
          body: { decision: "REJECT", reason_code: "INTERNAL_ERROR" },
        });
      }
    });
  });
  server.requestTimeout = config.requestTimeoutMs + 5000;
  server.headersTimeout = config.requestTimeoutMs + 10000;

  await new Promise<void>((resolve) => {
    server.listen(config.port, config.host, () => resolve());
  });
  logger.info("gatekeeper agent listening", {
    host: config.host,
    port: config.port,
    kurier: config.kurierApiKey ? "configured" : "not configured (local proofs only)",
    requireKurierFinalized: config.requireKurierFinalized,
    requestTimeoutMs: config.requestTimeoutMs,
  });

  const shutdown = () => {
    logger.info("shutting down");
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  logger.error("fatal startup error", {
    error: err instanceof Error ? err.message : String(err),
  });
  process.exit(1);
});
