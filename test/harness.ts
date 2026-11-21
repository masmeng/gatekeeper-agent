// End-to-end test harness for the Proof Gatekeeper agent.
//   npm test
// Builds the project, starts the compiled server on a test port with a
// throwaway HMAC secret (NOT a real platform secret), replays the fixtures,
// and asserts decisions, reason codes, response signatures, and that every
// returned proof verifies locally against the exported verification key.
// Kurier is intentionally NOT exercised here (no API key in tests); the
// harness asserts the local-proof path and documents that Kurier needs a key.
import { spawn, type ChildProcess } from "node:child_process";
import crypto from "node:crypto";
import { execSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const PORT = 18777;
const BASE = `http://127.0.0.1:${PORT}`;
// Throwaway test-only secret (generated per run, never a real platform secret).
const TEST_SECRET = crypto.randomBytes(32).toString("hex");
const STORE_PATH = path.join(os.tmpdir(), `gk-test-store-${process.pid}.json`);

const ZKEY = path.join(ROOT, "circuits", "gatekeeper_final.zkey");

let failures = 0;
let passes = 0;

function check(name: string, cond: boolean, detail = ""): void {
  if (cond) {
    passes++;
    console.log(`  PASS  ${name}`);
  } else {
    failures++;
    console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

function sign(secret: string, raw: Buffer): string {
  return crypto.createHmac("sha256", secret).update(raw).digest("hex");
}

interface PostResult {
  status: number;
  raw: Buffer;
  body: Record<string, unknown>;
  sigHeader?: string;
}

function checkResponseSignature(res: PostResult, secret: string): boolean {
  // Recompute the HMAC over the exact response bytes and compare it with
  // the x-agent-games-signature header the server sent.
  const header = res.sigHeader ?? "";
  if (!header) return false;
  const expected = sign(secret, res.raw);
  const a = Buffer.from(expected, "hex");
  const b = Buffer.from(header.toLowerCase(), "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function postWithSigHeader(
  raw: Buffer,
  secret: string | null,
): Promise<PostResult> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (secret !== null) headers["x-agent-games-signature"] = sign(secret, raw);
  const res = await fetch(`${BASE}/agent`, { method: "POST", headers, body: raw });
  const buf = Buffer.from(await res.arrayBuffer());
  let body: Record<string, unknown> = {};
  try {
    body = JSON.parse(buf.toString("utf8")) as Record<string, unknown>;
  } catch {
    body = { _unparsable: buf.toString("utf8") };
  }
  return { status: res.status, raw: buf, body, sigHeader: res.headers.get("x-agent-games-signature") ?? undefined };
}

function loadFixture(name: string): Record<string, unknown> {
  const raw = fs.readFileSync(path.join(ROOT, "test", "fixtures", name), "utf8");
  return JSON.parse(raw) as Record<string, unknown>;
}

function freshTimestamps(obj: Record<string, unknown>): Record<string, unknown> {
  const now = Date.now();
  const clone = JSON.parse(JSON.stringify(obj)) as Record<string, unknown>;
  clone.issued_at = new Date(now - 60_000).toISOString();
  clone.deadline_at = new Date(now + 3_600_000).toISOString();
  return clone;
}

async function waitReady(server: ChildProcess, timeoutMs = 30000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${BASE}/health`);
      if (res.ok) return true;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}

async function main(): Promise<void> {
  console.log("== Proof Gatekeeper harness ==");
  console.log("building...");
  execSync("npm run build", { cwd: ROOT, stdio: "pipe" });
  console.log("build ok");

  const vk = await snarkjs.zKey.exportVerificationKey(ZKEY);

  const server = spawn("node", [path.join(ROOT, "dist", "src", "index.js")], {
    cwd: ROOT,
    env: {
      ...process.env,
      AGENT_GAMES_HMAC_SECRET: TEST_SECRET,
      KURIER_API_KEY: "",
      PORT: String(PORT),
      HOST: "127.0.0.1",
      USED_PROOFS_PATH: STORE_PATH,
      NODE_ENV: "test",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let serverLog = "";
  server.stdout?.on("data", (d: Buffer) => { serverLog += d.toString(); });
  server.stderr?.on("data", (d: Buffer) => { serverLog += d.toString(); });

  try {
    if (!(await waitReady(server))) {
      console.log("FAIL  server did not become ready");
      console.log(serverLog.slice(-2000));
      server.kill("SIGTERM");
      process.exit(1);
    }
    console.log("server ready");

    // 1. Preflight
    console.log("case: preflight");
    {
      const req = freshTimestamps(loadFixture("preflight.json"));
      const res = await postWithSigHeader(Buffer.from(JSON.stringify(req)), TEST_SECRET);
      check("preflight status 200", res.status === 200, `got ${res.status}`);
      check("preflight body", res.body.ok === true && res.body.protocolVersion === "v1", JSON.stringify(res.body));
      check("preflight response signed", checkResponseSignature(res, TEST_SECRET));
    }

    // 2. Valid task -> APPROVE with a locally-verifiable proof
    console.log("case: valid task");
    {
      const req = freshTimestamps(loadFixture("valid-task.json"));
      const res = await postWithSigHeader(Buffer.from(JSON.stringify(req)), TEST_SECRET);
      check("valid status 200", res.status === 200, `got ${res.status}`);
      check("valid decision APPROVE", res.body.decision === "APPROVE", JSON.stringify(res.body).slice(0, 200));
      check("valid reason OK", res.body.reason_code === "OK");
      check("valid response signed", checkResponseSignature(res, TEST_SECRET));
      const proof = res.body.proof as unknown;
      const signals = res.body.public_signals as string[] | undefined;
      check("valid proof present", proof !== undefined && Array.isArray(signals) && signals.length === 13);
      if (proof && signals) {
        check("valid publicSignals[11] == 1 (approve)", signals[11] === "1", `got ${signals[11]}`);
        const verified = await snarkjs.groth16.verify(vk, signals, proof);
        check("valid proof verifies locally", verified === true);
      }
      check("valid proof_tx echoed", res.body.proof_tx === (req.input as Record<string, unknown>).proof_tx);
    }

    // 3. Trap task (VK substitution) -> REJECT with a decision=0 proof
    console.log("case: trap task (VK substitution)");
    {
      const req = freshTimestamps(loadFixture("trap-task.json"));
      const res = await postWithSigHeader(Buffer.from(JSON.stringify(req)), TEST_SECRET);
      check("trap status 200", res.status === 200, `got ${res.status}`);
      check("trap decision REJECT", res.body.decision === "REJECT", JSON.stringify(res.body).slice(0, 200));
      check("trap reason VK_SUBSTITUTION", res.body.reason_code === "VK_SUBSTITUTION");
      check("trap response signed", checkResponseSignature(res, TEST_SECRET));
      const proof = res.body.proof as unknown;
      const signals = res.body.public_signals as string[] | undefined;
      check("trap proof present", proof !== undefined && Array.isArray(signals) && signals.length === 13);
      if (proof && signals) {
        check("trap publicSignals[11] == 0 (reject)", signals[11] === "0", `got ${signals[11]}`);
        const verified = await snarkjs.groth16.verify(vk, signals, proof);
        check("trap proof verifies locally", verified === true);
      }
    }

    // 4. Bad HMAC -> 401
    console.log("case: bad HMAC");
    {
      const req = freshTimestamps(loadFixture("valid-task.json"));
      const res = await postWithSigHeader(
        Buffer.from(JSON.stringify(req)),
        "00".repeat(32),
      );
      check("bad HMAC status 401", res.status === 401, `got ${res.status}`);
    }

    // 5. Missing signature -> 401
    console.log("case: missing signature");
    {
      const req = freshTimestamps(loadFixture("valid-task.json"));
      const res = await postWithSigHeader(Buffer.from(JSON.stringify(req)), null);
      check("missing signature status 401", res.status === 401, `got ${res.status}`);
    }

    // 6. Replay of the valid task (same proof_tx) -> REJECT PROOF_REUSED
    console.log("case: replay (same proof_tx)");
    {
      const req = freshTimestamps(loadFixture("valid-task.json"));
      const res = await postWithSigHeader(Buffer.from(JSON.stringify(req)), TEST_SECRET);
      check("replay status 200", res.status === 200, `got ${res.status}`);
      check("replay decision REJECT", res.body.decision === "REJECT", JSON.stringify(res.body).slice(0, 200));
      check("replay reason PROOF_REUSED", res.body.reason_code === "PROOF_REUSED");
    }

    // 7. Recipient mismatch -> REJECT RECIPIENT_MISMATCH
    console.log("case: recipient mismatch");
    {
      const req = freshTimestamps(loadFixture("valid-task.json"));
      (req.input as Record<string, unknown>).condition_recipient =
        "0x1111111111111111111111111111111111111111";
      (req.input as Record<string, unknown>).proof_tx =
        "0xc1c2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f02";
      const res = await postWithSigHeader(Buffer.from(JSON.stringify(req)), TEST_SECRET);
      check("recipient mismatch REJECT", res.body.decision === "REJECT");
      check("recipient mismatch reason", res.body.reason_code === "RECIPIENT_MISMATCH");
    }

    // 8. Expired (current_block == expiry_block) -> REJECT EXPIRED
    console.log("case: expired");
    {
      const req = freshTimestamps(loadFixture("valid-task.json"));
      (req.input as Record<string, unknown>).current_block = 8430000;
      (req.input as Record<string, unknown>).proof_tx =
        "0xd1d2d3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f03";
      const res = await postWithSigHeader(Buffer.from(JSON.stringify(req)), TEST_SECRET);
      check("expired REJECT", res.body.decision === "REJECT");
      check("expired reason", res.body.reason_code === "EXPIRED");
    }

    // 9. Amount exceeds max -> REJECT AMOUNT_EXCEEDS_MAX
    console.log("case: amount exceeds max");
    {
      const req = freshTimestamps(loadFixture("valid-task.json"));
      (req.input as Record<string, unknown>).amount = "1500";
      (req.input as Record<string, unknown>).proof_tx =
        "0xe1e2e3e4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f04";
      const res = await postWithSigHeader(Buffer.from(JSON.stringify(req)), TEST_SECRET);
      check("amount REJECT", res.body.decision === "REJECT");
      check("amount reason", res.body.reason_code === "AMOUNT_EXCEEDS_MAX");
    }

    // 10. Balance below minimum -> REJECT BALANCE_BELOW_MINIMUM
    console.log("case: balance below minimum");
    {
      const req = freshTimestamps(loadFixture("valid-task.json"));
      (req.input as Record<string, unknown>).public_balance = "500";
      (req.input as Record<string, unknown>).proof_tx =
        "0xf1f2f3f4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f05";
      const res = await postWithSigHeader(Buffer.from(JSON.stringify(req)), TEST_SECRET);
      check("balance REJECT", res.body.decision === "REJECT");
      check("balance reason", res.body.reason_code === "BALANCE_BELOW_MINIMUM");
    }

    // 11. Health endpoint
    console.log("case: health");
    {
      const res = await fetch(`${BASE}/health`);
      check("health 200", res.status === 200);
      const body = (await res.json()) as Record<string, unknown>;
      check("health body", body.ok === true);
    }
  } finally {
    server.kill("SIGTERM");
    try { fs.unlinkSync(STORE_PATH); } catch { /* ignore */ }
  }

  console.log(`\n== ${passes} passed, ${failures} failed ==`);
  if (failures > 0) {
    console.log("server log (tail):");
    console.log(serverLog.slice(-3000));
  }
  // Explicit exit: tsx keeps an esbuild service alive that would otherwise
  // hold the process open after main() returns.
  process.exit(failures > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error("harness crashed", err);
  process.exitCode = 1;
});
