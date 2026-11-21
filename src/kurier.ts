// Kurier REST client (zkVerify proof verification via Horizen Labs' Kurier).
//
// Endpoints (zkVerify docs, https://docs.zkverify.io/overview/getting-started/kurier):
//   POST {base}/submit-proof/{apiKey}
//     body: { proofType: "groth16", vkRegistered: true,
//             proofOptions: { library: "snarkjs", curve: "bn128" },
//             proofData: { proof, publicSignals, vk: <registered vkHash> } }
//     -> { jobId, optimisticVerify }
//   GET  {base}/job-status/{apiKey}/{jobId}
//     -> { status: "Queued" | "Valid" | "Submitted" | "IncludedInBlock"
//                   | "Finalized" | "Failed", ... }
// Poll every 5s (Kurier docs) until Finalized / Failed / timeout.
// The gatekeeper VK is ALREADY registered by the platform, so this client
// never calls register-vk; it submits with vkRegistered: true and the
// registered vkHash from /api/circuit-info.
import { config } from "./config.js";
import type { Groth16Proof } from "./envelope.js";
import { logger } from "./logger.js";

export type KurierStatus =
  | "Queued"
  | "Valid"
  | "Submitted"
  | "IncludedInBlock"
  | "Finalized"
  | "Failed"
  | string;

export interface KurierSubmitResult {
  jobId: string;
  optimisticVerify?: string;
}

export interface KurierJobResult {
  status: KurierStatus;
  /** On-chain tx reference when the job exposes one (field name varies). */
  txHash?: string;
  raw: unknown;
}

export class KurierError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KurierError";
  }
}

function baseUrl(): string {
  return config.kurierBaseUrl.replace(/\/$/, "");
}

async function fetchJson(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<unknown> {
  const res = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
  const text = await res.text();
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    throw new KurierError(`Kurier returned non-JSON (HTTP ${res.status})`);
  }
  if (!res.ok) {
    throw new KurierError(`Kurier HTTP ${res.status}: ${text.slice(0, 300)}`);
  }
  return data;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Submit a Groth16 proof for verification. Returns the job id. */
export async function submitProof(
  proof: Groth16Proof,
  publicSignals: string[],
  vkHash: string,
): Promise<KurierSubmitResult> {
  if (!config.kurierApiKey) throw new KurierError("KURIER_API_KEY is not set");
  const url = `${baseUrl()}/submit-proof/${config.kurierApiKey}`;
  const data = await fetchJson(
    url,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: vkHash },
      }),
    },
    15000,
  );
  if (!isRecord(data) || typeof data.jobId !== "string" || data.jobId === "") {
    throw new KurierError("Kurier submit-proof response has no jobId");
  }
  const optimisticVerify =
    typeof data.optimisticVerify === "string" ? data.optimisticVerify : undefined;
  if (optimisticVerify !== undefined && optimisticVerify !== "success") {
    throw new KurierError(`Kurier optimistic verification failed: ${optimisticVerify}`);
  }
  return { jobId: data.jobId, optimisticVerify };
}

/** Fetch the current status of a Kurier job. */
export async function getJobStatus(jobId: string): Promise<KurierJobResult> {
  if (!config.kurierApiKey) throw new KurierError("KURIER_API_KEY is not set");
  const url = `${baseUrl()}/job-status/${config.kurierApiKey}/${jobId}`;
  const data = await fetchJson(url, { method: "GET" }, 15000);
  if (!isRecord(data) || typeof data.status !== "string") {
    throw new KurierError("Kurier job-status response has no status");
  }
  const txHash =
    (typeof data.txHash === "string" && data.txHash) ||
    (typeof data.transactionHash === "string" && data.transactionHash) ||
    (typeof data.tx === "string" && data.tx) ||
    undefined;
  return { status: data.status, txHash, raw: data };
}

export interface FinalizeOutcome {
  finalized: boolean;
  jobId: string;
  status: KurierStatus;
  txHash?: string;
}

/**
 * Submit a proof and poll until it is Finalized, Failed, or the timeout
 * expires. Never throws for a timeout — it returns finalized: false so the
 * caller can fail closed. Throws only for transport/submission errors.
 */
export async function submitAndWaitForFinalized(
  proof: Groth16Proof,
  publicSignals: string[],
  vkHash: string,
  timeoutMs: number,
): Promise<FinalizeOutcome> {
  const { jobId } = await submitProof(proof, publicSignals, vkHash);
  logger.info("kurier job submitted", { jobId });
  const deadline = Date.now() + timeoutMs;
  let lastStatus: KurierStatus = "Submitted";
  let lastTx: string | undefined;
  while (Date.now() < deadline) {
    const job = await getJobStatus(jobId);
    lastStatus = job.status;
    lastTx = job.txHash ?? lastTx;
    if (job.status === "Finalized") {
      return { finalized: true, jobId, status: job.status, txHash: job.txHash };
    }
    if (job.status === "Failed") {
      return { finalized: false, jobId, status: job.status, txHash: job.txHash };
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    await new Promise((r) => setTimeout(r, Math.min(config.kurierPollIntervalMs, remaining)));
  }
  return { finalized: false, jobId, status: lastStatus, txHash: lastTx };
}
