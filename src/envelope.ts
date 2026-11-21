// Task envelope types, validation, and field encodings.
//
// Authoritative shapes (https://agentgames.zkverify.io/build):
//   Inbound task:
//     { "type": "agent-games.proof-gatekeeper.v1", "task_id": "gk_8d31_...",
//       "mode": "competition", "issued_at": "<iso>", "deadline_at": "<iso>",
//       "input": { "registered_vk": "0x...", "proof_vk": "0x...",
//                  "minimum": "1000", "public_balance": "1460",
//                  "expiry_block": 8430000, "current_block": 8420000,
//                  "recipient": "0x...", "condition_recipient": "0x...",
//                  "amount": "500", "max_transfer": "1000",
//                  "proof_tx": "0x..." } }
//   Preflight request:
//     { "type": "agent-games.preflight.v1", "agent_id": "agt_...",
//       "issued_at": "<iso>", "nonce": "abc123" }
//   Agent response:
//     { "decision": "APPROVE" | "REJECT", "reason_code": "...",
//       "proof": { pi_a, pi_b, pi_c, protocol, curve },
//       "public_signals": ["...", ...], "proof_tx": "0x..." }
//
// NOTE on the task signature: the envelope carries no separate signature field.
// The platform authenticates the task with the HMAC signature header
// (x-agent-games-signature) over the raw body — that IS the task signature
// the Security checklist refers to, and it is verified before parsing.
import { createRequire } from "node:module";
import { FIELD_PRIME, TASK_ID_ENCODING } from "./config.js";

// js-sha3 ships a CJS build; its ESM wrapper only exposes a default object,
// so load it via createRequire to get the named keccak_256 export reliably.
const require = createRequire(import.meta.url);
const { keccak_256 } = require("js-sha3") as {
  keccak_256: (msg: string) => string;
};

export const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
export const PREFLIGHT_TYPE = "agent-games.preflight.v1";

export interface TaskInput {
  registered_vk: string;
  proof_vk: string;
  minimum: string;
  public_balance: string;
  expiry_block: number;
  current_block: number;
  recipient: string;
  condition_recipient: string;
  amount: string;
  max_transfer: string;
  /** Optional on-chain audit pointer for the presented proof. */
  proof_tx?: string;
}

export interface TaskEnvelope {
  type: string;
  task_id: string;
  mode: string;
  issued_at: string;
  deadline_at: string;
  input: TaskInput;
}

export interface PreflightRequest {
  type: string;
  agent_id?: string;
  issued_at?: string;
  nonce?: string;
}

export type Decision = "APPROVE" | "REJECT";

/** Groth16 proof object exactly as snarkjs returns it. */
export interface Groth16Proof {
  pi_a: [string, string, string];
  pi_b: [[string, string], [string, string], [string, string]];
  pi_c: [string, string, string];
  protocol: string;
  curve: string;
}

export interface AgentResponse {
  decision: Decision;
  reason_code: string;
  proof?: Groth16Proof;
  public_signals?: string[];
  proof_tx?: string;
}

export type EnvelopeParseResult =
  | { ok: true; envelope: TaskEnvelope }
  | { ok: false; reason: string };

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function asDecimalString(v: unknown, field: string): string | null {
  if (typeof v === "number" && Number.isInteger(v) && v >= 0) return String(v);
  if (typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v.trim())) return v.trim();
  return null;
}

function asBlockNumber(v: unknown, field: string): number | null {
  if (typeof v === "number" && Number.isInteger(v) && v >= 0) return v;
  if (typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v.trim())) {
    const n = Number(v.trim());
    return Number.isSafeInteger(n) ? n : null;
  }
  return null;
}

function asAddress(v: unknown, field: string): string | null {
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(s)) return null;
  return s.toLowerCase();
}

function asHexHash(v: unknown, field: string): string | null {
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (!/^0x[0-9a-fA-F]+$/.test(s)) return null;
  return s.toLowerCase();
}

/** Validate + normalize a parsed JSON body into a TaskEnvelope. */
export function parseTaskEnvelope(body: unknown): EnvelopeParseResult {
  if (!isRecord(body)) return { ok: false, reason: "INVALID_ENVELOPE" };
  if (body.type !== TASK_TYPE) return { ok: false, reason: "INVALID_ENVELOPE" };
  if (typeof body.task_id !== "string" || body.task_id.trim() === "") {
    return { ok: false, reason: "INVALID_ENVELOPE" };
  }
  if (body.mode !== "competition" && body.mode !== "practice") {
    return { ok: false, reason: "INVALID_ENVELOPE" };
  }
  if (typeof body.issued_at !== "string" || Number.isNaN(Date.parse(body.issued_at))) {
    return { ok: false, reason: "INVALID_ENVELOPE" };
  }
  if (typeof body.deadline_at !== "string" || Number.isNaN(Date.parse(body.deadline_at))) {
    return { ok: false, reason: "INVALID_ENVELOPE" };
  }
  if (!isRecord(body.input)) return { ok: false, reason: "INVALID_ENVELOPE" };
  const i = body.input;

  const registered_vk = asHexHash(i.registered_vk, "registered_vk");
  const proof_vk = asHexHash(i.proof_vk, "proof_vk");
  const minimum = asDecimalString(i.minimum, "minimum");
  const public_balance = asDecimalString(i.public_balance, "public_balance");
  const expiry_block = asBlockNumber(i.expiry_block, "expiry_block");
  const current_block = asBlockNumber(i.current_block, "current_block");
  const recipient = asAddress(i.recipient, "recipient");
  const condition_recipient = asAddress(i.condition_recipient, "condition_recipient");
  const amount = asDecimalString(i.amount, "amount");
  const max_transfer = asDecimalString(i.max_transfer, "max_transfer");
  if (
    !registered_vk || !proof_vk || minimum === null || public_balance === null ||
    expiry_block === null || current_block === null || !recipient ||
    !condition_recipient || amount === null || max_transfer === null
  ) {
    return { ok: false, reason: "INVALID_ENVELOPE" };
  }
  let proof_tx: string | undefined;
  if (i.proof_tx !== undefined && i.proof_tx !== null && i.proof_tx !== "") {
    proof_tx = asHexHash(i.proof_tx, "proof_tx") ?? undefined;
    if (proof_tx === undefined) return { ok: false, reason: "INVALID_ENVELOPE" };
  }
  return {
    ok: true,
    envelope: {
      type: TASK_TYPE,
      task_id: (body.task_id as string).trim(),
      mode: body.mode as string,
      issued_at: body.issued_at as string,
      deadline_at: body.deadline_at as string,
      input: {
        registered_vk, proof_vk, minimum, public_balance, expiry_block,
        current_block, recipient, condition_recipient, amount, max_transfer,
        ...(proof_tx ? { proof_tx } : {}),
      },
    },
  };
}

/** Detect a preflight request (checked after HMAC verification). */
export function parsePreflight(body: unknown): PreflightRequest | null {
  if (!isRecord(body) || body.type !== PREFLIGHT_TYPE) return null;
  return {
    type: PREFLIGHT_TYPE,
    agent_id: typeof body.agent_id === "string" ? body.agent_id : undefined,
    issued_at: typeof body.issued_at === "string" ? body.issued_at : undefined,
    nonce: typeof body.nonce === "string" ? body.nonce : undefined,
  };
}

/** Ethereum address (0x + 40 hex) -> BN128 field element, decimal string. */
export function addressToField(address: string): string {
  return BigInt(address).toString();
}

/** 0x hash (e.g. a vk hash) -> BN128 field element, decimal string (mod p). */
export function hashToField(hex: string): string {
  return (BigInt(hex) % FIELD_PRIME).toString();
}

/**
 * Encode the platform `task_id` string into the single field element the
 * gatekeeper circuit expects for `taskId`.
 * ASSUMPTION A1: keccak256(task_id) mod FIELD_PRIME. See config.ts.
 */
export function encodeTaskId(taskId: string): string {
  if (TASK_ID_ENCODING !== "keccak256-mod-p") {
    throw new Error(`Unsupported TASK_ID_ENCODING: ${TASK_ID_ENCODING}`);
  }
  const digestHex = keccak_256(taskId);
  return (BigInt("0x" + digestHex) % FIELD_PRIME).toString();
}

/** The replay-protection reference for a task: proof_tx if present, else task_id. */
export function referenceKey(envelope: TaskEnvelope): string {
  return envelope.input.proof_tx ?? `task:${envelope.task_id}`;
}
