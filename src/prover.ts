// Local Groth16 proof generation + verification with snarkjs.
//
// Circuit facts (verified empirically against the shipped artifacts — see
// README.md "Circuit signal map"):
//   * 13 input signals: minimum, publicBalance, expiryBlock, currentBlock,
//     recipient, conditionRecipient, amount, maxTransfer, taskId, decision,
//     registeredVkHash, proofVkHash, salt.
//   * 13 public signals, in order:
//       [0]  statement/task commitment (opaque; depends on taskId + salt)
//       [1]  registeredVkHash (vk hash mod FIELD_PRIME)
//       [2]  proofVkHash (vk hash mod FIELD_PRIME)
//       [3]  minimum            [4]  publicBalance
//       [5]  expiryBlock        [6]  currentBlock
//       [7]  recipient          [8]  conditionRecipient
//       [9]  amount             [10] maxTransfer
//       [11] decision (1 = approve, 0 = reject)
//       [12] taskId (encoded field element)
//   * `salt` is a PRIVATE input (blinding): it never appears in public signals.
//   * The circuit asserts decision == evaluation, so a proof can only be
//     generated for the decision the inputs actually justify.
import crypto from "node:crypto";
import * as snarkjs from "snarkjs";
import { config } from "./config.js";
import {
  addressToField,
  encodeTaskId,
  hashToField,
  type Groth16Proof,
  type TaskEnvelope,
} from "./envelope.js";
import { logger } from "./logger.js";

export const PUBLIC_SIGNAL_INDEX = {
  commitment: 0,
  registeredVkHash: 1,
  proofVkHash: 2,
  minimum: 3,
  publicBalance: 4,
  expiryBlock: 5,
  currentBlock: 6,
  recipient: 7,
  conditionRecipient: 8,
  amount: 9,
  maxTransfer: 10,
  decision: 11,
  taskId: 12,
} as const;

/** The 13 circuit inputs, as decimal strings (snarkjs accepts these). */
export interface CircuitInput {
  minimum: string;
  publicBalance: string;
  expiryBlock: string;
  currentBlock: string;
  recipient: string;
  conditionRecipient: string;
  amount: string;
  maxTransfer: string;
  taskId: string;
  decision: string;
  registeredVkHash: string;
  proofVkHash: string;
  salt: string;
}

export function buildCircuitInput(
  envelope: TaskEnvelope,
  decisionValue: 0 | 1,
  salt: string,
): CircuitInput {
  const i = envelope.input;
  return {
    minimum: i.minimum,
    publicBalance: i.public_balance,
    expiryBlock: String(i.expiry_block),
    currentBlock: String(i.current_block),
    recipient: addressToField(i.recipient),
    conditionRecipient: addressToField(i.condition_recipient),
    amount: i.amount,
    maxTransfer: i.max_transfer,
    taskId: encodeTaskId(envelope.task_id),
    decision: String(decisionValue),
    registeredVkHash: hashToField(i.registered_vk),
    proofVkHash: hashToField(i.proof_vk),
    salt,
  };
}

/** Fresh random 128-bit salt per proof (private blinding input). */
export function randomSalt(): string {
  return BigInt("0x" + crypto.randomBytes(16).toString("hex")).toString();
}

// Proof generation is CPU-bound; serialize it so concurrent requests do not
// thrash the process. A simple promise-chain mutex.
let proofQueue: Promise<void> = Promise.resolve();

function withProofSlot<T>(fn: () => Promise<T>): Promise<T> {
  const run = proofQueue.then(fn);
  // Keep the chain alive even if this run rejects.
  proofQueue = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

let cachedVk: unknown | null = null;

export async function loadVerificationKey(): Promise<unknown> {
  if (cachedVk) return cachedVk;
  cachedVk = await snarkjs.zKey.exportVerificationKey(config.zkeyPath);
  return cachedVk;
}

/** Generate a Groth16 proof for the given circuit input. */
export async function generateProof(
  input: CircuitInput,
): Promise<{ proof: Groth16Proof; publicSignals: string[] }> {
  return withProofSlot(async () => {
    const started = Date.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input as unknown as Record<string, unknown>,
      config.wasmPath,
      config.zkeyPath,
    );
    logger.info("proof generated", { ms: Date.now() - started });
    return {
      proof: proof as unknown as Groth16Proof,
      publicSignals: publicSignals as string[],
    };
  });
}

/** Verify a proof locally against the exported verification key. */
export async function verifyProofLocally(
  proof: Groth16Proof,
  publicSignals: string[],
): Promise<boolean> {
  const vk = await loadVerificationKey();
  return snarkjs.groth16.verify(
    vk,
    publicSignals,
    proof as unknown as Parameters<typeof snarkjs.groth16.verify>[2],
  );
}
