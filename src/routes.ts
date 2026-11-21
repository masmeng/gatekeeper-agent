// Request handling for POST /agent (Proof Gatekeeper + preflight).
//
// Order of operations (per the spec):
//   1. Verify the HMAC signature over the RAW body — BEFORE parsing JSON.
//   2. Parse JSON and route by `type` (preflight vs. proof-gatekeeper task).
//   3. Run the deterministic decision checks (fail closed).
//   4. Generate a local Groth16 proof for the decided value and verify it
//      locally. A proof that cannot be generated/verified => REJECT.
//   5. Submit to Kurier and (when configured) wait for Finalized within the
//      remaining time budget. Not finalized in time => REJECT (fail closed).
//   6. Record the proof reference, return the signed decision.
//
// This module is transport-agnostic: it returns { status, body } and never
// touches the socket. Signing + the hard deadline race live in index.ts.
import { config } from "./config.js";
import { evaluateTask } from "./decision.js";
import {
  parsePreflight,
  parseTaskEnvelope,
  referenceKey,
  type AgentResponse,
  type Groth16Proof,
  type TaskEnvelope,
} from "./envelope.js";
import { verifyHmacSha256Hex } from "./hmac.js";
import { submitAndWaitForFinalized, KurierError } from "./kurier.js";
import { logger } from "./logger.js";
import {
  buildCircuitInput,
  generateProof,
  randomSalt,
  verifyProofLocally,
} from "./prover.js";
import type { UsedProofStore } from "./store.js";

export interface RouteContext {
  store: UsedProofStore;
  /** Absolute deadline (ms since epoch) for this request. */
  deadlineMs: number;
  /** Injectable clock (tests). */
  now?: Date;
}

export interface RouteResult {
  status: number;
  body: Record<string, unknown>;
}

function remainingMs(ctx: RouteContext): number {
  return ctx.deadlineMs - Date.now();
}

function timeoutResult(reasonCode: string): RouteResult {
  return {
    status: 200,
    body: { decision: "REJECT", reason_code: reasonCode } satisfies AgentResponse,
  };
}

/**
 * Generate a proof for the decided value and verify it locally.
 * Returns null when no proof could be produced (fail-closed callers treat
 * this as "respond without a proof", or reject outright for APPROVE).
 */
async function tryProve(
  envelope: TaskEnvelope,
  decisionValue: 0 | 1,
  ctx: RouteContext,
): Promise<{ proof: Groth16Proof; publicSignals: string[] } | null> {
  if (remainingMs(ctx) < 15000) {
    logger.warn("skipping proof generation: deadline too close", {
      taskId: envelope.task_id,
      remainingMs: remainingMs(ctx),
    });
    return null;
  }
  try {
    const input = buildCircuitInput(envelope, decisionValue, randomSalt());
    const { proof, publicSignals } = await generateProof(input);
    const valid = await verifyProofLocally(proof, publicSignals);
    if (!valid) {
      logger.error("local proof verification failed", { taskId: envelope.task_id });
      return null;
    }
    return { proof, publicSignals };
  } catch (err) {
    // The circuit refuses to prove a decision its inputs do not justify
    // (witness assert) — e.g. a REJECT whose on-chain conditions all pass
    // but which we reject for a platform-side rule (replay, expiry window).
    // That is expected for some REJECTs; the decision itself stands.
    logger.warn("proof generation failed", {
      taskId: envelope.task_id,
      decision: decisionValue,
      error: err instanceof Error ? err.message.split("\n")[0] : String(err),
    });
    return null;
  }
}

export async function handleAgent(
  rawBody: Buffer,
  headers: Record<string, string | string[] | undefined>,
  ctx: RouteContext,
): Promise<RouteResult> {
  // 1. HMAC over the raw body, BEFORE parsing.
  const signature = headers["x-agent-games-signature"];
  if (!verifyHmacSha256Hex(config.hmacSecret, rawBody, signature)) {
    return { status: 401, body: { error: "invalid_signature" } };
  }

  // 2. Parse JSON.
  let body: unknown;
  try {
    body = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return { status: 400, body: { error: "invalid_json" } };
  }

  // 2a. Preflight handshake.
  const preflight = parsePreflight(body);
  if (preflight) {
    logger.info("preflight", { agentId: preflight.agent_id ?? "unknown" });
    return { status: 200, body: { ok: true, protocolVersion: "v1" } };
  }

  // 2b. Task envelope.
  const parsed = parseTaskEnvelope(body);
  if (!parsed.ok) {
    return {
      status: 400,
      body: { error: "invalid_envelope", reason_code: parsed.reason },
    };
  }
  const envelope = parsed.envelope;
  const refKey = referenceKey(envelope);
  const logCtx = { taskId: envelope.task_id, mode: envelope.mode };

  // 3. Deterministic decision.
  const evaluation = evaluateTask(envelope, {
    isReferenceUsed: (k) => ctx.store.has(k),
    referenceKey: refKey,
    now: ctx.now,
  });
  logger.info("decision evaluated", {
    ...logCtx,
    decision: evaluation.decision,
    reasonCode: evaluation.reasonCode,
    failedChecks: evaluation.checks.filter((c) => !c.pass).map((c) => c.name),
  });

  // 4. Prove the decision (both APPROVE and REJECT are provable tasks).
  const proved = await tryProve(envelope, evaluation.decisionValue, ctx);

  if (evaluation.decision === "REJECT") {
    ctx.store.add({
      referenceKey: refKey,
      taskId: envelope.task_id,
      decision: "REJECT",
      reasonCode: evaluation.reasonCode,
      firstSeenAt: new Date().toISOString(),
    });
    const response: AgentResponse = {
      decision: "REJECT",
      reason_code: evaluation.reasonCode,
      ...(proved ? { proof: proved.proof, public_signals: proved.publicSignals } : {}),
      ...(envelope.input.proof_tx ? { proof_tx: envelope.input.proof_tx } : {}),
    };
    return { status: 200, body: response as unknown as Record<string, unknown> };
  }

  // APPROVE path — fail closed at every step from here on.
  if (!proved) {
    ctx.store.add({
      referenceKey: refKey,
      taskId: envelope.task_id,
      decision: "REJECT",
      reasonCode: "PROOF_GENERATION_FAILED",
      firstSeenAt: new Date().toISOString(),
    });
    return timeoutResult("PROOF_GENERATION_FAILED");
  }

  // 5. Kurier submission + finalization.
  let kurierTx: string | undefined;
  if (config.kurierApiKey) {
    const budget = Math.min(
      config.kurierFinalizeTimeoutMs,
      Math.max(0, remainingMs(ctx) - config.responseMarginMs),
    );
    if (budget <= 0) {
      logger.warn("no time budget left for Kurier finalization", logCtx);
      if (config.requireKurierFinalized) {
        return timeoutResult("VERIFICATION_NOT_FINALIZED");
      }
    } else {
      try {
        const outcome = await submitAndWaitForFinalized(
          proved.proof,
          proved.publicSignals,
          config.expectedVkHash,
          budget,
        );
        kurierTx = outcome.txHash;
        logger.info("kurier outcome", {
          ...logCtx,
          jobId: outcome.jobId,
          status: outcome.status,
          finalized: outcome.finalized,
        });
        if (config.requireKurierFinalized && !outcome.finalized) {
          ctx.store.add({
            referenceKey: refKey,
            taskId: envelope.task_id,
            decision: "REJECT",
            reasonCode: "VERIFICATION_NOT_FINALIZED",
            firstSeenAt: new Date().toISOString(),
          });
          return timeoutResult("VERIFICATION_NOT_FINALIZED");
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        logger.error("kurier submission failed", { ...logCtx, error: msg });
        if (err instanceof KurierError && config.requireKurierFinalized) {
          return timeoutResult("KURIER_ERROR");
        }
        // Kurier not required: proceed with the locally-verified proof.
        logger.warn("proceeding with locally-verified proof only", logCtx);
      }
    }
  } else {
    logger.warn(
      "KURIER_API_KEY is not set: returning the locally-verified proof without " +
        "on-chain finalization. Set KURIER_API_KEY to enable Kurier.",
      logCtx,
    );
  }

  ctx.store.add({
    referenceKey: refKey,
    taskId: envelope.task_id,
    decision: "APPROVE",
    reasonCode: "OK",
    firstSeenAt: new Date().toISOString(),
  });
  const response: AgentResponse = {
    decision: "APPROVE",
    reason_code: "OK",
    proof: proved.proof,
    public_signals: proved.publicSignals,
    ...(envelope.input.proof_tx || kurierTx
      ? { proof_tx: envelope.input.proof_tx ?? kurierTx }
      : {}),
  };
  return { status: 200, body: response as unknown as Record<string, unknown> };
}
