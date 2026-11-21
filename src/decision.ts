// Deterministic decision logic — the final safety rules, in code.
// NO language model makes the final call. APPROVE only when EVERY check passes;
// any failure, timeout, or uncertainty yields REJECT (fail closed).
//
// The gatekeeper circuit enforces the same evaluation: it asserts
//   decision == (proofVk == registeredVk
//                 && publicBalance >= minimum
//                 && currentBlock < expiryBlock
//                 && recipient == conditionRecipient
//                 && amount <= maxTransfer)
// so a proof generated with a decision that contradicts the inputs cannot be
// created at all (witness generation fails). The checks below mirror that
// evaluation and add the platform-side checks the circuit cannot see:
// the registered key must be the real gatekeeper vkHash, the proof reference
// must be fresh, and the task must be inside its validity window.
import { config } from "./config.js";
import type { TaskEnvelope } from "./envelope.js";

export type CheckName =
  | "registered_vk_is_gatekeeper"
  | "proof_vk_matches_registered"
  | "recipient_matches_condition"
  | "balance_meets_minimum"
  | "not_expired"
  | "amount_within_max"
  | "proof_reference_fresh"
  | "task_window_valid";

export interface CheckResult {
  name: CheckName;
  pass: boolean;
  /** reason_code to report when this check fails. */
  reasonCode: string;
  detail: string;
}

export interface Evaluation {
  /** 1 = approve, 0 = reject — the value fed to the circuit. */
  decisionValue: 0 | 1;
  decision: "APPROVE" | "REJECT";
  reasonCode: string;
  checks: CheckResult[];
}

export interface EvaluationContext {
  /** Returns true when the task's proof reference was already used. */
  isReferenceUsed: (referenceKey: string) => boolean;
  /** Reference key for this task (proof_tx, else task_id). */
  referenceKey: string;
  /** "now" for timestamp checks (injectable for tests). */
  now?: Date;
}

function fail(name: CheckName, reasonCode: string, detail: string): CheckResult {
  return { name, pass: false, reasonCode, detail };
}
function ok(name: CheckName, detail: string): CheckResult {
  return { name, pass: true, reasonCode: "OK", detail };
}

export function evaluateTask(
  envelope: TaskEnvelope,
  ctx: EvaluationContext,
): Evaluation {
  const input = envelope.input;
  const now = ctx.now ?? new Date();
  const checks: CheckResult[] = [];

  // 1. The registered key must be the real gatekeeper vkHash. A task that
  //    names any other "registered" key is a substitution trap: even if
  //    proof_vk equals it, the platform re-verifies against ITS OWN key.
  if (input.registered_vk.toLowerCase() !== config.expectedVkHash) {
    checks.push(
      fail(
        "registered_vk_is_gatekeeper",
        "VK_SUBSTITUTION",
        `registered_vk ${input.registered_vk} is not the registered gatekeeper vkHash`,
      ),
    );
  } else {
    checks.push(ok("registered_vk_is_gatekeeper", "registered_vk is the gatekeeper vkHash"));
  }

  // 2. The presented proof's key must match the registered key.
  if (input.proof_vk.toLowerCase() !== input.registered_vk.toLowerCase()) {
    checks.push(
      fail(
        "proof_vk_matches_registered",
        "VK_SUBSTITUTION",
        `proof_vk ${input.proof_vk} != registered_vk ${input.registered_vk}`,
      ),
    );
  } else {
    checks.push(ok("proof_vk_matches_registered", "proof_vk matches registered_vk"));
  }

  // 3. The transfer recipient must be the condition's recipient.
  if (input.recipient !== input.condition_recipient) {
    checks.push(
      fail(
        "recipient_matches_condition",
        "RECIPIENT_MISMATCH",
        `recipient ${input.recipient} != condition_recipient ${input.condition_recipient}`,
      ),
    );
  } else {
    checks.push(ok("recipient_matches_condition", "recipient matches condition_recipient"));
  }

  // 4. The public balance must meet the required minimum.
  if (BigInt(input.public_balance) < BigInt(input.minimum)) {
    checks.push(
      fail(
        "balance_meets_minimum",
        "BALANCE_BELOW_MINIMUM",
        `public_balance ${input.public_balance} < minimum ${input.minimum}`,
      ),
    );
  } else {
    checks.push(
      ok(
        "balance_meets_minimum",
        `public_balance ${input.public_balance} >= minimum ${input.minimum}`,
      ),
    );
  }

  // 5. The condition must not be expired: current_block < expiry_block.
  //    At equality the window is already closed (verified against the circuit).
  if (input.current_block >= input.expiry_block) {
    checks.push(
      fail(
        "not_expired",
        "EXPIRED",
        `current_block ${input.current_block} >= expiry_block ${input.expiry_block}`,
      ),
    );
  } else {
    checks.push(
      ok("not_expired", `current_block ${input.current_block} < expiry_block ${input.expiry_block}`),
    );
  }

  // 6. The amount must not exceed the maximum transfer.
  if (BigInt(input.amount) > BigInt(input.max_transfer)) {
    checks.push(
      fail(
        "amount_within_max",
        "AMOUNT_EXCEEDS_MAX",
        `amount ${input.amount} > max_transfer ${input.max_transfer}`,
      ),
    );
  } else {
    checks.push(
      ok("amount_within_max", `amount ${input.amount} <= max_transfer ${input.max_transfer}`),
    );
  }

  // 7. The proof reference must not have been used for another task.
  if (ctx.isReferenceUsed(ctx.referenceKey)) {
    checks.push(
      fail(
        "proof_reference_fresh",
        "PROOF_REUSED",
        `proof reference ${ctx.referenceKey} was already used`,
      ),
    );
  } else {
    checks.push(ok("proof_reference_fresh", "proof reference not seen before"));
  }

  // 8. The task must be inside its validity window (issued_at <= now <= deadline_at,
  //    with a small clock-skew tolerance). A task whose deadline already passed
  //    is rejected even if everything else looks fine.
  const issuedAt = Date.parse(envelope.issued_at);
  const deadlineAt = Date.parse(envelope.deadline_at);
  const nowMs = now.getTime();
  if (nowMs > deadlineAt) {
    checks.push(
      fail("task_window_valid", "TASK_EXPIRED", `now is past deadline_at ${envelope.deadline_at}`),
    );
  } else if (nowMs < issuedAt - config.clockSkewMs) {
    checks.push(
      fail(
        "task_window_valid",
        "TASK_NOT_YET_VALID",
        `now is before issued_at ${envelope.issued_at}`,
      ),
    );
  } else {
    checks.push(ok("task_window_valid", "now is inside [issued_at, deadline_at]"));
  }

  const failed = checks.find((c) => !c.pass);
  if (failed) {
    return {
      decisionValue: 0,
      decision: "REJECT",
      reasonCode: failed.reasonCode,
      checks,
    };
  }
  return { decisionValue: 1, decision: "APPROVE", reasonCode: "OK", checks };
}
