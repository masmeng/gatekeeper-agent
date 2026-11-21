# Proof Gatekeeper Agent — zkVerify Agent Games

A production-ready TypeScript (Node.js) HTTP service that plays **Proof
Gatekeeper**: it receives signed task envelopes, deterministically decides
APPROVE / REJECT, generates a local Groth16 proof with snarkjs, optionally
finalizes it through Kurier, and returns a signed decision. No language model
makes the final call — the safety rules are deterministic code, and the
circuit itself refuses to prove a decision its inputs do not justify.

> **Status: local build + verification only.** The agent is NOT registered or
> live. To enter the competition you must deploy it to a public HTTPS URL,
> register that endpoint on the dashboard, rotate the secret, and pass
> preflight (see "Deploy & register" below).

## How it works

```
platform POST /agent ──► HMAC verify (raw body, timing-safe)
                    ──► parse envelope (preflight vs. task)
                    ──► deterministic checks (fail closed)
                    ──► snarkjs Groth16 proof (decision 0/1)
                    ──► local verify against exported VK
                    ──► Kurier submit + poll to Finalized (if key set)
                    ──► record proof reference (replay protection)
                    ──► 200 { decision, reason_code, proof,
                             public_signals, proof_tx } + signature
```

- **60 s hard deadline** per request (the platform enforces it). The whole
  pipeline — proof generation is ~0.4 s for this circuit — fits comfortably.
  On any timeout, error, or uncertainty the service answers REJECT.
- **Fail closed:** APPROVE requires every check to pass, a locally-verified
  proof, and (when Kurier is configured) a Finalized job. Anything else is a
  REJECT with a `reason_code`.
- **Replay protection:** every answered `proof_tx` (or `task_id` when no
  `proof_tx` is present) is recorded in `data/used-proofs.json`; a repeat is
  rejected as `PROOF_REUSED`.

## Circuit signal map (verified empirically)

The `/build` page does **not** publish the gatekeeper circuit's signal names.
They were recovered by probing the shipped `gatekeeper.wasm` (signals are
matched by FNV hash inside the witness calculator) and confirmed by
generating proofs and inspecting `publicSignals`. The verification key has
`nPublic = 13`, protocol `groth16`, curve `bn128`.

**13 circuit inputs** (`src/prover.ts`, `buildCircuitInput`):

| Input | Value |
|---|---|
| `minimum` | envelope `input.minimum` |
| `publicBalance` | envelope `input.public_balance` |
| `expiryBlock` | envelope `input.expiry_block` |
| `currentBlock` | envelope `input.current_block` |
| `recipient` | envelope `input.recipient` as a field element (address as BigInt) |
| `conditionRecipient` | envelope `input.condition_recipient` as a field element |
| `amount` | envelope `input.amount` |
| `maxTransfer` | envelope `input.max_transfer` |
| `taskId` | encoded field element (see Assumption A1) |
| `decision` | `1` = approve, `0` = reject |
| `registeredVkHash` | envelope `input.registered_vk` as a field element (hash mod p) |
| `proofVkHash` | envelope `input.proof_vk` as a field element (hash mod p) |
| `salt` | fresh random 128-bit value per proof (**private** input) |

**13 public signals, in order** (`src/prover.ts`, `PUBLIC_SIGNAL_INDEX`):

| # | Signal | Meaning |
|---|---|---|
| 0 | commitment | opaque statement/task commitment (changes with `taskId` + `salt`) |
| 1 | registeredVkHash | `registered_vk` mod FIELD_PRIME |
| 2 | proofVkHash | `proof_vk` mod FIELD_PRIME |
| 3 | minimum | |
| 4 | publicBalance | |
| 5 | expiryBlock | |
| 6 | currentBlock | |
| 7 | recipient | address as BigInt |
| 8 | conditionRecipient | address as BigInt |
| 9 | amount | |
| 10 | maxTransfer | |
| 11 | decision | `1` approve / `0` reject |
| 12 | taskId | encoded field element |

**Circuit semantics (proven by experiment):** the circuit asserts
`decision == (proofVk == registeredVk && publicBalance >= minimum &&
currentBlock < expiryBlock && recipient == conditionRecipient &&
amount <= maxTransfer)`. A proof for the wrong decision cannot be generated
(witness generation fails with an assert). `salt` never appears in the public
signals. Expiry is strict: `currentBlock == expiryBlock` is already expired.

## Decision checks (`src/decision.ts`)

APPROVE only when **all** of these pass; the first failure sets
`reason_code`:

| Check | Fails as |
|---|---|
| `registered_vk` equals the registered gatekeeper vkHash `0x6b79c601…77b0` | `VK_SUBSTITUTION` |
| `proof_vk` equals `registered_vk` | `VK_SUBSTITUTION` |
| `recipient` equals `condition_recipient` | `RECIPIENT_MISMATCH` |
| `public_balance >= minimum` | `BALANCE_BELOW_MINIMUM` |
| `current_block < expiry_block` | `EXPIRED` |
| `amount <= max_transfer` | `AMOUNT_EXCEEDS_MAX` |
| `proof_tx` not previously used | `PROOF_REUSED` |
| now inside `[issued_at, deadline_at]` (±2 min skew) | `TASK_EXPIRED` / `TASK_NOT_YET_VALID` |

Additional fail-closed outcomes: `PROOF_GENERATION_FAILED` (no proof could be
made for the approved decision), `VERIFICATION_NOT_FINALIZED` (Kurier did not
finalize in time), `KURIER_ERROR`, `TIMEOUT`, `INTERNAL_ERROR`. The task
signature the Security checklist refers to is the HMAC header
`x-agent-games-signature` over the raw body — the envelope carries no separate
signature field, and HMAC verification runs before any JSON parsing (401 on
mismatch).

## Assumptions (spec gaps — read before deploying)

- **A1 — `taskId` encoding.** The circuit takes `taskId` as one field element
  but the platform sends `task_id` as a string (`"gk_8d31_..."`). This service
  encodes it as **keccak256(task_id) mod FIELD_PRIME** (the standard
  EVM-compatible mapping of a string into a field element). Implemented in
  `src/envelope.ts` (`encodeTaskId`), configurable via `TASK_ID_ENCODING`.
  If the platform publishes a different encoding, change it there.
- **A2 — HMAC format.** The spec names the header (`x-agent-games-signature`)
  but not the digest encoding. This service uses **HMAC-SHA256, lowercase
  hex**; on verification it also accepts a `sha256=` prefix. Responses are
  signed the same way over the raw response body.
- **A3 — Kurier job-status endpoint.** The `/build` page shows only
  `submit-proof`. The poll endpoint `GET /job-status/{apiKey}/{jobId}` (5 s
  interval, statuses `Queued → Valid → Submitted → IncludedInBlock →
  Finalized | Failed`) comes from the official Kurier docs
  (https://docs.zkverify.io/overview/getting-started/kurier). Swagger:
  https://api.kurier.xyz/docs (mainnet), https://api-testnet.kurier.xyz/docs
  (testnet).
- **A4 — Finalized gating vs. the 60 s deadline.** When `KURIER_API_KEY` is
  set and `KURIER_REQUIRE_FINALIZED=true` (default), an APPROVE is only
  returned after the Kurier job reaches Finalized, within a bounded wait
  (`KURIER_FINALIZE_TIMEOUT_MS`, default 20 s). If it does not finalize in
  time the answer is REJECT (`VERIFICATION_NOT_FINALIZED`). When no Kurier
  key is set, the service still generates and locally verifies the proof and
  returns it, and logs that on-chain finalization is pending key setup.
- **A5 — `proof_tx` in the response** echoes the task's `proof_tx` (as in the
  spec's example). If the task has none, the Kurier finalized tx hash is used
  when available.

## Run

```bash
npm install
cp .env.example .env   # fill in AGENT_GAMES_HMAC_SECRET (required)
npm run build
npm start              # node dist/src/index.js — listens on $PORT (default 3000)
```

Development (auto-reload): `npm run dev`. Typecheck only: `npm run typecheck`.

Required env: `AGENT_GAMES_HMAC_SECRET` (dashboard → Rotate Secret; the
service refuses to start without a real, non-placeholder value). Optional:
`KURIER_API_KEY`, `KURIER_BASE_URL` (default mainnet;
`https://api-testnet.kurier.xyz/api/v1` for testnet), `KURIER_REQUIRE_FINALIZED`,
`KURIER_FINALIZE_TIMEOUT_MS`, `PORT`, `HOST`. See `.env.example`.

## Test

```bash
npm test
```

Builds the project, starts the compiled server on a test port with a
throwaway secret, and replays the fixtures in `test/fixtures/`:

- preflight → `{ ok: true, protocolVersion: "v1" }`, signed
- valid task → APPROVE + a proof that verifies locally (13 public signals,
  `publicSignals[11] == "1"`)
- trap task (VK substitution) → REJECT `VK_SUBSTITUTION` + a decision=0 proof
  that verifies locally
- bad HMAC → 401; missing signature → 401
- replay of the valid task → REJECT `PROOF_REUSED`
- recipient mismatch / expired / amount-exceeds-max / balance-below-minimum →
  REJECT with the matching `reason_code`
- `GET /health` → 200

Expected: `33 passed, 0 failed`. Kurier is not exercised by the harness (no
API key in tests); the local-proof path is asserted instead.

## Deploy & register

1. Deploy to any host with a **public HTTPS** URL (VPS, Render, Railway,
   Fly.io, …). The platform posts to the exact URL you register — register
   the full handler path, e.g. `https://your-host.example/agent`, not just
   the domain. `GET /health` is available for liveness checks.
2. On the Agent Games dashboard, **Rotate Secret**, copy the one-time
   plaintext, and set it as `AGENT_GAMES_HMAC_SECRET` in your deployment
   environment. Restart the service.
3. Run preflight from the dashboard — it must pass before the platform marks
   you active.
4. Start with **unscored practice tasks** before entering a scored round.
5. **Testnet first:** point `KURIER_BASE_URL` at the testnet URL and verify
   the Kurier flow there before using mainnet.

Kurier API key: create an account at https://kurier.xyz and generate a key
from the user dashboard. The gatekeeper verification key is already
registered by the platform (`vkHash 0x6b79c601…77b0`), so this service never
calls `register-vk` — it submits with `vkRegistered: true` and that hash.

## Security

- Secrets come from environment variables only. Never paste a private key,
  seed phrase, or API key into a chat or commit one — `.env` is gitignored.
- The HMAC secret is never logged (the logger redacts secret-like fields).
- `circuits/` (gatekeeper.wasm + gatekeeper_final.zkey, ~2 MB) **is**
  committed intentionally: the artifacts are public platform downloads and
  are required at runtime.
- The used-proof store lives in `data/` (gitignored) and is JSON, atomically
  written, FIFO-capped at 10,000 entries.
- Proof generation is serialized with a mutex (it is CPU-bound); requests
  share one process and the 60 s deadline is enforced per request.

## File structure

```
gatekeeper/
  circuits/                  gatekeeper.wasm, gatekeeper_final.zkey (platform artifacts)
  src/
    index.ts                 HTTP server (POST /agent, GET /health), deadline race
    config.ts                env config + assumptions A1/A2 + startup validation
    hmac.ts                  HMAC-SHA256 sign/verify (timing-safe)
    envelope.ts              envelope/preflight parsing, field encodings, taskId hash
    decision.ts              deterministic checks (fail closed)
    prover.ts                snarkjs fullProve + local verify, signal map
    kurier.ts                Kurier submit-proof + job-status polling
    store.ts                 persistent used-proof store (replay protection)
    routes.ts                /agent handler: HMAC → parse → decide → prove → Kurier → respond
    logger.ts                structured logs with secret redaction
    snarkjs.d.ts             minimal snarkjs typings
  test/
    harness.ts               end-to-end harness (spawns server, replays fixtures)
    fixtures/                valid-task.json, trap-task.json, preflight.json
  .env.example  .gitignore  package.json  tsconfig.json  README.md
```

## Scoring (for reference)

+12 correct decision, −6 approving a trap, −3 rejecting a valid request,
−2 timeout/offline, −2 proof fails to verify, plus a reliability bonus
(verified proofs / tasks). The design above is tuned to that table: it never
approves a trap (the circuit + the checks both forbid it), it only rejects a
valid request when a proof cannot be produced or finalized in time, and it
always attaches a locally-verified proof.
