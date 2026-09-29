// System-One decision receipts: canonical bytes, and replay verification.
//
// ## Why a decision receipt can be verified at all
//
// For an autoregressive completion, `outputCommitment` is unfalsifiable. The
// provider sampled tokens with a random seed; nobody — not the requester, not
// an auditor, not us — can re-run the job and get the same bytes, so the
// commitment only ever meant "the provider hashed something it emitted."
//
// A System-One decision is one deterministic encoder pass with no sampler.
// The same artifact over the same state produces the same probabilities. So
// the requester, who already holds the plaintext they sent, can re-run it and
// check the commitment themselves — offline, with no cooperation from the
// provider and no trust in any coordinator. That is `verifyDecisionReceipt`,
// and it is the first output claim in cocore anyone can independently check.
//
// ## What this does NOT prove
//
// Not confidentiality. A decision is served by an attached engine, which is
// out-of-process by construction, so the machine operator could read the
// state. Nothing here changes that, and nothing here should be described as
// confidential or attested.
//
// Not the artifact, by itself. `receipt.params.modelDigest` is a provider
// CLAIM about which weights ran; no one verifies it at publish time. What
// makes it worth having is that this function makes it falsifiable — run the
// artifact the receipt names, and either the commitment matches or you hold a
// signed receipt that contradicts its own computation. Pass `ranDigest` to
// pin that you actually ran what was claimed.
//
// ## Canonical bytes
//
// Both commitments cover canonical JSON, which is what makes replay possible
// across implementations. Deliberately NOT `canonicalize()` from
// `./canonical.ts`: that is the *signing* form, which forbids floats, and a
// decision is nothing but floats. This is a separate contract — sorted keys
// for the request, fixed field order for answers — pinned against the Rust
// engine (`provider/src/engines/decision.rs`) by a cross-language fixture.

import { sha256Hex } from "./publish.ts";
import type { Finding, ValidationReport } from "./validate.ts";
import type { JobRecord, ReceiptRecord } from "./types.ts";

export type DecisionQuestionType = "noul" | "choice" | "score";

export interface DecisionQuestion {
  type: DecisionQuestionType;
  instructions: unknown;
  /** `noul`: optional true/false descriptions. `choice`: option → description.
   *  `score`: ordered level descriptions. */
  criteria?: unknown;
}

export interface DecisionRequest {
  state: unknown;
  questions: Record<string, DecisionQuestion>;
}

/** The provider's answers envelope — what `outputCommitment` covers. */
export interface DecisionAnswersEnvelope {
  model: string;
  answers: Record<string, unknown>;
  usage?: { input_tokens?: number; output_tokens?: number };
}

/**
 * The exact bytes the requester sealed, and therefore what `inputCommitment`
 * covers.
 *
 * Keys are sorted recursively so the same logical request commits to the same
 * digest regardless of how any implementation's JSON serializer ordered its
 * object keys. Arrays keep their order — a score question's `criteria` levels
 * are ordered, and reordering them would change the question being asked.
 */
export function canonicalDecisionRequest(
  // Structurally looser than DecisionRequest so the console can pass its
  // already-validated raw questions without a cast: canonicalization does not
  // care what shape a question has, only that the bytes are deterministic.
  request: { state: unknown; questions: Record<string, unknown> },
  model: string,
): string {
  return JSON.stringify(sortKeys({ model, state: request.state, questions: request.questions }));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (typeof value !== "object" || value === null) return value;
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(value as Record<string, unknown>).sort()) {
    out[k] = sortKeys((value as Record<string, unknown>)[k]);
  }
  return out;
}

/**
 * Re-emit an answers envelope in the engine's canonical form — what
 * `outputCommitment` covers.
 *
 * Field order is fixed (`type` first, then the answer, then the distribution,
 * then confidence) and every map is emitted with sorted keys, so two honest
 * providers whose decision servers happened to order JSON keys differently
 * still produce byte-identical output. Mirrors `DecisionResult::
 * to_canonical_json` in the Rust engine; the cross-language fixture pins them
 * together.
 *
 * Unknown answer fields are dropped rather than passed through: the canonical
 * form is a closed shape, and silently carrying an extra key would let two
 * implementations disagree on the bytes.
 */
export function canonicalDecisionAnswers(envelope: DecisionAnswersEnvelope): string {
  const answers = Object.keys(envelope.answers)
    .sort()
    .map((id) => `${JSON.stringify(id)}:${canonicalAnswer(envelope.answers[id])}`)
    .join(",");
  return (
    `{"model":${JSON.stringify(envelope.model)},` +
    `"answers":{${answers}},` +
    `"usage":{"input_tokens":${int(envelope.usage?.input_tokens ?? 0)},` +
    `"output_tokens":${int(envelope.usage?.output_tokens ?? 0)}}}`
  );
}

/**
 * Format a decision number the way the provider does.
 *
 * This is the subtle one. Every probability, score and confidence is an f64 on
 * the provider, and both Rust's serde_json and Python's json print an integral
 * f64 with a trailing `.0` — `1.0`, not `1`. JavaScript has no such
 * distinction and `JSON.stringify(1)` gives `1`, so leaning on it here would
 * make the verifier disagree with the provider on exactly the answers a
 * confident model produces (`noul: 1`, `noul: 0`, `score: 2`) and fail honest
 * receipts as if they were forged.
 *
 * Exponent notation is refused rather than guessed at: Rust prints `1e21`
 * where JavaScript prints `1e+21`, and no probability or score should ever be
 * out there. A value that formats that way is not a decision number.
 */
function f64(n: unknown): string {
  if (typeof n !== "number" || !Number.isFinite(n)) {
    throw new Error(`decision value is not a finite number: ${JSON.stringify(n)}`);
  }
  const s = String(n);
  if (s.includes("e") || s.includes("E")) {
    throw new Error(`decision value ${s} is outside the canonical range (exponent notation)`);
  }
  return Number.isInteger(n) ? `${s}.0` : s;
}

/** Token counts are integers on the provider (u64), so no `.0`. */
function int(n: unknown): string {
  if (typeof n !== "number" || !Number.isInteger(n)) return "0";
  return String(n);
}

function canonicalAnswer(raw: unknown): string {
  const a = (raw ?? {}) as Record<string, unknown>;
  const type = a["type"];
  if (type === "noul") {
    return `{"type":"noul","noul":${f64(a["noul"])}}`;
  }
  if (type === "choice") {
    return (
      `{"type":"choice","choice":${JSON.stringify(a["choice"])},` +
      `"probabilities":${probabilities(a["probabilities"])}` +
      `${confidence(a["confidence"])}}`
    );
  }
  const legend = legendOf(a["legend"]);
  return (
    `{"type":"score","score":${f64(a["score"])}` +
    `${legend}` +
    `,"probabilities":${probabilities(a["probabilities"])}` +
    `${confidence(a["confidence"])}}`
  );
}

function probabilities(value: unknown): string {
  if (typeof value !== "object" || value === null) return "{}";
  const src = value as Record<string, unknown>;
  const body = Object.keys(src)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${f64(src[k])}`)
    .join(",");
  return `{${body}}`;
}

function confidence(value: unknown): string {
  if (value === undefined || value === null) return "";
  return `,"confidence":${f64(value)}`;
}

/** Level descriptions, always strings — see the Rust `Answer::Score` doc: a
 *  numeric legend entry could not be canonicalized identically here. Omitted
 *  entirely when empty, as the provider omits it. */
function legendOf(value: unknown): string {
  if (typeof value !== "object" || value === null) return "";
  const src = value as Record<string, unknown>;
  const keys = Object.keys(src).sort();
  if (keys.length === 0) return "";
  const body = keys
    .map((k) => {
      const v = src[k];
      return `${JSON.stringify(k)}:${JSON.stringify(typeof v === "string" ? v : JSON.stringify(v))}`;
    })
    .join(",");
  return `,"legend":{${body}}`;
}

/** Runs a decision request against a model and returns the raw envelope.
 *  {@link systemOneRunner} builds one for any `/v1/systemone` server. */
export type DecisionRunner = (
  request: DecisionRequest & { model: string },
) => Promise<DecisionAnswersEnvelope>;

/**
 * A runner backed by any System-One server — `ollaya serve`, `laya serve`,
 * Unsloth Desktop, or the hosted API.
 *
 * Point it at YOUR OWN server. The whole value of replay verification is that
 * the second run is one you control; re-running against the provider that
 * issued the receipt proves nothing.
 */
export function systemOneRunner(baseUrl: string, apiKey?: string): DecisionRunner {
  const url = `${baseUrl.replace(/\/$/, "")}/v1/systemone`;
  return async (request) => {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}),
      },
      body: JSON.stringify(request),
    });
    if (!res.ok) {
      throw new Error(`decision server ${url} answered ${res.status}: ${await res.text()}`);
    }
    const body = (await res.json()) as Record<string, unknown>;
    // Accept the enveloped and bare shapes, as the provider engine does.
    const answers =
      typeof body["answers"] === "object" && body["answers"] !== null
        ? (body["answers"] as Record<string, unknown>)
        : Object.fromEntries(
            Object.entries(body).filter(
              ([k]) => !["model", "usage", "id", "object", "created"].includes(k),
            ),
          );
    return {
      model: typeof body["model"] === "string" ? body["model"] : request.model,
      answers,
      usage: body["usage"] as DecisionAnswersEnvelope["usage"],
    };
  };
}

export interface VerifyDecisionOptions {
  receipt: ReceiptRecord;
  job: JobRecord;
  /** The state + questions the requester sent. They have these already; that
   *  is what makes this verifiable without anyone's cooperation. */
  request: DecisionRequest;
  /** Re-runs the decision. Omit to check the commitments' internal
   *  consistency only (`replayed` will be false in the result). */
  runner?: DecisionRunner;
  /** SHA-256 of the artifact the RUNNER used. When given, it is compared with
   *  the receipt's `params.modelDigest` claim, so a match means you re-ran the
   *  weights the provider named rather than merely something that agreed. */
  ranDigest?: string;
}

export interface DecisionVerification extends ValidationReport {
  /** True when the model was actually re-run. False means only the input
   *  commitment and record consistency were checked. */
  replayed: boolean;
  /** The artifact the receipt claims ran, if any. */
  claimedDigest: string | undefined;
  /** The output commitment our own replay produced, when we replayed. */
  recomputedOutputCommitment: string | undefined;
}

/**
 * Check a decision receipt against the computation it claims to describe.
 *
 * Three things are verified, in increasing strength:
 *
 *   1. `inputCommitment` — the job really commits to the request you sent, so
 *      the provider was asked what you think it was asked.
 *   2. `outputCommitment` — re-running the decision reproduces the exact bytes
 *      the provider signed. This is the one chat can never offer.
 *   3. `params.modelDigest` — the artifact you ran is the one the receipt
 *      named (only when `ranDigest` is supplied).
 *
 * A mismatch at step 2 is not ambiguous: the provider signed a receipt whose
 * output its own claimed model does not produce.
 */
export async function verifyDecisionReceipt(
  opts: VerifyDecisionOptions,
): Promise<DecisionVerification> {
  const findings: Finding[] = [];
  const { receipt, job, request } = opts;
  const claimedDigest = receipt.params?.modelDigest;

  // The receipt must be about this job's model at all, before any of the rest
  // means anything.
  if (receipt.model !== job.model) {
    findings.push({
      severity: "error",
      code: "decision-model-mismatch",
      message: `receipt.model ${JSON.stringify(receipt.model)} is not the job's model ${JSON.stringify(job.model)}`,
    });
  }

  // 1. Did the job commit to the request we actually sent?
  const canonicalRequest = canonicalDecisionRequest(request, receipt.model);
  const inputCommitment = await sha256Hex(new TextEncoder().encode(canonicalRequest));
  if (inputCommitment !== job.inputCommitment) {
    findings.push({
      severity: "error",
      code: "decision-input-commitment-mismatch",
      message:
        `the job commits to ${job.inputCommitment} but the request supplied here canonicalizes ` +
        `to ${inputCommitment} — this receipt is not for the decision you passed in`,
    });
  }
  if (receipt.inputCommitment !== job.inputCommitment) {
    findings.push({
      severity: "error",
      code: "decision-input-commitment-disagreement",
      message: `receipt.inputCommitment ${receipt.inputCommitment} does not match job.inputCommitment ${job.inputCommitment}`,
    });
  }

  // 3. Did we run what the receipt named? Checked before the replay so the
  // report says so even if the replay then fails.
  if (opts.ranDigest !== undefined) {
    if (claimedDigest === undefined) {
      findings.push({
        severity: "warn",
        code: "decision-no-model-digest",
        message:
          "the receipt names no model artifact, so a matching replay proves only that SOME model " +
          "agrees — ask the provider to declare COCORE_MODEL_DIGESTS",
      });
    } else if (claimedDigest.toLowerCase() !== opts.ranDigest.toLowerCase()) {
      findings.push({
        severity: "error",
        code: "decision-model-digest-mismatch",
        message: `the receipt claims artifact ${claimedDigest} but you replayed ${opts.ranDigest}`,
      });
    }
  }

  if (!opts.runner) {
    return {
      ok: findings.every((f) => f.severity !== "error"),
      findings,
      replayed: false,
      claimedDigest,
      recomputedOutputCommitment: undefined,
    };
  }

  // 2. The replay itself.
  let recomputed: string | undefined;
  try {
    const envelope = await opts.runner({ ...request, model: receipt.model });
    recomputed = await sha256Hex(new TextEncoder().encode(canonicalDecisionAnswers(envelope)));
    if (recomputed !== receipt.outputCommitment) {
      findings.push({
        severity: "error",
        code: "decision-output-commitment-mismatch",
        message:
          `the receipt commits to output ${receipt.outputCommitment} but re-running the decision ` +
          `produced ${recomputed}. Either the provider did not run the model it named, or it ` +
          `altered the answer. Both contradict a receipt it signed.`,
      });
    }
  } catch (e) {
    findings.push({
      severity: "warn",
      code: "decision-replay-failed",
      message: `could not re-run the decision, so the output is unverified: ${(e as Error).message}`,
    });
  }

  return {
    ok: findings.every((f) => f.severity !== "error"),
    findings,
    replayed: recomputed !== undefined,
    claimedDigest,
    recomputedOutputCommitment: recomputed,
  };
}
