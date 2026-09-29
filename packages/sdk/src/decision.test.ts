// Tests for decision-receipt replay verification.
//
// The load-bearing one is the cross-language fixture: if the TypeScript
// canonicalization and the Rust engine's disagree by a single key order, every
// honest receipt fails to verify and replay verification is worthless. The
// rest cover what the verifier is supposed to catch.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "vitest";

import {
  canonicalDecisionAnswers,
  canonicalDecisionRequest,
  verifyDecisionReceipt,
  type DecisionAnswersEnvelope,
  type DecisionRequest,
} from "./decision.ts";
import { sha256Hex } from "./publish.ts";
import type { JobRecord, ReceiptRecord } from "./types.ts";

function findFixture(): string {
  // packages/sdk/src/ → ../../../target/
  const here = new URL(".", import.meta.url).pathname;
  return join(here, "..", "..", "..", "target", "decision-cross-lang-fixture.json");
}

describe("cross-language canonicalization", () => {
  test("TS reproduces the Rust engine's canonical answer bytes", () => {
    // provider/tests/cross_lang_fixture.rs writes this. From a fresh clone run
    // `cargo test --test cross_lang_fixture` in provider/ first.
    const fixture = JSON.parse(readFileSync(findFixture(), "utf-8")) as {
      upstreamReply: DecisionAnswersEnvelope;
      canonicalAnswers: string;
      outputCommitment: string;
    };

    // The fixture's upstream reply deliberately has awkward key order; both
    // implementations must erase it identically.
    assert.equal(canonicalDecisionAnswers(fixture.upstreamReply), fixture.canonicalAnswers);
  });

  test("and therefore the same output commitment", async () => {
    const fixture = JSON.parse(readFileSync(findFixture(), "utf-8")) as {
      upstreamReply: DecisionAnswersEnvelope;
      outputCommitment: string;
    };
    const digest = await sha256Hex(
      new TextEncoder().encode(canonicalDecisionAnswers(fixture.upstreamReply)),
    );
    assert.equal(digest, fixture.outputCommitment);
  });
});

describe("number formatting", () => {
  // The trap. Rust's serde_json and Python's json print an integral f64 as
  // `1.0`; JavaScript's JSON.stringify prints `1`. A confident decision model
  // answers with exactly 1 and 0, so leaning on JSON.stringify here would make
  // the verifier disagree with the provider on precisely those answers and
  // fail honest receipts as if they were forged.
  test("integral decision values print as floats, token counts do not", () => {
    const canonical = canonicalDecisionAnswers({
      model: "m",
      answers: { q: { type: "noul", noul: 1 } },
      usage: { input_tokens: 12, output_tokens: 0 },
    });
    assert.ok(canonical.includes('"noul":1.0'), canonical);
    // Token counts are u64 on the provider — they must NOT gain a `.0`.
    assert.ok(canonical.includes('"input_tokens":12,"output_tokens":0'), canonical);
  });

  test("a non-finite value is refused rather than silently mis-hashed", () => {
    assert.throws(() =>
      canonicalDecisionAnswers({
        model: "m",
        answers: { q: { type: "noul", noul: Number.NaN } },
      }),
    );
  });
});

describe("canonicalDecisionRequest", () => {
  const request: DecisionRequest = {
    state: "x",
    questions: {
      zeta: { type: "noul", instructions: "z" },
      alpha: { type: "choice", instructions: "a", criteria: { b: "bee", a: "ay" } },
    },
  };

  test("is stable across caller key order", () => {
    const shuffled: DecisionRequest = {
      questions: {
        alpha: { criteria: { a: "ay", b: "bee" }, instructions: "a", type: "choice" },
        zeta: { instructions: "z", type: "noul" },
      },
      state: "x",
    };
    assert.equal(canonicalDecisionRequest(request, "m"), canonicalDecisionRequest(shuffled, "m"));
  });

  test("keeps score levels in order — they are ordered, not a set", () => {
    const scored: DecisionRequest = {
      state: "x",
      questions: { sev: { type: "score", instructions: "s", criteria: ["low", "high"] } },
    };
    assert.ok(canonicalDecisionRequest(scored, "m").includes('["low","high"]'));
  });
});

// --- verifier ---------------------------------------------------------------

const REQUEST: DecisionRequest = {
  state: "Third time this year you've double-charged me.",
  questions: { urgent: { type: "noul", instructions: "The message conveys urgency." } },
};
const ANSWERS: DecisionAnswersEnvelope = {
  model: "convaiinnovations/laya",
  answers: { urgent: { type: "noul", noul: 0.97 } },
  usage: { input_tokens: 31, output_tokens: 0 },
};

async function fixtures(overrides?: {
  modelDigest?: string;
  outputCommitment?: string;
}): Promise<{ job: JobRecord; receipt: ReceiptRecord }> {
  const model = "convaiinnovations/laya";
  const inputCommitment = await sha256Hex(
    new TextEncoder().encode(canonicalDecisionRequest(REQUEST, model)),
  );
  const outputCommitment =
    overrides?.outputCommitment ??
    (await sha256Hex(new TextEncoder().encode(canonicalDecisionAnswers(ANSWERS))));
  return {
    job: { model, inputCommitment, inputFormat: "decision-v1" } as JobRecord,
    receipt: {
      job: { uri: "at://did:plc:r/dev.cocore.compute.job/1", cid: "bafyjob" },
      requester: "did:plc:r",
      model,
      inputCommitment,
      outputCommitment,
      tokens: { in: 31, out: 0 },
      startedAt: "2026-09-29T00:00:00Z",
      completedAt: "2026-09-29T00:00:00Z",
      price: { amount: 31, currency: "CC" },
      attestation: { uri: "at://did:plc:p/dev.cocore.compute.attestation/1", cid: "bafyatt" },
      ...(overrides?.modelDigest ? { params: { modelDigest: overrides.modelDigest } } : {}),
    } as ReceiptRecord,
  };
}

describe("verifyDecisionReceipt", () => {
  test("an honest receipt verifies by replay", async () => {
    const { job, receipt } = await fixtures();
    const report = await verifyDecisionReceipt({
      receipt,
      job,
      request: REQUEST,
      runner: async () => ANSWERS,
    });
    assert.equal(report.ok, true, JSON.stringify(report.findings));
    assert.equal(report.replayed, true);
  });

  // The whole point: a provider that signed a receipt whose output its own
  // claimed model does not produce has contradicted itself.
  test("a tampered answer fails, and the finding says why", async () => {
    const { job, receipt } = await fixtures();
    const report = await verifyDecisionReceipt({
      receipt,
      job,
      request: REQUEST,
      // The provider flipped the decision but committed to the honest one.
      runner: async () => ({
        ...ANSWERS,
        answers: { urgent: { type: "noul", noul: 0.02 } },
      }),
    });
    assert.equal(report.ok, false);
    const finding = report.findings.find((f) => f.code === "decision-output-commitment-mismatch");
    assert.ok(finding, "must name the output mismatch");
    assert.ok(finding.message.includes("did not run the model it named"));
  });

  test("a receipt for a different request is caught before any replay", async () => {
    const { job, receipt } = await fixtures();
    const report = await verifyDecisionReceipt({
      receipt,
      job,
      request: { ...REQUEST, state: "something else entirely" },
    });
    assert.equal(report.ok, false);
    assert.ok(report.findings.some((f) => f.code === "decision-input-commitment-mismatch"));
  });

  test("without a runner it checks the commitments but reports it did not replay", async () => {
    const { job, receipt } = await fixtures();
    const report = await verifyDecisionReceipt({ receipt, job, request: REQUEST });
    assert.equal(report.ok, true);
    assert.equal(report.replayed, false);
  });

  // The point of the lexicon's `decision-v1`: the record describes its own
  // bytes, so a later reader knows to re-canonicalize them as a decision
  // rather than taking the caller's word for it.
  test("a job that doesn't declare decision-v1 still verifies, but says so", async () => {
    const { job, receipt } = await fixtures();
    const report = await verifyDecisionReceipt({
      receipt,
      job: { ...job, inputFormat: undefined },
      request: REQUEST,
      runner: async () => ANSWERS,
    });
    assert.equal(report.ok, true, "a legacy job is not invalid");
    const warn = report.findings.find((f) => f.code === "decision-job-format-missing");
    assert.ok(warn);
    assert.equal(warn.severity, "warn");
  });

  test("replaying a different artifact than the receipt named is an error", async () => {
    const { job, receipt } = await fixtures({ modelDigest: "a".repeat(64) });
    const report = await verifyDecisionReceipt({
      receipt,
      job,
      request: REQUEST,
      runner: async () => ANSWERS,
      ranDigest: "b".repeat(64),
    });
    assert.equal(report.ok, false);
    assert.ok(report.findings.some((f) => f.code === "decision-model-digest-mismatch"));
  });

  // Absence of a digest is allowed — but a green result then means less, and
  // the report has to say so rather than implying the artifact was confirmed.
  test("a receipt naming no artifact warns instead of silently passing", async () => {
    const { job, receipt } = await fixtures();
    const report = await verifyDecisionReceipt({
      receipt,
      job,
      request: REQUEST,
      runner: async () => ANSWERS,
      ranDigest: "b".repeat(64),
    });
    assert.equal(report.ok, true, "a missing claim is not a failure");
    const warn = report.findings.find((f) => f.code === "decision-no-model-digest");
    assert.ok(warn);
    assert.equal(warn.severity, "warn");
  });

  test("an unreachable model server leaves the output unverified, not verified", async () => {
    const { job, receipt } = await fixtures();
    const report = await verifyDecisionReceipt({
      receipt,
      job,
      request: REQUEST,
      runner: async () => {
        throw new Error("connection refused");
      },
    });
    assert.equal(report.replayed, false);
    assert.ok(report.findings.some((f) => f.code === "decision-replay-failed"));
  });
});
