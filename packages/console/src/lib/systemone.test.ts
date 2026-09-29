// Tests for the System-One (`/v1/systemone`) contract: request validation,
// model-alias resolution, the canonical bytes that become `inputCommitment`,
// and the mapping of dispatch failures onto the statuses Jev clients retry.

import assert from "node:assert/strict";
import { describe, test } from "vitest";

import type { DispatchErrorCode } from "./inference-dispatch.server.ts";
import {
  canonicalDecisionPrompt,
  dispatchErrorToSystemOneResponse,
  parseDecisionCompletion,
  parseSystemOneRequest,
  resolveDecisionModel,
  systemOneResponse,
  type ParsedSystemOneRequest,
} from "./systemone.server.ts";

const NOUL_BODY = {
  model: "jev-latest",
  state: "Hi, I've been trying to connect my Stripe account for 3 days.",
  questions: {
    is_urgent: { type: "noul", instructions: "The message conveys urgency." },
  },
};

function parsed(body: unknown): ParsedSystemOneRequest {
  const r = parseSystemOneRequest(body);
  assert.ok(!("status" in r), `expected a parse, got ${JSON.stringify(r)}`);
  return r;
}

describe("parseSystemOneRequest", () => {
  test("parses the three question types", () => {
    const r = parsed({
      state: "x",
      questions: {
        urgent: { type: "noul", instructions: "It is urgent" },
        next: {
          type: "choice",
          instructions: "Pick one",
          criteria: { refund: "issue a refund", escalate: "send to a human" },
        },
        severity: {
          type: "score",
          instructions: "How severe",
          criteria: ["low", "medium", "high"],
        },
      },
    });
    assert.equal(r.questions["urgent"]!.type, "noul");
    assert.equal(r.questions["next"]!.type, "choice");
    assert.deepEqual(r.questions["next"]!.options, ["refund", "escalate"]);
    assert.equal(r.questions["severity"]!.type, "score");
  });

  test("defaults the model to the SDK's own default", () => {
    const r = parsed({ state: "x", questions: NOUL_BODY.questions });
    assert.equal(r.requestedModel, "jev-latest");
  });

  // 422, not 400: it is what the System-One API documents for a validation
  // failure and what its SDKs surface as one rather than a retryable fault.
  test("validation failures are 422 and name the field at fault", () => {
    const cases: Array<[unknown, string]> = [
      ["not an object", "must be a JSON object"],
      [{ questions: NOUL_BODY.questions }, "`state` is required"],
      [{ state: "", questions: NOUL_BODY.questions }, "must not be empty"],
      [{ state: "x" }, "`questions` is required"],
      [{ state: "x", questions: {} }, "at least one question"],
      [
        { state: "x", questions: { q: { type: "vibes", instructions: "hm" } } },
        'expected "noul", "choice", or "score"',
      ],
      [{ state: "x", questions: { q: { type: "noul" } } }, "missing `instructions`"],
    ];
    for (const [body, fragment] of cases) {
      const r = parseSystemOneRequest(body);
      assert.ok("status" in r, `expected an error for ${JSON.stringify(body)}`);
      assert.equal(r.status, 422);
      assert.ok(
        r.message.includes(fragment),
        `message ${JSON.stringify(r.message)} should mention ${JSON.stringify(fragment)}`,
      );
    }
  });

  test("enforces the documented criteria limits", () => {
    const tooFewLevels = parseSystemOneRequest({
      state: "x",
      questions: { q: { type: "score", instructions: "Rate", criteria: ["only one"] } },
    });
    assert.ok("status" in tooFewLevels);
    assert.ok(tooFewLevels.message.includes("2–10"));

    const noOptions = parseSystemOneRequest({
      state: "x",
      questions: { q: { type: "choice", instructions: "Pick", criteria: {} } },
    });
    assert.ok("status" in noOptions);
    assert.ok(noOptions.message.includes("no options"));

    const tooMany = parseSystemOneRequest({
      state: "x",
      questions: {
        q: {
          type: "choice",
          instructions: "Pick",
          criteria: Object.fromEntries(
            Array.from({ length: 256 }, (_, i) => [`opt${i}`, "an option"]),
          ),
        },
      },
    });
    assert.ok("status" in tooMany);
    assert.ok(tooMany.message.includes("the limit is 255"));
  });
});

describe("resolveDecisionModel", () => {
  const online = [
    "mlx-community/Qwen3.6-35B-A3B-4bit",
    "convaiinnovations/laya",
    "convaiinnovations/laya-multilingual",
  ];

  test("resolves the aliases every Jev client hardcodes", () => {
    // Multilingual is preferred: it is the local servers' default and has the
    // longer context.
    assert.equal(resolveDecisionModel("jev-latest", online), "convaiinnovations/laya-multilingual");
    assert.equal(resolveDecisionModel("laya", online), "convaiinnovations/laya-multilingual");
  });

  test("falls through to the next known model when the preferred one is offline", () => {
    assert.equal(
      resolveDecisionModel("jev-latest", ["convaiinnovations/laya"]),
      "convaiinnovations/laya",
    );
  });

  test("a concrete model id is honored verbatim", () => {
    // Even one we've never heard of: the caller may be running something new,
    // and dispatch reports "no provider serves it" better than we could.
    assert.equal(resolveDecisionModel("some-org/new-decider", online), "some-org/new-decider");
  });

  test("404s with the known set when no decision model is online", () => {
    const r = resolveDecisionModel("jev-latest", ["mlx-community/Qwen3.6-35B-A3B-4bit"]);
    assert.ok(typeof r !== "string");
    assert.equal(r.status, 404);
    assert.equal(r.code, "model_not_found");
    assert.ok(r.message.includes("convaiinnovations/laya"));
  });
});

describe("canonicalDecisionPrompt", () => {
  // The sealed bytes are what `inputCommitment` covers, so two callers whose
  // JSON serializers ordered keys differently must commit to the same thing.
  test("is stable across caller key order", () => {
    const a = canonicalDecisionPrompt(
      parsed({
        state: "x",
        questions: {
          zeta: { type: "noul", instructions: "z" },
          alpha: { type: "choice", instructions: "a", criteria: { b: "bee", a: "ay" } },
        },
      }),
      "convaiinnovations/laya",
    );
    const b = canonicalDecisionPrompt(
      parsed({
        questions: {
          alpha: { criteria: { a: "ay", b: "bee" }, instructions: "a", type: "choice" },
          zeta: { instructions: "z", type: "noul" },
        },
        state: "x",
      }),
      "convaiinnovations/laya",
    );
    assert.equal(a, b);
    assert.equal(
      a,
      '{"model":"convaiinnovations/laya","questions":{"alpha":{"criteria":{"a":"ay","b":"bee"},"instructions":"a","type":"choice"},"zeta":{"instructions":"z","type":"noul"}},"state":"x"}',
    );
  });

  test("keeps score levels in order — they are ordered, not a set", () => {
    const prompt = canonicalDecisionPrompt(
      parsed({
        state: "x",
        questions: { sev: { type: "score", instructions: "s", criteria: ["low", "high"] } },
      }),
      "m",
    );
    assert.ok(prompt.includes('["low","high"]'));
  });

  test("carries the resolved model, not the alias the caller sent", () => {
    const prompt = canonicalDecisionPrompt(parsed(NOUL_BODY), "convaiinnovations/laya");
    assert.ok(prompt.includes('"model":"convaiinnovations/laya"'));
    assert.ok(!prompt.includes("jev-latest"));
  });
});

describe("parseDecisionCompletion", () => {
  const questions = parsed(NOUL_BODY).questions;

  test("reads the provider's canonical envelope", () => {
    const r = parseDecisionCompletion(
      '{"model":"convaiinnovations/laya","answers":{"is_urgent":{"type":"noul","noul":0.94}},"usage":{"input_tokens":31,"output_tokens":0}}',
      questions,
      "fallback",
    );
    assert.ok(!("status" in r));
    assert.equal(r.model, "convaiinnovations/laya");
    assert.equal(r.inputTokens, 31);
    // Non-autoregressive: nothing is generated.
    assert.equal(r.outputTokens, 0);
  });

  test("a provider that answers nothing, prose, or the wrong questions is a 502", () => {
    for (const text of [
      "Sure! That sounds urgent.",
      "[1,2,3]",
      '{"model":"laya"}',
      '{"answers":{"something_else":{"type":"noul","noul":0.5}}}',
    ]) {
      const r = parseDecisionCompletion(text, questions, "fallback");
      assert.ok("status" in r, `expected an error for ${text}`);
      assert.equal(r.status, 502);
      assert.equal(r.code, "malformed_decision");
    }
  });
});

describe("dispatchErrorToSystemOneResponse", () => {
  // Jev SDKs retry 429/529 with backoff and hard-fail everything else, so a
  // capacity blip must answer 529 — a 503 would be equally true and would
  // surface to the caller as a dead end.
  test("capacity-shaped failures answer 529 so Jev clients back off", () => {
    const capacity: DispatchErrorCode[] = [
      "no-providers-connected",
      "no-capacity",
      "no-providers-for-country",
      "no-providers-for-version",
      "target-provider-not-connected",
    ];
    for (const code of capacity) {
      assert.equal(dispatchErrorToSystemOneResponse(code).status, 529, code);
    }
  });

  test("a model that nobody serves is still a 404", () => {
    const r = dispatchErrorToSystemOneResponse("no-providers-for-model");
    assert.equal(r.status, 404);
    assert.equal(r.code, "model_not_found");
  });

  test("pipeline failures keep their chat-surface status", () => {
    assert.equal(dispatchErrorToSystemOneResponse("pds-publish-failed").status, 502);
  });
});

describe("systemOneResponse", () => {
  test("is the documented shape plus cocore's provenance block", async () => {
    const res = systemOneResponse(
      {
        model: "convaiinnovations/laya",
        answers: { is_urgent: { type: "noul", noul: 0.94 } },
        inputTokens: 31,
        outputTokens: 0,
      },
      { x_cocore: { receiptUri: "at://did:plc:x/dev.cocore.compute.receipt/abc" } },
    );
    assert.equal(res.status, 200);
    const body = (await res.json()) as Record<string, unknown>;
    assert.deepEqual(body["usage"], { input_tokens: 31, output_tokens: 0 });
    assert.equal(body["model"], "convaiinnovations/laya");
    assert.ok(body["answers"]);
    assert.ok(body["x_cocore"]);
  });
});
