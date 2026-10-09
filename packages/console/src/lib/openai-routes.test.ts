// Handler-level contract test for the OpenAI-compatible chat
// completions endpoint. The pure SSE encoder is covered in
// openai-chat-completions.test.ts; here we drive `handleChatCompletions`
// itself so a regression that returns a JSON body (or throws) for a
// `stream: true` request is caught — that is exactly what surfaces in
// OpenAI clients like Apollo as "The response is not a stream."
//
// We mock the two external seams (API-key lookup + OAuth restore, and
// the dispatch generator) but keep the REAL `authenticate` /
// `runTraced` path, since the effect/o11y conversion is what touched it.

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import type { DispatchEvent, DispatchInputs } from "./inference-dispatch.server.ts";

// Mutable knobs the hoisted mocks read.
const state = vi.hoisted(() => ({
  events: [] as DispatchEvent[],
  // The inputs of the most recent dispatch, so a test can assert what a
  // handler forwarded to the provider.
  lastInputs: null as DispatchInputs | null,
  // Machines `resolveProBonoProviderKeys` reports as serving the caller free.
  proBonoKeys: new Set<string>(),
  sessionPresent: true,
  // Resolved by the AppView-store fallback for a cocore- key the local
  // store rejects (null = the AppView declines it too).
  appviewKey: null as { id: string; did: string; name: string } | null,
  // verifyServiceAuth result for a JWT-shaped bearer.
  serviceAuth: { ok: true, did: "did:plc:servicetokendidservicetok" } as
    | { ok: true; did: string }
    | { ok: false; status: number; error: string; message: string },
}));

vi.mock("@/lib/api-keys.server.ts", () => ({
  // The local console store only knows its own keys; treat anything but the
  // canonical test key as a miss so the AppView fallback gets exercised.
  resolveBearerKey: (presented: string) =>
    presented === "cocore-testkey"
      ? { id: "key-1", did: "did:plc:testtesttesttesttesttest", name: "test" }
      : null,
}));

vi.mock("@/lib/api-keys-appview.server.ts", () => ({
  resolveBearerKeyViaAppview: async (_presented: string) => state.appviewKey,
}));

vi.mock("@/lib/service-auth.server.ts", () => ({
  verifyServiceAuth: async (_request: Request, _lxm: string) => state.serviceAuth,
}));

vi.mock("@/integrations/auth/atproto.server.ts", async () => {
  const { Effect } = await import("effect");
  return {
    // authenticate() runs this through the real runTraced boundary.
    restoreAtprotoSessionEffect: () =>
      state.sessionPresent ? Effect.succeed({ session: "fake" }) : Effect.succeed(null),
  };
});

vi.mock("@/lib/inference-dispatch.server.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./inference-dispatch.server.ts")>();
  return {
    ...actual,
    runDispatch: async function* (inputs: DispatchInputs): AsyncGenerator<DispatchEvent> {
      state.lastInputs = inputs;
      for (const ev of state.events) yield ev;
    },
  };
});

vi.mock("@/lib/pro-bono.server.ts", () => ({
  resolveProBonoProviderKeys: async (_did: string) => state.proBonoKeys,
}));

import { handleChatCompletions, handleProBonoChatCompletions } from "./openai-routes.server.ts";

function streamRequest(body: Record<string, unknown>): Request {
  return new Request("https://console.test/v1/chat/completions", {
    method: "POST",
    headers: { authorization: "Bearer cocore-testkey", "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

const baseBody = {
  model: "stub",
  messages: [{ role: "user", content: "hi" }],
  stream: true,
};

const weatherTools = [
  {
    type: "function",
    function: {
      name: "get_weather",
      description: "Get weather",
      parameters: {
        type: "object",
        properties: { city: { type: "string" } },
        required: ["city"],
      },
    },
  },
];

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("handleChatCompletions wire contract", () => {
  beforeEach(() => {
    state.sessionPresent = true;
    state.appviewKey = null;
    state.serviceAuth = { ok: true, did: "did:plc:servicetokendidservicetok" };
  });

  test("stream:true happy path returns text/event-stream, not JSON", async () => {
    state.events = [
      { kind: "chunk", seq: 0, channel: "content", text: "hello" },
      { kind: "complete", tokensIn: 1, tokensOut: 1, receiptUri: "at://x" },
    ];
    const res = await handleChatCompletions(streamRequest(baseBody));
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type") ?? "").toMatch(/^text\/event-stream/);
    const text = await res.text();
    expect(text).toContain("data: [DONE]");
  });

  test("stream:true with an error dispatch STILL returns an event-stream", async () => {
    // The regression guard: a dispatch failure must keep the SSE
    // content-type so the client renders the error rather than throwing
    // "not a stream" on a JSON body.
    state.events = [{ kind: "error", reason: "no providers", code: "no-providers-connected" }];
    const res = await handleChatCompletions(streamRequest(baseBody));
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type") ?? "").toMatch(/^text\/event-stream/);
  });

  test("a bad API key is the one case that is allowed to be JSON (401)", async () => {
    const req = new Request("https://console.test/v1/chat/completions", {
      method: "POST",
      headers: { authorization: "Bearer not-a-cocore-key", "content-type": "application/json" },
      body: JSON.stringify(baseBody),
    });
    const res = await handleChatCompletions(req);
    expect(res.status).toBe(401);
    expect(res.headers.get("content-type") ?? "").toMatch(/application\/json/);
  });

  test("tool requests require the requested model in toolCallModels when reported", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify([
              {
                did: "did:plc:provider",
                supportedModels: ["model-a"],
                attestedAt: new Date().toISOString(),
                active: true,
                supportsToolCalls: true,
                toolCallModels: ["model-b"],
              },
            ]),
            { status: 200, headers: { "content-type": "application/json" } },
          ),
      ),
    );
    const res = await handleChatCompletions(
      streamRequest({ ...baseBody, model: "model-a", stream: false, tools: weatherTools }),
    );
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error.type).toBe("tool_calls_not_supported");
  });

  test("tool requests pass gating when toolCallModels contains the requested model", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify([
              {
                did: "did:plc:provider",
                supportedModels: ["model-a"],
                attestedAt: new Date().toISOString(),
                active: true,
                supportsToolCalls: true,
                toolCallModels: ["model-a"],
              },
            ]),
            { status: 200, headers: { "content-type": "application/json" } },
          ),
      ),
    );
    state.events = [
      { kind: "chunk", seq: 0, channel: "content", text: "ok" },
      { kind: "complete", tokensIn: 1, tokensOut: 1, receiptUri: "at://x" },
    ];
    const res = await handleChatCompletions(
      streamRequest({ ...baseBody, model: "model-a", stream: false, tools: weatherTools }),
    );
    expect(res.status).toBe(200);
  });

  test("a cocore- key the local store rejects authenticates via the AppView store", async () => {
    // The Locale bug: a key minted through the documented AppView
    // createApiKey lands in account.db, not console.db. The fallback must
    // resolve it so inference runs instead of 401ing.
    state.events = [{ kind: "complete", tokensIn: 1, tokensOut: 1, receiptUri: "at://x" }];
    state.appviewKey = { id: "k2", did: "did:plc:appviewmintedkeydidaaaa", name: "appview" };
    const req = new Request("https://console.test/v1/chat/completions", {
      method: "POST",
      headers: { authorization: "Bearer cocore-appviewminted", "content-type": "application/json" },
      body: JSON.stringify(baseBody),
    });
    const res = await handleChatCompletions(req);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type") ?? "").toMatch(/^text\/event-stream/);
  });

  test("a valid service-auth token (JWT) authenticates inference — no API key", async () => {
    // mary's idea: hit inference with an AT Protocol service token.
    state.events = [{ kind: "complete", tokensIn: 1, tokensOut: 1, receiptUri: "at://x" }];
    const req = new Request("https://console.test/v1/chat/completions", {
      method: "POST",
      headers: {
        authorization: "Bearer header.payload.signature",
        "content-type": "application/json",
      },
      body: JSON.stringify(baseBody),
    });
    const res = await handleChatCompletions(req);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type") ?? "").toMatch(/^text\/event-stream/);
  });

  test("a service token for a DID with no cocore session returns onboarding_required", async () => {
    state.sessionPresent = false;
    const req = new Request("https://console.test/v1/chat/completions", {
      method: "POST",
      headers: {
        authorization: "Bearer header.payload.signature",
        "content-type": "application/json",
      },
      body: JSON.stringify(baseBody),
    });
    const res = await handleChatCompletions(req);
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: { code: string | null } };
    expect(body.error.code).toBe("onboarding_required");
  });

  test("an invalid service token is rejected with its verify error", async () => {
    state.serviceAuth = { ok: false, status: 401, error: "BadJwtSignature", message: "bad sig" };
    const req = new Request("https://console.test/v1/chat/completions", {
      method: "POST",
      headers: {
        authorization: "Bearer header.payload.signature",
        "content-type": "application/json",
      },
      body: JSON.stringify(baseBody),
    });
    const res = await handleChatCompletions(req);
    expect(res.status).toBe(401);
    expect(res.headers.get("content-type") ?? "").toMatch(/application\/json/);
  });
});

describe("handleProBonoChatCompletions", () => {
  beforeEach(() => {
    state.sessionPresent = true;
    state.appviewKey = null;
    state.lastInputs = null;
    state.proBonoKeys = new Set(["did:plc:providerproviderprovider:machine1"]);
    // Pro bono receipts carry zero tokens; emit content so the buffered
    // path doesn't read the completion as an empty-output stall.
    state.events = [
      { kind: "chunk", seq: 0, channel: "content", text: '{"headline":"h","summary":"s"}' },
      { kind: "complete", tokensIn: 0, tokensOut: 0, receiptUri: "at://x" },
    ];
  });

  const proBonoRequest = (body: Record<string, unknown>) =>
    new Request("https://console.test/v1/probono/chat/completions", {
      method: "POST",
      headers: { authorization: "Bearer cocore-testkey", "content-type": "application/json" },
      body: JSON.stringify(body),
    });

  test("forwards response_format json_schema as outputSchema (was dropped)", async () => {
    // Observed 2026-10-08: asked for {headline, summary}, the pro bono path
    // dispatched no outputSchema and the model returned {headline,
    // summary_sentence}. The schema must reach the provider like the paid path.
    const schema = {
      type: "object",
      properties: { headline: { type: "string" }, summary: { type: "string" } },
      required: ["headline", "summary"],
      additionalProperties: false,
    };
    const res = await handleProBonoChatCompletions(
      proBonoRequest({
        ...baseBody,
        stream: false,
        response_format: {
          type: "json_schema",
          json_schema: { name: "story", strict: true, schema },
        },
      }),
    );
    expect(res.status).toBe(200);
    expect(state.lastInputs?.outputSchema?.name).toBe("story");
    expect(state.lastInputs?.outputSchema?.schema).toEqual(schema);
    // Still routed only to the pro bono machines.
    expect(state.lastInputs?.allowedProviderDids).toEqual(state.proBonoKeys);
  });

  test("forwards tools and tool_choice like the paid path", async () => {
    const res = await handleProBonoChatCompletions(
      proBonoRequest({
        ...baseBody,
        stream: false,
        tools: weatherTools,
        tool_choice: { type: "function", function: { name: "get_weather" } },
      }),
    );
    expect(res.status).toBe(200);
    expect(state.lastInputs?.tools).toEqual(weatherTools);
    expect(state.lastInputs?.toolChoice).toBeDefined();
    expect(state.lastInputs?.toolChoiceFunction).toBe("get_weather");
  });

  test("a plain request carries no schema or tool fields", async () => {
    const res = await handleProBonoChatCompletions(proBonoRequest({ ...baseBody, stream: false }));
    expect(res.status).toBe(200);
    expect(state.lastInputs).not.toBeNull();
    expect(state.lastInputs).not.toHaveProperty("outputSchema");
    expect(state.lastInputs).not.toHaveProperty("tools");
  });

  test("still fails closed with 503 when no machine offers the caller pro bono", async () => {
    state.proBonoKeys = new Set();
    const res = await handleProBonoChatCompletions(proBonoRequest(baseBody));
    expect(res.status).toBe(503);
    expect(state.lastInputs).toBeNull();
  });
});
