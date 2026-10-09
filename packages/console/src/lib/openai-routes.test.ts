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
  // The DispatchInputs each handler handed to runDispatch, in call order.
  dispatched: [] as DispatchInputs[],
  // Machine-scoped keys resolveProBonoProviderKeys returns.
  proBonoKeys: new Set<string>(["did:plc:provider:machine1"]),
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
      state.dispatched.push(inputs);
      for (const ev of state.events) yield ev;
    },
  };
});

vi.mock("@/lib/pro-bono.server.ts", () => ({
  resolveProBonoProviderKeys: async (_did: string) => state.proBonoKeys,
}));

vi.mock("@/lib/admission.server.ts", () => ({
  admit: async () => ({ refusal: null, result: null, note: null }),
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

describe("handleProBonoChatCompletions forwards the same wire contract", () => {
  const responseFormat = {
    type: "json_schema",
    json_schema: {
      name: "digest",
      strict: true,
      schema: {
        type: "object",
        properties: { summary: { type: "string" } },
        required: ["summary"],
      },
    },
  };

  beforeEach(() => {
    state.sessionPresent = true;
    state.appviewKey = null;
    state.dispatched = [];
    state.proBonoKeys = new Set(["did:plc:provider:machine1"]);
    state.events = [
      { kind: "chunk", seq: 0, channel: "content", text: '{"summary":"ok"}' },
      { kind: "complete", tokensIn: 1, tokensOut: 1, receiptUri: "at://x" },
    ];
  });

  test("response_format json_schema reaches dispatch as outputSchema, same as the paid route", async () => {
    // Regression: the pro-bono route dropped outputSchema, so a schema-bound
    // caller got unconstrained output (renamed keys; a reasoning model never
    // emitted the JSON at all).
    const body = { ...baseBody, stream: false, response_format: responseFormat };
    expect((await handleProBonoChatCompletions(streamRequest(body))).status).toBe(200);
    expect((await handleChatCompletions(streamRequest(body))).status).toBe(200);
    const [proBono, paid] = state.dispatched;
    const expected = {
      name: "digest",
      strict: true,
      schema: responseFormat.json_schema.schema,
    };
    expect(proBono!.outputSchema).toEqual(expected);
    expect(paid!.outputSchema).toEqual(expected);
    // Pro-bono routing stays pinned to the elected machines.
    expect(proBono!.allowedProviderDids).toEqual(new Set(["did:plc:provider:machine1"]));
  });

  test("tools and tool_choice are forwarded when a pro-bono machine has verified tool calling", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify([
              {
                did: "did:plc:provider",
                machineId: "machine1",
                supportedModels: ["stub"],
                attestedAt: new Date().toISOString(),
                active: true,
                toolCallModels: ["stub"],
              },
            ]),
            { status: 200, headers: { "content-type": "application/json" } },
          ),
      ),
    );
    const res = await handleProBonoChatCompletions(
      streamRequest({
        ...baseBody,
        stream: false,
        tools: weatherTools,
        tool_choice: { type: "function", function: { name: "get_weather" } },
      }),
    );
    expect(res.status).toBe(200);
    const [inputs] = state.dispatched;
    expect(inputs!.tools?.[0]?.function.name).toBe("get_weather");
    expect(inputs!.toolChoice).toBe("required");
    expect(inputs!.toolChoiceFunction).toBe("get_weather");
  });

  test("tool requests are gated on the pro-bono machines, not the whole network", async () => {
    // A billed sibling machine of the same owner (machine2) supports tools,
    // but the elected pro-bono machine does not — must 400, not route.
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify([
              {
                did: "did:plc:provider",
                machineId: "machine1",
                supportedModels: ["stub"],
                attestedAt: new Date().toISOString(),
                active: true,
                toolCallModels: [],
              },
              {
                did: "did:plc:provider",
                machineId: "machine2",
                supportedModels: ["stub"],
                attestedAt: new Date().toISOString(),
                active: true,
                toolCallModels: ["stub"],
              },
            ]),
            { status: 200, headers: { "content-type": "application/json" } },
          ),
      ),
    );
    const res = await handleProBonoChatCompletions(
      streamRequest({ ...baseBody, stream: false, tools: weatherTools }),
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: { type: string } }).error.type).toBe(
      "tool_calls_not_supported",
    );
    expect(state.dispatched).toHaveLength(0);
  });
});
