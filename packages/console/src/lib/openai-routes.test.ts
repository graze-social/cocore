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

import { describe, expect, test, vi } from "vitest";

import type { DispatchEvent } from "./inference-dispatch.server.ts";

// Mutable knobs the hoisted mocks read.
const state = vi.hoisted(() => ({
  events: [] as DispatchEvent[],
}));

vi.mock("@/lib/api-keys.server.ts", () => ({
  resolveBearerKey: (presented: string) =>
    presented.startsWith("cocore-")
      ? { id: "key-1", did: "did:plc:testtesttesttesttesttest", name: "test" }
      : null,
}));

vi.mock("@/integrations/auth/atproto.server.ts", async () => {
  const { Effect } = await import("effect");
  return {
    // authenticate() runs this through the real runTraced boundary.
    restoreAtprotoSessionEffect: () => Effect.succeed({ session: "fake" }),
  };
});

vi.mock("@/lib/inference-dispatch.server.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./inference-dispatch.server.ts")>();
  return {
    ...actual,
    runDispatch: async function* (): AsyncGenerator<DispatchEvent> {
      for (const ev of state.events) yield ev;
    },
  };
});

import { handleChatCompletions } from "./openai-routes.server.ts";

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

describe("handleChatCompletions wire contract", () => {
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
});
