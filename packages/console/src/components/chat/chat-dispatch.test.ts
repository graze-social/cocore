// Routing tests for the browser-side dispatch SSE consumer. The advisor's
// chunks are already decrypted by the server route by the time they reach this
// module, so we mock `fetch` with a canned SSE body and assert that content vs
// reasoning chunks land on the right callbacks and result fields.

import assert from "node:assert/strict";
import { afterEach, describe, test } from "vitest";

import { dispatchChatTurn } from "./chat-dispatch.ts";

/** Build a Response whose body streams the given SSE text in one chunk. */
function sseResponse(body: string): Response {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(body));
      controller.close();
    },
  });
  return new Response(stream, {
    status: 200,
    headers: { "content-type": "text/event-stream" },
  });
}

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("dispatchChatTurn channel routing", () => {
  test("reasoning chunks route to onReasoning, content to onChunk", async () => {
    const sse = [
      `event: meta\ndata: ${JSON.stringify({ providerDid: "did:plc:p", jobUri: "at://j" })}\n\n`,
      `event: chunk\ndata: ${JSON.stringify({ seq: 0, channel: "reasoning", text: "thinking… " })}\n\n`,
      `event: chunk\ndata: ${JSON.stringify({ seq: 1, channel: "content", text: "the " })}\n\n`,
      `event: chunk\ndata: ${JSON.stringify({ seq: 2, channel: "content", text: "answer" })}\n\n`,
      `event: complete\ndata: ${JSON.stringify({ tokensIn: 3, tokensOut: 4, receiptUri: "at://r" })}\n\n`,
    ].join("");
    globalThis.fetch = async () => sseResponse(sse);

    const content: string[] = [];
    const reasoning: string[] = [];
    const result = await dispatchChatTurn({
      model: "stub",
      prompt: "hi",
      maxTokensOut: 16,
      onChunk: (t) => content.push(t),
      onReasoning: (t) => reasoning.push(t),
    });

    assert.deepEqual(reasoning, ["thinking… "]);
    assert.deepEqual(content, ["the ", "answer"]);
    assert.equal(result.text, "the answer");
    assert.equal(result.reasoning, "thinking… ");
    assert.equal(result.tokensIn, 3);
    assert.equal(result.tokensOut, 4);
  });

  test("a chunk with no channel defaults to the answer (content)", async () => {
    const sse =
      `event: chunk\ndata: ${JSON.stringify({ seq: 0, text: "plain" })}\n\n` +
      `event: complete\ndata: ${JSON.stringify({ tokensIn: 1, tokensOut: 1, receiptUri: "" })}\n\n`;
    globalThis.fetch = async () => sseResponse(sse);

    const result = await dispatchChatTurn({
      model: "stub",
      prompt: "hi",
      maxTokensOut: 16,
    });
    assert.equal(result.text, "plain");
    assert.equal(result.reasoning, "");
  });
});
