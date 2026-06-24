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

  test("attaches images as structured messages on the latest user turn", async () => {
    const sse = `event: complete\ndata: ${JSON.stringify({ tokensIn: 1, tokensOut: 1, receiptUri: "" })}\n\n`;
    let sentBody: Record<string, unknown> = {};
    globalThis.fetch = async (_url, init) => {
      sentBody = JSON.parse((init as RequestInit).body as string) as Record<string, unknown>;
      return sseResponse(sse);
    };

    await dispatchChatTurn({
      model: "vlm",
      prompt: "user: describe this",
      transcript: [{ role: "user", text: "describe this" }],
      images: [{ mime: "image/png", data: "aGVsbG8=" }],
      maxTokensOut: 16,
    });

    // The body carries structured messages; the last turn has the image part.
    const messages = sentBody["messages"] as Array<{ role: string; content: unknown }>;
    assert.ok(Array.isArray(messages), "expected messages in the body");
    assert.deepEqual(messages[messages.length - 1], {
      role: "user",
      content: [
        { type: "text", text: "describe this" },
        { type: "image", mime: "image/png", data: "aGVsbG8=" },
      ],
    });
  });

  test("no messages field when there are no images (text path)", async () => {
    const sse = `event: complete\ndata: ${JSON.stringify({ tokensIn: 1, tokensOut: 1, receiptUri: "" })}\n\n`;
    let sentBody: Record<string, unknown> = {};
    globalThis.fetch = async (_url, init) => {
      sentBody = JSON.parse((init as RequestInit).body as string) as Record<string, unknown>;
      return sseResponse(sse);
    };
    await dispatchChatTurn({ model: "stub", prompt: "hi", maxTokensOut: 16 });
    assert.equal(sentBody["messages"], undefined);
    assert.equal(sentBody["prompt"], "hi");
  });

  test("image chunks route to onImage and populate result.images", async () => {
    const sse = [
      `event: meta\ndata: ${JSON.stringify({ providerDid: "did:plc:p", jobUri: "at://j" })}\n\n`,
      `event: chunk\ndata: ${JSON.stringify({ seq: 0, channel: "image", mime: "image/png", data: "aGVsbG8=" })}\n\n`,
      `event: complete\ndata: ${JSON.stringify({ tokensIn: 5, tokensOut: 6, receiptUri: "at://r", outputFormat: "images-v1" })}\n\n`,
    ].join("");
    globalThis.fetch = async () => sseResponse(sse);

    const images: Array<{ mime: string; data: string }> = [];
    const content: string[] = [];
    const result = await dispatchChatTurn({
      model: "stub-flux",
      prompt: "a red apple",
      maxTokensOut: 16,
      onChunk: (t) => content.push(t),
      onImage: (img) => images.push(img),
    });

    assert.deepEqual(images, [{ mime: "image/png", data: "aGVsbG8=" }]);
    assert.deepEqual(result.images, [{ mime: "image/png", data: "aGVsbG8=" }]);
    assert.equal(result.outputFormat, "images-v1");
    assert.equal(result.text, ""); // no text on an image turn
    assert.deepEqual(content, []);
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
