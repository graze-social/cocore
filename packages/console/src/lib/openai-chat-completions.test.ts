// Tests for the OpenAI-shaped error mapping + buffered response
// drainer, plus the streaming path's wire contract (it MUST be an
// SSE stream — `text/event-stream` with `data:` frames and a
// terminal `[DONE]` — for OpenAI clients like Apollo to accept it).

import assert from "node:assert/strict";
import { describe, test } from "vitest";

import type { DispatchErrorCode, DispatchEvent } from "./inference-dispatch.server.ts";
import {
  bufferedResponse,
  dispatchErrorToHttpResponse,
  normalizeMessageContent,
  parseRequest,
  streamingResponse,
} from "./openai-chat-completions.server.ts";

describe("normalizeMessageContent", () => {
  test("passes through plain strings", () => {
    assert.equal(normalizeMessageContent("hello"), "hello");
  });

  test("extracts text from OpenAI-style content parts", () => {
    assert.equal(
      normalizeMessageContent([
        { type: "text", text: "line one" },
        { type: "text", text: "line two" },
      ]),
      "line one\nline two",
    );
  });

  test("treats null/undefined as empty", () => {
    assert.equal(normalizeMessageContent(null), "");
    assert.equal(normalizeMessageContent(undefined), "");
  });

  test("rejects non-text parts when no text is present", () => {
    assert.equal(normalizeMessageContent([{ type: "image_url", image_url: { url: "x" } }]), null);
  });
});

describe("parseRequest", () => {
  test("accepts Cursor/OpenAI array message content", () => {
    const parsed = parseRequest({
      model: "stub",
      messages: [{ role: "user", content: [{ type: "text", text: "hello from cursor" }] }],
    });
    assert.notEqual(typeof parsed, "string");
    if (typeof parsed === "string") return;
    assert.equal(parsed.messages[0]!.content, "hello from cursor");
  });
});

describe("dispatchErrorToHttpResponse", () => {
  test("no-providers-for-model becomes 404 model_not_found", () => {
    const out = dispatchErrorToHttpResponse("no-providers-for-model");
    assert.equal(out.status, 404);
    assert.equal(out.type, "invalid_request_error");
    assert.equal(out.code, "model_not_found");
  });

  test("no-friends-for-model also becomes 404 with its own code", () => {
    const out = dispatchErrorToHttpResponse("no-friends-for-model");
    assert.equal(out.status, 404);
    assert.equal(out.code, "no_friends_for_model");
  });

  test("no-friends-available becomes 503 service_unavailable_error", () => {
    const out = dispatchErrorToHttpResponse("no-friends-available");
    assert.equal(out.status, 503);
    assert.equal(out.type, "service_unavailable_error");
    assert.equal(out.code, "no_friends_available");
  });

  test("no-providers-connected becomes 503 with the matching code", () => {
    const out = dispatchErrorToHttpResponse("no-providers-connected");
    assert.equal(out.status, 503);
    assert.equal(out.code, "no_providers_connected");
  });

  test("pipeline failures collapse to 502 server_error with a distinct code", () => {
    for (const code of [
      "pds-publish-failed",
      "provider-encryption-key-malformed",
      "chunk-decrypt-failed",
      "advisor-rejected",
      "advisor-transport",
      "unknown",
    ] as DispatchErrorCode[]) {
      const out = dispatchErrorToHttpResponse(code);
      assert.equal(out.status, 502, `expected 502 for ${code}`);
      assert.equal(out.type, "server_error", `expected server_error type for ${code}`);
    }
  });

  test("provider-payouts-not-eligible becomes 403 permission_error", () => {
    const out = dispatchErrorToHttpResponse("provider-payouts-not-eligible");
    assert.equal(out.status, 403);
    assert.equal(out.type, "permission_error");
  });
});

async function* yieldEvents(events: DispatchEvent[]): AsyncIterable<DispatchEvent> {
  for (const ev of events) yield ev;
}

describe("bufferedResponse error mapping", () => {
  test("happy path: aggregates chunks into a single OpenAI chat completion body", async () => {
    const res = await bufferedResponse(
      "chatcmpl-id",
      "stub",
      yieldEvents([
        { kind: "chunk", seq: 0, channel: "content", text: "hello " },
        { kind: "chunk", seq: 1, channel: "content", text: "world" },
        { kind: "complete", tokensIn: 3, tokensOut: 2, receiptUri: "at://x" },
      ]),
    );
    assert.equal(res.status, 200);
    const body = (await res.json()) as {
      choices: Array<{ message: { content: string } }>;
      usage: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
    };
    assert.equal(body.choices[0]!.message.content, "hello world");
    assert.equal(body.usage.prompt_tokens, 3);
    assert.equal(body.usage.completion_tokens, 2);
    assert.equal(body.usage.total_tokens, 5);
  });

  test("reasoning chunks surface as message.reasoning_content, separate from content", async () => {
    const res = await bufferedResponse(
      "chatcmpl-id",
      "stub",
      yieldEvents([
        { kind: "chunk", seq: 0, channel: "reasoning", text: "let me think… " },
        { kind: "chunk", seq: 1, channel: "reasoning", text: "2+2=4" },
        { kind: "chunk", seq: 2, channel: "content", text: "The answer is 4." },
        { kind: "complete", tokensIn: 3, tokensOut: 6, receiptUri: "at://x" },
      ]),
    );
    const body = (await res.json()) as {
      choices: Array<{ message: { content: string; reasoning_content?: string } }>;
    };
    assert.equal(body.choices[0]!.message.content, "The answer is 4.");
    assert.equal(body.choices[0]!.message.reasoning_content, "let me think… 2+2=4");
  });

  test("no reasoning_content field when the model emitted no reasoning", async () => {
    const res = await bufferedResponse(
      "chatcmpl-id",
      "stub",
      yieldEvents([
        { kind: "chunk", seq: 0, channel: "content", text: "hi" },
        { kind: "complete", tokensIn: 1, tokensOut: 1, receiptUri: "" },
      ]),
    );
    const body = (await res.json()) as {
      choices: Array<{ message: { reasoning_content?: string } }>;
    };
    assert.equal(body.choices[0]!.message.reasoning_content, undefined);
  });

  test("provider credit surfaces as an x_cocore block on the completion", async () => {
    const res = await bufferedResponse(
      "chatcmpl-id",
      "stub",
      yieldEvents([
        { kind: "chunk", seq: 0, channel: "content", text: "hi" },
        {
          kind: "complete",
          tokensIn: 1,
          tokensOut: 1,
          receiptUri: "at://did:plc:p/dev.cocore.compute.receipt/1",
          providerCredit: {
            did: "did:plc:p",
            handle: "devingaffney.com",
            displayName: null,
            machineLabel: "Mac-mini.local",
            line: "this completion lovingly created for you by devingaffney.com via their Mac-mini.local server",
          },
        },
      ]),
    );
    assert.equal(res.status, 200);
    const body = (await res.json()) as {
      x_cocore?: {
        credit?: string;
        receiptUri?: string;
        provider?: { handle?: string; machineLabel?: string };
      };
    };
    assert.ok(body.x_cocore, "expected an x_cocore block");
    assert.match(body.x_cocore!.credit ?? "", /lovingly created for you by devingaffney\.com/);
    assert.equal(body.x_cocore!.provider?.machineLabel, "Mac-mini.local");
    assert.equal(body.x_cocore!.receiptUri, "at://did:plc:p/dev.cocore.compute.receipt/1");
  });

  test("no x_cocore block when the completion carries no provider credit", async () => {
    const res = await bufferedResponse(
      "chatcmpl-id",
      "stub",
      yieldEvents([
        { kind: "chunk", seq: 0, channel: "content", text: "hi" },
        { kind: "complete", tokensIn: 1, tokensOut: 1, receiptUri: "" },
      ]),
    );
    const body = (await res.json()) as { x_cocore?: unknown };
    assert.equal(body.x_cocore, undefined);
  });

  test("no-providers-for-model returns 404 with OpenAI's model_not_found code", async () => {
    const res = await bufferedResponse(
      "chatcmpl-id",
      "stub",
      yieldEvents([
        {
          kind: "error",
          reason: "no connected provider serves model 'stub' (4 providers online overall)",
          code: "no-providers-for-model",
        },
      ]),
    );
    assert.equal(res.status, 404);
    const body = (await res.json()) as {
      error: { message: string; type: string; code: string | null };
    };
    assert.equal(body.error.type, "invalid_request_error");
    assert.equal(body.error.code, "model_not_found");
    assert.match(body.error.message, /stub/);
  });

  test("no-capacity (failover exhausted) returns a clean, retryable 503 with no internals", async () => {
    const res = await bufferedResponse(
      "chatcmpl-id",
      "stub",
      yieldEvents([
        {
          kind: "error",
          reason: "The model is temporarily unavailable. Please retry.",
          code: "no-capacity",
        },
      ]),
    );
    assert.equal(res.status, 503);
    const body = (await res.json()) as {
      error: { message: string; type: string; code: string | null };
    };
    assert.equal(body.error.type, "service_unavailable_error");
    assert.equal(body.error.code, "model_unavailable");
    // Crucially, the message must NOT leak advisor internals — no provider
    // DID, no "attested", no "preflighted N", no `/jobs 503` plumbing.
    assert.doesNotMatch(body.error.message, /did:plc|attested|preflight|\/jobs|advisor/i);
    assert.match(body.error.message, /temporarily unavailable/i);
  });

  test("no-friends-available returns 503 with no_friends_available code", async () => {
    const res = await bufferedResponse(
      "chatcmpl-id",
      "stub",
      yieldEvents([
        {
          kind: "error",
          reason: "you have no friends; add some at /friends",
          code: "no-friends-available",
        },
      ]),
    );
    assert.equal(res.status, 503);
    const body = (await res.json()) as { error: { code: string | null } };
    assert.equal(body.error.code, "no_friends_available");
  });

  test("error events short-circuit the buffered response (no 200 emitted after)", async () => {
    const res = await bufferedResponse(
      "chatcmpl-id",
      "stub",
      yieldEvents([
        { kind: "chunk", seq: 0, channel: "content", text: "partial" },
        { kind: "error", reason: "boom", code: "advisor-rejected" },
      ]),
    );
    assert.equal(res.status, 502);
    const body = (await res.json()) as { error: { message: string } };
    assert.equal(body.error.message, "boom");
  });
});

/** Parse an SSE Response body into its `data:` payloads. Returns the
 *  raw payload strings in order (including the terminal `[DONE]`), so a
 *  test can assert both the framing and the decoded chunk shapes. */
async function readSseData(res: Response): Promise<string[]> {
  const text = await res.text();
  const out: string[] = [];
  for (const block of text.split("\n\n")) {
    for (const line of block.split("\n")) {
      if (line.startsWith("data: ")) out.push(line.slice(6));
    }
  }
  return out;
}

describe("streamingResponse is an SSE stream", () => {
  test("happy path: text/event-stream with role delta, content chunk, and [DONE]", async () => {
    const res = streamingResponse(
      "chatcmpl-id",
      "stub",
      yieldEvents([
        { kind: "chunk", seq: 0, channel: "content", text: "hello world" },
        { kind: "complete", tokensIn: 3, tokensOut: 2, receiptUri: "at://x" },
      ]),
    );

    // The contract Apollo et al. check: 200 + text/event-stream. A
    // non-stream content-type here is exactly what surfaces client-side
    // as "The response is not a stream."
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /^text\/event-stream/);

    const data = await readSseData(res);
    assert.equal(data.at(-1), "[DONE]");

    // First frame is the role-only delta OpenAI clients expect.
    const first = JSON.parse(data[0]!) as {
      object: string;
      choices: Array<{ delta: { role?: string; content?: string }; finish_reason: string | null }>;
    };
    assert.equal(first.object, "chat.completion.chunk");
    assert.equal(first.choices[0]!.delta.role, "assistant");

    // The content chunk carries the streamed text.
    const contents = data
      .slice(0, -1)
      .map((d) => JSON.parse(d) as { choices: Array<{ delta: { content?: string } }> })
      .map((c) => c.choices[0]!.delta.content ?? "")
      .join("");
    assert.equal(contents, "hello world");
  });

  test("reasoning chunks ride delta.reasoning_content, content rides delta.content", async () => {
    const res = streamingResponse(
      "chatcmpl-id",
      "stub",
      yieldEvents([
        { kind: "chunk", seq: 0, channel: "reasoning", text: "thinking… " },
        { kind: "chunk", seq: 1, channel: "content", text: "answer" },
        { kind: "complete", tokensIn: 1, tokensOut: 2, receiptUri: "at://x" },
      ]),
    );
    const data = await readSseData(res);
    const deltas = data
      .slice(0, -1)
      .map((d) => JSON.parse(d) as { choices: Array<{ delta: Record<string, unknown> }> })
      .map((c) => c.choices[0]!.delta);
    const reasoning = deltas.map((d) => (d.reasoning_content as string) ?? "").join("");
    const content = deltas.map((d) => (d.content as string) ?? "").join("");
    assert.equal(reasoning, "thinking… ");
    assert.equal(content, "answer");
  });

  test("an error-first dispatch streams the error on the DEFAULT event (OpenAI shape)", async () => {
    // Regression guard for the Apollo "response is not a stream" bug:
    // dispatch errors must ride a default-event `data:` frame carrying an
    // `{ error: {...} }` object (the de-facto OpenAI mid-stream error
    // shape), NOT a named `event: error` frame that minimal SSE clients
    // drop. OpenAI interrupts with the error frame and closes — there is
    // deliberately no `[DONE]` terminator after an error.
    const res = streamingResponse(
      "chatcmpl-id",
      "stub",
      yieldEvents([
        {
          kind: "error",
          reason: "no connected provider serves model 'stub'",
          code: "no-providers-for-model",
        },
      ]),
    );

    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /^text\/event-stream/);

    const text = await res.text();
    // No named SSE event — error rides the default `data:` channel.
    assert.doesNotMatch(text, /^event:/m);
    // And no [DONE] after an error — OpenAI interrupts and closes.
    assert.doesNotMatch(text, /\[DONE\]/);

    const data: string[] = [];
    for (const block of text.split("\n\n")) {
      for (const line of block.split("\n")) {
        if (line.startsWith("data: ")) data.push(line.slice(6));
      }
    }
    const errFrame = data.find((d) => d.includes('"error"'))!;
    const parsed = JSON.parse(errFrame) as { error: { code: string; type: string } };
    assert.equal(parsed.error.code, "model_not_found");
    assert.equal(parsed.error.type, "invalid_request_error");
  });
});
