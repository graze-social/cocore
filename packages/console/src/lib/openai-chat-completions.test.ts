// Tests for the OpenAI-shaped error mapping + buffered response
// drainer, plus the streaming path's wire contract (it MUST be an
// SSE stream — `text/event-stream` with `data:` frames and a
// terminal `[DONE]` — for OpenAI clients like Apollo to accept it).

import assert from "node:assert/strict";
import { describe, test } from "vitest";

import { MESSAGES_V1, parseEnvelope } from "@cocore/sdk/multimodal-envelope";

import type { DispatchErrorCode, DispatchEvent } from "./inference-dispatch.server.ts";
import {
  buildJobInput,
  bufferedResponse,
  dispatchErrorToHttpResponse,
  normalizeMessageContent,
  parseRequest,
  requestHasImages,
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

  test("rejects an unparseable image url with no text", () => {
    // "x" is neither a data: URI nor http(s) — nothing we can turn into an
    // image, and no text either, so the message is rejected.
    assert.equal(normalizeMessageContent([{ type: "image_url", image_url: { url: "x" } }]), null);
  });

  test("accepts a data-URI image as a structured part", () => {
    const out = normalizeMessageContent([
      { type: "text", text: "what is this?" },
      { type: "image_url", image_url: { url: "data:image/png;base64,aGVsbG8=" } },
    ]);
    assert.deepEqual(out, [
      { type: "text", text: "what is this?" },
      { type: "image", mime: "image/png", data: "aGVsbG8=" },
    ]);
  });

  test("marks an http(s) image url as a remote part to fetch", () => {
    const out = normalizeMessageContent([
      { type: "image_url", image_url: { url: "https://example.com/cat.png" } },
    ]);
    assert.deepEqual(out, [{ type: "image_remote", url: "https://example.com/cat.png" }]);
  });
});

describe("buildJobInput", () => {
  test("text-only request keeps the legacy flattened bytes, no inputFormat", async () => {
    const parsed = parseRequest({
      model: "stub",
      messages: [{ role: "user", content: "hello" }],
    });
    assert.notEqual(typeof parsed, "string");
    if (typeof parsed === "string") return;
    assert.equal(requestHasImages(parsed.messages), false);
    const { payloadBytes, inputFormat } = await buildJobInput(parsed.messages);
    assert.equal(inputFormat, undefined);
    assert.equal(new TextDecoder().decode(payloadBytes), "user: hello");
  });

  test("image request produces a messages-v1 envelope", async () => {
    const parsed = parseRequest({
      model: "vlm",
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: "describe" },
            { type: "image_url", image_url: { url: "data:image/png;base64,aGVsbG8=" } },
          ],
        },
      ],
    });
    assert.notEqual(typeof parsed, "string");
    if (typeof parsed === "string") return;
    assert.equal(requestHasImages(parsed.messages), true);
    const { payloadBytes, inputFormat } = await buildJobInput(parsed.messages);
    assert.equal(inputFormat, MESSAGES_V1);
    const env = parseEnvelope(payloadBytes);
    assert.deepEqual(env.messages, [
      {
        role: "user",
        content: [
          { type: "text", text: "describe" },
          { type: "image", mime: "image/png", data: "aGVsbG8=" },
        ],
      },
    ]);
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

  test("no-providers-for-version becomes 503 (retryable as the fleet updates)", () => {
    const out = dispatchErrorToHttpResponse("no-providers-for-version");
    assert.equal(out.status, 503);
    assert.equal(out.type, "service_unavailable_error");
    assert.equal(out.code, "no_providers_for_version");
  });
});

describe("parseRequest min_provider_version", () => {
  const base = { model: "stub", messages: [{ role: "user", content: "hi" }] };

  test("accepts a dotted-numeric version and normalizes nothing", () => {
    const parsed = parseRequest({ ...base, min_provider_version: "0.9.32" });
    assert.notEqual(typeof parsed, "string");
    if (typeof parsed === "string") return;
    assert.equal(parsed.minProviderVersion, "0.9.32");
  });

  test("tolerates a leading v and trims whitespace", () => {
    const parsed = parseRequest({ ...base, min_provider_version: " v1.2.3 " });
    assert.notEqual(typeof parsed, "string");
    if (typeof parsed === "string") return;
    assert.equal(parsed.minProviderVersion, "v1.2.3");
  });

  test("treats null/absent as no floor", () => {
    for (const v of [undefined, null]) {
      const parsed = parseRequest({ ...base, min_provider_version: v });
      assert.notEqual(typeof parsed, "string");
      if (typeof parsed === "string") return;
      assert.equal(parsed.minProviderVersion, undefined);
    }
  });

  test("rejects a non-version string with a 400-shaped message", () => {
    const parsed = parseRequest({ ...base, min_provider_version: "latest" });
    assert.equal(typeof parsed, "string");
    if (typeof parsed !== "string") return;
    assert.match(parsed, /min_provider_version/);
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

// ─── Tool calling tests ───

describe("parseRequest with tools", () => {
  test("extracts tools and toolChoice from an OpenAI-compatible request", () => {
    const parsed = parseRequest({
      model: "stub",
      messages: [{ role: "user", content: "What's the weather in Tokyo?" }],
      tools: [
        {
          type: "function",
          function: {
            name: "get_weather",
            description: "Get weather for a city",
            parameters: {
              type: "object",
              properties: { city: { type: "string" } },
              required: ["city"],
            },
          },
        },
      ],
      tool_choice: "auto",
    });
    assert.notEqual(typeof parsed, "string");
    if (typeof parsed === "string") return;
    assert.ok(parsed.tools, "tools should be present");
    assert.equal(parsed.tools!.length, 1);
    assert.equal(parsed.tools![0]!.function.name, "get_weather");
    assert.equal(parsed.toolChoice, "auto");
  });

  test("parses tool_choice object form into required + toolChoiceFunction", () => {
    const parsed = parseRequest({
      model: "stub",
      messages: [{ role: "user", content: "What's the weather?" }],
      tools: [
        {
          type: "function",
          function: { name: "get_weather", description: "Get weather" },
        },
      ],
      tool_choice: { type: "function", function: { name: "get_weather" } },
    });
    assert.notEqual(typeof parsed, "string");
    if (typeof parsed === "string") return;
    assert.equal(parsed.toolChoice, "required");
    assert.equal(parsed.toolChoiceFunction, "get_weather");
  });

  test("rejects tool_choice object with wrong type", () => {
    const parsed = parseRequest({
      model: "stub",
      messages: [{ role: "user", content: "hi" }],
      tool_choice: { type: "code", function: { name: "foo" } },
    });
    assert.equal(typeof parsed, "string");
    assert.match(parsed as string, /type must be 'function'/);
  });

  test("rejects tool_choice object missing function.name", () => {
    const parsed = parseRequest({
      model: "stub",
      messages: [{ role: "user", content: "hi" }],
      tool_choice: { type: "function", function: {} },
    });
    assert.equal(typeof parsed, "string");
    assert.match(parsed as string, /function\.name/);
  });

  test("passes through tool_calls and tool_call_id on messages", () => {
    const parsed = parseRequest({
      model: "stub",
      messages: [
        { role: "user", content: "What's the weather?" },
        {
          role: "assistant",
          content: null,
          tool_calls: [
            {
              id: "call_abc",
              type: "function",
              function: { name: "get_weather", arguments: '{"city":"Tokyo"}' },
            },
          ],
        },
        { role: "tool", tool_call_id: "call_abc", content: '{"temperature":22}' },
      ],
    });
    assert.notEqual(typeof parsed, "string");
    if (typeof parsed === "string") return;
    // The assistant message should carry tool_calls.
    const assistant = parsed.messages.find((m) => m.role === "assistant");
    assert.ok(assistant, "assistant message present");
    assert.ok(assistant!.tool_calls, "tool_calls present on assistant");
    assert.equal(assistant!.tool_calls![0]!.function.name, "get_weather");
    // The tool message should carry tool_call_id.
    const tool = parsed.messages.find((m) => m.role === "tool");
    assert.ok(tool, "tool message present");
    assert.equal(tool!.tool_call_id, "call_abc");
  });

  test("rejects tool_calls that is not an array", () => {
    const parsed = parseRequest({
      model: "stub",
      messages: [
        { role: "user", content: "hi" },
        { role: "assistant", content: null, tool_calls: "not-an-array" as unknown as never },
      ],
    });
    assert.equal(typeof parsed, "string");
    assert.match(parsed as string, /tool_calls must be an array/);
  });
});

describe("bufferedResponse with tool calls", () => {
  test("reassembles tool_call chunks into tool_calls with finish_reason=tool_calls", async () => {
    const res = await bufferedResponse(
      "chatcmpl-id",
      "stub",
      yieldEvents([
        // First delta: id + function name
        {
          kind: "chunk",
          seq: 0,
          channel: "tool_call",
          text: JSON.stringify([
            {
              index: 0,
              id: "call_abc123",
              type: "function",
              function: { name: "get_weather", arguments: "" },
            },
          ]),
        },
        // Second delta: arguments fragment
        {
          kind: "chunk",
          seq: 1,
          channel: "tool_call",
          text: JSON.stringify([
            {
              index: 0,
              function: { arguments: '{"city":"Tokyo"}' },
            },
          ]),
        },
        { kind: "complete", tokensIn: 10, tokensOut: 5, receiptUri: "at://x" },
      ]),
    );
    assert.equal(res.status, 200);
    const body = (await res.json()) as {
      choices: Array<{
        message: {
          tool_calls?: Array<{
            id: string;
            type: string;
            function: { name: string; arguments: string };
          }>;
          content: string;
        };
        finish_reason: string;
      }>;
    };
    assert.equal(body.choices[0]!.finish_reason, "tool_calls");
    assert.ok(body.choices[0]!.message.tool_calls, "tool_calls present");
    assert.equal(body.choices[0]!.message.tool_calls!.length, 1);
    const tc = body.choices[0]!.message.tool_calls![0]!;
    assert.equal(tc.id, "call_abc123");
    assert.equal(tc.type, "function");
    assert.equal(tc.function.name, "get_weather");
    assert.equal(tc.function.arguments, '{"city":"Tokyo"}');
  });

  test("content + tool_calls: content is preserved alongside tool calls", async () => {
    const res = await bufferedResponse(
      "chatcmpl-id",
      "stub",
      yieldEvents([
        { kind: "chunk", seq: 0, channel: "content", text: "Let me check the weather." },
        {
          kind: "chunk",
          seq: 1,
          channel: "tool_call",
          text: JSON.stringify([
            {
              index: 0,
              id: "call_1",
              type: "function",
              function: { name: "get_weather", arguments: '{"city":"NYC"}' },
            },
          ]),
        },
        { kind: "complete", tokensIn: 5, tokensOut: 10, receiptUri: "at://x" },
      ]),
    );
    const body = (await res.json()) as {
      choices: Array<{
        message: { content: string; tool_calls?: unknown[] };
        finish_reason: string;
      }>;
    };
    assert.equal(body.choices[0]!.finish_reason, "tool_calls");
    assert.equal(body.choices[0]!.message.content, "Let me check the weather.");
    assert.ok(body.choices[0]!.message.tool_calls);
  });

  test("no tool_calls when no tool_call chunks arrive", async () => {
    const res = await bufferedResponse(
      "chatcmpl-id",
      "stub",
      yieldEvents([
        { kind: "chunk", seq: 0, channel: "content", text: "just a normal response" },
        { kind: "complete", tokensIn: 1, tokensOut: 1, receiptUri: "at://x" },
      ]),
    );
    const body = (await res.json()) as {
      choices: Array<{
        message: { tool_calls?: unknown[] };
        finish_reason: string;
      }>;
    };
    assert.equal(body.choices[0]!.finish_reason, "stop");
    assert.equal(body.choices[0]!.message.tool_calls, undefined);
  });
});

describe("streamingResponse with tool calls", () => {
  test("emits delta.tool_calls in SSE when tool_call channel chunks arrive", async () => {
    const res = streamingResponse(
      "chatcmpl-id",
      "stub",
      yieldEvents([
        {
          kind: "chunk",
          seq: 0,
          channel: "tool_call",
          text: JSON.stringify([
            {
              index: 0,
              id: "call_abc",
              type: "function",
              function: { name: "get_weather", arguments: '{"city":"Tokyo"}' },
            },
          ]),
        },
        { kind: "complete", tokensIn: 5, tokensOut: 3, receiptUri: "at://x" },
      ]),
    );
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /^text\/event-stream/);

    const data = await readSseData(res);
    assert.equal(data.at(-1), "[DONE]");

    const chunks = data
      .filter((d) => d !== "[DONE]")
      .map(
        (d) =>
          JSON.parse(d) as {
            choices: Array<{
              delta: { tool_calls?: unknown[] };
              finish_reason: string | null;
            }>;
          },
      );

    // Find the chunk that carries tool_calls (skip [DONE] terminator).
    const toolCallChunk = chunks.find((c) => c.choices[0]?.delta.tool_calls);

    assert.ok(toolCallChunk, "at least one SSE chunk should carry delta.tool_calls");
    const tc = toolCallChunk!.choices[0]!.delta.tool_calls as Array<{
      id: string;
      function: { name: string; arguments: string };
    }>;
    assert.equal(tc[0]!.id, "call_abc");
    assert.equal(tc[0]!.function.name, "get_weather");
    assert.equal(tc[0]!.function.arguments, '{"city":"Tokyo"}');

    const finalChunk = chunks.at(-1)!;
    assert.equal(finalChunk.choices[0]!.finish_reason, "tool_calls");
  });

  test("emits content and tool_calls in separate SSE chunks", async () => {
    const res = streamingResponse(
      "chatcmpl-id",
      "stub",
      yieldEvents([
        { kind: "chunk", seq: 0, channel: "content", text: "Checking" },
        {
          kind: "chunk",
          seq: 1,
          channel: "tool_call",
          text: JSON.stringify([
            {
              index: 0,
              id: "call_1",
              type: "function",
              function: { name: "lookup", arguments: "{}" },
            },
          ]),
        },
        { kind: "complete", tokensIn: 1, tokensOut: 2, receiptUri: "at://x" },
      ]),
    );
    const data = await readSseData(res);
    const chunks = data
      .slice(0, -1) // drop [DONE]
      .map(
        (d) =>
          JSON.parse(d) as {
            choices: Array<{ delta: Record<string, unknown>; finish_reason: string | null }>;
          },
      );

    const contentChunks = chunks.filter((c) => c.choices[0]?.delta.content);
    const toolCallChunks = chunks.filter((c) => c.choices[0]?.delta.tool_calls);

    assert.ok(contentChunks.length > 0, "at least one content chunk");
    assert.ok(toolCallChunks.length > 0, "at least one tool_call chunk");
    assert.equal(chunks.at(-1)!.choices[0]!.finish_reason, "tool_calls");
  });
});

describe("parseRequest with response_format", () => {
  test("parses response_format json_schema into outputSchema", () => {
    const parsed = parseRequest({
      model: "stub",
      messages: [{ role: "user", content: "List 3 fruits as JSON." }],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "fruit_list",
          strict: true,
          schema: {
            type: "object",
            properties: {
              fruits: { type: "array", items: { type: "string" } },
            },
            required: ["fruits"],
          },
        },
      },
    });
    assert.notEqual(typeof parsed, "string");
    if (typeof parsed === "string") return;
    assert.ok(parsed.outputSchema, "outputSchema should be present");
    assert.equal(parsed.outputSchema!.name, "fruit_list");
    assert.equal(parsed.outputSchema!.strict, true);
    assert.ok(parsed.outputSchema!.schema.properties, "schema should have properties");
  });

  test("parses response_format without strict field", () => {
    const parsed = parseRequest({
      model: "stub",
      messages: [{ role: "user", content: "Return JSON." }],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "simple",
          schema: { type: "object" },
        },
      },
    });
    assert.notEqual(typeof parsed, "string");
    if (typeof parsed === "string") return;
    assert.ok(parsed.outputSchema);
    assert.equal(parsed.outputSchema!.name, "simple");
    assert.equal(parsed.outputSchema!.strict, undefined);
  });

  test("rejects response_format with wrong type", () => {
    const parsed = parseRequest({
      model: "stub",
      messages: [{ role: "user", content: "hi" }],
      response_format: { type: "text" },
    });
    assert.equal(typeof parsed, "string");
    assert.match(parsed as string, /json_schema/);
  });

  test("rejects response_format missing json_schema.name", () => {
    const parsed = parseRequest({
      model: "stub",
      messages: [{ role: "user", content: "hi" }],
      response_format: {
        type: "json_schema",
        json_schema: { schema: { type: "object" } },
      },
    });
    assert.equal(typeof parsed, "string");
    assert.match(parsed as string, /name/);
  });

  test("rejects response_format missing json_schema.schema", () => {
    const parsed = parseRequest({
      model: "stub",
      messages: [{ role: "user", content: "hi" }],
      response_format: {
        type: "json_schema",
        json_schema: { name: "test" },
      },
    });
    assert.equal(typeof parsed, "string");
    assert.match(parsed as string, /schema/);
  });
});
