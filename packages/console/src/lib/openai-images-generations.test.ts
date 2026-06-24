import assert from "node:assert/strict";
import { describe, test } from "vitest";

import type { DispatchEvent } from "@/lib/inference-dispatch.server.ts";
import {
  collectImageDispatch,
  editsJobInput,
  generationsJobInput,
  generationsResponse,
  type ImageSlotResult,
  parseGenerationsRequest,
} from "@/lib/openai-images-generations.server.ts";
import { parseImagesEnvelope } from "@cocore/sdk/images-envelope";
import { parseEnvelope } from "@cocore/sdk/multimodal-envelope";

async function* events(...evs: DispatchEvent[]): AsyncGenerator<DispatchEvent> {
  for (const e of evs) yield e;
}

describe("parseGenerationsRequest", () => {
  test("accepts a minimal valid request and defaults n=1", () => {
    const out = parseGenerationsRequest({ model: "stub-flux", prompt: "a fox" });
    assert.deepEqual(out, { model: "stub-flux", prompt: "a fox", n: 1 });
  });

  test("rejects missing model / prompt", () => {
    assert.equal(typeof parseGenerationsRequest({ prompt: "x" }), "string");
    assert.equal(typeof parseGenerationsRequest({ model: "stub-flux" }), "string");
  });

  test('rejects response_format "url" with a clear message', () => {
    const out = parseGenerationsRequest({
      model: "stub-flux",
      prompt: "x",
      response_format: "url",
    });
    assert.equal(typeof out, "string");
    assert.match(out as string, /b64_json/);
  });

  test("accepts b64_json and bounds n to 1..4", () => {
    assert.deepEqual(parseGenerationsRequest({ model: "m", prompt: "x", response_format: "b64_json", n: 4 }), {
      model: "m",
      prompt: "x",
      n: 4,
    });
    assert.equal(typeof parseGenerationsRequest({ model: "m", prompt: "x", n: 5 }), "string");
    assert.equal(typeof parseGenerationsRequest({ model: "m", prompt: "x", n: 0 }), "string");
  });
});

describe("job input builders", () => {
  test("generationsJobInput seals the raw prompt (text path)", () => {
    const { payloadBytes, inputFormat } = generationsJobInput("a fox");
    assert.equal(inputFormat, undefined);
    assert.equal(new TextDecoder().decode(payloadBytes), "a fox");
  });

  test("editsJobInput seals a messages-v1 envelope with the reference image", () => {
    const { payloadBytes, inputFormat } = editsJobInput({
      model: "stub-flux",
      prompt: "make it watercolor",
      n: 1,
      image: { mime: "image/png", data: "aGVsbG8=" },
    });
    assert.equal(inputFormat, "messages-v1");
    const env = parseEnvelope(payloadBytes);
    assert.equal(env.messages.length, 1);
    assert.deepEqual(env.messages[0]!.content, [
      { type: "text", text: "make it watercolor" },
      { type: "image", mime: "image/png", data: "aGVsbG8=" },
    ]);
  });
});

describe("collectImageDispatch", () => {
  test("collects image chunks and the terminal receipt", async () => {
    const result = await collectImageDispatch(
      events(
        { kind: "meta", jobUri: "at://j", jobCid: "c", authUri: "at://a", inputCommitment: "x", providerDid: "did:plc:p", sessionId: "s" },
        { kind: "chunk", seq: 0, channel: "image", mime: "image/png", data: "AAAA" },
        { kind: "complete", tokensIn: 1, tokensOut: 2, receiptUri: "at://r", outputFormat: "images-v1" },
      ),
    );
    assert.deepEqual(result.images, [{ mime: "image/png", data: "AAAA" }]);
    assert.equal(result.receiptUri, "at://r");
    assert.equal(result.error, undefined);
  });

  test("captures a dispatch error code", async () => {
    const result = await collectImageDispatch(
      events({ kind: "error", reason: "nope", code: "no-providers-for-model" }),
    );
    assert.equal(result.error, "no-providers-for-model");
    assert.deepEqual(result.images, []);
  });
});

describe("generationsResponse", () => {
  test("shapes one slot into OpenAI data[] + x_cocore receiptUris", async () => {
    const slots: ImageSlotResult[] = [
      { images: [{ mime: "image/png", data: "AAAA" }], receiptUri: "at://r1" },
    ];
    const res = generationsResponse(slots);
    assert.equal(res.status, 200);
    const body = (await res.json()) as {
      data: { b64_json: string }[];
      x_cocore?: { receiptUris?: string[]; partial?: boolean };
    };
    assert.equal(body.data.length, 1);
    assert.equal(body.data[0]!.b64_json, "AAAA");
    assert.deepEqual(body.x_cocore?.receiptUris, ["at://r1"]);
    assert.equal(body.x_cocore?.partial, undefined);
  });

  test("marks partial when one slot errored but another produced an image", async () => {
    const slots: ImageSlotResult[] = [
      { images: [{ mime: "image/png", data: "AAAA" }], receiptUri: "at://r1" },
      { images: [], receiptUri: null, error: "no-capacity" },
    ];
    const res = generationsResponse(slots);
    const body = (await res.json()) as { data: unknown[]; x_cocore?: { partial?: boolean } };
    assert.equal(body.data.length, 1);
    assert.equal(body.x_cocore?.partial, true);
  });
});

describe("cross-check: envelope helpers are importable from the SDK", () => {
  test("images envelope round-trips (sanity)", () => {
    const env = parseImagesEnvelope(
      new TextEncoder().encode('{"images":[{"data":"AAAA","mime":"image/png"}],"v":1}'),
    );
    assert.equal(env.images.length, 1);
  });
});
