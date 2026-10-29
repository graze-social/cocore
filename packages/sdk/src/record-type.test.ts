// Regression guard for graze-social/cocore#257: every record we write to a
// PDS must carry `$type`. A strictly-validating PDS rejects a record without
// it (`InvalidRecord: Record missing required $type field`), which surfaced as
// every paid job failing with `pds_publish_failed`.
//
// The check here is @atproto/lexicon's `assertValidRecord`, which — like a
// strict PDS — requires `$type` to be present and equal to the collection.

import { afterEach, describe, expect, it, vi } from "vitest";

import { ids, lexicons } from "./lex-runtime.ts";
import { BridgeRecordTransport, PdsRecordTransport, submitJob } from "./publish.ts";
import { withRecordType } from "./record-type.ts";

const REQUESTER = "did:plc:jijwtzgroy76samnivlqrpec";
const EXCHANGE = "did:web:exchange.cocore.dev";

/** Every createRecord body the stubbed fetch saw, by URL. */
function captureFetch(respond: (url: string, body: Record<string, unknown>) => unknown) {
  const calls: { url: string; body: Record<string, unknown> }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: { body: string }) => {
      const body = JSON.parse(init.body) as Record<string, unknown>;
      calls.push({ url, body });
      return new Response(JSON.stringify(respond(url, body)), { status: 200 });
    }),
  );
  return calls;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

function submit(transport: BridgeRecordTransport | PdsRecordTransport) {
  return submitJob({
    transport,
    requesterDid: REQUESTER,
    inputs: {
      model: "gemma-4-12b",
      inputBytes: new TextEncoder().encode("hello"),
      maxTokensOut: 16,
      priceCeiling: { amount: 100, currency: "USD" },
      exchangeDid: EXCHANGE,
      outputSchema: { name: "out", strict: true, schema: { type: "object" } },
      tools: [{ type: "function", function: { name: "f", parameters: { type: "object" } } }],
      toolChoice: "auto",
    },
  });
}

describe("withRecordType", () => {
  it("stamps $type = collection when missing", () => {
    expect(withRecordType("dev.cocore.compute.job", { a: 1 })).toEqual({
      $type: "dev.cocore.compute.job",
      a: 1,
    });
  });

  it("leaves an existing $type alone and does not copy", () => {
    const rec = { $type: "dev.cocore.compute.termsAcceptance", sig: "x" };
    expect(withRecordType("dev.cocore.compute.termsAcceptance", rec)).toBe(rec);
  });

  it("does not mutate its input (signed bodies stay byte-identical)", () => {
    const rec = { a: 1 };
    withRecordType("dev.cocore.compute.job", rec);
    expect(rec).toEqual({ a: 1 });
  });
});

describe("records written to a PDS validate against their lexicon", () => {
  it("the validator really does require $type (so this test means something)", async () => {
    const t = new PdsRecordTransport({ pdsEndpoint: "https://pds.test", accessToken: "t" });
    captureFetch((_url, body) => ({
      uri: `at://${REQUESTER}/${body["collection"] as string}/3k`,
      cid: "bafyreigh2akiscaildc5sgz5wybizysiehxiv4dhpwwqouytxnvgkpkcaq",
    }));
    const out = await submit(t);
    // The builders' in-memory records carry no $type; the transport adds it.
    expect(() =>
      lexicons.assertValidRecord(
        ids.DevCocoreComputePaymentAuthorization,
        out.authorization.record,
      ),
    ).toThrow(/\$type/);
  });

  it("PdsRecordTransport: paymentAuthorization + job carry $type and validate", async () => {
    const calls = captureFetch((_url, body) => ({
      uri: `at://${REQUESTER}/${body["collection"] as string}/3k`,
      cid: "bafyreigh2akiscaildc5sgz5wybizysiehxiv4dhpwwqouytxnvgkpkcaq",
    }));
    await submit(new PdsRecordTransport({ pdsEndpoint: "https://pds.test", accessToken: "t" }));

    expect(calls.map((c) => c.body["collection"])).toEqual([
      ids.DevCocoreComputePaymentAuthorization,
      ids.DevCocoreComputeJob,
    ]);
    for (const { body } of calls) {
      const collection = body["collection"] as string;
      const record = body["record"] as Record<string, unknown>;
      expect(record["$type"]).toBe(collection);
      expect(() => lexicons.assertValidRecord(collection, record)).not.toThrow();
    }
  });

  it("BridgeRecordTransport mirrors the same $type-framed record", async () => {
    const calls = captureFetch(() => ({}));
    await submit(new BridgeRecordTransport({ endpoint: "http://bridge.test" }));
    for (const { body } of calls) {
      const collection = body["collection"] as string;
      const record = body["body"] as Record<string, unknown>;
      expect(record["$type"]).toBe(collection);
      expect(() => lexicons.assertValidRecord(collection, record)).not.toThrow();
    }
  });
});
