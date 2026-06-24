// Verifies that the requester-side writers (publishPaymentAuthorization,
// publishJob, submitJob) build records that satisfy the lexicons'
// shape and that the chosen transport receives the right
// repo/collection/record on the wire.

import { describe, expect, it } from "vitest";
import {
  BridgeRecordTransport,
  PdsRecordTransport,
  publishJob,
  publishPaymentAuthorization,
  sha256Hex,
  submitJob,
  type RecordTransport,
} from "./publish.ts";

const REQUESTER = "did:plc:test-requester";
const EXCHANGE = "did:web:exchange.local";

class CapturingTransport implements RecordTransport {
  calls: { repo: string; collection: string; record: Record<string, unknown> }[] = [];

  async publish<T extends Record<string, unknown>>(args: {
    repo: string;
    collection: string;
    record: T;
  }): Promise<{ uri: string; cid: string }> {
    this.calls.push({ repo: args.repo, collection: args.collection, record: args.record });
    const rkey = (this.calls.length - 1).toString().padStart(8, "0");
    return {
      uri: `at://${args.repo}/${args.collection}/${rkey}`,
      cid: `bafy-${rkey}`,
    };
  }
}

describe("publishPaymentAuthorization", () => {
  it("produces a lexicon-shaped record with sane defaults", async () => {
    const t = new CapturingTransport();
    const out = await publishPaymentAuthorization({
      transport: t,
      requesterDid: REQUESTER,
      inputs: {
        exchange: EXCHANGE,
        ceiling: { amount: 100, currency: "USD" },
      },
    });

    expect(t.calls).toHaveLength(1);
    expect(t.calls[0]!.collection).toBe("dev.cocore.compute.paymentAuthorization");
    expect(t.calls[0]!.repo).toBe(REQUESTER);

    const rec = out.record;
    expect(rec.exchange).toBe(EXCHANGE);
    expect(rec.scope).toBe("singleJob");
    expect(rec.nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(typeof rec.expiresAt).toBe("string");
    expect(typeof rec.createdAt).toBe("string");
    expect(out.ref.uri).toContain("dev.cocore.compute.paymentAuthorization");
  });

  it("propagates session scope + sessionBudget", async () => {
    const t = new CapturingTransport();
    const out = await publishPaymentAuthorization({
      transport: t,
      requesterDid: REQUESTER,
      inputs: {
        exchange: EXCHANGE,
        ceiling: { amount: 100, currency: "USD" },
        scope: "session",
        sessionBudget: { amount: 5000, currency: "USD" },
      },
    });
    expect(out.record.scope).toBe("session");
    expect(out.record.sessionBudget).toEqual({ amount: 5000, currency: "USD" });
  });
});

describe("publishJob", () => {
  it("strong-refs the named paymentAuthorization", async () => {
    const t = new CapturingTransport();
    const authRef = {
      uri: `at://${REQUESTER}/dev.cocore.compute.paymentAuthorization/abc`,
      cid: "bafy-auth",
    };

    const out = await publishJob({
      transport: t,
      requesterDid: REQUESTER,
      inputs: {
        model: "test-model",
        inputCommitment: "a".repeat(64),
        maxTokensOut: 256,
        priceCeiling: { amount: 100, currency: "USD" },
        paymentAuthorization: authRef,
      },
    });
    expect(out.record.paymentAuthorization).toEqual(authRef);
    expect(out.record.acceptedTrustLevel).toBe("self-attested");
    expect(out.record.nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(t.calls[0]!.collection).toBe("dev.cocore.compute.job");
    // Batch fields are omitted when not requested.
    expect(out.record.batchId).toBeUndefined();
    expect(out.record.outputIndex).toBeUndefined();
    expect(out.record.outputCount).toBeUndefined();
  });

  it("stamps multi-output batch fields when provided", async () => {
    const t = new CapturingTransport();
    const out = await publishJob({
      transport: t,
      requesterDid: REQUESTER,
      inputs: {
        model: "stub-flux",
        inputCommitment: "b".repeat(64),
        maxTokensOut: 4,
        priceCeiling: { amount: 100, currency: "CC" },
        paymentAuthorization: { uri: "at://x/y/z", cid: "bafy" },
        batchId: "0".repeat(32),
        outputIndex: 0,
        outputCount: 3,
      },
    });
    expect(out.record.batchId).toBe("0".repeat(32));
    expect(out.record.outputIndex).toBe(0);
    expect(out.record.outputCount).toBe(3);
  });
});

describe("submitJob", () => {
  it("publishes auth then job, both repo'd at the requester", async () => {
    const t = new CapturingTransport();
    const result = await submitJob({
      transport: t,
      requesterDid: REQUESTER,
      inputs: {
        model: "test-model",
        inputBytes: new TextEncoder().encode("hello"),
        maxTokensOut: 256,
        priceCeiling: { amount: 100, currency: "USD" },
        exchangeDid: EXCHANGE,
      },
    });

    expect(t.calls).toHaveLength(2);
    expect(t.calls[0]!.collection).toBe("dev.cocore.compute.paymentAuthorization");
    expect(t.calls[1]!.collection).toBe("dev.cocore.compute.job");
    expect(t.calls[0]!.repo).toBe(REQUESTER);
    expect(t.calls[1]!.repo).toBe(REQUESTER);

    const expectedCommitment = await sha256Hex(new TextEncoder().encode("hello"));
    expect(result.job.record.inputCommitment).toBe(expectedCommitment);
    expect(result.job.record.paymentAuthorization).toEqual(result.authorization.ref);
    expect(result.job.record.acceptedExchanges).toEqual([EXCHANGE]);
  });
});

describe("BridgeRecordTransport", () => {
  it("POSTs to dev.cocore.bridge.publish with an IndexedRecord envelope", async () => {
    const captured: { url: string; init: RequestInit } = { url: "", init: {} };
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (url: string, init: RequestInit) => {
      captured.url = url;
      captured.init = init;
      return new Response(null, { status: 202 });
    }) as typeof fetch;
    try {
      const t = new BridgeRecordTransport({ endpoint: "http://localhost:8080" });
      await t.publish({
        repo: REQUESTER,
        collection: "dev.cocore.compute.job",
        record: { hello: "world" },
      });
      expect(captured.url).toBe("http://localhost:8080/xrpc/dev.cocore.bridge.publish");
      const body = JSON.parse(String(captured.init.body));
      expect(body).toMatchObject({
        collection: "dev.cocore.compute.job",
        repo: REQUESTER,
        body: { hello: "world" },
      });
      expect(body.uri).toMatch(
        /^at:\/\/did:plc:test-requester\/dev\.cocore\.compute\.job\/[0-9a-f]{16}$/,
      );
      expect(body.rkey).toMatch(/^[0-9a-f]{16}$/);
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});

describe("PdsRecordTransport", () => {
  it("POSTs to com.atproto.repo.createRecord with Bearer auth", async () => {
    const captured: { url: string; init: RequestInit } = { url: "", init: {} };
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (url: string, init: RequestInit) => {
      captured.url = url;
      captured.init = init;
      return new Response(
        JSON.stringify({ uri: `at://${REQUESTER}/dev.cocore.compute.job/abc`, cid: "bafy-pds" }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as typeof fetch;
    try {
      const t = new PdsRecordTransport({ pdsEndpoint: "https://pds.example", accessToken: "tok" });
      const out = await t.publish({
        repo: REQUESTER,
        collection: "dev.cocore.compute.job",
        record: { hello: "world" },
      });
      expect(captured.url).toBe("https://pds.example/xrpc/com.atproto.repo.createRecord");
      const headers = captured.init.headers as Record<string, string>;
      expect(headers.authorization).toBe("Bearer tok");
      expect(out.uri).toContain("dev.cocore.compute.job");
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});
