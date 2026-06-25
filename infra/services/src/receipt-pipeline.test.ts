// Tests for the receipt-pipeline retry + reconcile logic.
//
// These tests target the failure mode we caught in production
// (settlement records never written when receipts arrive at the
// firehose before their job / payment auth / attestation deps).
// They exercise the pipeline against an in-memory store and a
// fake Exchange so we can deterministically drive resolve-failed
// → dep-arrives → retry → settled.

import { describe, expect, it, beforeEach } from "vitest";

import { Firehose, type IndexedRecord } from "@cocore/sdk";
import type { ReceiptRecord, JobRecord, AttestationRecord } from "@cocore/sdk/types";
import type { Exchange, SettlementOutcome } from "@cocore/exchange";

import {
  createReceiptPipeline,
  type ReceiptPipeline,
  type ReconcileSummary,
  type RecentOutcomeEntry,
} from "./receipt-pipeline.ts";

// In-memory store keyed by URI. Mirrors the surface
// `PipelineStore` requires + adds an `upsert` helper for tests.
function makeStore() {
  const rows = new Map<string, IndexedRecord>();
  return {
    rows,
    upsert(rec: IndexedRecord) {
      rows.set(rec.uri, rec);
    },
    get(uri: string): IndexedRecord | null {
      return rows.get(uri) ?? null;
    },
    listByCollection(collection: string, limit?: number): IndexedRecord[] {
      const out: IndexedRecord[] = [];
      for (const r of rows.values()) if (r.collection === collection) out.push(r);
      return typeof limit === "number" ? out.slice(0, limit) : out;
    },
  };
}

// Fake Exchange that the test fully controls. We don't need real
// signature verification or settlement publishing — only the
// outcome shape the pipeline branches on.
function makeFakeExchange(opts: {
  /** URIs of records the exchange will treat as "in the store"
   *  for resolve purposes. Anything outside the set triggers a
   *  resolve-failed with that URI as the `missing` field. */
  resolved: Set<string>;
  /** Optional: when set, force `onReceipt` to return a `rejected`
   *  outcome with these finding codes — simulates the verifier
   *  failure mode (e.g. the currency-mismatch bug that hit prod). */
  rejectWithFindings?: string[];
}): Exchange & { settled: string[] } {
  const settled: string[] = [];
  const settledMap = new Map<string, SettlementOutcome & { kind: "settled" }>();

  async function onReceipt(rec: IndexedRecord<ReceiptRecord>): Promise<SettlementOutcome> {
    const prior = settledMap.get(rec.uri);
    if (prior) return { kind: "duplicate", settlement: prior.settlement };

    // Mirror the real exchange's resolve order: job, then
    // paymentAuthorization (via job), then attestation. The test
    // controls which are "in store" via opts.resolved.
    const jobUri = rec.body.job.uri;
    if (!opts.resolved.has(jobUri)) return { kind: "resolve-failed", missing: jobUri };
    // The fake doesn't look at the actual job record; it just
    // confirms presence. The real exchange would also look up
    // job.paymentAuthorization, but for this test the resolved
    // set + the attestation URI is enough.
    const attUri = rec.body.attestation.uri;
    if (!opts.resolved.has(attUri)) return { kind: "resolve-failed", missing: attUri };

    if (opts.rejectWithFindings && opts.rejectWithFindings.length > 0) {
      return {
        kind: "rejected",
        report: {
          ok: false,
          findings: opts.rejectWithFindings.map((code) => ({
            severity: "error" as const,
            code,
            message: `synthetic test failure: ${code}`,
          })),
        },
      };
    }

    settled.push(rec.uri);
    const settlement = {
      uri: `at://exchange/settlement/${rec.uri.split("/").pop()}`,
      cid: `bafyfake-${rec.uri.split("/").pop()}`,
    };
    const outcome = { kind: "settled" as const, settlement };
    settledMap.set(rec.uri, outcome);
    return outcome;
  }
  // Cast to the Exchange shape; we only use onReceipt.
  return { onReceipt, settled } as unknown as Exchange & { settled: string[] };
}

// Fake ledger that records applied receipts but doesn't touch
// real balances.
function makeFakeLedger() {
  const applied: Array<{ uri: string; tokens: number; requesterDid: string; providerDid: string }> =
    [];
  return {
    ledger: {
      applyReceipt(args: {
        uri: string;
        tokens: number;
        requesterDid: string;
        providerDid: string;
      }): boolean {
        applied.push(args);
        return true;
      },
      applyRefreshIfDue(_did: string): void {},
    },
    applied,
  };
}

// Build a receipt record body that references a job + attestation
// by URI. The pipeline only inspects body.job.uri / body.attestation.uri
// / body.requester / body.tokens, so the rest can be minimal.
function makeReceipt(args: {
  rkey: string;
  providerDid: string;
  requesterDid: string;
  jobUri: string;
  attestationUri: string;
  tokens?: { in: number; out: number };
  price?: { amount: number; currency: string };
}): IndexedRecord<ReceiptRecord> {
  // ReceiptRecord doesn't carry `$type` or a top-level `provider` in
  // the codegen'd shape — provider DID lives at the record's `repo`
  // field on the indexed envelope (one level up). The pipeline reads
  // body.requester / body.tokens / body.job / body.attestation, plus
  // env.repo for the provider — that's all the test needs to mimic.
  const body: ReceiptRecord = {
    job: { uri: args.jobUri, cid: "bafyfake-job" },
    requester: args.requesterDid,
    model: "stub",
    inputCommitment: "0".repeat(64),
    outputCommitment: "1".repeat(64),
    tokens: args.tokens ?? { in: 10, out: 5 },
    startedAt: "2026-01-01T00:00:00Z",
    completedAt: "2026-01-01T00:00:01Z",
    price: args.price ?? { amount: 15, currency: "CC" },
    attestation: { uri: args.attestationUri, cid: "bafyfake-att" },
    enclaveSignature: "AAAA",
  };
  return {
    uri: `at://${args.providerDid}/dev.cocore.compute.receipt/${args.rkey}`,
    cid: `bafyfake-receipt-${args.rkey}`,
    collection: "dev.cocore.compute.receipt",
    repo: args.providerDid,
    rkey: args.rkey,
    body,
  };
}

// Build a "job arrives" record. The exchange only checks that the
// URI is in `opts.resolved`; the body shape doesn't matter for the
// pipeline's tests. Returned so the test can dispatch it through
// the firehose to trigger the reactive retry.
function makeJobRecord(uri: string, requesterDid: string): IndexedRecord<JobRecord> {
  return {
    uri,
    cid: "bafyfake-job",
    collection: "dev.cocore.compute.job",
    repo: requesterDid,
    rkey: uri.split("/").pop() ?? "",
    body: { $type: "dev.cocore.compute.job" } as unknown as JobRecord,
  };
}

const policy = {
  tokenGrant: 1_000_000,
  tokenFloor: 100_000,
  treasuryDid: "did:plc:treasury",
  treasuryFeeBps: 500,
  selfLoopFeeWaived: true,
  weeklyRefreshAmount: 0,
  refreshCadenceMinutes: 10_080,
  patronageFractionBps: 0,
  patronageCadenceDays: 30,
};

describe("ReceiptPipeline", () => {
  let store: ReturnType<typeof makeStore>;
  let firehose: Firehose;
  let logs: string[];

  function setup(opts: { exchangeResolved: Set<string>; rejectWithFindings?: string[] }): {
    pipeline: ReceiptPipeline;
    exchange: Exchange & { settled: string[] };
    ledgerApplied: Array<{
      uri: string;
      tokens: number;
      requesterDid: string;
      providerDid: string;
    }>;
  } {
    const exchange = makeFakeExchange({
      resolved: opts.exchangeResolved,
      ...(opts.rejectWithFindings ? { rejectWithFindings: opts.rejectWithFindings } : {}),
    });
    const { ledger, applied: ledgerApplied } = makeFakeLedger();
    const pipeline = createReceiptPipeline({
      exchange,
      ledger: ledger as unknown as Parameters<typeof createReceiptPipeline>[0]["ledger"],
      ledgerPolicy: policy,
      firehose,
      store,
      treasuryDid: "did:plc:treasury",
      feeBps: 500,
      maxRetries: 4,
      log: (l) => logs.push(l),
    });
    pipeline.attach();
    return { pipeline, exchange, ledgerApplied };
  }

  beforeEach(() => {
    store = makeStore();
    firehose = new Firehose();
    logs = [];
  });

  it("settles a receipt whose deps are already in the exchange's resolve set", async () => {
    const jobUri = "at://did:plc:requester/dev.cocore.compute.job/job1";
    const attUri = "at://did:plc:provider/dev.cocore.compute.attestation/att1";
    const { pipeline, exchange } = setup({
      exchangeResolved: new Set([jobUri, attUri]),
    });

    const receipt = makeReceipt({
      rkey: "r1",
      providerDid: "did:plc:provider",
      requesterDid: "did:plc:requester",
      jobUri,
      attestationUri: attUri,
    });
    store.upsert(receipt);
    await firehose.dispatch(receipt);

    expect(exchange.settled).toEqual([receipt.uri]);
    expect(pipeline.pendingSnapshot()).toEqual([]);

    // The recentOutcomes ring buffer is what the admin pipelineState
    // endpoint exposes. Confirm it captured this settle with the
    // settlement URI populated. Annotated against RecentOutcomeEntry
    // so a future change to the entry shape forces an update here.
    const recent: RecentOutcomeEntry[] = pipeline.recentOutcomes();
    expect(recent).toHaveLength(1);
    expect(recent[0]).toMatchObject({
      receiptUri: receipt.uri,
      kind: "settled",
      tag: "fresh",
    });
    expect(recent[0]?.settlementUri).toMatch(/^at:\/\/exchange\/settlement\//);
  });

  it("settles a pro-bono receipt without moving any tokens (no cut, unmetered)", async () => {
    // A pro-bono receipt is free + unmetered: price.amount is 0 and the
    // tokens are zero. The exchange settles it (audit trail), but the
    // pipeline's token-movement guard (amount > 0) means the ledger never
    // debits the requester or credits the provider — the carve-out for
    // explicitly unlimited usage.
    const jobUri = "at://did:plc:requester/dev.cocore.compute.job/probono";
    const attUri = "at://did:plc:provider/dev.cocore.compute.attestation/att-probono";
    const { exchange, ledgerApplied } = setup({
      exchangeResolved: new Set([jobUri, attUri]),
    });

    const receipt = makeReceipt({
      rkey: "pb1",
      providerDid: "did:plc:provider",
      requesterDid: "did:plc:requester",
      jobUri,
      attestationUri: attUri,
      tokens: { in: 0, out: 0 },
      price: { amount: 0, currency: "CC" },
    });
    store.upsert(receipt);
    await firehose.dispatch(receipt);

    // Settled (the settlement record is the audit trail) ...
    expect(exchange.settled).toEqual([receipt.uri]);
    // ... but no balance moved: the ledger was never touched.
    expect(ledgerApplied).toEqual([]);
  });

  it("parks a receipt on resolve-failed and retries when the missing dep arrives", async () => {
    const jobUri = "at://did:plc:requester/dev.cocore.compute.job/job2";
    const attUri = "at://did:plc:provider/dev.cocore.compute.attestation/att2";
    // Start with NO deps resolved.
    const exchangeResolved = new Set<string>();
    const { pipeline, exchange } = setup({ exchangeResolved });

    const receipt = makeReceipt({
      rkey: "r2",
      providerDid: "did:plc:provider",
      requesterDid: "did:plc:requester",
      jobUri,
      attestationUri: attUri,
    });
    store.upsert(receipt);
    await firehose.dispatch(receipt);

    // First pass: resolve-failed on the job. Parked.
    expect(exchange.settled).toEqual([]);
    expect(pipeline.pendingSnapshot()).toEqual([{ missing: jobUri, waiters: [receipt.uri] }]);

    // Job arrives. Tell the fake exchange it's now resolved AND
    // dispatch it through the firehose so the reactive retry fires.
    exchangeResolved.add(jobUri);
    const job = makeJobRecord(jobUri, "did:plc:requester");
    store.upsert(job);
    await firehose.dispatch(job);

    // Receipt should have re-tried; now resolve-failed on the
    // attestation. So still not settled, but now parked on the
    // attestation URI.
    expect(exchange.settled).toEqual([]);
    expect(pipeline.pendingSnapshot()).toEqual([{ missing: attUri, waiters: [receipt.uri] }]);

    // Attestation arrives.
    exchangeResolved.add(attUri);
    const att: IndexedRecord<AttestationRecord> = {
      uri: attUri,
      cid: "bafyfake-att",
      collection: "dev.cocore.compute.attestation",
      repo: "did:plc:provider",
      rkey: attUri.split("/").pop() ?? "",
      body: { $type: "dev.cocore.compute.attestation" } as unknown as AttestationRecord,
    };
    store.upsert(att);
    await firehose.dispatch(att);

    // Now both deps are present — settled.
    expect(exchange.settled).toEqual([receipt.uri]);
    expect(pipeline.pendingSnapshot()).toEqual([]);
  });

  it("reconcile catches receipts that the reactive path missed (post-restart scenario)", async () => {
    const jobUri = "at://did:plc:requester/dev.cocore.compute.job/job3";
    const attUri = "at://did:plc:provider/dev.cocore.compute.attestation/att3";
    // Deps are resolved from the start, but the pipeline NEVER sees
    // the receipt via the firehose — simulating a process that
    // missed it (e.g. the receipt was indexed during a window when
    // the bridge couldn't reach the services container).
    const { pipeline, exchange } = setup({
      exchangeResolved: new Set([jobUri, attUri]),
    });

    const receipt = makeReceipt({
      rkey: "r3",
      providerDid: "did:plc:provider",
      requesterDid: "did:plc:requester",
      jobUri,
      attestationUri: attUri,
    });
    // Insert directly into store; do NOT dispatch through firehose.
    store.upsert(receipt);

    expect(exchange.settled).toEqual([]);

    // Reconcile loop picks it up.
    const summary: ReconcileSummary = await pipeline.reconcileUnsettledReceipts();
    expect(summary).toMatchObject({
      attempted: 1,
      settled: 1,
      stillResolveFailed: 0,
      rejected: 0,
    });
    expect(exchange.settled).toEqual([receipt.uri]);
  });

  it("reconcile skips already-settled receipts (idempotent)", async () => {
    const jobUri = "at://did:plc:requester/dev.cocore.compute.job/job4";
    const attUri = "at://did:plc:provider/dev.cocore.compute.attestation/att4";
    const { pipeline, exchange } = setup({
      exchangeResolved: new Set([jobUri, attUri]),
    });
    const receipt = makeReceipt({
      rkey: "r4",
      providerDid: "did:plc:provider",
      requesterDid: "did:plc:requester",
      jobUri,
      attestationUri: attUri,
    });
    store.upsert(receipt);

    // Simulate a settlement record landing in the store (as if the
    // exchange's publisher had dispatched it). The reconcile loop
    // uses the settlement record's body.receipt.uri to know what's
    // already settled.
    store.upsert({
      uri: "at://exchange/settlement/r4",
      cid: "bafyfake-set",
      collection: "dev.cocore.compute.settlement",
      repo: "did:plc:exchange",
      rkey: "r4",
      body: { receipt: { uri: receipt.uri } } as unknown,
    } as IndexedRecord);

    const summary = await pipeline.reconcileUnsettledReceipts();
    expect(summary.scanned).toBe(1);
    expect(summary.attempted).toBe(0);
    expect(exchange.settled).toEqual([]); // never called onReceipt
  });

  it("recentOutcomes surfaces rejected receipts with finding codes (the deceptive failure we hit in prod)", async () => {
    // Simulates the v0.5→closed-loop currency-mismatch bug: dep
    // records exist (resolveRecord succeeds for all of them) but
    // the verifier rejects because receipt.price.currency ("CC")
    // doesn't match job.priceCeiling.currency ("USD"). The ring
    // buffer must capture this with the finding codes so an
    // operator hitting /xrpc/dev.cocore.admin.pipelineState can
    // see what's wrong without Railway log access.
    const jobUri = "at://did:plc:requester/dev.cocore.compute.job/job-cc";
    const attUri = "at://did:plc:provider/dev.cocore.compute.attestation/att-cc";
    const { pipeline, exchange } = setup({
      exchangeResolved: new Set([jobUri, attUri]),
      rejectWithFindings: ["currency-mismatch"],
    });

    const receipt = makeReceipt({
      rkey: "rcc",
      providerDid: "did:plc:provider",
      requesterDid: "did:plc:requester",
      jobUri,
      attestationUri: attUri,
    });
    store.upsert(receipt);
    await firehose.dispatch(receipt);

    // No settlement should have been published.
    expect(exchange.settled).toEqual([]);

    // But the ring buffer captures the rejection with the finding
    // code — that's what makes the failure mode visible to
    // operators going forward.
    const recent = pipeline.recentOutcomes();
    expect(recent).toHaveLength(1);
    expect(recent[0]).toMatchObject({
      receiptUri: receipt.uri,
      kind: "rejected",
      findings: ["currency-mismatch"],
    });
  });

  it("reconcile skips terminally rejected receipts instead of re-attempting every pass", async () => {
    // The prod log-spam mode: a handful of receipts with immutable
    // verification failures (currency-mismatch from the USD→CC
    // pivot, expired auths) got re-verified and re-logged on every
    // reconcile tick forever. After the first rejection the pipeline
    // must remember the verdict and skip the receipt.
    const jobUri = "at://did:plc:requester/dev.cocore.compute.job/job-term";
    const attUri = "at://did:plc:provider/dev.cocore.compute.attestation/att-term";
    const { pipeline } = setup({
      exchangeResolved: new Set([jobUri, attUri]),
      rejectWithFindings: ["currency-mismatch", "auth-expired"],
    });

    const receipt = makeReceipt({
      rkey: "rterm",
      providerDid: "did:plc:provider",
      requesterDid: "did:plc:requester",
      jobUri,
      attestationUri: attUri,
    });
    store.upsert(receipt);

    // First pass: the receipt is attempted, rejected, and remembered.
    const first = await pipeline.reconcileUnsettledReceipts();
    expect(first).toMatchObject({ attempted: 1, rejected: 1, skippedRejected: 0 });

    // Every later pass: skipped, not re-verified, not re-logged.
    const second = await pipeline.reconcileUnsettledReceipts();
    expect(second).toMatchObject({ attempted: 0, rejected: 0, skippedRejected: 1 });
    expect(logs.filter((l) => l.includes("rejected")).length).toBe(1);
  });

  it("stops re-parking after maxRetries (caps work on truly unreachable deps)", async () => {
    const jobUri = "at://did:plc:requester/dev.cocore.compute.job/job5";
    const attUri = "at://did:plc:provider/dev.cocore.compute.attestation/att5";
    const { pipeline } = setup({ exchangeResolved: new Set() });

    const receipt = makeReceipt({
      rkey: "r5",
      providerDid: "did:plc:provider",
      requesterDid: "did:plc:requester",
      jobUri,
      attestationUri: attUri,
    });
    store.upsert(receipt);

    // Drive 5 attempts (maxRetries=4 from setup, so the 5th is
    // over budget). Each attempt parks on the same jobUri, then
    // dispatches a fake unrelated record to clear the waiter set
    // (the firehose's all-records handler removes the waiter on
    // dispatch). We call processReceipt directly to avoid setting
    // up the dep-arrival dance — the retry counter cares only about
    // call count.
    for (let i = 0; i < 5; i++) {
      await pipeline.processReceipt(receipt, true);
    }
    const gaveUpLines = logs.filter((l) => l.includes("giving up after 4 retries"));
    expect(gaveUpLines.length).toBeGreaterThanOrEqual(1);
  });

  it("never moves balances for a rejected receipt (forced-debit guard)", async () => {
    // A malicious provider publishes a receipt to their OWN PDS naming a
    // victim as `requester`. Deps resolve, but the verifier rejects it
    // (bad signature, etc.). The ledger MUST NOT move tokens — otherwise
    // the attacker drains the victim into their own balance.
    const jobUri = "at://did:plc:victim/dev.cocore.compute.job/jobx";
    const attUri = "at://did:plc:attacker/dev.cocore.compute.attestation/attx";
    const { ledgerApplied } = setup({
      exchangeResolved: new Set([jobUri, attUri]),
      rejectWithFindings: ["sig-invalid"],
    });
    const receipt = makeReceipt({
      rkey: "rx",
      providerDid: "did:plc:attacker",
      requesterDid: "did:plc:victim",
      jobUri,
      attestationUri: attUri,
      tokens: { in: 500_000, out: 500_000 },
      price: { amount: 1_000_000, currency: "CC" },
    });
    store.upsert(receipt);
    await firehose.dispatch(receipt);

    expect(ledgerApplied).toEqual([]);
  });

  it("debits the verified price.amount, not the self-reported token count", async () => {
    // Settlement only checks `price.amount` against the ceiling. A
    // provider could pair a small, ceiling-passing price with a huge
    // token count; the ledger must move price.amount, never raw tokens.
    const jobUri = "at://did:plc:requester/dev.cocore.compute.job/jobp";
    const attUri = "at://did:plc:provider/dev.cocore.compute.attestation/attp";
    const { exchange, ledgerApplied } = setup({
      exchangeResolved: new Set([jobUri, attUri]),
    });
    const receipt = makeReceipt({
      rkey: "rp",
      providerDid: "did:plc:provider",
      requesterDid: "did:plc:requester",
      jobUri,
      attestationUri: attUri,
      tokens: { in: 9_999, out: 9_999 }, // self-reported, inflated
      price: { amount: 15, currency: "CC" }, // verified, ceiling-checked
    });
    store.upsert(receipt);
    await firehose.dispatch(receipt);

    expect(exchange.settled).toEqual([receipt.uri]);
    expect(ledgerApplied).toEqual([
      {
        uri: receipt.uri,
        tokens: 15,
        requesterDid: "did:plc:requester",
        providerDid: "did:plc:provider",
      },
    ]);
  });
});
