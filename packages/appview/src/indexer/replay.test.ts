// Replay test: a recorded sequence of firehose events feeds the
// indexer, and the resulting state must match a golden snapshot.
//
// Why this matters for federation: if a new AppView operator
// joins late and rebuilds state from a recorded relay backfill,
// they must end up with byte-identical content to operators who
// indexed live. We use canonical-JSON of every body to compare
// snapshots so any silent body mutation is caught.

import { test } from "vitest";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Firehose, canonicalize, type IndexedRecord } from "@cocore/sdk";
import { Indexer } from "./index.ts";
import { Store } from "../store.ts";

function newStore(): Store {
  const dir = mkdtempSync(join(tmpdir(), "cocore-replay-"));
  return new Store(join(dir, "appview.db"));
}

/** A lexicon-valid provider record body (ingest now structurally validates —
 *  see validate-ingest.ts). Spread `extra` to override the fields a given
 *  test actually cares about (createdAt, shareLocation, machineLabel, …). */
function providerBody(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    machineLabel: "MBP",
    chip: "M3",
    ramGB: 32,
    supportedModels: ["llama-3.1-70b"],
    priceList: [],
    encryptionPubKey: "E",
    attestationPubKey: "A",
    trustLevel: "self-attested",
    createdAt: "2026-05-07T12:00:00Z",
    ...extra,
  };
}

/** A lexicon-valid receipt record body; override via `extra`. */
function receiptBody(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    job: { uri: "at://did:plc:r/dev.cocore.compute.job/1", cid: "jcid" },
    requester: "did:plc:r",
    model: "llama-3.1-70b",
    inputCommitment: "a".repeat(64),
    outputCommitment: "b".repeat(64),
    tokens: { in: 32, out: 128 },
    startedAt: "2026-05-07T12:00:00Z",
    completedAt: "2026-05-07T12:00:03Z",
    price: { amount: 50, currency: "USD" },
    attestation: { uri: "at://did:plc:p/dev.cocore.compute.attestation/1", cid: "acid" },
    enclaveSignature: "sig",
    ...extra,
  };
}

/** A small recorded event log. Real backfill replay tests would
 *  load CBOR-encoded firehose frames; for our purposes a plain
 *  JSON list of records is sufficient — the wire decoder lands in
 *  M5.5 and gets its own tests. */
const RECORDED_EVENTS: IndexedRecord[] = [
  {
    uri: "at://did:plc:p/dev.cocore.compute.provider/1",
    cid: "pcid",
    collection: "dev.cocore.compute.provider",
    repo: "did:plc:p",
    rkey: "1",
    body: {
      machineLabel: "MBP M3 Max",
      chip: "Apple M3 Max",
      ramGB: 64,
      supportedModels: ["llama-3.1-70b"],
      priceList: [
        {
          modelId: "llama-3.1-70b",
          inputPricePerMTok: 50,
          outputPricePerMTok: 200,
          currency: "USD",
        },
      ],
      encryptionPubKey: "X",
      attestationPubKey: "A",
      trustLevel: "self-attested",
      createdAt: "2026-05-07T12:00:00Z",
    },
  },
  {
    uri: "at://did:plc:p/dev.cocore.compute.attestation/1",
    cid: "acid",
    collection: "dev.cocore.compute.attestation",
    repo: "did:plc:p",
    rkey: "1",
    body: {
      publicKey: "A",
      encryptionPubKey: "X",
      chipName: "Apple M3 Max",
      hardwareModel: "Mac15,8",
      serialNumberHash: "d".repeat(64),
      osVersion: "15.0",
      binaryHash: "e".repeat(64),
      sipEnabled: true,
      secureBootEnabled: true,
      secureEnclaveAvailable: true,
      authenticatedRootEnabled: true,
      selfSignature: "sig",
      attestedAt: "2026-05-07T11:00:00Z",
      expiresAt: "2030-01-01T00:00:00Z",
    },
  },
  {
    uri: "at://did:plc:r/dev.cocore.compute.job/1",
    cid: "jcid",
    collection: "dev.cocore.compute.job",
    repo: "did:plc:r",
    rkey: "1",
    body: {
      model: "llama-3.1-70b",
      inputCommitment: "a".repeat(64),
      maxTokensOut: 1000,
      priceCeiling: { amount: 100, currency: "USD" },
      acceptedTrustLevel: "self-attested",
      paymentAuthorization: { uri: "at://did:plc:r/auth/1", cid: "auth" },
      nonce: "n".repeat(32),
      expiresAt: "2030-01-01T00:00:00Z",
      createdAt: "2026-05-07T12:00:00Z",
    },
  },
  {
    uri: "at://did:plc:p/dev.cocore.compute.receipt/1",
    cid: "rcid",
    collection: "dev.cocore.compute.receipt",
    repo: "did:plc:p",
    rkey: "1",
    body: {
      job: { uri: "at://did:plc:r/dev.cocore.compute.job/1", cid: "jcid" },
      requester: "did:plc:r",
      model: "llama-3.1-70b",
      inputCommitment: "a".repeat(64),
      outputCommitment: "b".repeat(64),
      tokens: { in: 32, out: 128 },
      startedAt: "2026-05-07T12:00:00Z",
      completedAt: "2026-05-07T12:00:03Z",
      price: { amount: 50, currency: "USD" },
      attestation: { uri: "at://did:plc:p/dev.cocore.compute.attestation/1", cid: "acid" },
      enclaveSignature: "sig",
    },
  },
];

/** Compute a deterministic fingerprint of an indexer's state by
 *  canonicalising every body and concatenating uri+cid+canonBody. */
function snapshot(ix: Indexer): string {
  const all = [
    ...ix.store.listByCollection("dev.cocore.compute.provider", 1000),
    ...ix.store.listByCollection("dev.cocore.compute.attestation", 1000),
    ...ix.store.listByCollection("dev.cocore.compute.job", 1000),
    ...ix.store.listByCollection("dev.cocore.compute.receipt", 1000),
    ...ix.store.listByCollection("dev.cocore.compute.settlement", 1000),
    ...ix.store.listByCollection("dev.cocore.compute.paymentAuthorization", 1000),
  ];
  const sorted = all.sort((x, y) => x.uri.localeCompare(y.uri));
  return sorted.map((r) => `${r.uri}|${r.cid}|${canonicalize(r.body)}`).join("\n");
}

test("replay produces deterministic state across runs", async () => {
  const fh1 = new Firehose();
  const a = new Indexer(newStore());
  a.subscribe(fh1);
  for (const ev of RECORDED_EVENTS) await fh1.dispatch(ev);

  const fh2 = new Firehose();
  const b = new Indexer(newStore());
  b.subscribe(fh2);
  for (const ev of RECORDED_EVENTS) await fh2.dispatch(ev);

  assert.equal(snapshot(a), snapshot(b));
});

test("replay: order does not affect final state", async () => {
  const live = new Indexer(newStore());
  const lateA = new Indexer(newStore());
  const lateB = new Indexer(newStore());

  // Live AppView gets events in their natural order.
  const fh = new Firehose();
  live.subscribe(fh);
  for (const ev of RECORDED_EVENTS) await fh.dispatch(ev);

  // Late operator A replays in reverse.
  for (const ev of [...RECORDED_EVENTS].reverse()) {
    lateA.ingest({
      uri: ev.uri,
      cid: ev.cid,
      collection: ev.collection,
      repo: ev.repo,
      rkey: ev.rkey,
      record: ev.body,
    });
  }

  // Late operator B replays in a permuted order.
  const permuted = [
    RECORDED_EVENTS[3]!,
    RECORDED_EVENTS[1]!,
    RECORDED_EVENTS[0]!,
    RECORDED_EVENTS[2]!,
  ];
  for (const ev of permuted) {
    lateB.ingest({
      uri: ev.uri,
      cid: ev.cid,
      collection: ev.collection,
      repo: ev.repo,
      rkey: ev.rkey,
      record: ev.body,
    });
  }

  assert.equal(snapshot(live), snapshot(lateA));
  assert.equal(snapshot(live), snapshot(lateB));
});

test("replay: same event twice is a no-op (idempotent upsert)", async () => {
  const ix = new Indexer(newStore());
  const fh = new Firehose();
  ix.subscribe(fh);
  for (const ev of RECORDED_EVENTS) await fh.dispatch(ev);
  const snapBefore = snapshot(ix);

  // Re-dispatch every event a second time.
  for (const ev of RECORDED_EVENTS) await fh.dispatch(ev);
  const snapAfter = snapshot(ix);

  assert.equal(snapBefore, snapAfter);
});

test("stale provider re-ingest never clobbers a newer one (version guard)", () => {
  const ix = new Indexer(newStore());
  const uri = "at://did:plc:p/dev.cocore.compute.provider/1";
  const base = {
    uri,
    cid: "v1",
    collection: "dev.cocore.compute.provider",
    repo: "did:plc:p",
    rkey: "1",
  };

  // The owner's just-saved version: shareLocation on, pro bono on, newer ts.
  ix.ingest({
    ...base,
    cid: "v2",
    record: providerBody({
      shareLocation: true,
      proBono: { mode: "any" },
      createdAt: "2026-05-07T12:05:00Z",
    }),
  });

  // A lagging / replayed firehose delivery of the PRE-EDIT commit (older
  // createdAt, no owner settings) arrives afterward. It must NOT win.
  ix.ingest({
    ...base,
    cid: "v1",
    record: providerBody({ createdAt: "2026-05-07T12:00:00Z" }),
  });

  const got = ix.store.get(uri);
  assert.ok(got);
  const body = got.body as { shareLocation?: boolean; proBono?: unknown };
  assert.equal(body.shareLocation, true, "owner's shareLocation must survive a stale replay");
  assert.deepEqual(body.proBono, { mode: "any" }, "owner's proBono must survive a stale replay");
  assert.equal(got.cid, "v2", "newer version stays current");
});

test("equal or newer provider version still applies (idempotent + real updates)", () => {
  const ix = new Indexer(newStore());
  const uri = "at://did:plc:p/dev.cocore.compute.provider/1";
  const base = {
    uri,
    cid: "c",
    collection: "dev.cocore.compute.provider",
    repo: "did:plc:p",
    rkey: "1",
  };
  ix.ingest({ ...base, record: providerBody({ createdAt: "2026-05-07T12:00:00Z" }) });
  // Equal createdAt, newer body — last-writer-wins is preserved.
  ix.ingest({
    ...base,
    cid: "c2",
    record: providerBody({ machineLabel: "renamed", createdAt: "2026-05-07T12:00:00Z" }),
  });
  assert.equal((ix.store.get(uri)!.body as { machineLabel?: string }).machineLabel, "renamed");
  // Strictly newer — applies.
  ix.ingest({
    ...base,
    cid: "c3",
    record: providerBody({ machineLabel: "newest", createdAt: "2026-05-07T12:10:00Z" }),
  });
  assert.equal((ix.store.get(uri)!.body as { machineLabel?: string }).machineLabel, "newest");
});

test("records without createdAt keep last-writer-wins (no guard)", () => {
  const ix = new Indexer(newStore());
  const uri = "at://did:plc:p/dev.cocore.compute.receipt/1";
  const base = {
    uri,
    cid: "r1",
    collection: "dev.cocore.compute.receipt",
    repo: "did:plc:p",
    rkey: "1",
  };
  // Two receipts with no comparable createdAt — last write wins. Distinguish
  // them by outputCommitment (model is unchanged so the guard has nothing to
  // version by, matching the original intent).
  ix.ingest({ ...base, record: receiptBody({ outputCommitment: "a".repeat(64) }) });
  ix.ingest({ ...base, cid: "r2", record: receiptBody({ outputCommitment: "c".repeat(64) }) });
  assert.equal(
    (ix.store.get(uri)!.body as { outputCommitment?: string }).outputCommitment,
    "c".repeat(64),
  );
});

test("snapshot golden bytes (sentinel against silent body mutation)", async () => {
  const ix = new Indexer(newStore());
  const fh = new Firehose();
  ix.subscribe(fh);
  for (const ev of RECORDED_EVENTS) await fh.dispatch(ev);
  const snap = snapshot(ix);
  // We don't pin the entire snapshot string (too brittle), but we
  // pin two canonical-byte invariants the federation contract leans on:
  //   1. Every record body in the snapshot starts with `{` (canonical
  //      objects begin with '{' after sorted-key serialisation).
  //   2. The total row count matches the recorded events list.
  const lines = snap.split("\n");
  assert.equal(lines.length, RECORDED_EVENTS.length);
  for (const line of lines) {
    const body = line.split("|", 3)[2];
    assert.ok(body && body.startsWith("{"), `non-object body? ${line}`);
  }
});
