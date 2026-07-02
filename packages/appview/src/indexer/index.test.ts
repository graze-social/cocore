import { test } from "vitest";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../store.ts";
import { Indexer } from "./index.ts";

function newStore(): Store {
  const dir = mkdtempSync(join(tmpdir(), "cocore-test-"));
  return new Store(join(dir, "appview.db"));
}

/** A lexicon-valid receipt body (ingest structurally validates — H4). */
function receiptBody(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    job: { uri: "at://did:plc:p/dev.cocore.compute.job/1", cid: "jcid" },
    requester: "did:plc:r",
    model: "m",
    inputCommitment: "a".repeat(64),
    outputCommitment: "b".repeat(64),
    tokens: { in: 1, out: 1 },
    startedAt: "2026-05-07T12:00:00Z",
    completedAt: "2026-05-07T12:00:03Z",
    price: { amount: 50, currency: "USD" },
    attestation: { uri: "at://did:plc:p/dev.cocore.compute.attestation/1", cid: "acid" },
    enclaveSignature: "sig",
    ...extra,
  };
}

test("ingest stores cocore records", () => {
  const store = newStore();
  const idx = new Indexer(store);
  const ok = idx.ingest({
    uri: "at://did:plc:p/dev.cocore.compute.receipt/1",
    cid: "bafycid",
    collection: "dev.cocore.compute.receipt",
    repo: "did:plc:p",
    rkey: "1",
    record: receiptBody(),
  });
  assert.equal(ok, true);
  const got = store.get("at://did:plc:p/dev.cocore.compute.receipt/1");
  assert.ok(got);
  assert.equal(got.collection, "dev.cocore.compute.receipt");
});

test("ingest ignores non-cocore collections", () => {
  const store = newStore();
  const idx = new Indexer(store);
  const ok = idx.ingest({
    uri: "at://did:plc:p/app.bsky.feed.post/1",
    cid: "bafycid",
    collection: "app.bsky.feed.post",
    repo: "did:plc:p",
    rkey: "1",
    record: {},
  });
  assert.equal(ok, false);
  assert.equal(store.get("at://did:plc:p/app.bsky.feed.post/1"), null);
});

test("listByCollection returns inserted records", () => {
  const store = newStore();
  const idx = new Indexer(store);
  for (let i = 0; i < 3; i++) {
    idx.ingest({
      uri: `at://did:plc:p/dev.cocore.compute.receipt/${i}`,
      cid: `bafy${i}`,
      collection: "dev.cocore.compute.receipt",
      repo: "did:plc:p",
      rkey: String(i),
      record: receiptBody({ outputCommitment: String(i).repeat(64).slice(0, 64) }),
    });
  }
  const all = store.listByCollection("dev.cocore.compute.receipt");
  assert.equal(all.length, 3);
});

// ---- H4: ingest validation ----------------------------------------------

test("H4: ingest drops a receipt missing required lexicon fields", () => {
  const store = newStore();
  const idx = new Indexer(store);
  const uri = "at://did:plc:p/dev.cocore.compute.receipt/bad";
  const ok = idx.ingest({
    uri,
    cid: "bafybad",
    collection: "dev.cocore.compute.receipt",
    repo: "did:plc:p",
    rkey: "bad",
    // Missing job/attestation/inputCommitment/etc. — the pre-fix behavior
    // stored this verbatim and read APIs surfaced it as a canonical receipt.
    record: { model: "m", tokens: { in: 1, out: 1 } },
  });
  assert.equal(ok, false);
  assert.equal(store.get(uri), null);
});

test("H4: ingest drops a receipt whose field is the wrong type", () => {
  const store = newStore();
  const idx = new Indexer(store);
  const uri = "at://did:plc:p/dev.cocore.compute.receipt/typed";
  const ok = idx.ingest({
    uri,
    cid: "bafytyped",
    collection: "dev.cocore.compute.receipt",
    repo: "did:plc:p",
    rkey: "typed",
    // `model` is a lexicon string; a number is a type violation the structural
    // check catches (ref-typed fields like `tokens` are presence-checked only).
    record: receiptBody({ model: 123 }),
  });
  assert.equal(ok, false);
  assert.equal(store.get(uri), null);
});

test("H4: ingest drops an oversized record", () => {
  const store = newStore();
  const idx = new Indexer(store);
  const uri = "at://did:plc:p/dev.cocore.compute.receipt/big";
  const ok = idx.ingest({
    uri,
    cid: "bafybig",
    collection: "dev.cocore.compute.receipt",
    repo: "did:plc:p",
    rkey: "big",
    record: receiptBody({ model: "x".repeat(2 * 1024 * 1024) }),
  });
  assert.equal(ok, false);
  assert.equal(store.get(uri), null);
});

test("H4: ingest drops a record whose body.provider disagrees with its repo", () => {
  const store = newStore();
  const idx = new Indexer(store);
  // A hypothetical provider-bound record naming a different provider than the
  // signing repo is a forgery (defense-in-depth for a future NSID that
  // denormalizes provider). Use a provider record with an injected provider.
  const uri = "at://did:plc:attacker/dev.cocore.compute.provider/1";
  const ok = idx.ingest({
    uri,
    cid: "bafyforge",
    collection: "dev.cocore.compute.provider",
    repo: "did:plc:attacker",
    rkey: "1",
    record: {
      machineLabel: "MBP",
      chip: "M3",
      ramGB: 32,
      supportedModels: ["m"],
      priceList: [],
      encryptionPubKey: "E",
      attestationPubKey: "A",
      trustLevel: "self-attested",
      createdAt: "2026-05-07T12:00:00Z",
      provider: "did:plc:victim",
    },
  });
  assert.equal(ok, false);
  assert.equal(store.get(uri), null);
});
