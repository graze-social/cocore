// AppView federation proof.
//
// Two independent AppView operators subscribed to the same firehose
// MUST end up with byte-equivalent indexed state for any cocore
// record they both observe. That's the read-side mirror of the
// exchange federation proof in packages/exchange/src/firehose.test.ts: it
// says no AppView is privileged, and re-running the same record
// stream against a freshly-spun-up AppView reconstructs the same
// answers.
//
// What may differ between operators (out of scope here):
//   - retention policy, indexing latency, pagination cursors,
//     convenience endpoints layered above the firehose.
//
// What MUST NOT differ:
//   - whether a given (uri, cid) row exists, given both saw the
//     event for it
//   - the canonical body bytes
//   - the verifyReceipt verdict

import { test } from "vitest";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  Firehose,
  canonicalize,
  verifyReceipt,
  type AttestationRecord,
  type IndexedRecord,
  type JobRecord,
  type ReceiptRecord,
} from "@cocore/sdk";
import { Indexer } from "./index.ts";
import { Store } from "../store.ts";

function newStore(): Store {
  const dir = mkdtempSync(join(tmpdir(), "cocore-federation-"));
  return new Store(join(dir, "appview.db"));
}

const REQUESTER = "did:plc:requester";
const PROVIDER = "did:plc:provider";

function fixtureScene() {
  const fh = new Firehose();
  const a = new Indexer(newStore());
  const b = new Indexer(newStore());
  a.subscribe(fh);
  b.subscribe(fh);

  const job: IndexedRecord<JobRecord> = {
    uri: "at://did:plc:requester/dev.cocore.compute.job/1",
    cid: "jcid",
    collection: "dev.cocore.compute.job",
    repo: REQUESTER,
    rkey: "1",
    body: {
      model: "m",
      inputCommitment: "a".repeat(64),
      maxTokensOut: 100,
      priceCeiling: { amount: 100, currency: "USD" },
      acceptedTrustLevel: "self-attested",
      paymentAuthorization: { uri: "at://did:plc:requester/auth/1", cid: "auth" },
      nonce: "n".repeat(32),
      expiresAt: "2030-01-01T00:00:00Z",
      createdAt: "2026-05-07T12:00:00Z",
    },
  };
  const att: IndexedRecord<AttestationRecord> = {
    uri: "at://did:plc:provider/dev.cocore.compute.attestation/1",
    cid: "acid",
    collection: "dev.cocore.compute.attestation",
    repo: PROVIDER,
    rkey: "1",
    body: {
      publicKey: "A",
      encryptionPubKey: "E",
      chipName: "M3",
      hardwareModel: "Mac15,8",
      serialNumberHash: "d".repeat(64),
      osVersion: "15",
      binaryHash: "e".repeat(64),
      sipEnabled: true,
      secureBootEnabled: true,
      secureEnclaveAvailable: true,
      authenticatedRootEnabled: true,
      selfSignature: "attsig",
      attestedAt: "2026-05-07T11:00:00Z",
      expiresAt: "2030-01-01T00:00:00Z",
    },
  };
  const receipt: IndexedRecord<ReceiptRecord> = {
    uri: "at://did:plc:provider/dev.cocore.compute.receipt/1",
    cid: "rcid",
    collection: "dev.cocore.compute.receipt",
    repo: PROVIDER,
    rkey: "1",
    body: {
      job: { uri: job.uri, cid: job.cid },
      requester: REQUESTER,
      model: "m",
      inputCommitment: "a".repeat(64),
      outputCommitment: "b".repeat(64),
      tokens: { in: 1, out: 1 },
      startedAt: "2026-05-07T12:00:00Z",
      completedAt: "2026-05-07T12:00:03Z",
      price: { amount: 50, currency: "USD" },
      attestation: { uri: att.uri, cid: att.cid },
      enclaveSignature: "sig",
    },
  };

  return { fh, a, b, job, att, receipt };
}

test("two AppViews see identical indexed rows after the same firehose stream", async () => {
  const { fh, a, b, job, att, receipt } = fixtureScene();
  await fh.dispatch(job);
  await fh.dispatch(att);
  await fh.dispatch(receipt);

  for (const collection of [
    "dev.cocore.compute.job",
    "dev.cocore.compute.attestation",
    "dev.cocore.compute.receipt",
  ]) {
    const inA = a.store.listByCollection(collection);
    const inB = b.store.listByCollection(collection);
    assert.equal(inA.length, inB.length, `count mismatch for ${collection}`);
    // Compare canonicalised bodies to catch any silent body mutation.
    const aSorted = [...inA].sort((x, y) => x.uri.localeCompare(y.uri));
    const bSorted = [...inB].sort((x, y) => x.uri.localeCompare(y.uri));
    for (let i = 0; i < aSorted.length; i++) {
      assert.equal(aSorted[i]!.uri, bSorted[i]!.uri);
      assert.equal(aSorted[i]!.cid, bSorted[i]!.cid);
      assert.equal(canonicalize(aSorted[i]!.body), canonicalize(bSorted[i]!.body));
    }
  }
});

test("verifyReceipt agrees across two AppViews on the same data", async () => {
  const { fh, a, b, job, att, receipt } = fixtureScene();
  await fh.dispatch(job);
  await fh.dispatch(att);
  await fh.dispatch(receipt);

  const aReceipt = a.store.get(receipt.uri)!.body as ReceiptRecord;
  const aJob = a.store.get(job.uri)!.body as JobRecord;
  const aAtt = a.store.get(att.uri)!.body as AttestationRecord;

  const bReceipt = b.store.get(receipt.uri)!.body as ReceiptRecord;
  const bJob = b.store.get(job.uri)!.body as JobRecord;
  const bAtt = b.store.get(att.uri)!.body as AttestationRecord;

  const reportA = verifyReceipt(aReceipt, aJob, aAtt);
  const reportB = verifyReceipt(bReceipt, bJob, bAtt);
  assert.equal(reportA.ok, reportB.ok);
  assert.deepEqual(
    reportA.findings.map((f) => f.code),
    reportB.findings.map((f) => f.code),
  );
});

test("replay: a fresh AppView joining late catches up by replay", async () => {
  // Operator B comes online after A has been indexing for a while.
  // We model "catch-up via firehose history" as feeding the same
  // events to B in the same order.
  const fh = new Firehose();
  const a = new Indexer(newStore());
  const b = new Indexer(newStore());
  a.subscribe(fh);

  const { job, att, receipt } = fixtureScene();
  await fh.dispatch(job);
  await fh.dispatch(att);
  await fh.dispatch(receipt);

  // Now B subscribes and replays the same three events out of band
  // (e.g. by re-fetching from a relay's backfill window).
  b.subscribe(fh);
  for (const ev of [job, att, receipt]) {
    b.ingest({
      uri: ev.uri,
      cid: ev.cid,
      collection: ev.collection,
      repo: ev.repo,
      rkey: ev.rkey,
      record: ev.body,
    });
  }

  const aReceipt = a.store.get(receipt.uri);
  const bReceipt = b.store.get(receipt.uri);
  assert.ok(aReceipt && bReceipt);
  assert.equal(canonicalize(aReceipt.body), canonicalize(bReceipt.body));
});

test("non-cocore records on the same firehose are dropped by both AppViews", async () => {
  const { fh, a, b } = fixtureScene();
  await fh.dispatch({
    uri: "at://did:plc:somebody/app.bsky.feed.post/1",
    cid: "bcid",
    collection: "app.bsky.feed.post",
    repo: "did:plc:somebody",
    rkey: "1",
    body: { text: "hello" },
  });
  // Both AppViews ignore non-cocore collections — the indexer
  // filters at ingest time.
  for (const ix of [a, b]) {
    const all = ix.store.listByCollection("app.bsky.feed.post");
    assert.equal(all.length, 0);
  }
});

test("out-of-order arrival converges: receipt before its job is still indexed", async () => {
  // We test the row-set invariant, not validation: receipts arriving
  // before their job is a real-world firehose case (different
  // providers/requesters, jitter). The verifier handles missing
  // referenced records gracefully; the indexer must not drop anything.
  const { fh, a, b, job, att, receipt } = fixtureScene();
  await fh.dispatch(receipt); // receipt first
  await fh.dispatch(att);
  await fh.dispatch(job);

  for (const ix of [a, b]) {
    assert.ok(ix.store.get(receipt.uri));
    assert.ok(ix.store.get(att.uri));
    assert.ok(ix.store.get(job.uri));
  }
});
