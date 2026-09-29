// Drift guard: every JSON file we ship under lexicons/dev/cocore/compute
// MUST be in both the runtime registry and the public ids map. This
// test exists because the registry is a hand-maintained list of
// imports — easy to forget to extend when adding a new lexicon.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "vitest";
import assert from "node:assert/strict";

import { ids, lexicons, schemas } from "./lex-runtime.ts";

const LEX_DIR = fileURLToPath(new URL("../../../lexicons/dev/cocore/compute/", import.meta.url));

function nsidsOnDisk(): string[] {
  return readdirSync(LEX_DIR)
    .filter((f) => f.endsWith(".json"))
    .map((f) => {
      const raw = readFileSync(join(LEX_DIR, f), "utf-8");
      const doc = JSON.parse(raw) as { id?: unknown };
      assert.equal(typeof doc.id, "string", `${f} missing id`);
      return doc.id as string;
    })
    .sort();
}

test("lex-runtime registry contains every on-disk lexicon", () => {
  const onDisk = nsidsOnDisk();
  // Restrict to dev.cocore.* — the registry also bundles
  // com.atproto.repo.strongRef as a vendored stub, which has no
  // matching JSON file under lexicons/.
  const inRegistry = schemas
    .map((s) => s.id)
    .filter((id) => id.startsWith("dev.cocore."))
    .sort();
  // Use deepEqual on sorted arrays so the test failure message names
  // the missing/extra NSID, not just "not equal".
  assert.deepEqual(inRegistry, onDisk);
});

test("lex-runtime ids map covers every on-disk lexicon", () => {
  const onDisk = new Set<string>(nsidsOnDisk());
  // ids has narrow literal-string types; widen to string here so we
  // can compare against on-disk filenames symmetrically.
  const inIds = new Set<string>(Object.values(ids));
  for (const nsid of onDisk) {
    assert.ok(inIds.has(nsid), `ids map missing ${nsid}`);
  }
  for (const nsid of inIds) {
    assert.ok(onDisk.has(nsid), `ids map has stale entry ${nsid}`);
  }
});

// Invariant 3 (CLAUDE.md): "Lexicons evolve additively. New behavior is a new
// optional field or a new NSID." That only holds if a validator running an
// OLDER lexicon tolerates a record carrying a field it has never heard of —
// otherwise every additive change is a flag-day break, and a provider that
// ships a new field is rejected by every consumer that hasn't redeployed.
//
// This pins the tolerance rather than trusting it. It is not a test of
// `modelDigest` specifically; it is the guard for every field added after it.
test("a record carrying unknown fields still validates (additive evolution)", () => {
  const CID = "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a";
  const receipt = {
    $type: ids.DevCocoreComputeReceipt,
    job: { uri: "at://did:plc:requester/dev.cocore.compute.job/1", cid: CID },
    requester: "did:plc:requester",
    model: "m",
    inputCommitment: "a".repeat(64),
    outputCommitment: "b".repeat(64),
    tokens: { in: 1, out: 0 },
    startedAt: "2026-09-29T00:00:00.000Z",
    completedAt: "2026-09-29T00:00:00.000Z",
    price: { amount: 1, currency: "CC" },
    attestation: { uri: "at://did:plc:provider/dev.cocore.compute.attestation/1", cid: CID },
    enclaveSignature: new Uint8Array([1, 2, 3]),
  };

  // Baseline: the record itself is valid, so a failure below is about the
  // added field and not about the fixture.
  lexicons.assertValidRecord(ids.DevCocoreComputeReceipt, receipt);

  // What an old validator sees from a provider running a newer lexicon.
  lexicons.assertValidRecord(ids.DevCocoreComputeReceipt, {
    ...receipt,
    aFieldFromTheFuture: "x",
  });
  lexicons.assertValidRecord(ids.DevCocoreComputeReceipt, {
    ...receipt,
    params: { maxTokens: 1, aParamFromTheFuture: "x" },
  });
});
