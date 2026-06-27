// Unit tests for the CAS read-modify-write transactor — the single path all
// console + agent record mutations funnel through. These exercise the contract
// that makes concurrent writers safe: field-scoped patches, last-writer-wins
// under swap conflict, fail-closed on read errors, and bounded retry.
//
// The transactor is storage-agnostic (it takes a CasRecordStore), so we drive
// it with an in-memory fake that models real PDS compare-and-swap: a write only
// commits when its swapRecord matches the current CID, and every commit moves
// the CID. That lets us inject a competing writer between a read and its write
// to force the exact `InvalidSwap` race the transactor must survive.

import assert from "node:assert/strict";
import { describe, test } from "vitest";

import {
  type CasRecordStore,
  isRecordNotFound,
  isSwapConflict,
  RecordNotFoundError,
  transactRecord,
} from "./record-transactor.server.ts";

const noSleep = async () => {};

/** In-memory PDS-like store with real swap semantics. `interpose` runs once,
 *  just before the next `write` lands, to simulate a competing commit. */
class FakeStore implements CasRecordStore {
  cid: string | null;
  value: Record<string, unknown> | null;
  reads = 0;
  writes = 0;
  private seq = 0;
  failReadWith: Error | null = null;
  failWriteWith: Error | null = null;
  interpose: (() => void) | null = null;

  constructor(initial?: { value: Record<string, unknown> }) {
    if (initial) {
      this.value = { ...initial.value };
      this.cid = "cid-0";
    } else {
      this.value = null;
      this.cid = null;
    }
  }

  async read(): Promise<{ cid: string; value: Record<string, unknown> } | null> {
    this.reads += 1;
    if (this.failReadWith) throw this.failReadWith;
    if (this.value === null || this.cid === null) return null;
    return { cid: this.cid, value: { ...this.value } };
  }

  async write(
    _rkey: string,
    value: Record<string, unknown>,
    swapRecord: string | null,
  ): Promise<{ cid: string }> {
    // A competitor commits between the transactor's read and this write.
    if (this.interpose) {
      const fn = this.interpose;
      this.interpose = null;
      fn();
    }
    this.writes += 1;
    if (this.failWriteWith) throw this.failWriteWith;
    if ((this.cid ?? null) !== (swapRecord ?? null)) {
      throw new Error("InvalidSwap");
    }
    this.seq += 1;
    this.cid = `cid-${this.seq}`;
    this.value = { ...value };
    return { cid: this.cid };
  }

  /** Commit a competing change directly (as if another writer won the race). */
  commitExternal(mutate: (v: Record<string, unknown>) => Record<string, unknown>): void {
    this.seq += 1;
    this.cid = `ext-${this.seq}`;
    this.value = mutate(this.value ? { ...this.value } : {});
  }
}

describe("transactRecord", () => {
  test("applies a field-scoped patch and preserves all other fields", async () => {
    const store = new FakeStore({
      value: { active: true, supportedModels: ["a"], unknownFutureField: 42 },
    });
    const { value } = await transactRecord(store, "rk", (v) => ({ ...v, active: false }), {
      sleep: noSleep,
    });
    assert.equal(value.active, false);
    // Agent-authored + entirely-unknown fields ride through untouched — this is
    // what makes a new field immune to the "forgot the allowlist" clobber.
    assert.deepEqual(value.supportedModels, ["a"]);
    assert.equal(value.unknownFutureField, 42);
    assert.equal(store.writes, 1);
  });

  test("stampCreatedAt bumps createdAt to now; off by default", async () => {
    const store = new FakeStore({ value: { active: true, createdAt: "2000-01-01T00:00:00.000Z" } });
    const off = await transactRecord(store, "rk", (v) => ({ ...v }), { sleep: noSleep });
    assert.equal(off.value.createdAt, "2000-01-01T00:00:00.000Z");

    const before = Date.now();
    const on = await transactRecord(store, "rk", (v) => ({ ...v }), {
      sleep: noSleep,
      stampCreatedAt: true,
    });
    const stamped = Date.parse(on.value.createdAt as string);
    assert.ok(stamped >= before, "createdAt should be bumped to ~now");
  });

  test("retries on swap conflict and merges the competitor's change (last-writer-wins per field)", async () => {
    const store = new FakeStore({ value: { active: true, proBono: { mode: "any" } } });
    // Between our read and our write, a competing writer flips a DIFFERENT
    // field (shareLocation) and commits, moving the CID. Our first write loses
    // the swap; the transactor re-reads (now seeing shareLocation) and replays.
    store.interpose = () => {
      store.commitExternal((v) => ({ ...v, shareLocation: true }));
    };
    const { value } = await transactRecord(store, "rk", (v) => ({ ...v, active: false }), {
      sleep: noSleep,
    });
    assert.equal(store.writes, 2, "first write conflicts, second succeeds");
    assert.equal(value.active, false, "our field wins (we committed last)");
    assert.equal(value.shareLocation, true, "competitor's untouched field survives");
    assert.deepEqual(value.proBono, { mode: "any" }, "pre-existing field survives");
  });

  test("a READ failure aborts the transaction and never writes", async () => {
    const store = new FakeStore({ value: { active: true } });
    store.failReadWith = new Error("503 Application failed to respond");
    await assert.rejects(
      () => transactRecord(store, "rk", (v) => ({ ...v, active: false }), { sleep: noSleep }),
      /503/,
    );
    assert.equal(store.writes, 0, "must not write a guessed default on a failed read");
    assert.equal(store.value?.active, true, "record untouched");
  });

  test("throws RecordNotFoundError when absent and createIfMissing is false", async () => {
    const store = new FakeStore();
    await assert.rejects(
      () => transactRecord(store, "rk", (v) => ({ ...v, active: false }), { sleep: noSleep }),
      RecordNotFoundError,
    );
    assert.equal(store.writes, 0);
  });

  test("creates the record (null swap) when createIfMissing is set", async () => {
    const store = new FakeStore();
    const { value } = await transactRecord(
      store,
      "rk",
      (v) => ({ ...v, active: true, machineLabel: "new" }),
      { sleep: noSleep, createIfMissing: true },
    );
    assert.equal(value.active, true);
    assert.equal(value.machineLabel, "new");
    assert.equal(store.writes, 1);
  });

  test("gives up after maxAttempts of persistent conflict, surfacing the conflict", async () => {
    const store = new FakeStore({ value: { active: true } });
    // Every write loses the swap (a relentless competitor).
    const original = store.write.bind(store);
    store.write = async (rkey, value, _swap) =>
      original(rkey, value, "stale-cid-that-never-matches");
    await assert.rejects(
      () =>
        transactRecord(store, "rk", (v) => ({ ...v, active: false }), {
          sleep: noSleep,
          maxAttempts: 3,
        }),
      isSwapConflict,
    );
    assert.equal(store.writes, 3, "tried exactly maxAttempts times");
  });

  test("a non-conflict write error is not retried", async () => {
    const store = new FakeStore({ value: { active: true } });
    store.failWriteWith = new Error("401 Unauthorized");
    await assert.rejects(
      () => transactRecord(store, "rk", (v) => ({ ...v, active: false }), { sleep: noSleep }),
      /401/,
    );
    assert.equal(store.writes, 1, "auth errors fail fast, no retry");
  });
});

describe("error classifiers", () => {
  test("isSwapConflict matches InvalidSwap and descriptive forms only", () => {
    assert.ok(isSwapConflict(new Error("InvalidSwap")));
    assert.ok(isSwapConflict(new Error("Record was at bafy... but expected bafy...")));
    assert.ok(isSwapConflict("invalid swap"));
    assert.ok(!isSwapConflict(new Error("RecordNotFound")));
    assert.ok(!isSwapConflict(new Error("503 upstream")));
  });

  test("isRecordNotFound matches 404 forms, not swap conflicts", () => {
    assert.ok(isRecordNotFound(new Error("RecordNotFound")));
    assert.ok(isRecordNotFound(new Error("Could not locate record")));
    assert.ok(!isRecordNotFound(new Error("InvalidSwap")));
    assert.ok(!isRecordNotFound(new Error("503 upstream")));
  });
});
