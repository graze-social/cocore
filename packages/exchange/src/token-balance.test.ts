// Tests for the TokenLedger. Each test instantiates an in-memory
// sqlite, exercises one slice of the surface, and asserts on the
// resulting balances + emitted events.

import { test } from "vitest";
import assert from "node:assert/strict";
import Database from "better-sqlite3";

import { TokenLedger, type TokenLedgerPolicy } from "./token-balance.ts";

/** Policy values matching the cocore.dev defaults: 1M grant, 100K
 *  floor, 5% treasury fee, weekly refresh, monthly patronage rebate
 *  of 80% of treasury. */
const POLICY: TokenLedgerPolicy = {
  tokenGrant: 1_000_000,
  tokenFloor: 100_000,
  treasuryDid: "did:plc:treasury",
  treasuryFeeBps: 500,
  selfLoopFeeWaived: true,
  weeklyRefreshAmount: 70_000,
  refreshCadenceMinutes: 7 * 24 * 60,
  patronageFractionBps: 8000,
  patronageCadenceDays: 30,
};

function freshLedger(): TokenLedger {
  return new TokenLedger(new Database(":memory:"));
}

test("getOrInitBalance lazy-grants 1M tokens and flags pendingGrant", () => {
  const l = freshLedger();
  const r = l.getOrInitBalance("did:plc:alice", POLICY);
  assert.equal(r.balance, 1_000_000);
  assert.equal(r.pendingGrant, true);
  const events = l.listEvents("did:plc:alice");
  assert.equal(events.length, 1);
  assert.equal(events[0]?.kind, "grant");
  assert.equal(events[0]?.tokensDelta, 1_000_000);
});

test("getOrInitBalance is idempotent — repeat returns pendingGrant=false", () => {
  const l = freshLedger();
  l.getOrInitBalance("did:plc:alice", POLICY);
  const second = l.getOrInitBalance("did:plc:alice", POLICY);
  assert.equal(second.balance, 1_000_000);
  assert.equal(second.pendingGrant, false);
  assert.equal(l.listEvents("did:plc:alice").length, 1, "no duplicate grant event");
});

test("applyReceipt does a 3-way conservation transfer (requester / provider / treasury)", () => {
  const l = freshLedger();
  const applied = l.applyReceipt(
    {
      uri: "at://did:plc:alice/dev.cocore.compute.job/jjj1",
      requesterDid: "did:plc:alice",
      providerDid: "did:plc:bob",
      tokens: 200_000,
    },
    POLICY,
  );
  assert.equal(applied, true);
  // 5% of 200K = 10K to treasury; 190K to provider; requester loses 200K.
  assert.equal(l.peekBalance("did:plc:alice"), 1_000_000 - 200_000);
  assert.equal(l.peekBalance("did:plc:bob"), 1_000_000 + 190_000);
  assert.equal(l.peekBalance("did:plc:treasury"), 1_000_000 + 10_000);
});

test("applyReceipt conserves tokens for odd-bps rounding", () => {
  const l = freshLedger();
  // 100 tokens at 500 bps → provider 95, treasury 5. Sums to 100.
  l.applyReceipt(
    {
      uri: "at://did:plc:alice/dev.cocore.compute.job/x",
      requesterDid: "did:plc:alice",
      providerDid: "did:plc:bob",
      tokens: 100,
    },
    POLICY,
  );
  assert.equal(l.peekBalance("did:plc:alice"), 1_000_000 - 100);
  assert.equal(l.peekBalance("did:plc:bob"), 1_000_000 + 95);
  assert.equal(l.peekBalance("did:plc:treasury"), 1_000_000 + 5);

  // 99 tokens at 500 bps. The fee is now derived from the SAME shared
  // `computeFee` the settlement path uses (M5), which floors the TREASURY
  // fee: floor(99 * 500 / 10000) = floor(4.95) = 4; provider gets the
  // remainder 99 - 4 = 95. Sum: 95 + 4 = 99. Conserved. (The prior
  // implementation floored the provider share instead — 94 to provider,
  // 5 to treasury — which conserved too but rounded the opposite way and
  // diverged from the published settlement's exchangeFee. Unifying on
  // computeFee makes the ledger fee and the settlement fee identical.)
  l.applyReceipt(
    {
      uri: "at://did:plc:alice/dev.cocore.compute.job/y",
      requesterDid: "did:plc:alice",
      providerDid: "did:plc:bob",
      tokens: 99,
    },
    POLICY,
  );
  assert.equal(l.peekBalance("did:plc:alice"), 1_000_000 - 199);
  assert.equal(l.peekBalance("did:plc:bob"), 1_000_000 + 95 + 95);
  assert.equal(l.peekBalance("did:plc:treasury"), 1_000_000 + 5 + 4);
});

test("applyReceipt with treasuryFeeBps=0 routes 100% to provider, no treasury-fee event", () => {
  const l = freshLedger();
  const policy = { ...POLICY, treasuryFeeBps: 0 };
  l.applyReceipt(
    {
      uri: "at://did:plc:alice/dev.cocore.compute.job/zero-fee",
      requesterDid: "did:plc:alice",
      providerDid: "did:plc:bob",
      tokens: 1_000,
    },
    policy,
  );
  assert.equal(l.peekBalance("did:plc:alice"), 1_000_000 - 1_000);
  assert.equal(l.peekBalance("did:plc:bob"), 1_000_000 + 1_000);
  // Treasury balance is still 1M (the initial grant on first touch), no
  // additional treasury-fee event.
  const treasuryEvents = l.listEvents("did:plc:treasury");
  assert.equal(treasuryEvents.length, 1, "treasury only has its own grant event");
  assert.equal(treasuryEvents[0]?.kind, "grant");
});

test("applyReceipt self-loop with selfLoopFeeWaived=true is a zero-net transfer", () => {
  // Regression: self-loop receipts used to break conservation. The
  // ledger read a snapshot of the balance, computed
  // receipt-out/receipt-in independently, and applied two
  // `tokens = ?` writes derived from the same snapshot. The second
  // write overwrote the first, so the user "gained"
  // receipt.tokens - providerShare per self-loop receipt. The fix
  // (aggregate per-DID deltas, apply each unique DID once) plus
  // honoring selfLoopFeeWaived on self-loops produces a true
  // zero-net transfer.
  const l = freshLedger();
  l.applyReceipt(
    {
      uri: "at://did:plc:alice/dev.cocore.compute.job/self-loop-waived",
      requesterDid: "did:plc:alice",
      providerDid: "did:plc:alice",
      tokens: 47,
    },
    POLICY,
  );
  assert.equal(
    l.peekBalance("did:plc:alice"),
    1_000_000,
    "self-loop with fee waived should net to zero for the user",
  );
  assert.equal(
    l.peekBalance("did:plc:treasury"),
    1_000_000,
    "treasury gets no fee on a waived self-loop (only its onboarding grant)",
  );
  const aliceEvents = l.listEvents("did:plc:alice");
  // Three events: grant, receipt-out, receipt-in (no treasury-fee).
  assert.equal(aliceEvents.length, 3);
  assert.equal(aliceEvents[1]?.kind, "receipt-out");
  assert.equal(aliceEvents[1]?.tokensDelta, -47);
  assert.equal(aliceEvents[2]?.kind, "receipt-in");
  assert.equal(aliceEvents[2]?.tokensDelta, 47);
  // Both event rows report the same post-receipt balance — the
  // receipt-out and receipt-in fired atomically so there's only
  // one "after" state.
  assert.equal(aliceEvents[1]?.balanceAfter, 1_000_000);
  assert.equal(aliceEvents[2]?.balanceAfter, 1_000_000);
});

test("applyReceipt self-loop with selfLoopFeeWaived=false charges the treasury fee", () => {
  const l = freshLedger();
  const policy = { ...POLICY, selfLoopFeeWaived: false };
  l.applyReceipt(
    {
      uri: "at://did:plc:alice/dev.cocore.compute.job/self-loop-not-waived",
      requesterDid: "did:plc:alice",
      providerDid: "did:plc:alice",
      tokens: 100,
    },
    policy,
  );
  // User: spent 100, earned 95 back as provider, net -5
  assert.equal(l.peekBalance("did:plc:alice"), 1_000_000 - 5);
  // Treasury: gained 5
  assert.equal(l.peekBalance("did:plc:treasury"), 1_000_000 + 5);
});

test("applyReceipt is idempotent on receipt URI (second call is a no-op)", () => {
  const l = freshLedger();
  const receipt = {
    uri: "at://did:plc:alice/dev.cocore.compute.job/dedup",
    requesterDid: "did:plc:alice",
    providerDid: "did:plc:bob",
    tokens: 1_000,
  };
  assert.equal(l.applyReceipt(receipt, POLICY), true);
  assert.equal(l.applyReceipt(receipt, POLICY), false);
  assert.equal(l.peekBalance("did:plc:alice"), 1_000_000 - 1_000);
  assert.equal(l.peekBalance("did:plc:bob"), 1_000_000 + 950);
});

test("applyRefreshIfDue fires once per cadence window, not before", () => {
  const l = freshLedger();
  const policy = { ...POLICY, refreshCadenceMinutes: 0.001 }; // tiny window for test
  l.getOrInitBalance("did:plc:alice", POLICY);
  // First call: too soon (just granted).
  assert.equal(
    l.applyRefreshIfDue("did:plc:alice", { ...POLICY, refreshCadenceMinutes: 999_999 }),
    false,
  );
  // With cadence ~60ms, a 100ms pause lets the window elapse.
  return new Promise<void>((resolve) => {
    setTimeout(() => {
      assert.equal(l.applyRefreshIfDue("did:plc:alice", policy), true);
      assert.equal(l.peekBalance("did:plc:alice"), 1_000_000 + 70_000);
      // Immediate second call: no refresh (cadence not yet re-elapsed).
      assert.equal(l.applyRefreshIfDue("did:plc:alice", policy), false);
      resolve();
    }, 100);
  });
});

test("applyRefreshIfDue is a no-op when weeklyRefreshAmount=0", () => {
  const l = freshLedger();
  l.getOrInitBalance("did:plc:alice", POLICY);
  const policy = { ...POLICY, weeklyRefreshAmount: 0 };
  assert.equal(l.applyRefreshIfDue("did:plc:alice", policy), false);
});

test("applyRefreshIfDue ignores dormant DIDs (no balance row exists)", () => {
  const l = freshLedger();
  const policy = { ...POLICY, refreshCadenceMinutes: 1 };
  // Never called getOrInitBalance — DID is dormant.
  assert.equal(l.applyRefreshIfDue("did:plc:never-existed", policy), false);
});

test("checkAdmission accepts fresh DID for small ceiling, rejects when short", () => {
  const l = freshLedger();
  const okRes = l.checkAdmission("did:plc:alice", 100_000, POLICY);
  assert.equal(okRes.ok, true);
  assert.equal(okRes.balance, 1_000_000);
  assert.equal(okRes.required, 200_000);

  // Drain alice via receipts: 950K out -> 50K left.
  l.applyReceipt(
    {
      uri: "at://did:plc:alice/dev.cocore.compute.job/drain",
      requesterDid: "did:plc:alice",
      providerDid: "did:plc:bob",
      tokens: 950_000,
    },
    POLICY,
  );
  const shortRes = l.checkAdmission("did:plc:alice", 100_000, POLICY);
  assert.equal(shortRes.ok, false);
  assert.equal(shortRes.balance, 50_000);
  assert.equal(shortRes.shortBy, 150_000);
});

test("distributePatronage credits active members pro-rata and debits treasury", () => {
  const l = freshLedger();
  // Seed: a few receipts between alice and bob. Treasury accrues 5% of
  // each. Their patronage = tokens flowed through them.
  l.applyReceipt(
    {
      uri: "at://x/1",
      requesterDid: "did:plc:alice",
      providerDid: "did:plc:bob",
      tokens: 100_000,
    },
    POLICY,
  );
  l.applyReceipt(
    {
      uri: "at://x/2",
      requesterDid: "did:plc:bob",
      providerDid: "did:plc:alice",
      tokens: 50_000,
    },
    POLICY,
  );

  const treasuryBefore = l.peekBalance("did:plc:treasury");
  // 5% of 100K + 5% of 50K = 7,500.
  assert.equal(treasuryBefore, 1_000_000 + 7_500);

  // Distribute over a wide window covering both receipts.
  const start = new Date("2020-01-01T00:00:00Z");
  const end = new Date("2030-01-01T00:00:00Z");
  const r = l.distributePatronage(start, end, POLICY);
  assert.equal(r.alreadyDistributed, false);
  assert.ok(r.totalPatronage > 0);
  // The per-recipient floor() can shave up to (num_recipients - 1)
  // tokens off the headline 80%. Assert "≤ target, within recipient
  // count" rather than exact equality.
  const target = Math.floor((treasuryBefore * 8000) / 10000);
  assert.ok(r.totalDistributed <= target);
  assert.ok(target - r.totalDistributed <= r.recipients.length);
  // Treasury debited by exactly the actual sum of recipient credits.
  assert.equal(l.peekBalance("did:plc:treasury"), treasuryBefore - r.totalDistributed);
  // Each recipient has a patronage-in event.
  for (const recip of r.recipients) {
    const events = l.listEvents(recip.did);
    const last = events[events.length - 1];
    assert.equal(last?.kind, "patronage-in");
    assert.equal(last?.tokensDelta, recip.tokensCredited);
  }
});

test("distributePatronage is idempotent on (start, end) window", () => {
  const l = freshLedger();
  l.applyReceipt(
    {
      uri: "at://x/1",
      requesterDid: "did:plc:alice",
      providerDid: "did:plc:bob",
      tokens: 100_000,
    },
    POLICY,
  );
  const start = new Date("2020-01-01T00:00:00Z");
  const end = new Date("2030-01-01T00:00:00Z");
  const first = l.distributePatronage(start, end, POLICY);
  assert.equal(first.alreadyDistributed, false);
  assert.ok(first.totalDistributed > 0);
  const treasuryAfter = l.peekBalance("did:plc:treasury");

  const second = l.distributePatronage(start, end, POLICY);
  assert.equal(second.alreadyDistributed, true);
  assert.equal(second.totalDistributed, 0);
  // Treasury unchanged.
  assert.equal(l.peekBalance("did:plc:treasury"), treasuryAfter);
});

test("totalEventDelta == sum of mints (grants + refreshes) for a healthy ledger", () => {
  const l = freshLedger();
  l.getOrInitBalance("did:plc:alice", POLICY);
  l.getOrInitBalance("did:plc:bob", POLICY);
  l.getOrInitBalance("did:plc:treasury", POLICY);
  // 3 grants of 1M each = 3M minted.
  assert.equal(l.totalEventDelta(), 3 * 1_000_000);
  // A receipt is pure conservation; doesn't change the sum.
  l.applyReceipt(
    {
      uri: "at://x/1",
      requesterDid: "did:plc:alice",
      providerDid: "did:plc:bob",
      tokens: 100_000,
    },
    POLICY,
  );
  assert.equal(l.totalEventDelta(), 3 * 1_000_000);
});

test("reconcile reports ok=true on a healthy ledger after grants + receipts + refreshes", () => {
  const l = freshLedger();
  // Three accounts, three grants. One non-self-loop receipt for 100K
  // tokens. Conservation holds: sum of deltas = sum of mints = 3M;
  // each balance equals replay-of-events; no negatives; no idempotency
  // collisions.
  l.getOrInitBalance("did:plc:alice", POLICY);
  l.getOrInitBalance("did:plc:bob", POLICY);
  l.getOrInitBalance("did:plc:treasury", POLICY);
  l.applyReceipt(
    {
      uri: "at://alice/job/1",
      requesterDid: "did:plc:alice",
      providerDid: "did:plc:bob",
      tokens: 100_000,
    },
    POLICY,
  );
  const r = l.reconcile();
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.totalDelta, 3 * 1_000_000);
  assert.equal(r.totalMints, 3 * 1_000_000);
  assert.equal(r.totalBalance, 3 * 1_000_000);
  assert.equal(r.balanceCacheDrifts.length, 0);
  assert.equal(r.negativeBalances.length, 0);
  assert.equal(r.didCount, 3);
  assert.equal(r.eventCount, 3 + 3); // 3 grants + receipt-out + receipt-in + treasury-fee
  assert.equal(r.receiptsProcessed, 1);
});

test("reconcile detects a balance-cache drift and rebuildBalanceCache fixes it", () => {
  const l = freshLedger();
  l.getOrInitBalance("did:plc:alice", POLICY);
  l.getOrInitBalance("did:plc:bob", POLICY);
  l.getOrInitBalance("did:plc:treasury", POLICY);
  l.applyReceipt(
    {
      uri: "at://alice/job/2",
      requesterDid: "did:plc:alice",
      providerDid: "did:plc:bob",
      tokens: 100_000,
    },
    POLICY,
  );
  // Corrupt the cache manually — pretend a write was dropped.
  const db = (l as unknown as { db: Database.Database }).db;
  db.prepare(`UPDATE token_balance SET tokens = tokens + 9999 WHERE did = ?`).run("did:plc:alice");
  const drifted = l.reconcile();
  assert.equal(drifted.ok, false);
  assert.equal(drifted.balanceCacheDrifts.length, 1);
  assert.equal(drifted.balanceCacheDrifts[0]?.did, "did:plc:alice");
  assert.equal(drifted.balanceCacheDrifts[0]?.delta, 9999);
  // Rebuild + recheck.
  const fix = l.rebuildBalanceCache();
  assert.equal(fix.changed, 1);
  const after = l.reconcile();
  assert.equal(after.ok, true, JSON.stringify(after));
});

test("applyReceipt under 50 sequential parallel-ish calls preserves conservation", () => {
  // Node + better-sqlite3 are synchronous, so true OS-level
  // concurrency doesn't apply — but a tight loop still exercises
  // the txn boundary and the idempotency table under load. After
  // 50 receipts, sum of mints, sum of deltas, and sum of balances
  // all agree.
  const l = freshLedger();
  l.getOrInitBalance("did:plc:alice", POLICY);
  l.getOrInitBalance("did:plc:bob", POLICY);
  l.getOrInitBalance("did:plc:treasury", POLICY);
  for (let i = 0; i < 50; i += 1) {
    l.applyReceipt(
      {
        uri: `at://alice/job/${i}`,
        requesterDid: "did:plc:alice",
        providerDid: "did:plc:bob",
        tokens: 100,
      },
      POLICY,
    );
  }
  const r = l.reconcile();
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.receiptsProcessed, 50);
  // 5% fee floored on 100 = 5; provider gets 95; treasury gets 5.
  assert.equal(l.peekBalance("did:plc:alice"), 1_000_000 - 50 * 100);
  assert.equal(l.peekBalance("did:plc:bob"), 1_000_000 + 50 * 95);
  assert.equal(l.peekBalance("did:plc:treasury"), 1_000_000 + 50 * 5);
});

test("duplicate applyReceipt calls (same URI) don't double-credit", () => {
  // Idempotency table guards against retries from a flaky upstream
  // re-emitting the same receipt. Second call must be a no-op.
  const l = freshLedger();
  l.getOrInitBalance("did:plc:alice", POLICY);
  l.getOrInitBalance("did:plc:bob", POLICY);
  l.getOrInitBalance("did:plc:treasury", POLICY);
  const receipt = {
    uri: "at://alice/job/dup",
    requesterDid: "did:plc:alice",
    providerDid: "did:plc:bob",
    tokens: 1_000,
  };
  assert.equal(l.applyReceipt(receipt, POLICY), true, "first apply succeeds");
  assert.equal(l.applyReceipt(receipt, POLICY), false, "second apply is no-op");
  assert.equal(l.applyReceipt(receipt, POLICY), false, "third apply is no-op");
  const r = l.reconcile();
  assert.equal(r.ok, true);
  assert.equal(r.receiptsProcessed, 1);
  // Net movement only applied once: alice -1000, bob +950, treasury +50.
  assert.equal(l.peekBalance("did:plc:alice"), 1_000_000 - 1_000);
  assert.equal(l.peekBalance("did:plc:bob"), 1_000_000 + 950);
  assert.equal(l.peekBalance("did:plc:treasury"), 1_000_000 + 50);
});

test("leaderboard ranks balances, earners, and spenders, excluding system DIDs", () => {
  const l = freshLedger();
  // alice spends a lot across two receipts; bob and carol earn.
  l.applyReceipt(
    {
      uri: "at://r/1",
      requesterDid: "did:plc:alice",
      providerDid: "did:plc:bob",
      tokens: 300_000,
    },
    POLICY,
  );
  l.applyReceipt(
    {
      uri: "at://r/2",
      requesterDid: "did:plc:alice",
      providerDid: "did:plc:carol",
      tokens: 100_000,
    },
    POLICY,
  );
  l.applyReceipt(
    {
      uri: "at://r/3",
      requesterDid: "did:plc:dave",
      providerDid: "did:plc:bob",
      tokens: 50_000,
    },
    POLICY,
  );

  const board = l.leaderboard({ limit: 10, excludeDids: ["did:plc:treasury"] });

  // Treasury accrues the fee but is excluded from every list.
  for (const list of [board.topBalances, board.topEarners, board.topSpenders]) {
    assert.ok(!list.some((e) => e.did === "did:plc:treasury"), "treasury must be excluded");
  }

  // Spenders: alice spent 400k (300k + 100k), dave spent 50k.
  assert.equal(board.topSpenders[0]?.did, "did:plc:alice");
  assert.equal(board.topSpenders[0]?.amount, 400_000);
  assert.equal(board.topSpenders[1]?.did, "did:plc:dave");
  assert.equal(board.topSpenders[1]?.amount, 50_000);

  // Earners: bob earned post-fee on 300k + 50k; carol on 100k.
  // bob (332_500) > carol (95_000).
  assert.equal(board.topEarners[0]?.did, "did:plc:bob");
  assert.equal(board.topEarners[1]?.did, "did:plc:carol");
  assert.ok(
    (board.topEarners[0]?.amount ?? 0) > (board.topEarners[1]?.amount ?? 0),
    "earners ranked by total received",
  );

  // Balances: bob (grant + earnings) tops the list; alice (grant - 400k)
  // is the lightest non-treasury wallet.
  assert.equal(board.topBalances[0]?.did, "did:plc:bob");
  assert.equal(board.topBalances.at(-1)?.did, "did:plc:alice");

  // limit is honored.
  const tiny = l.leaderboard({ limit: 1, excludeDids: ["did:plc:treasury"] });
  assert.equal(tiny.topSpenders.length, 1);
  assert.equal(tiny.topSpenders[0]?.did, "did:plc:alice");
});

test("listEvents desc returns newest-first so a fresh event leads", () => {
  const l = freshLedger();
  // grant (oldest) then a receipt-out (newest) for alice.
  l.applyReceipt(
    {
      uri: "at://alice/job/desc",
      requesterDid: "did:plc:alice",
      providerDid: "did:plc:bob",
      tokens: 50_000,
    },
    POLICY,
  );
  const asc = l.listEvents("did:plc:alice");
  const desc = l.listEvents("did:plc:alice", 100, "desc");
  // asc still leads with the grant (back-compat for replay callers).
  assert.equal(asc[0]?.kind, "grant");
  // desc leads with the most recent event.
  assert.equal(desc[0]?.kind, "receipt-out");
  assert.equal(desc.at(-1)?.kind, "grant");
});

test("summarizeEvents rolls up credited / debited / patronage over full history", () => {
  const l = freshLedger();
  // alice spends as requester; bob earns as provider.
  l.applyReceipt(
    {
      uri: "at://alice/job/sum1",
      requesterDid: "did:plc:alice",
      providerDid: "did:plc:bob",
      tokens: 100_000,
    },
    POLICY,
  );
  // Distribute patronage so alice receives a patronage-in event.
  const start = new Date("2020-01-01T00:00:00Z");
  const end = new Date("2030-01-01T00:00:00Z");
  l.distributePatronage(start, end, POLICY);

  const s = l.summarizeEvents("did:plc:alice");
  const patronageIn = s.byKind.find((k) => k.kind === "patronage-in")?.total ?? 0;
  assert.ok(patronageIn > 0, "alice received a patronage rebate");
  // Credited = grant (1M) + patronage rebate; debited = the 100K spent.
  assert.equal(s.totalDebited, 100_000);
  assert.equal(s.totalCredited, 1_000_000 + patronageIn);
  // net == credited - debited, which equals the cached balance.
  assert.equal(s.net, s.totalCredited - s.totalDebited);
  assert.equal(s.net, l.peekBalance("did:plc:alice"));
});
