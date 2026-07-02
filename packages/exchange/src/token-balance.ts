// Token-balance ledger.
//
// Sqlite-backed runtime over four tables:
//
//   token_balance         did -> current balance + last-touch timestamps
//   token_event           audit log; one row per balance change
//   processed_receipt     idempotency: receipt URI -> processed_at
//   processed_period      idempotency: patronage period -> processed_at
//
// ## Mechanics
//
//   * Conservation 95/5. `applyReceipt` is a three-way transfer:
//     requester `-tokens`; provider `+tokens * (1 - feeBps/10000)`;
//     treasury `+remainder`. No tokens are minted or burned; the
//     event log sums to zero per receipt.
//   * Lazy grant. `getOrInitBalance` mints `tokenGrant` the first
//     time a DID is touched, writes a `grant` event.
//   * Lazy weekly refresh. `applyRefreshIfDue` mints
//     `weeklyRefresh.amountPerDid` once per `cadenceMinutes` window
//     when the DID's balance is touched. Dormant DIDs accrue
//     nothing — the "use-it-to-keep-it" semantic.
//   * Monthly patronage. `distributePatronage` takes a half-open
//     `[start, end)` window, sums every DID's |delta| over `kind
//     IN ('receipt-in','receipt-out')` events in the window, and
//     debits the treasury by `fractionBps / 10000` of its balance
//     pro-rata across active DIDs. Idempotent on `(start, end)`.
//
// All balance-changing operations are single sqlite transactions
// that update `token_balance` and append `token_event` rows. The
// audit log is the canonical history; the balance column is a cache
// of `sum(token_event.tokens_delta) per did`.

import type { Database as DB, Statement } from "better-sqlite3";

import { computeFee } from "./exchange.ts";

export interface TokenLedgerPolicy {
  /** Tokens granted on first touch. Set to 0 to disable. */
  tokenGrant: number;
  /** Minimum post-dispatch balance required to admit a new job. */
  tokenFloor: number;
  /** DID that receives the treasury fee on every receipt. */
  treasuryDid: string;
  /** Basis points of each receipt's token cost routed to the
   *  treasury account. 500 = 5%. The remainder goes to the provider. */
  treasuryFeeBps: number;
  /** Minimum treasury fee in tokens. Floor on the bps calculation.
   *  Additive — defaults to 0 (no floor) when omitted, preserving the
   *  pure-bps behavior. MUST mirror the exchange FeePolicy.minMinor so
   *  the ledger's recorded fee and the published settlement's fee agree
   *  (they share `computeFee`). */
  feeMinMinor?: number;
  /** Waive the treasury fee on self-loop receipts (requester DID
   *  equals provider DID — e.g. a user running a job on their own
   *  machine via the exchange). When true and the receipt is a
   *  self-loop, the ledger applies a zero-net transfer: the user
   *  neither pays nor earns, treasury accrues nothing. Mirrors the
   *  settlement record's `exchangeFee=0` for self-loops so the
   *  audit log and the published settlement agree. */
  selfLoopFeeWaived: boolean;
  /** Tokens credited per refresh tick. 0 disables refresh. */
  weeklyRefreshAmount: number;
  /** Minutes between refresh ticks for a single DID. */
  refreshCadenceMinutes: number;
  /** Basis points of the treasury balance distributed each
   *  patronage tick. 0 disables. */
  patronageFractionBps: number;
  /** Days between patronage ticks. Used only by the scheduler; the
   *  ledger itself is invoked per-period. */
  patronageCadenceDays: number;
}

type TokenEventKind =
  | "grant"
  | "receipt-in"
  | "receipt-out"
  | "treasury-fee"
  | "refresh"
  | "patronage-in"
  | "patronage-out";

export interface TokenEvent {
  did: string;
  kind: TokenEventKind;
  tokensDelta: number;
  balanceAfter: number;
  reference: string | null;
  createdAt: string;
}

/** Lifetime roll-up of a DID's ledger activity. `byKind` is one row
 *  per event kind the DID has ever seen, with a signed `total`;
 *  `totalCredited` / `totalDebited` are the positive / negative
 *  magnitudes summed across kinds, and `net` is their difference
 *  (which equals the DID's current balance for an account whose only
 *  events are mints and transfers). */
export interface EventSummary {
  did: string;
  totalCredited: number;
  totalDebited: number;
  net: number;
  byKind: Array<{ kind: TokenEventKind; count: number; total: number }>;
}

/** One ranked row on the public leaderboard — a DID and the metric
 *  value it's ranked by (current balance, total earned, or total
 *  spent, depending on which list it appears in). */
export interface LeaderboardEntry {
  did: string;
  amount: number;
}

export interface AdmissionResult {
  ok: boolean;
  balance: number;
  required: number;
  shortBy: number;
  pendingGrant: boolean;
}

export interface PatronageDistributionResult {
  /** Treasury balance immediately before the distribution. */
  treasuryBefore: number;
  /** Total tokens removed from treasury and distributed. */
  totalDistributed: number;
  /** Sum of all patronage scores across recipients. */
  totalPatronage: number;
  /** One entry per recipient that got a non-zero credit. */
  recipients: Array<{
    did: string;
    patronageScore: number;
    tokensCredited: number;
  }>;
  /** True when this (start, end) period was already distributed
   *  and the call was a no-op. */
  alreadyDistributed: boolean;
}

export class TokenLedger {
  private readonly db: DB;
  private readonly stmtGetBalance: Statement;
  private readonly stmtInsertBalance: Statement;
  private readonly stmtUpdateBalance: Statement;
  private readonly stmtInsertEvent: Statement;
  private readonly stmtCheckReceipt: Statement;
  private readonly stmtMarkReceipt: Statement;
  private readonly stmtCheckPeriod: Statement;
  private readonly stmtMarkPeriod: Statement;

  constructor(db: DB) {
    this.db = db;
    this.db.exec(SCHEMA);
    this.runMigrations();
    this.stmtGetBalance = this.db.prepare(
      `SELECT did, tokens, grant_at, last_refresh_at, last_event_at, updated_at
         FROM token_balance WHERE did = ?`,
    );
    this.stmtInsertBalance = this.db.prepare(
      `INSERT INTO token_balance
         (did, tokens, grant_at, last_refresh_at, last_event_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
    );
    this.stmtUpdateBalance = this.db.prepare(
      `UPDATE token_balance
          SET tokens = ?, last_refresh_at = ?, last_event_at = ?, updated_at = ?
        WHERE did = ?`,
    );
    this.stmtInsertEvent = this.db.prepare(
      `INSERT INTO token_event
         (did, kind, tokens_delta, balance_after, reference, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
    );
    this.stmtCheckReceipt = this.db.prepare(
      `SELECT receipt_uri FROM processed_receipt WHERE receipt_uri = ?`,
    );
    this.stmtMarkReceipt = this.db.prepare(
      `INSERT INTO processed_receipt (receipt_uri, processed_at) VALUES (?, ?)`,
    );
    this.stmtCheckPeriod = this.db.prepare(
      `SELECT period_start FROM processed_period
         WHERE period_start = ? AND period_end = ?`,
    );
    this.stmtMarkPeriod = this.db.prepare(
      `INSERT INTO processed_period (period_start, period_end, processed_at)
         VALUES (?, ?, ?)`,
    );
  }

  /** One-shot migration: add the two new timestamp columns to
   *  pre-2026-05-11 `token_balance` rows. Best-effort — if the
   *  column already exists, sqlite errors with "duplicate column
   *  name" and we ignore. Also drops the now-unused
   *  `processed_stripe` table from earlier pivots. */
  private runMigrations(): void {
    const tryAlter = (sql: string) => {
      try {
        this.db.exec(sql);
      } catch (e) {
        if (!(e instanceof Error) || !/duplicate column name/.test(e.message)) {
          // Anything other than "column already exists" is a real
          // schema problem; surface it.
          throw e;
        }
      }
    };
    tryAlter(`ALTER TABLE token_balance ADD COLUMN last_refresh_at TEXT`);
    tryAlter(`ALTER TABLE token_balance ADD COLUMN last_event_at TEXT`);
    // Backfill where the column was just added; harmless on a
    // fresh DB (no rows match).
    this.db.exec(
      `UPDATE token_balance SET last_refresh_at = grant_at
         WHERE last_refresh_at IS NULL;
       UPDATE token_balance SET last_event_at = updated_at
         WHERE last_event_at IS NULL;
       DROP TABLE IF EXISTS processed_stripe;`,
    );
  }

  // ─── balance reads ─────────────────────────────────────────────

  /** Get the current balance, lazy-creating the row with the grant
   *  if absent. Returns `{ balance, pendingGrant }` so the caller
   *  can publish a tokenGrant record on the firehose. Does NOT
   *  apply refresh — call `touchAndGetBalance` instead when the
   *  read is part of a balance-touching operation. */
  getOrInitBalance(
    did: string,
    policy: TokenLedgerPolicy,
  ): { balance: number; pendingGrant: boolean } {
    const row = this.stmtGetBalance.get(did) as DbRow | undefined;
    if (row) return { balance: row.tokens, pendingGrant: false };
    const now = new Date().toISOString();
    this.db.transaction(() => {
      this.stmtInsertBalance.run(did, policy.tokenGrant, now, now, now, now);
      this.stmtInsertEvent.run(did, "grant", policy.tokenGrant, policy.tokenGrant, null, now);
    })();
    return { balance: policy.tokenGrant, pendingGrant: true };
  }

  /** Like getOrInitBalance, but ALSO applies any pending refresh
   *  for the DID before returning. This is the right call from any
   *  code path where the touch counts as "evidence of liveness" (a
   *  receipt, an explicit balance read by an authenticated user,
   *  etc.). */
  touchAndGetBalance(
    did: string,
    policy: TokenLedgerPolicy,
  ): { balance: number; pendingGrant: boolean; refreshed: boolean } {
    const init = this.getOrInitBalance(did, policy);
    const refreshed = this.applyRefreshIfDue(did, policy);
    return {
      balance: this.peekBalance(did),
      pendingGrant: init.pendingGrant,
      refreshed,
    };
  }

  /** Read-only balance lookup. Returns 0 for DIDs that have never
   *  been touched. Doesn't apply refresh. */
  peekBalance(did: string): number {
    const row = this.stmtGetBalance.get(did) as DbRow | undefined;
    return row?.tokens ?? 0;
  }

  /** Walk the audit log for a DID. Defaults to oldest-first
   *  (`order: "asc"`) — callers that replay history or assert on the
   *  most-recent event via `events[events.length - 1]` rely on that.
   *  Pass `order: "desc"` for a newest-first feed (what the account
   *  UI wants so a fresh patronage rebate shows at the top instead of
   *  scrolling off the end of the window). */
  listEvents(did: string, limit = 100, order: "asc" | "desc" = "asc"): TokenEvent[] {
    const dir = order === "desc" ? "DESC" : "ASC";
    const rows = this.db
      .prepare(
        `SELECT did, kind, tokens_delta, balance_after, reference, created_at
           FROM token_event WHERE did = ? ORDER BY id ${dir} LIMIT ?`,
      )
      .all(did, limit) as Array<{
      did: string;
      kind: TokenEventKind;
      tokens_delta: number;
      balance_after: number;
      reference: string | null;
      created_at: string;
    }>;
    return rows.map((r) => ({
      did: r.did,
      kind: r.kind,
      tokensDelta: r.tokens_delta,
      balanceAfter: r.balance_after,
      reference: r.reference,
      createdAt: r.created_at,
    }));
  }

  /** Roll up a DID's entire audit log into per-kind totals plus the
   *  three numbers the account UI leads with: lifetime tokens
   *  credited (every positive delta), lifetime tokens debited (every
   *  negative delta, reported as a positive magnitude), and the net.
   *
   *  Computed over the WHOLE history with one indexed GROUP BY — the
   *  display feed is windowed (see `listEvents(..., "desc")`), but
   *  these aggregates must not be, or a member with hundreds of
   *  receipts would see totals that drift every time the window
   *  scrolls. Each per-kind `total` is signed (receipt-out is
   *  negative, patronage-in positive, …); within a kind the sign is
   *  consistent, so credited/debited fall out of summing the
   *  positive vs. negative per-kind totals. */
  summarizeEvents(did: string): EventSummary {
    const rows = this.db
      .prepare(
        `SELECT kind, COUNT(*) as count, COALESCE(SUM(tokens_delta), 0) as total
           FROM token_event WHERE did = ?
          GROUP BY kind`,
      )
      .all(did) as Array<{ kind: TokenEventKind; count: number; total: number }>;
    let totalCredited = 0;
    let totalDebited = 0;
    for (const r of rows) {
      if (r.total > 0) totalCredited += r.total;
      else totalDebited += -r.total;
    }
    return {
      did,
      totalCredited,
      totalDebited,
      net: totalCredited - totalDebited,
      byKind: rows,
    };
  }

  // ─── leaderboards ──────────────────────────────────────────────

  /** Rank accounts three ways for the public leaderboard:
   *
   *    * `topBalances` — largest current wallets, from the
   *      `token_balance` cache (= replayed audit-log sum per DID).
   *    * `topEarners`  — most tokens received as a provider, summed
   *      over `receipt-in` events.
   *    * `topSpenders` — most tokens spent as a requester, summed
   *      over `receipt-out` events (stored as negative deltas; we
   *      report the absolute magnitude).
   *
   *  System DIDs (treasury, autoresponder, …) are excluded via
   *  `excludeDids` so the board reflects real members, not the
   *  cooperative's own balance sheet. Each list is capped at `limit`
   *  (1..100) and only includes positive amounts.
   *
   *  Every query is a single indexed aggregation — cheap enough to
   *  run on demand, though the bridge memoizes the result for a short
   *  TTL so a hot leaderboard page doesn't re-scan per request. */
  leaderboard(opts: { limit?: number; excludeDids?: string[] } = {}): {
    generatedAt: string;
    topBalances: LeaderboardEntry[];
    topEarners: LeaderboardEntry[];
    topSpenders: LeaderboardEntry[];
  } {
    const limit = Math.min(Math.max(opts.limit ?? 20, 1), 100);
    const exclude = (opts.excludeDids ?? []).filter((d) => typeof d === "string" && d.length > 0);
    // Build a reusable `did NOT IN (?, ?, …)` fragment + params. With
    // an empty exclude set the fragment collapses to a no-op `1=1`.
    const notIn = exclude.length > 0 ? `did NOT IN (${exclude.map(() => "?").join(", ")})` : "1=1";

    const topBalances = this.db
      .prepare(
        `SELECT did, tokens AS amount FROM token_balance
          WHERE tokens > 0 AND ${notIn}
          ORDER BY tokens DESC LIMIT ?`,
      )
      .all(...exclude, limit) as LeaderboardEntry[];

    const topEarners = this.db
      .prepare(
        `SELECT did, SUM(tokens_delta) AS amount FROM token_event
          WHERE kind = 'receipt-in' AND ${notIn}
          GROUP BY did HAVING amount > 0
          ORDER BY amount DESC LIMIT ?`,
      )
      .all(...exclude, limit) as LeaderboardEntry[];

    const topSpenders = this.db
      .prepare(
        `SELECT did, SUM(ABS(tokens_delta)) AS amount FROM token_event
          WHERE kind = 'receipt-out' AND ${notIn}
          GROUP BY did HAVING amount > 0
          ORDER BY amount DESC LIMIT ?`,
      )
      .all(...exclude, limit) as LeaderboardEntry[];

    return {
      generatedAt: new Date().toISOString(),
      topBalances,
      topEarners,
      topSpenders,
    };
  }

  // ─── conservation transfer ─────────────────────────────────────

  /** Apply a receipt's token movement as a 3-way conservation
   *  transfer: requester loses `tokens`; provider gains the
   *  post-fee remainder; treasury gains the fee. Idempotent on
   *  receipt URI. Returns true if applied, false on duplicate. */
  applyReceipt(
    receipt: { uri: string; requesterDid: string; providerDid: string; tokens: number },
    policy: TokenLedgerPolicy,
  ): boolean {
    if (this.stmtCheckReceipt.get(receipt.uri)) return false;
    this.getOrInitBalance(receipt.requesterDid, policy);
    this.getOrInitBalance(receipt.providerDid, policy);
    this.getOrInitBalance(policy.treasuryDid, policy);

    // Self-loop detection. When the requester and provider are the
    // same DID (a user running a job on their own machine via the
    // exchange), the receipt-out and receipt-in events both hit one
    // balance row. The old implementation read a snapshot of that
    // row and applied two `tokens = ?` updates derived from the
    // same snapshot, so the second write overwrote the first and
    // the user effectively gained `receipt.tokens - providerShare`
    // (a conservation violation).
    //
    // Two fixes:
    //   1. Honor `selfLoopFeeWaived` on self-loop — treasury gets
    //      nothing, so the user nets to zero. Mirrors the
    //      settlement record's `exchangeFee=0`.
    //   2. Compute a per-DID net delta map and apply each unique
    //      DID once. No snapshot-and-overwrite for collisions.
    const isSelfLoop = receipt.requesterDid === receipt.providerDid;
    const waiveFee = isSelfLoop && policy.selfLoopFeeWaived;
    // M5: derive the treasury fee from the SAME `computeFee` the
    // settlement path uses, so the ledger movement and the published
    // settlement's exchangeFee can never diverge. `computeFee` floors to
    // `feeMinMinor` then clamps to the price, so `treasuryShare` never
    // exceeds `receipt.tokens` and `providerShare` is never negative.
    const treasuryShare = waiveFee
      ? 0
      : computeFee(receipt.tokens, {
          bps: policy.treasuryFeeBps,
          minMinor: policy.feeMinMinor ?? 0,
        });
    const providerShare = receipt.tokens - treasuryShare;

    // Aggregate signed deltas by DID. In a non-self-loop receipt
    // requester/provider/treasury are three different DIDs (or
    // possibly two if treasury == provider for self-funded
    // operators), so the map collapses neatly to whatever shape
    // the policy actually exhibits.
    const deltas = new Map<string, number>();
    const bump = (did: string, n: number) => {
      deltas.set(did, (deltas.get(did) ?? 0) + n);
    };
    bump(receipt.requesterDid, -receipt.tokens);
    bump(receipt.providerDid, providerShare);
    if (treasuryShare > 0) bump(policy.treasuryDid, treasuryShare);

    const now = new Date().toISOString();
    this.db.transaction(() => {
      this.stmtMarkReceipt.run(receipt.uri, now);

      // First apply every balance update so the row is at its final
      // state before we emit any audit events. Each event's
      // `balance_after` is read from the row after the update so
      // the audit log reflects the post-receipt state — for self-
      // loops the receipt-out and receipt-in both report the same
      // final balance, which is what conservation actually demands
      // (the two events fired atomically, the balance only has one
      // post-state).
      for (const [did, delta] of deltas) {
        const row = this.stmtGetBalance.get(did) as DbRow;
        const next = row.tokens + delta;
        this.stmtUpdateBalance.run(next, row.last_refresh_at, now, now, did);
      }

      // Now emit the audit-log rows. We always emit receipt-out and
      // receipt-in (even when waived), so the per-receipt audit
      // trail is consistent across self-loop and non-self-loop —
      // the only difference is whether a treasury-fee row also
      // lands.
      const reqAfter = (this.stmtGetBalance.get(receipt.requesterDid) as DbRow).tokens;
      this.stmtInsertEvent.run(
        receipt.requesterDid,
        "receipt-out",
        -receipt.tokens,
        reqAfter,
        receipt.uri,
        now,
      );
      const provAfter = (this.stmtGetBalance.get(receipt.providerDid) as DbRow).tokens;
      this.stmtInsertEvent.run(
        receipt.providerDid,
        "receipt-in",
        providerShare,
        provAfter,
        receipt.uri,
        now,
      );
      if (treasuryShare > 0) {
        const treaAfter = (this.stmtGetBalance.get(policy.treasuryDid) as DbRow).tokens;
        this.stmtInsertEvent.run(
          policy.treasuryDid,
          "treasury-fee",
          treasuryShare,
          treaAfter,
          receipt.uri,
          now,
        );
      }
    })();
    return true;
  }

  // ─── lazy refresh ──────────────────────────────────────────────

  /** Issue the weekly refresh to `did` if its `last_refresh_at` is
   *  older than the policy's `refreshCadenceMinutes`. Returns
   *  true if a refresh was issued. No-op when
   *  `weeklyRefreshAmount` is 0 (refresh disabled). */
  applyRefreshIfDue(did: string, policy: TokenLedgerPolicy): boolean {
    if (policy.weeklyRefreshAmount <= 0 || policy.refreshCadenceMinutes <= 0) {
      return false;
    }
    const row = this.stmtGetBalance.get(did) as DbRow | undefined;
    if (!row) return false;
    const nowMs = Date.now();
    const lastMs = Date.parse(row.last_refresh_at ?? row.grant_at);
    if (Number.isNaN(lastMs)) return false;
    if (nowMs - lastMs < policy.refreshCadenceMinutes * 60_000) return false;
    const nowIso = new Date(nowMs).toISOString();
    const next = row.tokens + policy.weeklyRefreshAmount;
    this.db.transaction(() => {
      this.stmtUpdateBalance.run(next, nowIso, nowIso, nowIso, did);
      this.stmtInsertEvent.run(did, "refresh", policy.weeklyRefreshAmount, next, null, nowIso);
    })();
    return true;
  }

  // ─── admission check ───────────────────────────────────────────

  /** Job-dispatch admission check. Returns whether `did` has
   *  enough tokens to dispatch a job with `priceCeilingTokens` cost
   *  while still leaving `tokenFloor` headroom. */
  checkAdmission(
    did: string,
    priceCeilingTokens: number,
    policy: TokenLedgerPolicy,
  ): AdmissionResult {
    const init = this.getOrInitBalance(did, policy);
    const required = priceCeilingTokens + policy.tokenFloor;
    const ok = init.balance >= required;
    return {
      ok,
      balance: init.balance,
      required,
      shortBy: ok ? 0 : required - init.balance,
      pendingGrant: init.pendingGrant,
    };
  }

  // ─── patronage rebate ──────────────────────────────────────────

  /** Distribute the policy's configured fraction of the treasury
   *  balance to active members in proportion to their patronage
   *  during [periodStart, periodEnd). Idempotent on the period — a
   *  second call with the same window is a no-op. Returns the
   *  per-recipient breakdown so the caller can emit a
   *  `dev.cocore.account.tokenPatronage` record per row. */
  distributePatronage(
    periodStart: Date,
    periodEnd: Date,
    policy: TokenLedgerPolicy,
  ): PatronageDistributionResult {
    if (policy.patronageFractionBps <= 0) {
      return {
        treasuryBefore: 0,
        totalDistributed: 0,
        totalPatronage: 0,
        recipients: [],
        alreadyDistributed: false,
      };
    }
    const startIso = periodStart.toISOString();
    const endIso = periodEnd.toISOString();
    if (this.stmtCheckPeriod.get(startIso, endIso)) {
      return {
        treasuryBefore: 0,
        totalDistributed: 0,
        totalPatronage: 0,
        recipients: [],
        alreadyDistributed: true,
      };
    }
    // Aggregate patronage per DID over receipt-in / receipt-out
    // events within the window. abs(tokens_delta) because we want
    // the sum of "tokens that flowed through this DID" — both
    // earning and spending count.
    const rows = this.db
      .prepare(
        `SELECT did, SUM(ABS(tokens_delta)) as patronage
           FROM token_event
          WHERE kind IN ('receipt-in', 'receipt-out')
            AND created_at >= ? AND created_at < ?
            AND did != ?
          GROUP BY did
          HAVING patronage > 0`,
      )
      .all(startIso, endIso, policy.treasuryDid) as Array<{ did: string; patronage: number }>;
    const totalPatronage = rows.reduce((s, r) => s + r.patronage, 0);
    const treasuryRow = this.stmtGetBalance.get(policy.treasuryDid) as DbRow | undefined;
    const treasuryBefore = treasuryRow?.tokens ?? 0;
    if (totalPatronage === 0 || treasuryBefore === 0) {
      // Still mark the period processed so we don't repeatedly
      // scan for zero-result periods.
      const nowIso = new Date().toISOString();
      this.stmtMarkPeriod.run(startIso, endIso, nowIso);
      return {
        treasuryBefore,
        totalDistributed: 0,
        totalPatronage: 0,
        recipients: [],
        alreadyDistributed: false,
      };
    }
    const toDistribute = Math.floor((treasuryBefore * policy.patronageFractionBps) / 10000);
    const recipients: PatronageDistributionResult["recipients"] = [];
    const nowIso = new Date().toISOString();
    let actuallyDistributed = 0;
    this.db.transaction(() => {
      this.stmtMarkPeriod.run(startIso, endIso, nowIso);
      for (const r of rows) {
        const credit = Math.floor((toDistribute * r.patronage) / totalPatronage);
        if (credit <= 0) continue;
        actuallyDistributed += credit;
        const recipientRow = this.stmtGetBalance.get(r.did) as DbRow;
        const nextBal = recipientRow.tokens + credit;
        this.stmtUpdateBalance.run(nextBal, recipientRow.last_refresh_at, nowIso, nowIso, r.did);
        this.stmtInsertEvent.run(
          r.did,
          "patronage-in",
          credit,
          nextBal,
          `${startIso}/${endIso}`,
          nowIso,
        );
        recipients.push({
          did: r.did,
          patronageScore: r.patronage,
          tokensCredited: credit,
        });
      }
      // Debit the treasury by the exact sum of credits (handles
      // floor() loss without bleeding it into "anyone in
      // particular").
      if (actuallyDistributed > 0) {
        const treasNext = treasuryBefore - actuallyDistributed;
        this.stmtUpdateBalance.run(
          treasNext,
          treasuryRow!.last_refresh_at,
          nowIso,
          nowIso,
          policy.treasuryDid,
        );
        this.stmtInsertEvent.run(
          policy.treasuryDid,
          "patronage-out",
          -actuallyDistributed,
          treasNext,
          `${startIso}/${endIso}`,
          nowIso,
        );
      }
    })();
    return {
      treasuryBefore,
      totalDistributed: actuallyDistributed,
      totalPatronage,
      recipients,
      alreadyDistributed: false,
    };
  }

  // ─── audit helper ──────────────────────────────────────────────

  /** Sum all event deltas; the ledger sums to
   *  `(grants issued so far) + (refreshes)`. Useful as a smoke
   *  test that conservation is holding. */
  totalEventDelta(): number {
    const row = this.db
      .prepare(`SELECT COALESCE(SUM(tokens_delta), 0) as total FROM token_event`)
      .get() as { total: number };
    return row.total;
  }

  // ─── reconcile ─────────────────────────────────────────────────

  /** End-to-end audit of the ledger's state. Verifies the
   *  invariants that any honest closed-loop ledger MUST hold:
   *
   *  1. **Conservation.** Sum of every `tokens_delta` in
   *     `token_event` equals the sum of mints (grant + refresh)
   *     minus burns (currently none — soft decay was removed). Any
   *     non-mint event must net to zero across its participants
   *     (receipts split 3 ways but sum to zero; patronage debits
   *     treasury and credits recipients in equal measure).
   *  2. **Cache integrity.** Each row in `token_balance.tokens` is
   *     a denormalized cache of `SUM(token_event.tokens_delta)`
   *     for that DID. If the cache drifts from the audit log,
   *     the cache is wrong (the audit log is canonical).
   *  3. **Non-negative balances.** The CHECK constraint on
   *     `token_balance.tokens >= 0` should never let us see a
   *     negative balance — surface anyway as a belt-and-suspenders
   *     check.
   *  4. **Idempotency tables.** Every receipt URI appears at most
   *     once in `processed_receipt`; every (period_start, period_end)
   *     appears at most once in `processed_period`. The PRIMARY
   *     KEYs enforce this; we surface the row count + uniqueness
   *     as a sanity number.
   *  5. **System total.** Sum of every balance equals the sum of
   *     every mint event. A drift here means either a balance was
   *     credited without an event row, or vice versa.
   *
   *  Returns a structured report a caller can stuff into JSON or
   *  feed to a dashboard. `ok: true` means every invariant held.
   *
   *  Cheap to run — every check is one indexed SQL aggregation.
   *  Designed to be hit on demand by an operator (or a 5-min cron)
   *  for launch-day reconciliation. */
  reconcile(): LedgerReconcileReport {
    const generatedAt = new Date().toISOString();

    // Invariant 1: total event deltas.
    const totalDelta = this.totalEventDelta();
    const mintsRow = this.db
      .prepare(
        `SELECT COALESCE(SUM(tokens_delta), 0) as total
           FROM token_event
          WHERE kind IN ('grant', 'refresh')`,
      )
      .get() as { total: number };
    const totalMints = mintsRow.total;
    const totalDeltaMatchesMints = totalDelta === totalMints;

    // Invariant 2: per-DID balance cache vs replayed event sum.
    // Pull computed sums first, then join against the cache so a
    // DID that has events but no balance row (impossible today but
    // worth flagging) still shows up.
    const computedSums = this.db
      .prepare(
        `SELECT did, COALESCE(SUM(tokens_delta), 0) as computed
           FROM token_event
          GROUP BY did`,
      )
      .all() as Array<{ did: string; computed: number }>;
    const cachedBalances = new Map<string, number>(
      (
        this.db.prepare(`SELECT did, tokens FROM token_balance`).all() as Array<{
          did: string;
          tokens: number;
        }>
      ).map((r) => [r.did, r.tokens]),
    );
    const balanceCacheDrifts: LedgerReconcileReport["balanceCacheDrifts"] = [];
    for (const { did, computed } of computedSums) {
      const cached = cachedBalances.get(did) ?? null;
      if (cached !== computed) {
        balanceCacheDrifts.push({ did, cached, computed, delta: (cached ?? 0) - computed });
      }
    }
    // Also catch the reverse: a balance row with no events backing it.
    const computedDids = new Set(computedSums.map((r) => r.did));
    for (const [did, cached] of cachedBalances) {
      if (!computedDids.has(did) && cached !== 0) {
        balanceCacheDrifts.push({ did, cached, computed: 0, delta: cached });
      }
    }

    // Invariant 3: non-negative balances.
    const negativeBalances = this.db
      .prepare(`SELECT did, tokens FROM token_balance WHERE tokens < 0`)
      .all() as Array<{ did: string; tokens: number }>;

    // Invariant 4: idempotency table sizes.
    const receiptsRow = this.db.prepare(`SELECT COUNT(*) as n FROM processed_receipt`).get() as {
      n: number;
    };
    const periodsRow = this.db.prepare(`SELECT COUNT(*) as n FROM processed_period`).get() as {
      n: number;
    };

    // Invariant 5: system total.
    const totalBalanceRow = this.db
      .prepare(`SELECT COALESCE(SUM(tokens), 0) as total FROM token_balance`)
      .get() as { total: number };
    const totalBalance = totalBalanceRow.total;
    const totalBalanceMatchesMints = totalBalance === totalMints;

    // Counts.
    const didCount = cachedBalances.size;
    const eventCountRow = this.db.prepare(`SELECT COUNT(*) as n FROM token_event`).get() as {
      n: number;
    };

    const ok =
      totalDeltaMatchesMints &&
      balanceCacheDrifts.length === 0 &&
      negativeBalances.length === 0 &&
      totalBalanceMatchesMints;

    return {
      generatedAt,
      ok,
      totalDelta,
      totalMints,
      totalDeltaMatchesMints,
      balanceCacheDrifts,
      negativeBalances,
      totalBalance,
      totalBalanceMatchesMints,
      didCount,
      eventCount: eventCountRow.n,
      receiptsProcessed: receiptsRow.n,
      periodsProcessed: periodsRow.n,
    };
  }

  /** Rebuild every `token_balance.tokens` cache from the audit log.
   *  ONLY use this when `reconcile()` reports `balanceCacheDrifts` —
   *  the audit log is canonical, the cache is denormalized, so a
   *  rebuild is always safe (it's idempotent and converges every
   *  cache to the audit-log-derived value).
   *
   *  Returns the count of rows that changed, so an operator can see
   *  whether the rebuild actually had to do anything. */
  rebuildBalanceCache(): { changed: number } {
    let changed = 0;
    this.db.transaction(() => {
      const computed = this.db
        .prepare(
          `SELECT did, COALESCE(SUM(tokens_delta), 0) as computed
             FROM token_event
            GROUP BY did`,
        )
        .all() as Array<{ did: string; computed: number }>;
      const cached = new Map<string, number>(
        (
          this.db.prepare(`SELECT did, tokens FROM token_balance`).all() as Array<{
            did: string;
            tokens: number;
          }>
        ).map((r) => [r.did, r.tokens]),
      );
      const now = new Date().toISOString();
      const stmt = this.db.prepare(
        `UPDATE token_balance SET tokens = ?, updated_at = ? WHERE did = ?`,
      );
      for (const { did, computed: c } of computed) {
        if (cached.get(did) !== c) {
          stmt.run(c, now, did);
          changed += 1;
        }
      }
    })();
    return { changed };
  }
}

export interface LedgerReconcileReport {
  generatedAt: string;
  /** All invariants hold. */
  ok: boolean;
  /** Sum of every `tokens_delta` in the event log. */
  totalDelta: number;
  /** Sum of mint-event deltas (grant + refresh). The only sources
   *  of new tokens in the system. */
  totalMints: number;
  /** Invariant 1: `totalDelta === totalMints`. Receipts and
   *  patronage move tokens but net to zero across participants;
   *  only mints add to the total. */
  totalDeltaMatchesMints: boolean;
  /** Invariant 2: DIDs where `token_balance.tokens` disagrees with
   *  `SUM(token_event.tokens_delta) for that DID`. Empty = caches
   *  agree with the audit log. */
  balanceCacheDrifts: Array<{
    did: string;
    cached: number | null;
    computed: number;
    delta: number;
  }>;
  /** Invariant 3: any DID with a negative cached balance. Should
   *  always be empty (the CHECK constraint prevents it). */
  negativeBalances: Array<{ did: string; tokens: number }>;
  /** Invariant 5: sum of every balance in `token_balance`. */
  totalBalance: number;
  /** `totalBalance === totalMints`. */
  totalBalanceMatchesMints: boolean;
  didCount: number;
  eventCount: number;
  receiptsProcessed: number;
  periodsProcessed: number;
}

interface DbRow {
  did: string;
  tokens: number;
  grant_at: string;
  last_refresh_at: string | null;
  last_event_at: string | null;
  updated_at: string;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS token_balance (
  did TEXT PRIMARY KEY,
  tokens INTEGER NOT NULL CHECK (tokens >= 0),
  grant_at TEXT NOT NULL,
  last_refresh_at TEXT,
  last_event_at TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS token_event (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  did TEXT NOT NULL,
  kind TEXT NOT NULL,
  tokens_delta INTEGER NOT NULL,
  balance_after INTEGER NOT NULL,
  reference TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_token_event_did_id
  ON token_event (did, id);

CREATE INDEX IF NOT EXISTS ix_token_event_kind_created
  ON token_event (kind, created_at);

CREATE TABLE IF NOT EXISTS processed_receipt (
  receipt_uri TEXT PRIMARY KEY,
  processed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS processed_period (
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  processed_at TEXT NOT NULL,
  PRIMARY KEY (period_start, period_end)
);
`;
