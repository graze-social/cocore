// Durable settlement-side state for the Exchange.
//
// The Exchange holds three pieces of authoritative-adjacent state that
// MUST survive a process restart and MUST be consulted atomically with
// each settlement write, or a provider can double-charge:
//
//   settled_receipt          idempotency: receipt URI -> settled_at.
//                            A second observation of the same receipt
//                            URI is a duplicate, not a fresh charge.
//                            (M4: the old in-memory Map reset on
//                            restart and straddled awaits — a TOCTOU
//                            window + a restart both re-charged.)
//
//   consumed_authorization   single-use: authorization identity ->
//                            consumed_at. A `scope=singleJob`
//                            authorization is consumed by exactly one
//                            receipt; a second receipt (distinct rkey)
//                            strong-reffing the SAME authorization is
//                            rejected. (H1: idempotency keyed only on
//                            receipt URI let a provider mint N receipts
//                            against one authorization.)
//
//   authorization_charge     cumulative `amountCharged` per
//                            authorization, so a `scope=session`
//                            authorization can be capped at its
//                            declared `sessionBudget`. (H1)
//
// All three live in the same sqlite handle the TokenLedger uses, and
// every mutation runs inside one `db.transaction(...)` so the
// idempotency read, the single-use consume, the budget check, and the
// charge accrual are one atomic step — no window between "is this
// authorization already spent?" and "record that we spent it".
//
// Keyed by *authorization identity*: the paymentAuthorization's
// `nonce` when present (the lexicon's replay-protection field — 16
// random bytes hex-encoded), else the authorization record URI. The
// nonce is the stronger key because it is what the requester signed as
// unique; the URI is a safe fallback for any authorization shape that
// predates the nonce field.

import type { Database as DB } from "better-sqlite3";

/** Outcome of an atomic settle-consume attempt. */
export type ConsumeOutcome =
  | { kind: "ok" }
  /** This receipt URI already has a settlement (durable idempotency). */
  | { kind: "duplicate-receipt" }
  /** A singleJob authorization was already consumed by another receipt. */
  | { kind: "authorization-consumed" }
  /** A session authorization would exceed its sessionBudget. */
  | { kind: "budget-exceeded"; alreadyCharged: number; attempted: number; budget: number };

export interface ConsumeInputs {
  receiptUri: string;
  /** Authorization identity: nonce if the auth has one, else its URI. */
  authorizationKey: string;
  /** true for scope=singleJob authorizations (single-use). */
  singleUse: boolean;
  /** Amount this settlement charges, in integer minor units. */
  amountCharged: number;
  /** sessionBudget cap in integer minor units, or undefined when the
   *  authorization declares none (no cumulative cap enforced). */
  sessionBudget?: number;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS settled_receipt (
  receipt_uri TEXT PRIMARY KEY,
  settled_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS consumed_authorization (
  auth_key TEXT PRIMARY KEY,
  receipt_uri TEXT NOT NULL,
  consumed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS authorization_charge (
  auth_key TEXT PRIMARY KEY,
  total_charged INTEGER NOT NULL CHECK (total_charged >= 0),
  updated_at TEXT NOT NULL
);
`;

export class SettlementStore {
  private readonly db: DB;

  constructor(db: DB) {
    this.db = db;
    this.db.exec(SCHEMA);
  }

  /** Has this receipt URI already been settled? Fast-path read; the
   *  authoritative check is the atomic INSERT inside {@link consume}. */
  isReceiptSettled(receiptUri: string): boolean {
    const row = this.db
      .prepare(`SELECT receipt_uri FROM settled_receipt WHERE receipt_uri = ?`)
      .get(receiptUri);
    return row !== undefined;
  }

  /** The set of receipt URIs already settled. Rebuilds the in-memory
   *  fast-path cache and feeds verifyForChargeStrict's settledReceipts
   *  gate after a restart. */
  settledReceiptUris(): Set<string> {
    const rows = this.db.prepare(`SELECT receipt_uri FROM settled_receipt`).all() as Array<{
      receipt_uri: string;
    }>;
    return new Set(rows.map((r) => r.receipt_uri));
  }

  /** Atomically: reject a duplicate receipt URI, reject a re-used
   *  single-use authorization, reject a settlement that would push an
   *  authorization's cumulative charge past its sessionBudget, and —
   *  when none of those hold — durably mark the receipt settled,
   *  consume the authorization (single-use only), and accrue the
   *  charge. One transaction so there is no TOCTOU window between the
   *  checks and the writes.
   *
   *  Returns `{ kind: "ok" }` when the caller should proceed to
   *  publish the settlement; any other outcome means STOP. */
  consume(inputs: ConsumeInputs): ConsumeOutcome {
    const now = new Date().toISOString();
    const tx = this.db.transaction((): ConsumeOutcome => {
      // Durable idempotency: a second observation of the same receipt
      // URI is a duplicate. The PRIMARY KEY makes the later INSERT
      // fail, but we check first so we can distinguish this from an
      // authorization re-use.
      if (this.isReceiptSettled(inputs.receiptUri)) {
        return { kind: "duplicate-receipt" };
      }

      // H1 single-use: a scope=singleJob authorization is consumed by
      // exactly one receipt. A different receipt citing the same
      // authorization identity is a double-charge attempt.
      if (inputs.singleUse) {
        const consumed = this.db
          .prepare(`SELECT receipt_uri FROM consumed_authorization WHERE auth_key = ?`)
          .get(inputs.authorizationKey) as { receipt_uri: string } | undefined;
        if (consumed && consumed.receipt_uri !== inputs.receiptUri) {
          return { kind: "authorization-consumed" };
        }
      }

      // H1 sessionBudget: cumulative amountCharged across every
      // settlement under this authorization MUST NOT exceed the
      // declared budget.
      const priorRow = this.db
        .prepare(`SELECT total_charged FROM authorization_charge WHERE auth_key = ?`)
        .get(inputs.authorizationKey) as { total_charged: number } | undefined;
      const alreadyCharged = priorRow?.total_charged ?? 0;
      const nextTotal = alreadyCharged + inputs.amountCharged;
      if (inputs.sessionBudget !== undefined && nextTotal > inputs.sessionBudget) {
        return {
          kind: "budget-exceeded",
          alreadyCharged,
          attempted: inputs.amountCharged,
          budget: inputs.sessionBudget,
        };
      }

      // All checks passed — commit the durable state.
      this.db
        .prepare(`INSERT INTO settled_receipt (receipt_uri, settled_at) VALUES (?, ?)`)
        .run(inputs.receiptUri, now);
      if (inputs.singleUse) {
        this.db
          .prepare(
            `INSERT INTO consumed_authorization (auth_key, receipt_uri, consumed_at)
               VALUES (?, ?, ?)`,
          )
          .run(inputs.authorizationKey, inputs.receiptUri, now);
      }
      this.db
        .prepare(
          `INSERT INTO authorization_charge (auth_key, total_charged, updated_at)
             VALUES (?, ?, ?)
           ON CONFLICT(auth_key)
             DO UPDATE SET total_charged = ?, updated_at = ?`,
        )
        .run(inputs.authorizationKey, nextTotal, now, nextTotal, now);
      return { kind: "ok" };
    });
    return tx();
  }
}
