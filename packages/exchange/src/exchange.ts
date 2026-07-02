// The exchange orchestrator.
//
// Wires receipt-events from the firehose through verification and
// settlement-record publication. Every receipt is a pure token
// transfer that lands in the TokenLedger (see `token-balance.ts`);
// the settlement record this class publishes records the token
// movement for audit.
//
// Why publish a settlement at all? Two reasons:
//
//   1. The settlement strong-refs the active exchangePolicy and the
//      exchangeAttestation, pinning the fee math + signing key so
//      verifiers can re-derive the split offline from any future
//      vantage point.
//   2. It gives the AppView a single "this receipt has been
//      processed" event — useful for dashboards and idempotency.
//
// Stateless w.r.t. authority: the only durable state we hold is
// which receipts we've already settled, and that's recoverable from
// our PDS.

import type { Database as DB } from "better-sqlite3";

import { SettlementPublisher, type PublishedRecord } from "./publisher.ts";
import { SettlementStore } from "./settlement-store.ts";
import { type PrivateJwk, signSettlement } from "./signing.ts";
import type {
  AttestationRecord,
  IndexedRecord,
  JobRecord,
  PaymentAuthorizationRecord,
  ReceiptRecord,
} from "@cocore/sdk/types";
import {
  verifyForChargeStrict,
  type ValidationReport as VerificationReport,
} from "@cocore/sdk/validate";

export interface FeePolicy {
  /** Basis points (1/10000) of each receipt's TOKEN cost routed to
   *  the treasury account. e.g. 500 = 5%. The token movement
   *  itself happens in TokenLedger.applyReceipt; this number is
   *  carried into the settlement record so verifiers can confirm
   *  it matches the active exchangePolicy.fee.bps. */
  bps: number;
  /** Minimum fee in tokens. Floor on the bps calculation. */
  minMinor: number;
}

/** How the exchange handles self-loop receipts (requester DID ==
 *  provider DID). Mirrors the lexicon's `selfLoopRule`. */
export interface SelfLoopRule {
  /** When true, the exchange takes no fee on self-loop receipts.
   *  Both the settlement record and the ledger's applyReceipt
   *  should respect this. */
  feeWaived: boolean;
  /** Optional flat-fee floor for self-loop receipts. */
  minMinor?: number;
}

export interface ExchangeConfig {
  exchangeDid: string;
  feePolicy: FeePolicy;
  selfLoop?: SelfLoopRule;
  /** Strong-ref to the published `dev.cocore.compute.exchangePolicy`
   *  record this exchange operates under. Settlements pin this. */
  policyRef?: { uri: string; cid: string };
  /** Strong-ref to the published `dev.cocore.compute.exchangeAttestation`,
   *  pinning the signing key fingerprint. */
  attestationRef?: { uri: string; cid: string };
  /** ES256 private JWK. When set, every settlement gets a `sig`
   *  field over its canonical bytes. */
  signingKey?: PrivateJwk;
  publisher: SettlementPublisher;
  /** Resolves a strong-ref to its body. The firehose subscriber
   *  fills this out at runtime; tests pass an in-memory Map. */
  resolveRecord: (uri: string) => Promise<IndexedRecord | null>;
  /** Durable settlement-side state (settlement idempotency, single-use
   *  authorization consumption, sessionBudget accrual). When provided,
   *  settlement idempotency + authorization single-use survive a
   *  restart and are enforced atomically with each charge. Wire the
   *  same sqlite handle the TokenLedger uses. When omitted the exchange
   *  falls back to in-memory idempotency only (fine for unit tests that
   *  never restart, but NOT safe for production — pass a db). */
  db?: DB;
}

export type SettlementOutcome =
  | { kind: "settled"; settlement: PublishedRecord }
  | { kind: "rejected"; report: VerificationReport }
  | { kind: "duplicate"; settlement: PublishedRecord }
  | { kind: "resolve-failed"; missing: string };

export class Exchange {
  private readonly cfg: ExchangeConfig;
  /** In-memory fast-path cache in FRONT of the durable store. NOT the
   *  sole idempotency guard — the atomic INSERT in SettlementStore is
   *  authoritative and survives restarts / concurrent calls (M4). */
  private readonly settledByReceiptUri = new Map<string, PublishedRecord>();
  /** Durable settlement state. Present iff cfg.db was supplied. */
  private readonly store: SettlementStore | null;

  constructor(cfg: ExchangeConfig) {
    this.cfg = cfg;
    this.store = cfg.db ? new SettlementStore(cfg.db) : null;
  }

  /** Process one receipt observation. Idempotent on receipt URI.
   *  Verifies the receipt's signature + payment authorization, then
   *  publishes a settlement record. The actual token movement (the
   *  95/5 split between requester / provider / treasury) is done by
   *  the TokenLedger in a sibling firehose hook — not by this
   *  class. */
  async onReceipt(receiptIndexed: IndexedRecord<ReceiptRecord>): Promise<SettlementOutcome> {
    const receiptUri = receiptIndexed.uri;

    // Fast-path duplicate check. The AUTHORITATIVE idempotency guard is
    // the atomic INSERT in SettlementStore.consume below (M4) — this
    // Map is only a cache in front of it and is empty after a restart.
    const prior = this.settledByReceiptUri.get(receiptUri);
    if (prior) return { kind: "duplicate", settlement: prior };
    if (this.store?.isReceiptSettled(receiptUri)) {
      // Settled in a prior process life; the settlement record itself
      // lives on the PDS. We don't hold the PublishedRecord in memory,
      // so surface a rejection with a clear code rather than a
      // fabricated duplicate — the receipt is not re-charged either way.
      return {
        kind: "rejected",
        report: {
          ok: false,
          findings: [
            {
              severity: "error",
              code: "already-settled",
              message: `receipt ${receiptUri} was already settled in a prior process`,
            },
          ],
        },
      };
    }

    // Resolve the records the verifier needs.
    const jobRow = await this.cfg.resolveRecord(receiptIndexed.body.job.uri);
    if (!jobRow) return { kind: "resolve-failed", missing: receiptIndexed.body.job.uri };
    const job = jobRow.body as JobRecord;

    const authRow = await this.cfg.resolveRecord(job.paymentAuthorization.uri);
    if (!authRow) return { kind: "resolve-failed", missing: job.paymentAuthorization.uri };
    const authorization = authRow.body as PaymentAuthorizationRecord;

    // H2: the authorization MUST belong to the requester being debited.
    // verifyForChargeStrict already ties the authorization to THIS
    // exchange (authorization.exchange == exchangeDid) and to the job
    // (job.paymentAuthorization.uri == auth uri), but nothing checked
    // the authorization's OWNING REPO against receipt.requester. Without
    // it, a provider could point the receipt's job at some other party's
    // authorization and debit a stranger's budget. Mirror the
    // attestation-owner binding below: the exchange holds both record
    // repos, so it can bind identity here.
    if (authRow.repo !== receiptIndexed.body.requester) {
      return {
        kind: "rejected",
        report: {
          ok: false,
          findings: [
            {
              severity: "error",
              code: "authorization-owner-mismatch",
              message: `authorization ${job.paymentAuthorization.uri} is owned by ${authRow.repo}, not the receipt requester ${receiptIndexed.body.requester}`,
            },
          ],
        },
      };
    }

    const attestationRow = await this.cfg.resolveRecord(receiptIndexed.body.attestation.uri);
    if (!attestationRow)
      return { kind: "resolve-failed", missing: receiptIndexed.body.attestation.uri };
    const attestation = attestationRow.body as AttestationRecord;

    // H1 (0.9.23): the strong-ref'd attestation MUST be owned by the provider
    // being paid. The receipt's repo IS the provider; without this binding a
    // provider could point its receipt at another machine's (or a self-minted,
    // foreign-DID) attestation to launder a tier/posture it never earned. The
    // attestation's own selfSignature is verified inside verifyForChargeStrict;
    // here we tie that authentic attestation to this provider's identity.
    if (attestationRow.repo !== receiptIndexed.repo) {
      return {
        kind: "rejected",
        report: {
          ok: false,
          findings: [
            {
              severity: "error",
              code: "attestation-owner-mismatch",
              message: `attestation ${receiptIndexed.body.attestation.uri} is owned by ${attestationRow.repo}, not the receipt provider ${receiptIndexed.repo}`,
            },
          ],
        },
      };
    }

    // Strict pre-settlement verification: ES256 over the canonical
    // receipt bytes against attestation.publicKey, PLUS the attestation's own
    // selfSignature (H1). A tampered or unsigned receipt — or an unauthentic
    // attestation — is rejected before the ledger moves any tokens or a
    // settlement record gets written.
    const report = await verifyForChargeStrict(
      {
        exchangeDid: this.cfg.exchangeDid,
        // Draw already-settled URIs from the durable store when present
        // so the gate survives a restart; fall back to the in-memory
        // cache otherwise.
        settledReceipts: this.store
          ? this.store.settledReceiptUris()
          : new Set(this.settledByReceiptUri.keys()),
      },
      {
        receipt: receiptIndexed.body,
        receiptUri,
        job,
        jobOwnerDid: jobRow.repo,
        authorization,
        authorizationUri: job.paymentAuthorization,
      },
      attestation,
    );
    if (!report.ok) return { kind: "rejected", report };

    // Fee math (in tokens, not USD). Self-loop receipts get the
    // policy's waiver — typically zero so the user pays nothing
    // extra to run on their own machine via the exchange.
    //
    // Pro-bono receipts are the explicit no-cut carve-out: the provider
    // served the job for free (price.amount is 0, verified to be so by
    // checkProBonoInvariant above), so the exchange takes no fee and the
    // settlement is all zeros. Short-circuit BEFORE computeFeeWithSelfLoop —
    // a non-zero fee floor (minMinor) on a zero-price receipt would otherwise
    // drive providerShare negative and break amountCharged = payout + fee.
    const isProBono = receiptIndexed.body.proBono === true;
    const isSelfLoop = jobRow.repo === receiptIndexed.repo;
    const price = receiptIndexed.body.price.amount;
    const fee = isProBono
      ? 0
      : computeFeeWithSelfLoop(price, this.cfg.feePolicy, this.cfg.selfLoop, isSelfLoop);
    // M5: `fee` is already clamped to `price` inside computeFee, so
    // providerShare can never go negative (which the PDS would reject —
    // money.amount minimum:0 — stranding the receipt in a retry loop).
    const providerShare = price - fee;

    // H1/M4: atomically consume the authorization and durably record
    // the settlement BEFORE publishing. This is the single point that
    // rejects (a) a duplicate receipt across restarts/concurrency, (b) a
    // second receipt spending an already-consumed singleJob
    // authorization, and (c) a settlement that would push a session
    // authorization past its sessionBudget. Done in one DB transaction
    // so there is no window between check and record. When no db is
    // configured (unit tests) we fall back to the in-memory guard only.
    if (this.store) {
      const outcome = this.store.consume({
        receiptUri,
        authorizationKey: authorizationIdentity(job.paymentAuthorization.uri, authorization),
        // Pro-bono receipts charge 0 and take no exchange cut; they must
        // not consume a single-use authorization or accrue against a
        // session budget (all-zero invariant), so treat them as
        // non-single-use with a 0 charge — the receipt-URI idempotency
        // still applies.
        singleUse: !isProBono && authorization.scope === "singleJob",
        amountCharged: price,
        sessionBudget:
          authorization.scope === "session" ? authorization.sessionBudget?.amount : undefined,
      });
      if (outcome.kind === "duplicate-receipt") {
        const cached = this.settledByReceiptUri.get(receiptUri);
        if (cached) return { kind: "duplicate", settlement: cached };
        return {
          kind: "rejected",
          report: {
            ok: false,
            findings: [
              {
                severity: "error",
                code: "already-settled",
                message: `receipt ${receiptUri} was already settled`,
              },
            ],
          },
        };
      }
      if (outcome.kind === "authorization-consumed") {
        return {
          kind: "rejected",
          report: {
            ok: false,
            findings: [
              {
                severity: "error",
                code: "authorization-already-consumed",
                message: `payment authorization ${job.paymentAuthorization.uri} (scope=singleJob) was already consumed by another receipt`,
              },
            ],
          },
        };
      }
      if (outcome.kind === "budget-exceeded") {
        return {
          kind: "rejected",
          report: {
            ok: false,
            findings: [
              {
                severity: "error",
                code: "session-budget-exceeded",
                message: `charge ${outcome.attempted} on top of ${outcome.alreadyCharged} already charged exceeds sessionBudget ${outcome.budget} for authorization ${job.paymentAuthorization.uri}`,
              },
            ],
          },
        };
      }
    }

    // Build + publish the settlement. The processor reference tags
    // settlement as internal-ledger rather than an external chain id.
    const settlement = this.cfg.publisher.build({
      receipt: { uri: receiptUri, cid: receiptIndexed.cid },
      requesterAuthorization: job.paymentAuthorization,
      amountCharged: receiptIndexed.body.price,
      providerPayout: {
        amount: providerShare,
        currency: receiptIndexed.body.price.currency,
      },
      exchangeFee: { amount: fee, currency: receiptIndexed.body.price.currency },
      processorReference: "ledger",
      status: "settled",
      ...(this.cfg.policyRef ? { policy: this.cfg.policyRef } : {}),
      ...(this.cfg.attestationRef ? { exchangeAttestation: this.cfg.attestationRef } : {}),
    });
    const signed = this.cfg.signingKey
      ? { ...settlement, sig: await signSettlement(settlement, this.cfg.signingKey) }
      : settlement;
    const published = await this.cfg.publisher.publish(signed);
    this.settledByReceiptUri.set(receiptUri, published);
    return { kind: "settled", settlement: published };
  }
}

/** THE single fee computation. Both the settlement fee (here) and the
 *  ledger's treasury-fee split (token-balance.ts) MUST derive their
 *  fee from this so the published settlement and the recorded ledger
 *  movement can never disagree (M5). Integer minor units only — no
 *  floats near money.
 *
 *  M5 clamp: the bps fee is floored up to `minMinor`, then clamped DOWN
 *  to `amountMinor` so the fee never exceeds the price and providerShare
 *  (= amountMinor - fee) is never negative. A negative payout is
 *  unpublishable (money.amount minimum:0), which would otherwise strand
 *  a small-price receipt in an infinite retry loop. */
export function computeFee(amountMinor: number, policy: FeePolicy): number {
  const bpsAmount = Math.floor((amountMinor * policy.bps) / 10_000);
  const floored = Math.max(bpsAmount, policy.minMinor);
  return Math.min(floored, amountMinor);
}

/** Self-loop-aware fee. Falls back to {@link computeFee} when the
 *  receipt isn't a self-loop or no rule is configured. Self-loop flat
 *  floors are likewise clamped to the price so a self-loop payout can't
 *  go negative either. */
function computeFeeWithSelfLoop(
  amountMinor: number,
  policy: FeePolicy,
  selfLoop: SelfLoopRule | undefined,
  isSelfLoop: boolean,
): number {
  if (!isSelfLoop || !selfLoop) return computeFee(amountMinor, policy);
  if (selfLoop.feeWaived) return 0;
  return Math.min(selfLoop.minMinor ?? 0, amountMinor);
}

/** Authorization identity for single-use / budget bookkeeping. Prefer
 *  the lexicon's `nonce` (the requester-signed replay-protection field:
 *  16 random bytes hex-encoded) — it is what makes the authorization
 *  uniquely spendable. Fall back to the authorization record URI for any
 *  authorization shape lacking a usable nonce. */
function authorizationIdentity(uri: string, auth: PaymentAuthorizationRecord): string {
  const nonce = auth.nonce;
  if (typeof nonce === "string" && nonce.length > 0) return `nonce:${nonce}`;
  return `uri:${uri}`;
}
