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

import { SettlementPublisher, type PublishedRecord } from "./publisher.ts";
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
}

export type SettlementOutcome =
  | { kind: "settled"; settlement: PublishedRecord }
  | { kind: "rejected"; report: VerificationReport }
  | { kind: "duplicate"; settlement: PublishedRecord }
  | { kind: "resolve-failed"; missing: string };

export class Exchange {
  private readonly cfg: ExchangeConfig;
  private readonly settledByReceiptUri = new Map<string, PublishedRecord>();

  constructor(cfg: ExchangeConfig) {
    this.cfg = cfg;
  }

  /** Process one receipt observation. Idempotent on receipt URI.
   *  Verifies the receipt's signature + payment authorization, then
   *  publishes a settlement record. The actual token movement (the
   *  95/5 split between requester / provider / treasury) is done by
   *  the TokenLedger in a sibling firehose hook — not by this
   *  class. */
  async onReceipt(receiptIndexed: IndexedRecord<ReceiptRecord>): Promise<SettlementOutcome> {
    const receiptUri = receiptIndexed.uri;

    const prior = this.settledByReceiptUri.get(receiptUri);
    if (prior) return { kind: "duplicate", settlement: prior };

    // Resolve the records the verifier needs.
    const jobRow = await this.cfg.resolveRecord(receiptIndexed.body.job.uri);
    if (!jobRow) return { kind: "resolve-failed", missing: receiptIndexed.body.job.uri };
    const job = jobRow.body as JobRecord;

    const authRow = await this.cfg.resolveRecord(job.paymentAuthorization.uri);
    if (!authRow) return { kind: "resolve-failed", missing: job.paymentAuthorization.uri };
    const authorization = authRow.body as PaymentAuthorizationRecord;

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
        settledReceipts: new Set(this.settledByReceiptUri.keys()),
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
    const fee = isProBono
      ? 0
      : computeFeeWithSelfLoop(
          receiptIndexed.body.price.amount,
          this.cfg.feePolicy,
          this.cfg.selfLoop,
          isSelfLoop,
        );
    const providerShare = receiptIndexed.body.price.amount - fee;

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

function computeFee(amountMinor: number, policy: FeePolicy): number {
  const bpsAmount = Math.floor((amountMinor * policy.bps) / 10_000);
  return Math.max(bpsAmount, policy.minMinor);
}

/** Self-loop-aware fee. Falls back to {@link computeFee} when the
 *  receipt isn't a self-loop or no rule is configured. */
function computeFeeWithSelfLoop(
  amountMinor: number,
  policy: FeePolicy,
  selfLoop: SelfLoopRule | undefined,
  isSelfLoop: boolean,
): number {
  if (!isSelfLoop || !selfLoop) return computeFee(amountMinor, policy);
  if (selfLoop.feeWaived) return 0;
  return selfLoop.minMinor ?? 0;
}
