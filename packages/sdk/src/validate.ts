// Cross-record validators for dev.cocore.compute.* records.
//
// These run anywhere — AppView, exchange, SDK consumer — and return a
// structured findings list rather than throwing.
//
// Two tiers:
//   * `verifyReceipt` / `verifyForCharge` — synchronous, cover the
//     cheap structural checks (commitment equality, ceiling,
//     expiry, linkage) and assert that `enclaveSignature` is
//     present. Cheap to call on every record passing through the
//     AppView indexer or a smoke test.
//   * `verifyReceiptStrict` / `verifyForChargeStrict` — async,
//     superset of the above plus a real ES256 verification of
//     `enclaveSignature` against `attestation.publicKey`. The
//     exchange runs the strict variant before charging — the
//     receipt's body has to be cryptographically attested by the
//     enclave, not just well-shaped.

import { canonicalize } from "./canonical.ts";
import { verifyAttestationSignature, verifyReceiptSignature } from "./p256.ts";
import type {
  AttestationRecord,
  JobRecord,
  PaymentAuthorizationRecord,
  ReceiptRecord,
  SettlementRecord,
  StrongRef,
} from "./types.ts";

export type Severity = "error" | "warn";

export interface Finding {
  severity: Severity;
  code: string;
  message: string;
}

export interface ValidationReport {
  ok: boolean;
  findings: Finding[];
}

function err(out: Finding[], code: string, message: string): void {
  out.push({ severity: "error", code, message });
}

/** A `proBono: true` receipt is the explicit carve-out for free, unmetered
 *  work: the provider commits to taking no payment and counting no tokens.
 *  Enforce that invariant so a provider can't fly the pro-bono flag while
 *  still charging — `price.amount` and both token counts MUST be zero. A
 *  non-pro-bono receipt is unaffected. Shared by {@link verifyReceipt} and
 *  {@link verifyForCharge}. */
function checkProBonoInvariant(receipt: ReceiptRecord, findings: Finding[]): void {
  if (receipt.proBono !== true) return;
  if (receipt.price.amount !== 0) {
    err(
      findings,
      "pro-bono-nonzero-price",
      `receipt.proBono is true but price.amount is ${receipt.price.amount}, not 0`,
    );
  }
  if (receipt.tokens.in !== 0 || receipt.tokens.out !== 0) {
    err(
      findings,
      "pro-bono-nonzero-tokens",
      `receipt.proBono is true but tokens are { in: ${receipt.tokens.in}, out: ${receipt.tokens.out} }, not zero`,
    );
  }
}

function ok(findings: Finding[]): boolean {
  return findings.every((f) => f.severity !== "error");
}

/** Verify a receipt is internally consistent against its job and attestation. */
export function verifyReceipt(
  receipt: ReceiptRecord,
  job: JobRecord,
  attestation: AttestationRecord,
): ValidationReport {
  const findings: Finding[] = [];

  if (receipt.inputCommitment !== job.inputCommitment) {
    err(
      findings,
      "commitment-mismatch",
      "receipt.inputCommitment does not equal job.inputCommitment",
    );
  }
  if (receipt.model !== job.model) {
    err(
      findings,
      "model-mismatch",
      `receipt.model "${receipt.model}" does not match job.model "${job.model}"`,
    );
  }
  if (receipt.price.currency !== job.priceCeiling.currency) {
    err(
      findings,
      "currency-mismatch",
      "receipt.price.currency does not match job.priceCeiling.currency",
    );
  } else if (receipt.price.amount > job.priceCeiling.amount) {
    err(
      findings,
      "price-over-ceiling",
      `receipt.price.amount ${receipt.price.amount} exceeds priceCeiling ${job.priceCeiling.amount}`,
    );
  }
  checkProBonoInvariant(receipt, findings);

  const completedAt = Date.parse(receipt.completedAt);
  const jobExpires = Date.parse(job.expiresAt);
  if (completedAt > jobExpires) {
    err(findings, "job-expired", "receipt.completedAt is past job.expiresAt");
  }

  const attestedAt = Date.parse(attestation.attestedAt);
  const attestExpires = Date.parse(attestation.expiresAt);
  if (completedAt < attestedAt || completedAt > attestExpires) {
    err(
      findings,
      "attestation-stale",
      "receipt.completedAt is outside the attestation validity window",
    );
  }

  // Reconstruct the canonical bytes the provider signed; ensure the
  // body round-trips. The async {@link verifyReceiptStrict} wraps
  // this and adds a real ES256 verification against
  // attestation.publicKey.
  try {
    const { enclaveSignature: _drop, ...signed } = receipt;
    canonicalize(signed);
  } catch (e) {
    err(
      findings,
      "canonical-fail",
      `receipt body could not be canonicalised: ${(e as Error).message}`,
    );
  }
  if (!receipt.enclaveSignature || receipt.enclaveSignature.length === 0) {
    err(findings, "no-signature", "receipt is missing enclaveSignature");
  }

  return { ok: ok(findings), findings };
}

/** Strict superset of {@link verifyReceipt}: appends a real ES256
 *  verification of `receipt.enclaveSignature` over the canonical
 *  bytes of every other field, against `attestation.publicKey`.
 *  Async because WebCrypto is async; otherwise the API mirrors the
 *  sync version. */
export async function verifyReceiptStrict(
  receipt: ReceiptRecord,
  job: JobRecord,
  attestation: AttestationRecord,
): Promise<ValidationReport> {
  const baseline = verifyReceipt(receipt, job, attestation);
  const findings: Finding[] = [...baseline.findings];

  // Skip the crypto check if we already failed on a missing/empty
  // signature — verifyReceiptSignature would just return false and
  // double-up the finding.
  if (receipt.enclaveSignature && receipt.enclaveSignature.length > 0) {
    let valid: boolean;
    try {
      valid = await verifyReceiptSignature(
        receipt as unknown as { enclaveSignature?: string } & Record<string, unknown>,
        attestation.publicKey,
      );
    } catch (e) {
      err(
        findings,
        "signature-verify-error",
        `enclaveSignature verification threw: ${(e as Error).message}`,
      );
      return { ok: ok(findings), findings };
    }
    if (!valid) {
      err(
        findings,
        "signature-invalid",
        "enclaveSignature did not verify against attestation.publicKey",
      );
    }
  }
  return { ok: ok(findings), findings };
}

/** Verify a settlement record correctly chains receipt + authorization. */
export function verifySettlementChain(
  settlement: SettlementRecord,
  receipt: ReceiptRecord,
  authorization: PaymentAuthorizationRecord,
  exchangeDid: string,
): ValidationReport {
  const findings: Finding[] = [];

  if (authorization.exchange !== exchangeDid) {
    err(
      findings,
      "wrong-exchange",
      `authorization names exchange ${authorization.exchange}, but settlement was published by ${exchangeDid}`,
    );
  }
  if (authorization.ceiling.currency !== settlement.amountCharged.currency) {
    err(
      findings,
      "currency-mismatch",
      "authorization.ceiling.currency does not match settlement.amountCharged.currency",
    );
  } else if (settlement.amountCharged.amount > authorization.ceiling.amount) {
    err(
      findings,
      "over-ceiling",
      `settlement.amountCharged ${settlement.amountCharged.amount} exceeds authorization ceiling ${authorization.ceiling.amount}`,
    );
  }
  if (
    settlement.amountCharged.amount !==
    settlement.providerPayout.amount + settlement.exchangeFee.amount
  ) {
    err(findings, "split-mismatch", "amountCharged != providerPayout + exchangeFee");
  }
  if (settlement.status === "settled" && settlement.amountCharged.amount !== receipt.price.amount) {
    err(findings, "amount-vs-price", "for status=settled, amountCharged must equal receipt.price");
  }

  return { ok: ok(findings), findings };
}

/** Pre-charge verification for an exchange. Superset of verifyReceipt
 *  with the authorization-level checks (this exchange owns the auth,
 *  auth is unexpired, price within ceiling, etc.). */
export interface PreChargeContext {
  exchangeDid: string;
  /** Receipt URIs we've already published settlements for. */
  settledReceipts: Set<string>;
  /** Test/clock seam. */
  now?: () => Date;
}

export interface PreChargeInputs {
  receipt: ReceiptRecord;
  receiptUri: string;
  job: JobRecord;
  jobOwnerDid: string;
  authorization: PaymentAuthorizationRecord;
  authorizationUri: StrongRef;
}

export function verifyForCharge(ctx: PreChargeContext, inputs: PreChargeInputs): ValidationReport {
  const { receipt, job, authorization } = inputs;
  const findings: Finding[] = [];
  const now = ctx.now ? ctx.now() : new Date();

  if (ctx.settledReceipts.has(inputs.receiptUri)) {
    err(findings, "already-settled", `receipt ${inputs.receiptUri} has a prior settlement`);
  }
  if (receipt.requester !== inputs.jobOwnerDid) {
    err(
      findings,
      "job-owner-mismatch",
      `receipt.requester ${receipt.requester} does not match job-owning repo ${inputs.jobOwnerDid}`,
    );
  }
  if (authorization.exchange !== ctx.exchangeDid) {
    err(
      findings,
      "wrong-exchange",
      `authorization names ${authorization.exchange}; this exchange is ${ctx.exchangeDid}`,
    );
  }
  if (job.paymentAuthorization.uri !== inputs.authorizationUri.uri) {
    err(
      findings,
      "auth-job-link",
      "job.paymentAuthorization.uri does not equal supplied authorization uri",
    );
  }
  if (Date.parse(authorization.expiresAt) <= now.getTime()) {
    err(findings, "auth-expired", `authorization expired at ${authorization.expiresAt}`);
  }
  if (receipt.inputCommitment !== job.inputCommitment) {
    err(findings, "commitment-mismatch", "receipt.inputCommitment != job.inputCommitment");
  }
  if (receipt.price.currency !== job.priceCeiling.currency) {
    err(findings, "currency-mismatch", "receipt.price.currency != job.priceCeiling.currency");
  } else if (receipt.price.amount > job.priceCeiling.amount) {
    err(
      findings,
      "price-over-job-ceiling",
      `receipt.price.amount ${receipt.price.amount} > job.priceCeiling ${job.priceCeiling.amount}`,
    );
  }
  if (receipt.price.currency !== authorization.ceiling.currency) {
    err(
      findings,
      "currency-mismatch-auth",
      "receipt.price.currency != authorization.ceiling.currency",
    );
  } else if (receipt.price.amount > authorization.ceiling.amount) {
    err(
      findings,
      "price-over-auth-ceiling",
      `receipt.price.amount ${receipt.price.amount} > authorization.ceiling ${authorization.ceiling.amount}`,
    );
  }
  checkProBonoInvariant(receipt, findings);
  if (
    job.acceptedExchanges &&
    job.acceptedExchanges.length > 0 &&
    !job.acceptedExchanges.includes(ctx.exchangeDid)
  ) {
    err(
      findings,
      "exchange-not-allowed",
      `job.acceptedExchanges does not include ${ctx.exchangeDid}`,
    );
  }
  if (Date.parse(receipt.completedAt) > Date.parse(job.expiresAt)) {
    err(findings, "job-completed-after-expiry", "receipt.completedAt is past job.expiresAt");
  }
  if (!receipt.enclaveSignature || receipt.enclaveSignature.length === 0) {
    err(findings, "no-signature", "receipt is missing enclaveSignature");
  }

  return { ok: ok(findings), findings };
}

/** Strict superset of {@link verifyForCharge}: appends the same
 *  ES256 verification {@link verifyReceiptStrict} runs. The
 *  exchange uses this before charging — the receipt's body has to
 *  be cryptographically attested by the enclave, not just
 *  well-shaped. Async because WebCrypto is async. */
export async function verifyForChargeStrict(
  ctx: PreChargeContext,
  inputs: PreChargeInputs,
  attestation: AttestationRecord,
): Promise<ValidationReport> {
  const baseline = verifyForCharge(ctx, inputs);
  const findings: Finding[] = [...baseline.findings];

  // Skip the crypto check when the baseline already noted a missing
  // signature; verifyReceiptSignature would just return false and
  // double-up the finding.
  if (inputs.receipt.enclaveSignature && inputs.receipt.enclaveSignature.length > 0) {
    let valid: boolean;
    try {
      valid = await verifyReceiptSignature(
        inputs.receipt as unknown as { enclaveSignature?: string } & Record<string, unknown>,
        attestation.publicKey,
      );
    } catch (e) {
      err(
        findings,
        "signature-verify-error",
        `enclaveSignature verification threw: ${(e as Error).message}`,
      );
      return { ok: ok(findings), findings };
    }
    if (!valid) {
      err(
        findings,
        "signature-invalid",
        "enclaveSignature did not verify against attestation.publicKey",
      );
    }
  }

  // H1 (0.9.23): authenticate the ATTESTATION itself before settling against it.
  // Verifying the receipt against `attestation.publicKey` is meaningless if the
  // attestation is forged — a provider could mint a fresh attestation with a
  // self-chosen key and sign the receipt with it. Require the attestation's own
  // selfSignature to verify against its publicKey, so the posture fields (and
  // the key the receipt is checked against) are authentically the enclave's.
  // (The owner-DID binding — this attestation belongs to the provider being
  // paid — is enforced by the exchange, which holds both record repos.)
  if (attestation.selfSignature && attestation.selfSignature.length > 0) {
    let attestOk: boolean;
    try {
      attestOk = await verifyAttestationSignature(
        attestation as unknown as { selfSignature?: string } & Record<string, unknown>,
        attestation.publicKey,
      );
    } catch (e) {
      err(
        findings,
        "attestation-verify-error",
        `attestation selfSignature verification threw: ${(e as Error).message}`,
      );
      return { ok: ok(findings), findings };
    }
    if (!attestOk) {
      err(
        findings,
        "attestation-selfsig-invalid",
        "attestation.selfSignature did not verify against attestation.publicKey",
      );
    }
  } else {
    err(findings, "attestation-unsigned", "attestation is missing selfSignature");
  }
  return { ok: ok(findings), findings };
}

export function findingByCode(report: ValidationReport, code: string): Finding | undefined {
  return report.findings.find((f) => f.code === code);
}
