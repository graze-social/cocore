// Resolve an open `dev.cocore.compute.dispute` record after the
// operator has reviewed it. Mirrors PR #53's open-side bridge:
// the console holds the exchange's OAuth session and writes
// directly via PDS putRecord. The lexicon's `record.exchange ==
// repo it's published in` constraint is satisfied by construction
// (we use the exchange's own session).
//
// For refund verdicts (refund-full / refund-partial), the
// resolution also publishes a new `dev.cocore.compute.settlement`
// record with `status=refunded` and `refundOf` pointing at the
// original settlement, then strong-refs that new record from
// `outcome.refundSettlement`. The audit chain stays
// self-verifying: a verifier reading the dispute can walk to the
// refund settlement and to the original settlement without any
// out-of-band lookups.
//
// Signing: when COCORE_EXCHANGE_PRIVATE_KEY_JWK is set, both the
// refund settlement and the resolved dispute carry an ES256 `sig`
// field over the canonical bytes of every other field. Verifiers
// fetch the public half from the exchange's did:web doc (or from
// dev.cocore.compute.exchangeAttestation if pinned) and check.
// When unset (dev / staging), records publish unsigned.
//
// What this does NOT do (yet):
//   * No retry logic on swap-on-CID conflicts. If a parallel
//     resolve fires between our get and put, the put fails with
//     InvalidSwap and the operator retries.

import type { OAuthSession } from "@atcute/oauth-node-client";

import { runTraced } from "@/lib/o11y.server.ts";

import { cocoreConfig } from "@/lib/cocore-config.ts";
import { consoleDb } from "@/lib/console-db.server.ts";
import { signRecordIfConfigured } from "@/lib/signing.server.ts";
import { restoreAtprotoSessionEffect } from "@/integrations/auth/atproto.server.ts";
import { appviewBackedSession, appviewSessionInfo } from "@/lib/appview-backed-session.server.ts";
import { isAppviewForwardConfigured } from "@/lib/appview-pds-forward.server.ts";
import type { Did } from "@atcute/lexicons";
import { isDid } from "@atcute/lexicons/syntax";

const SETTLEMENT_COLLECTION = "dev.cocore.compute.settlement";
const DISPUTE_COLLECTION = "dev.cocore.compute.dispute";

type DisputeVerdict = "refund-full" | "refund-partial" | "uphold-charge" | "forfeit-payout";

interface MoneyJson {
  amount: number;
  currency: string;
}

interface StrongRefJson {
  uri: string;
  cid: string;
}

interface SettlementBody {
  receipt: StrongRefJson;
  requesterAuthorization: StrongRefJson;
  amountCharged: MoneyJson;
  providerPayout: MoneyJson;
  exchangeFee: MoneyJson;
  processorReference: string;
  status: "settled" | "refunded" | "disputed";
  refundOf?: StrongRefJson;
  policy?: StrongRefJson;
  exchangeAttestation?: StrongRefJson;
  sig?: string;
  settledAt: string;
}

interface DisputeBody {
  $type?: string;
  settlement: StrongRefJson;
  exchange: string;
  raisedBy: string;
  raisedAt: string;
  reason: { category: string; detail?: string };
  status: "open" | "resolved";
  outcome?: {
    verdict: DisputeVerdict;
    refundSettlement?: StrongRefJson;
    rationale?: string;
    decidedAt: string;
  };
  evidenceCid?: string;
  sig?: string;
  createdAt: string;
}

async function readPdsError(res: Response): Promise<string> {
  const text = await res.text();
  try {
    const j = JSON.parse(text) as { error?: string; message?: string };
    return j.message ?? j.error ?? text.slice(0, 400);
  } catch {
    return text.slice(0, 400) || `HTTP ${res.status}`;
  }
}

function rkeyFromUri(uri: string): string {
  return uri.slice(uri.lastIndexOf("/") + 1);
}

interface FetchedRecord<T> {
  uri: string;
  cid: string;
  value: T;
}

async function getRecord<T>(
  session: OAuthSession,
  collection: string,
  rkey: string,
): Promise<FetchedRecord<T>> {
  const params = new URLSearchParams({
    repo: session.did,
    collection,
    rkey,
  });
  const res = await session.handle(`/xrpc/com.atproto.repo.getRecord?${params}`, {
    method: "GET",
  });
  if (!res.ok) {
    throw new Error(`getRecord ${collection}/${rkey}: ${await readPdsError(res)}`);
  }
  const body = (await res.json()) as { uri?: string; cid?: string; value?: unknown };
  if (!body.uri || !body.cid || !body.value) {
    throw new Error(`getRecord ${collection}/${rkey}: malformed PDS response`);
  }
  return { uri: body.uri, cid: body.cid, value: body.value as T };
}

export interface ResolveDisputeInput {
  disputeUri: string;
  verdict: DisputeVerdict;
  rationale?: string;
  /** Required when verdict ∈ {refund-full, refund-partial}.
   *  Minor units of the ORIGINAL settlement's amountCharged
   *  currency. refund-full uses original.amountCharged.amount;
   *  refund-partial may be any value <= that. */
  refundAmountMinor?: number;
}

export interface ResolveDisputeResult {
  disputeUri: string;
  disputeCid: string;
  refundSettlementUri?: string;
  refundSettlementCid?: string;
}

export class ResolveDisputeError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "ResolveDisputeError";
  }
}

/** Restore the exchange's OAuth session. Throws ResolveDisputeError
 *  with code="exchange-not-onboarded" if no session is on file —
 *  callers map this to a 503-ish response. */
async function loadExchangeSession(): Promise<OAuthSession> {
  const exchangeDid = cocoreConfig().exchangeDid;
  if (!isDid(exchangeDid)) {
    throw new ResolveDisputeError(
      "exchange-not-onboarded",
      `cocoreConfig.exchangeDid is not a DID (${exchangeDid})`,
    );
  }
  // Single-owner cutover: when forwarding is configured the AppView owns and
  // solely refreshes the exchange service DID's session (its keep-alive is the
  // designated refresher — see packages/appview/src/auth/oauth-client.ts). A
  // local restore here would refresh in parallel and cannibalize the single-use
  // refresh token — precisely the 2026-06 settlement stall (a dead exchange
  // session blocking every settlement write). Replay dispute writes through the
  // AppView-backed session; only a DEFINITIVE "absent" means re-auth is needed.
  if (isAppviewForwardConfigured()) {
    const info = await appviewSessionInfo(exchangeDid);
    if (info.checked && !info.present) {
      throw new ResolveDisputeError(
        "exchange-not-onboarded",
        `no live AppView session for ${exchangeDid} — exchange must sign in to resolve disputes`,
      );
    }
    return appviewBackedSession(exchangeDid as Did);
  }
  const session = await runTraced(
    "auth.restoreSession",
    restoreAtprotoSessionEffect(exchangeDid as Did),
  );
  if (!session) {
    throw new ResolveDisputeError(
      "exchange-not-onboarded",
      `no OAuth session for ${exchangeDid} — exchange must sign in to resolve disputes`,
    );
  }
  return session;
}

async function publishRefundSettlement(
  session: OAuthSession,
  original: FetchedRecord<SettlementBody>,
  refundAmountMinor: number,
): Promise<{ uri: string; cid: string }> {
  const now = new Date().toISOString();
  const refundRecord: Record<string, unknown> = {
    $type: SETTLEMENT_COLLECTION,
    receipt: original.value.receipt,
    requesterAuthorization: original.value.requesterAuthorization,
    amountCharged: {
      amount: refundAmountMinor,
      currency: original.value.amountCharged.currency,
    },
    // No payout/fee on a refund — the money flows back to the
    // requester and the exchange waives its fee.
    providerPayout: { amount: 0, currency: original.value.providerPayout.currency },
    exchangeFee: { amount: 0, currency: original.value.exchangeFee.currency },
    // Placeholder until the actual Stripe refund object id is
    // known. Operator-published refunds may not have a Stripe
    // refund yet (the exchange could be reversing a payout via
    // a different mechanism). Leaving this opaque keeps the
    // record publishable without a Stripe round-trip.
    processorReference: Buffer.from(`refund=pending;refundOf=${original.uri}`).toString("base64"),
    status: "refunded",
    refundOf: { uri: original.uri, cid: original.cid },
    ...(original.value.policy ? { policy: original.value.policy } : {}),
    ...(original.value.exchangeAttestation
      ? { exchangeAttestation: original.value.exchangeAttestation }
      : {}),
    settledAt: now,
  };
  const sig = await signRecordIfConfigured(refundRecord);
  if (sig) refundRecord.sig = sig;
  const res = await session.handle(`/xrpc/com.atproto.repo.createRecord`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      repo: session.did,
      collection: SETTLEMENT_COLLECTION,
      record: refundRecord,
    }),
  });
  if (!res.ok) {
    throw new ResolveDisputeError(
      "refund-publish-failed",
      `createRecord refund settlement: ${await readPdsError(res)}`,
    );
  }
  const body = (await res.json()) as { uri?: string; cid?: string };
  if (!body.uri || !body.cid) {
    throw new ResolveDisputeError(
      "refund-publish-failed",
      "createRecord refund settlement: missing uri/cid in PDS response",
    );
  }
  return { uri: body.uri, cid: body.cid };
}

/** Best-effort: if the dispute came in via the
 *  charge.dispute.created bridge, flip its `pending_disputes`
 *  row to status="resolved" so an operator dashboard reflects
 *  the new state. No-op when no such row exists (manual /
 *  out-of-band disputes). */
function markPendingResolved(disputeUri: string): void {
  consoleDb()
    .prepare(
      `UPDATE pending_disputes
          SET status = 'resolved', updated_at = ?
        WHERE dispute_uri = ?`,
    )
    .run(new Date().toISOString(), disputeUri);
}

export async function resolveDispute(input: ResolveDisputeInput): Promise<ResolveDisputeResult> {
  // Validate inputs.
  if (!input.disputeUri.startsWith("at://")) {
    throw new ResolveDisputeError("bad-uri", "disputeUri must be an at:// URI");
  }
  const isRefund = input.verdict === "refund-full" || input.verdict === "refund-partial";
  if (isRefund) {
    if (
      typeof input.refundAmountMinor !== "number" ||
      !Number.isInteger(input.refundAmountMinor) ||
      input.refundAmountMinor <= 0
    ) {
      throw new ResolveDisputeError(
        "bad-refund-amount",
        `verdict ${input.verdict} requires a positive integer refundAmountMinor`,
      );
    }
  }

  const session = await loadExchangeSession();

  // Fetch the dispute and verify state.
  const dispute = await getRecord<DisputeBody>(
    session,
    DISPUTE_COLLECTION,
    rkeyFromUri(input.disputeUri),
  );
  if (dispute.value.status === "resolved") {
    throw new ResolveDisputeError(
      "already-resolved",
      `dispute ${input.disputeUri} is already resolved`,
    );
  }

  // For refund verdicts, fetch the original settlement and publish
  // the compensating refund settlement first. We do this before
  // updating the dispute so the dispute record's outcome can
  // carry a real strong-ref to the refund.
  let refundSettlement: { uri: string; cid: string } | undefined;
  if (isRefund) {
    const origUri = dispute.value.settlement.uri;
    if (!origUri.startsWith(`at://${session.did}/`)) {
      throw new ResolveDisputeError(
        "settlement-not-mine",
        `dispute references settlement ${origUri} outside the exchange's repo`,
      );
    }
    const original = await getRecord<SettlementBody>(
      session,
      SETTLEMENT_COLLECTION,
      rkeyFromUri(origUri),
    );
    const requestedAmount = input.refundAmountMinor!;
    if (
      input.verdict === "refund-full" &&
      requestedAmount !== original.value.amountCharged.amount
    ) {
      throw new ResolveDisputeError(
        "refund-amount-mismatch",
        `verdict refund-full requires refundAmountMinor=${original.value.amountCharged.amount}, got ${requestedAmount}`,
      );
    }
    if (
      input.verdict === "refund-partial" &&
      requestedAmount >= original.value.amountCharged.amount
    ) {
      throw new ResolveDisputeError(
        "refund-amount-too-large",
        `verdict refund-partial requires refundAmountMinor < original ${original.value.amountCharged.amount}`,
      );
    }
    refundSettlement = await publishRefundSettlement(session, original, requestedAmount);
  }

  // Build the resolved record and putRecord with swap-on-CID.
  const decidedAt = new Date().toISOString();
  const resolved: DisputeBody = {
    ...dispute.value,
    status: "resolved",
    outcome: {
      verdict: input.verdict,
      ...(refundSettlement ? { refundSettlement } : {}),
      ...(input.rationale ? { rationale: input.rationale } : {}),
      decidedAt,
    },
  };
  // Drop $type when echoing back via putRecord — the AT Protocol
  // PDS infers it from the collection. Re-sign over the canonical
  // bytes of every other field minus the prior `sig` (set when the
  // record was opened); the resolution carries its own signature.
  const {
    $type: _drop,
    sig: _priorSig,
    ...withoutType
  } = resolved as DisputeBody & {
    $type?: string;
  };
  void _drop;
  void _priorSig;
  const newSig = await signRecordIfConfigured(withoutType as Record<string, unknown>);
  const recordToPut: Record<string, unknown> = newSig
    ? { ...withoutType, sig: newSig }
    : withoutType;
  const res = await session.handle(`/xrpc/com.atproto.repo.putRecord`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      repo: session.did,
      collection: DISPUTE_COLLECTION,
      rkey: rkeyFromUri(input.disputeUri),
      record: recordToPut,
      swapRecord: dispute.cid,
    }),
  });
  if (!res.ok) {
    throw new ResolveDisputeError(
      "putRecord-failed",
      `putRecord dispute: ${await readPdsError(res)}`,
    );
  }
  const body = (await res.json()) as { uri?: string; cid?: string };
  if (!body.uri || !body.cid) {
    throw new ResolveDisputeError("putRecord-failed", "putRecord dispute: missing uri/cid");
  }

  // Update the audit table if this dispute came in via the
  // charge.dispute.created bridge from PR #53. No-op for
  // manual / out-of-band disputes.
  markPendingResolved(input.disputeUri);

  return {
    disputeUri: body.uri,
    disputeCid: body.cid,
    ...(refundSettlement
      ? {
          refundSettlementUri: refundSettlement.uri,
          refundSettlementCid: refundSettlement.cid,
        }
      : {}),
  };
}
