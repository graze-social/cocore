// Brokerage countersignature — the forkable-authority confidential gate (ADR-0004).
//
// Under ADR-0004 a receipt is `attested-confidential` only when a BROKERAGE the
// requester trusts has countersigned it, session-bound: the brokerage
// live-challenges the machine it dispatches to, so its signature proves
// "authority X routed THIS job to the machine it attested, and that machine
// served it." A self-published attestation record on the provider's own PDS is
// no longer sufficient — that was the seam astra walked through.
//
// Trust is relative to a NAMED authority (CA-style trust roots): the verifier
// checks the countersignature's `authority` is in its configured trust set and
// verifies the signature against that authority's DID document. Anyone can run
// a competing brokerage; a verifier chooses which to trust.

import { canonicalBytes } from "./canonical.ts";
import { SignatureVerifyError, verifyP256, verifyReceiptSignature } from "./p256.ts";

/** The countersignature block carried on a receipt (lexicon
 *  `dev.cocore.compute.receipt#brokerageCountersignature`). */
export interface BrokerageCountersignature {
  authority: string;
  machineId: string;
  nonce: string;
  /** base64 DER P-256 signature by the authority key. */
  sig: string;
}

/** The subset of a receipt this module reads. */
export interface ReceiptForWitness {
  requester?: string;
  job?: { uri?: string; cid?: string };
  attestation?: { uri?: string };
  brokerageCountersignature?: BrokerageCountersignature;
}

/** The EXACT canonical bytes a brokerage signs (ADR-0004). This is the
 *  cross-language contract — it MUST be byte-identical in the advisor (signer),
 *  the Python SDK, and the Rust provider/verifier. Keys are sorted by
 *  {@link canonicalBytes}; every field is bound so the witness can't be lifted
 *  onto a different job/requester/machine/attestation. */
export function brokerageWitnessMessage(fields: {
  authority: string;
  /** receipt.attestation.uri */
  attestation: string;
  /** receipt.job.cid */
  jobCid: string;
  /** receipt.job.uri */
  jobUri: string;
  machineId: string;
  nonce: string;
  /** receipt.requester */
  requester: string;
}): Uint8Array {
  return canonicalBytes({
    authority: fields.authority,
    attestation: fields.attestation,
    jobCid: fields.jobCid,
    jobUri: fields.jobUri,
    machineId: fields.machineId,
    nonce: fields.nonce,
    requester: fields.requester,
  });
}

export interface VerifyBrokerageOptions {
  /** Brokerage DIDs the caller trusts. Empty ⇒ nothing is confidential-valid
   *  (fail-closed — validity is always relative to a named, trusted authority). */
  trustedAuthorities: Iterable<string>;
  /** Resolve a brokerage DID to its raw 64-byte P-256 signing key (base64, the
   *  same X‖Y encoding attestation.publicKey uses), or null if unresolvable.
   *  Injected so DID-document resolution (did:web / did:plc) is the caller's
   *  concern and tests can stub it. */
  resolveAuthorityKeyB64: (did: string) => Promise<string | null>;
}

export interface BrokerageVerifyResult {
  ok: boolean;
  authority?: string;
  reason?: string;
}

/** Verify a receipt's brokerage countersignature (ADR-0004): the `authority` is
 *  in the trust set, its DID-document key verifies the session-bound signature,
 *  and every bound field is present on the receipt. Never throws — a bad/absent
 *  countersignature resolves `ok: false` with a reason. */
export async function verifyBrokerageCountersignature(
  receipt: ReceiptForWitness,
  opts: VerifyBrokerageOptions,
): Promise<BrokerageVerifyResult> {
  const cs = receipt.brokerageCountersignature;
  if (!cs) return { ok: false, reason: "no brokerage countersignature on the receipt" };

  const trusted = new Set<string>(opts.trustedAuthorities);
  if (!trusted.has(cs.authority)) {
    return {
      ok: false,
      authority: cs.authority,
      reason: `authority ${cs.authority} is not in the trust set`,
    };
  }

  const jobUri = receipt.job?.uri;
  const jobCid = receipt.job?.cid;
  const attestation = receipt.attestation?.uri;
  const requester = receipt.requester;
  if (!jobUri || !jobCid || !attestation || !requester || !cs.machineId || !cs.nonce || !cs.sig) {
    return {
      ok: false,
      authority: cs.authority,
      reason: "receipt or countersignature is missing a bound field",
    };
  }

  const key = await opts.resolveAuthorityKeyB64(cs.authority);
  if (!key) {
    return {
      ok: false,
      authority: cs.authority,
      reason: `could not resolve a signing key for authority ${cs.authority}`,
    };
  }

  const message = brokerageWitnessMessage({
    authority: cs.authority,
    attestation,
    jobCid,
    jobUri,
    machineId: cs.machineId,
    nonce: cs.nonce,
    requester,
  });
  try {
    const ok = await verifyP256(key, cs.sig, message);
    return ok
      ? { ok: true, authority: cs.authority }
      : { ok: false, authority: cs.authority, reason: "countersignature did not verify" };
  } catch (e) {
    if (e instanceof SignatureVerifyError) {
      return { ok: false, authority: cs.authority, reason: "countersignature verify error" };
    }
    throw e;
  }
}

/** The single call a confidential requester/auditor makes on a receipt
 *  (ADR-0004): the PROVIDER signed the receipt body (enclaveSignature) AND a
 *  trusted BROKERAGE witnessed the dispatch to the attested machine
 *  (brokerageCountersignature). Both must hold for the receipt to be
 *  confidential-valid — a self-published receipt without a trusted brokerage's
 *  countersignature is best-effort, no matter what its `tier` field claims. */
export async function verifyConfidentialReceipt(
  receipt: ReceiptForWitness & { enclaveSignature?: string } & Record<string, unknown>,
  opts: VerifyBrokerageOptions & {
    /** The signing key of the receipt's strong-reffed attestation. */
    providerPublicKeyB64: string;
    /** The attestation's `sigScheme` (for the enclaveSignature dispatch). */
    sigScheme?: string;
  },
): Promise<{ ok: boolean; reason?: string; authority?: string }> {
  const providerOk = await verifyReceiptSignature(
    receipt as { enclaveSignature?: string } & Record<string, unknown>,
    opts.providerPublicKeyB64,
    opts.sigScheme,
  );
  if (!providerOk) return { ok: false, reason: "provider enclaveSignature did not verify" };
  const witness = await verifyBrokerageCountersignature(receipt, opts);
  if (!witness.ok) return { ok: false, reason: witness.reason, authority: witness.authority };
  return { ok: true, authority: witness.authority };
}

// ---- Authority DID-document resolution -------------------------------
//
// A brokerage publishes its P-256 signing key in its DID document, as a
// `verificationMethod` with a `publicKeyJwk` (EC / P-256). The verifier resolves
// the DID, extracts that key, and uses it to check the countersignature. Anyone
// can run a brokerage; a verifier trusts a configured set of DIDs.

/** The default trusted brokerage: cocore's reference advisor. Callers with their
 *  own or additional brokerages extend this. */
export const DEFAULT_TRUSTED_BROKERAGE = "did:web:advisor.cocore.dev";

interface DidDocument {
  verificationMethod?: Array<{
    type?: string;
    publicKeyJwk?: { kty?: string; crv?: string; x?: string; y?: string };
  }>;
}

/** Extract a brokerage's raw 64-byte P-256 signing key (base64 X‖Y) from its DID
 *  document — the first `verificationMethod` carrying an EC / P-256
 *  `publicKeyJwk`. Returns null when the document has no usable P-256 key. Pure
 *  (no network), so it's unit-testable. */
export function brokerageKeyFromDidDoc(doc: DidDocument): string | null {
  for (const vm of doc.verificationMethod ?? []) {
    const jwk = vm.publicKeyJwk;
    if (jwk?.kty === "EC" && jwk.crv === "P-256" && jwk.x && jwk.y) {
      try {
        const x = b64urlToBytes(jwk.x);
        const y = b64urlToBytes(jwk.y);
        if (x.length === 32 && y.length === 32) {
          const raw = new Uint8Array(64);
          raw.set(x, 0);
          raw.set(y, 32);
          return bytesToB64(raw);
        }
      } catch {
        // try the next verificationMethod
      }
    }
  }
  return null;
}

/** Build the did:web / did:plc URL whose body is a DID document. Returns null
 *  for unsupported DID methods (the repo-wide did:plc + did:web policy). */
export function didDocumentUrl(did: string): string | null {
  if (did.startsWith("did:web:")) {
    const parts = did.slice("did:web:".length).split(":").map(decodeURIComponent);
    const host = parts[0];
    if (!host) return null;
    const path = parts.slice(1);
    return path.length === 0
      ? `https://${host}/.well-known/did.json`
      : `https://${host}/${path.join("/")}/did.json`;
  }
  if (did.startsWith("did:plc:")) {
    return `https://plc.directory/${encodeURIComponent(did)}`;
  }
  return null;
}

/** A caching resolver from a brokerage DID to its raw P-256 signing key (base64),
 *  fetching the DID document over https. Suitable as
 *  {@link VerifyBrokerageOptions.resolveAuthorityKeyB64}. `fetchImpl` defaults to
 *  the global `fetch`; tests inject a stub. Failures resolve null (never throw)
 *  so a bad/unreachable authority fails the countersignature closed. */
export function makeBrokerageKeyResolver(
  opts: {
    fetchImpl?: typeof fetch;
    cacheTtlMs?: number;
    now?: () => number;
  } = {},
): (did: string) => Promise<string | null> {
  const doFetch = opts.fetchImpl ?? fetch;
  const ttl = opts.cacheTtlMs ?? 5 * 60_000;
  const now = opts.now ?? (() => Date.now());
  const cache = new Map<string, { key: string | null; at: number }>();
  return async (did: string): Promise<string | null> => {
    const hit = cache.get(did);
    if (hit && now() - hit.at < ttl) return hit.key;
    const url = didDocumentUrl(did);
    let key: string | null = null;
    if (url) {
      try {
        const r = await doFetch(url, { headers: { accept: "application/json" } });
        if (r.ok) key = brokerageKeyFromDidDoc((await r.json()) as DidDocument);
      } catch {
        key = null;
      }
    }
    // Cache misses too (bounded by ttl) so a down authority doesn't get hammered.
    cache.set(did, { key, at: now() });
    return key;
  };
}

function b64urlToBytes(b64url: string): Uint8Array {
  const b64 = b64url
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(b64url.length / 4) * 4, "=");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin);
}
