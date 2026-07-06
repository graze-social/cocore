// P-256 ECDSA verification using WebCrypto.
//
// Receipts and attestations carry their signatures DER-encoded
// (matches Apple CryptoKit's wire format on macOS, and what the
// `p256` Rust crate produces on other platforms). WebCrypto's
// SubtleCrypto.verify only accepts raw r||s (64 bytes), so we
// decode the DER ourselves before delegating.
//
// SubtleCrypto handles the SHA-256 pre-hash internally when we ask
// for `{ name: 'ECDSA', hash: 'SHA-256' }`, which matches the Rust
// `p256::ecdsa::Signer for SigningKey` default and Apple's
// `P256.Signing.PrivateKey.signature(for:)`.

import { APP_ATTEST_APP_ID, verifyAppAttestAssertion } from "./appattest.ts";
import { canonicalize } from "./canonical.ts";

export class SignatureVerifyError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "SignatureVerifyError";
  }
}

/** Verify a P-256 ECDSA signature over `message` with the given
 *  public key. Both inputs use base64 in transit; the message is
 *  raw bytes as produced by [`canonicalize`]. */
export async function verifyP256(
  publicKeyB64: string,
  signatureDerB64: string,
  message: Uint8Array,
  // L6: opt-in signature-malleability guard. ECDSA admits two valid signatures
  // per message — (r, s) and (r, n - s) — so an attacker can flip any known-good
  // signature into a second valid form. Rejecting the high-S form (requiring
  // s <= n/2) makes the signature canonical and closes that.
  //
  // Off by DEFAULT because the current producers do NOT normalise: the Rust
  // provider signs via `p256::ecdsa::SigningKey::sign` WITHOUT calling
  // `normalize_s`, so ~50% of real receipts/attestations/session keys are
  // high-S (confirmed against target/confidential-attestation-fixture.json), and
  // Apple CryptoKit likewise does not guarantee low-S. Rejecting high-S here
  // would fail roughly half of all genuine signatures — a fail-OPEN-to-DoS, not
  // a security win. Enabling this by default is a follow-up gated on the provider
  // + enclave signers normalising to low-S first (a producer-side change). Until
  // then callers that control their producers can pass `requireLowS: true`.
  { requireLowS = false }: { requireLowS?: boolean } = {},
): Promise<boolean> {
  const pubRaw = decodeBase64(publicKeyB64);
  if (pubRaw.byteLength !== 64) {
    throw new SignatureVerifyError(
      "bad-pubkey-length",
      `expected 64 raw P-256 bytes (X||Y), got ${pubRaw.byteLength}`,
    );
  }
  const sigDer = decodeBase64(signatureDerB64);
  const sigRaw = derToRawSignature(sigDer);
  if (requireLowS && isHighS(sigRaw.subarray(32, 64))) {
    throw new SignatureVerifyError("high-s", "signature is not in canonical low-S form");
  }
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    // Copy into a plain ArrayBuffer-backed view: TS 5.7+ types the generic
    // `Uint8Array<ArrayBufferLike>` as not assignable to WebCrypto's
    // `BufferSource` (which wants `ArrayBuffer`). Runtime-equivalent.
    new Uint8Array(prefixUncompressed(pubRaw)),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    cryptoKey,
    new Uint8Array(sigRaw),
    new Uint8Array(message),
  );
}

/** Verify a receipt body's `enclaveSignature` against an attestation's
 *  `publicKey`. Strips the signature field AND any `$type` lexicon framing,
 *  canonicalises everything else, and runs WebCrypto. Returns false if the
 *  math fails or any field is missing/malformed.
 *
 *  The `$type` strip is essential and mirrors {@link verifyAttestationSignature}:
 *  the provider signs the receipt body BEFORE the record is written to its PDS,
 *  so the signed canonical bytes never include `$type`. An indexed/stored
 *  record DOES carry `$type` (atproto adds it), and because `$type` sorts to
 *  the front of the canonical JSON, leaving it in shifts every byte and makes
 *  the signature fail. Stripping it is a no-op when absent, so this is always
 *  safe. (Omitting this strip silently rejected every receipt once they began
 *  flowing through the indexer with `$type` populated — the 2026-06 stall.) */
export async function verifyReceiptSignature(
  receipt: { enclaveSignature?: string } & Record<string, unknown>,
  attestationPublicKeyB64: string,
  // ADR-0003: the receipt's enclaveSignature is signed by the attestation
  // identity, so it follows the ATTESTATION's `sigScheme`. Pass it from the
  // attestation record: 'appattest-assertion' verifies the signature as an App
  // Attest assertion (the non-exportable-key form); absent/'p256' is the raw
  // ECDSA default (unchanged for every existing receipt).
  sigScheme?: string,
): Promise<boolean> {
  const sig = receipt.enclaveSignature;
  if (!sig) return false;
  // Strip fields NOT covered by the provider's enclaveSignature: the lexicon
  // `$type` framing, the signature itself, and (ADR-0004) the
  // `brokerageCountersignature` — that's signed by the brokerage, not the
  // provider, and added after the provider signs.
  const {
    enclaveSignature: _omit,
    $type: _type,
    brokerageCountersignature: _cs,
    ...signed
  } = receipt as Record<string, unknown>;
  const message = new TextEncoder().encode(canonicalize(signed));
  if (sigScheme === "appattest-assertion") {
    return verifyAppAttestAssertion(attestationPublicKeyB64, sig, message, APP_ATTEST_APP_ID);
  }
  try {
    return await verifyP256(attestationPublicKeyB64, sig, message);
  } catch (e) {
    if (e instanceof SignatureVerifyError) return false;
    throw e;
  }
}

/** Verify an attestation record's `selfSignature` against its own
 *  `publicKey`. This is what authenticates every posture field — `cdHash`,
 *  `getTaskAllow`, `hardenedRuntime`, `encryptionPubKey`, … — as having been
 *  signed by the enclave key, so a verifier MUST run this before trusting any
 *  of them. (The MDA binding only proves `publicKey` is the device's key; the
 *  session-key signature only covers the ephemeral key. Neither covers
 *  posture.) Strips `selfSignature` (and any `$type` lexicon framing),
 *  canonicalises the rest, and runs WebCrypto. */
export async function verifyAttestationSignature(
  attestation: { selfSignature?: string } & Record<string, unknown>,
  publicKeyB64: string,
): Promise<boolean> {
  const sig = attestation.selfSignature;
  if (!sig) return false;
  const { selfSignature: _omit, $type: _type, ...signed } = attestation as Record<string, unknown>;
  // Try the record exactly as stored first (correct for any attestation whose
  // signed canonical bytes equal its stored bytes — the post-fix provider).
  // Fall back to the LEGACY reconstruction for attestations published by the
  // pre-2026-07 provider, whose signed bytes differed from the stored record
  // in two ways (see legacyAttestationBody). Those records can't be re-signed
  // (the signature is enclave-bound), so the verifier reconstructs what was
  // signed. The exact-as-stored form is always tried first, so this fallback
  // never weakens verification of a correctly-signed record — it only rescues
  // records that would otherwise be unverifiable forever.
  for (const body of [signed, legacyAttestationBody(signed)]) {
    const message = new TextEncoder().encode(canonicalize(body));
    try {
      if (await verifyP256(publicKeyB64, sig, message)) return true;
    } catch (e) {
      if (e instanceof SignatureVerifyError) continue;
      throw e;
    }
  }
  return false;
}

/** Reconstruct the canonical body the pre-2026-07 provider actually SIGNED,
 *  given the attestation as STORED on the PDS. Two divergences existed between
 *  what `provider/src/attestation.rs` signed and what it wrote:
 *
 *  1. `mdaCertChain` — the signed `unsigned` JSON always carried
 *     `"mdaCertChain":[]`, but the stored record used
 *     `#[serde(skip_serializing_if = "Vec::is_empty")]`, dropping the field
 *     entirely for the (overwhelmingly common) self-attested case. So restore
 *     `[]` when the field is absent. A NON-empty chain is stored verbatim and
 *     was signed verbatim, so leave it untouched.
 *  2. timestamps — the signed form used seconds-precision RFC3339
 *     (`SecondsFormat::Secs`), but the stored record serialized
 *     `DateTime<Utc>` at chrono's default sub-second precision
 *     (`...:08.384834Z`). Truncate the fractional seconds back off to recover
 *     the signed string.
 *
 *  This mirrors the post-fix provider, which now stores exactly what it signs
 *  (seconds-precision String timestamps, mdaCertChain only when non-empty) —
 *  so post-fix records verify on the as-stored attempt and never reach here. */
function legacyAttestationBody(signed: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...signed };
  if (!("mdaCertChain" in out)) out.mdaCertChain = [];
  for (const key of ["attestedAt", "expiresAt"]) {
    const v = out[key];
    if (typeof v === "string") out[key] = v.replace(/\.\d+(Z|[+-]\d\d:\d\d)$/, "$1");
  }
  return out;
}

// ---- internals -------------------------------------------------------

// The order n of the P-256 (secp256r1) curve, and n/2 (the low-S ceiling).
// A signature's s-component must satisfy s <= n/2 to be in canonical low-S form.
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_HALF_N = P256_N >> 1n;

/** True iff the 32-byte big-endian s-component is above n/2 (high-S). */
function isHighS(s32: Uint8Array): boolean {
  let s = 0n;
  for (const b of s32) s = (s << 8n) | BigInt(b);
  return s > P256_HALF_N;
}

/** True iff a DER-encoded P-256 signature is in the malleable high-S form
 *  (s > n/2). Exposed so producers/tests can assert their signers normalise to
 *  low-S before {@link verifyP256}'s `requireLowS` guard is turned on by default.
 *  Returns false for signatures that fail to parse (they can't be malleated
 *  into a valid form anyway). */
export function signatureIsHighS(signatureDerB64: string): boolean {
  try {
    const raw = derToRawSignature(decodeBase64(signatureDerB64));
    return isHighS(raw.subarray(32, 64));
  } catch {
    return false;
  }
}

function decodeBase64(b64: string): Uint8Array {
  // Node 18+ exposes Buffer; we avoid relying on it so this module
  // also works in browsers and edge runtimes.
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function prefixUncompressed(raw64: Uint8Array): Uint8Array {
  const out = new Uint8Array(65);
  out[0] = 0x04;
  out.set(raw64, 1);
  return out;
}

/** Convert a DER-encoded ECDSA signature to the IEEE P-1363 raw
 *  format WebCrypto expects: r (32 bytes) || s (32 bytes), big-endian,
 *  zero-padded. */
export function derToRawSignature(der: Uint8Array): Uint8Array {
  if (der.length < 8 || der[0] !== 0x30) {
    throw new SignatureVerifyError("bad-der", "not a DER SEQUENCE");
  }
  let pos = 2;
  // Length byte may be long-form for very long sigs, but a P-256
  // signature is always short-form.
  if ((der[1]! & 0x80) !== 0) {
    const lenBytes = der[1]! & 0x7f;
    pos = 2 + lenBytes;
  }
  const r = readDerInteger(der, pos);
  const s = readDerInteger(der, r.next);
  const out = new Uint8Array(64);
  out.set(padTo32(r.bytes), 0);
  out.set(padTo32(s.bytes), 32);
  return out;
}

function readDerInteger(der: Uint8Array, pos: number): { bytes: Uint8Array; next: number } {
  if (der[pos] !== 0x02) {
    throw new SignatureVerifyError("bad-der", `expected INTEGER at ${pos}`);
  }
  const len = der[pos + 1]!;
  let start = pos + 2;
  let actualLen = len;
  // Strip a single leading 0x00 padding byte added when the
  // high-order bit of the value would otherwise make it negative.
  if (actualLen > 32 && der[start] === 0x00) {
    start++;
    actualLen--;
  }
  if (actualLen > 32) {
    throw new SignatureVerifyError("bad-der", `INTEGER too long (${actualLen}) for P-256`);
  }
  return { bytes: der.slice(start, start + actualLen), next: start + actualLen };
}

function padTo32(b: Uint8Array): Uint8Array {
  if (b.length === 32) return b;
  if (b.length > 32) {
    throw new SignatureVerifyError("bad-der", "INTEGER > 32 bytes");
  }
  const out = new Uint8Array(32);
  out.set(b, 32 - b.length);
  return out;
}
