// Client-edge sealing for the confidential tier.
//
// NaCl crypto_box (X25519 + XSalsa20-Poly1305), wire format `nonce(24) ||
// box(plaintext)` — byte-identical to the provider's Rust `crypto.rs`
// (`SalsaBox`) and the Python `cocore/seal.py`, so any of them can open what
// another sealed. A confidential requester uses a FRESH ephemeral SENDER key
// per request (forward secrecy); the provider opens with the X25519 key the
// attestation binds.
//
// `sealConfidential` is the one call a privacy-demanding requester makes: it
// runs the fail-closed verifier FIRST and only seals when the provider proves
// the `attested-confidential` tier — otherwise it throws
// `ConfidentialUnavailableError` rather than silently sealing best-effort.

import nacl from "tweetnacl";
import { eciesSeal } from "./ecies.ts";
import type { AttestationRecord } from "./types.ts";
import type { Finding } from "./validate.ts";
import {
  type ProviderVerifyResult,
  type VerifyProviderOptions,
  verifyProviderForSeal,
} from "./verify-provider.ts";

/** Seal `plaintext` to `recipientPubKey` with `ephemeralSecret`. Returns the
 *  framed `nonce || box`. */
export function sealToProvider(
  plaintext: Uint8Array,
  recipientPubKey: Uint8Array,
  ephemeralSecret: Uint8Array,
): Uint8Array {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const body = nacl.box(plaintext, nonce, recipientPubKey, ephemeralSecret);
  const out = new Uint8Array(nonce.length + body.length);
  out.set(nonce, 0);
  out.set(body, nonce.length);
  return out;
}

/** Open a framed `nonce || box` from `senderPubKey`. Null on auth failure. */
export function openFromProvider(
  framed: Uint8Array,
  senderPubKey: Uint8Array,
  ephemeralSecret: Uint8Array,
): Uint8Array | null {
  if (framed.length <= nacl.box.nonceLength) return null;
  const nonce = framed.slice(0, nacl.box.nonceLength);
  const body = framed.slice(nacl.box.nonceLength);
  return nacl.box.open(body, nonce, senderPubKey, ephemeralSecret) ?? null;
}

/** Thrown when a confidential seal was demanded but the provider could not
 *  prove the tier — the prompt is NOT sealed. Carries the verifier findings. */
export class ConfidentialUnavailableError extends Error {
  readonly code = "confidential-unavailable";
  readonly findings: Finding[];
  constructor(findings: Finding[]) {
    const reasons = findings
      .filter((f) => f.severity === "error")
      .map((f) => f.code)
      .join(", ");
    super(`confidential tier unavailable: ${reasons || "verification failed"}`);
    this.name = "ConfidentialUnavailableError";
    this.findings = findings;
  }
}

export interface SealedRequest {
  /** The framed ciphertext to send to the provider. */
  ciphertext: Uint8Array;
  /** base64 of the per-request ephemeral SENDER public key — the
   *  `requester_pub_key` the provider needs to open the ciphertext. */
  senderPublicKey: string;
  /** The recomputed tier (always `attested-confidential` on success). */
  tier: ProviderVerifyResult["tier"];
  /** base64 of the key the prompt was sealed to (the enclave-signed ephemeral
   *  key, or the selfSignature-authenticated encryptionPubKey). */
  sealedToKey: string;
}

/**
 * Verify a provider for the confidential tier and seal `plaintext` to it,
 * fail-closed. Composes {@link verifyProviderForSeal} (`requireConfidential`)
 * with {@link sealToProvider}. Throws {@link ConfidentialUnavailableError} if
 * the provider can't prove the tier — the prompt is never sealed best-effort.
 */
export async function sealConfidential(
  plaintext: Uint8Array,
  attestation: AttestationRecord,
  mdaChain: string[] | undefined,
  opts: VerifyProviderOptions = {},
): Promise<SealedRequest> {
  const result = await verifyProviderForSeal(attestation, mdaChain, {
    ...opts,
    requireConfidential: true,
  });
  if (!result.ok || !result.sealToKey) {
    throw new ConfidentialUnavailableError(result.findings);
  }
  // Pick the wire codec from the provider's advertised `encScheme`. A
  // confidential (Secure Enclave) provider advertises `p256-ecies-se`, so the
  // prompt is sealed with ephemeral-static P-256 ECIES to the SE-resident key —
  // the decrypting scalar never leaves the enclave. An absent/`x25519` scheme
  // (best-effort, or an older agent) keeps the NaCl crypto_box path. The
  // ephemeral SENDER public key (`senderPublicKey`) is the `requester_pub_key`
  // the provider needs to recompute the shared secret either way.
  if (attestation.encScheme === "p256-ecies-se") {
    const { epk, blob } = await eciesSeal(base64ToBytes(result.sealToKey), plaintext);
    return {
      ciphertext: blob,
      senderPublicKey: bytesToBase64(epk),
      tier: result.tier,
      sealedToKey: result.sealToKey,
    };
  }
  const ephemeral = nacl.box.keyPair();
  const sealed = sealToProvider(plaintext, base64ToBytes(result.sealToKey), ephemeral.secretKey);
  return {
    ciphertext: sealed,
    senderPublicKey: bytesToBase64(ephemeral.publicKey),
    tier: result.tier,
    sealedToKey: result.sealToKey,
  };
}

// ---- internals -------------------------------------------------------

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin);
}
