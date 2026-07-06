// Brokerage authority signing (ADR-0004).
//
// The advisor IS a brokerage: it holds the socket, live-challenges the machine
// it dispatches to, and knows the job it's routing. So at DISPATCH time it can
// countersign a witness binding {authority, job, requester, machine,
// attestation, nonce} — every field is known before the job even runs. The
// signed block rides along in the `inference_request`; the provider embeds it in
// the receipt it publishes. A confidential requester later verifies it against
// this authority's DID document (see @cocore/sdk/brokerage).
//
// The authority is just an account: `COCORE_BROKERAGE_DID` (defaults to the
// advisor DID) + a P-256 signing key. Anyone can run a competing brokerage with
// a different account — validity is relative to whichever authority a verifier
// trusts.

import { createPrivateKey, createPublicKey, createSign, randomBytes } from "node:crypto";

import { brokerageWitnessMessage } from "@cocore/sdk/brokerage";

/** A block the advisor attaches to `inference_request` and the provider copies
 *  onto the receipt as `brokerageCountersignature`. Field names are the wire
 *  (snake_case) form; the receipt uses the lexicon camelCase names. */
interface BrokerageCountersignature {
  authority: string;
  machine_id: string;
  nonce: string;
  /** base64 DER P-256 signature. */
  sig: string;
}

export interface BrokerageAuthority {
  /** The authority DID published to requesters (its DID doc carries the key). */
  did: string;
  /** Raw 64-byte P-256 public key (base64 X‖Y) — what belongs in the DID doc
   *  and what the SDK verifier resolves. Logged at boot so ops can publish it. */
  publicKeyB64: string;
  /** Sign the witness for one dispatch. */
  sign(fields: {
    jobUri: string;
    jobCid: string;
    machineId: string;
    attestation: string;
    requester: string;
  }): BrokerageCountersignature;
}

/** A fresh 16-byte lowercase-hex witness nonce. */
function freshWitnessNonce(): string {
  return randomBytes(16).toString("hex");
}

/** Build this brokerage's DID document, publishing its P-256 signing key as a
 *  `JsonWebKey2020` verificationMethod. Served at `/.well-known/did.json` so a
 *  did:web verifier resolves the exact key the countersignature is checked
 *  against — no manual key-publishing step. `publicKeyB64` is the raw 64-byte
 *  X‖Y point (what {@link BrokerageAuthority.publicKeyB64} exposes). */
export function brokerageDidDocument(did: string, publicKeyB64: string): unknown {
  const raw = Buffer.from(publicKeyB64, "base64");
  const vmId = `${did}#brokerage`;
  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
    id: did,
    verificationMethod: [
      {
        id: vmId,
        type: "JsonWebKey2020",
        controller: did,
        publicKeyJwk: {
          kty: "EC",
          crv: "P-256",
          x: raw.subarray(0, 32).toString("base64url"),
          y: raw.subarray(32, 64).toString("base64url"),
        },
      },
    ],
    assertionMethod: [vmId],
  };
}

/** Load the brokerage authority from the environment, or null when it isn't
 *  configured (the advisor then simply attaches no countersignature and the
 *  confidential tier is unavailable through it — fail-closed, not a crash).
 *
 *  `COCORE_BROKERAGE_SIGNING_KEY_PEM` — a PKCS#8 P-256 private key (PEM).
 *  `COCORE_BROKERAGE_DID` — the authority DID (defaults to `COCORE_ADVISOR_DID`). */
export function loadBrokerageAuthority(
  env: Record<string, string | undefined> = process.env,
): BrokerageAuthority | null {
  const did = env["COCORE_BROKERAGE_DID"] ?? env["COCORE_ADVISOR_DID"];
  const pem = env["COCORE_BROKERAGE_SIGNING_KEY_PEM"];
  if (!did || !pem) return null;
  let privateKey: ReturnType<typeof createPrivateKey>;
  try {
    privateKey = createPrivateKey(pem);
  } catch {
    return null;
  }
  const publicKeyB64 = rawPublicKeyB64(privateKey);
  if (!publicKeyB64) return null;
  return {
    did,
    publicKeyB64,
    sign(fields) {
      const nonce = freshWitnessNonce();
      const message = brokerageWitnessMessage({
        authority: did,
        attestation: fields.attestation,
        jobCid: fields.jobCid,
        jobUri: fields.jobUri,
        machineId: fields.machineId,
        nonce,
        requester: fields.requester,
      });
      const sig = createSign("SHA256")
        .update(Buffer.from(message))
        .end()
        .sign(privateKey)
        .toString("base64");
      return { authority: did, machine_id: fields.machineId, nonce, sig };
    },
  };
}

/** Extract the raw 64-byte X‖Y P-256 public key (base64) from a private key. */
function rawPublicKeyB64(privateKey: ReturnType<typeof createPrivateKey>): string | null {
  try {
    const jwk = createPublicKey(privateKey).export({ format: "jwk" }) as { x?: string; y?: string };
    if (!jwk.x || !jwk.y) return null;
    return Buffer.concat([
      Buffer.from(jwk.x, "base64url"),
      Buffer.from(jwk.y, "base64url"),
    ]).toString("base64");
  } catch {
    return null;
  }
}
