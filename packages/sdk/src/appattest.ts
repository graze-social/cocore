// Apple App Attest attestation verification.
//
// Mirror of provider/src/appattest.rs in TypeScript so AppViews and requesters
// can verify the MDM-free "hardware-attested" path without re-implementing it.
// Parallel to mda.ts (which verifies an MDA x509 chain): this verifies an Apple
// App Attest *attestation object* (CBOR/WebAuthn-shaped) and confirms it is
// BOUND to the provider's receipt-signing key via the credential certificate's
// nonce extension.
//
// Binding (by construction in the helper): clientDataHash = sha256(signingPubKey),
// so here:
//   nonce == sha256(authData ‖ sha256(signingPubKey))  ==  credCert ext 1.2.840.113635.100.8.2
//
// Verification steps (Apple "Validating Apps That Connect to Your Server"),
// kept byte-for-byte aligned with the Rust verifier:
//   1. CBOR-decode; require fmt == "apple-appattest".
//   2. Verify the x5c chain (credCert → intermediate) to the embedded Apple App
//      Attest Root CA: signatures, validity, BasicConstraints.
//   3. nonce = sha256(authData ‖ sha256(signingPubKey)) == credCert nonce ext.
//   4. credentialId (authData) == sha256(credCert uncompressed pubkey) == keyId.
//   5. authData rpIdHash == sha256(appId), AAGUID is genuine, AT flag set.

import { X509Certificate, createHash } from "node:crypto";
import { parseExtensions } from "./mda.ts";
import { SignatureVerifyError, verifyP256 } from "./p256.ts";

/// Apple App Attest Root CA, P-384, valid 2020 → 2045.
/// Identical bytes to the Rust embed in provider/src/appattest.rs.
export const APPLE_APP_ATTEST_ROOT_CA_PEM =
  "-----BEGIN CERTIFICATE-----\n" +
  "MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw\n" +
  "JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK\n" +
  "QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa\n" +
  "Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv\n" +
  "biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y\n" +
  "bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh\n" +
  "NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au\n" +
  "Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/\n" +
  "MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw\n" +
  "CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn\n" +
  "53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV\n" +
  "oyFraWVIyd/dganmrduC1bmTBGwD\n" +
  "-----END CERTIFICATE-----\n";

/// Apple's App Attest nonce extension OID (dotted-int; Node-style).
const OID_APP_ATTEST_NONCE = "1.2.840.113635.100.8.2";

/// AAGUID for genuine production App Attest: ASCII "appattest" + 7 zero bytes.
export const AAGUID_PRODUCTION = Uint8Array.from([
  0x61, 0x70, 0x70, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0, 0, 0, 0, 0, 0, 0,
]);
/// AAGUID for the development environment: ASCII "appattestdevelop".
export const AAGUID_DEVELOPMENT = new TextEncoder().encode("appattestdevelop");

/// The cocore provider App ID ("TEAMID.bundleID"). rpIdHash = sha256 of this.
export const APP_ATTEST_APP_ID = "4L45P7CP9M.dev.cocore.provider";

/// WebAuthn authenticator-data "attested credential data included" flag.
const FLAG_AT = 0x40;

export interface AppAttestResult {
  valid: boolean;
  /** Attested App Attest public key as the uncompressed EC point (0x04‖X‖Y),
   *  base64. NB: the App Attest key, not the signing key — the binding is the
   *  nonce check, not this field. */
  attestedPubkeyUncompressed: string;
  /** sha256(attested pubkey) — equals authData credentialId and keyId. */
  keyId: string;
  aaguid: Uint8Array;
  rpIdHash: Uint8Array;
  /** True iff the nonce commits to sha256(authData ‖ sha256(signingPubKey)). */
  bindsSigningKey: boolean;
}

export class AppAttestError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "AppAttestError";
    this.code = code;
  }
}

export interface VerifyAppAttestOptions {
  /** Verify against this trust anchor instead of the embedded Apple root.
   *  The cross-lang test path passes the synthetic App Attest root. */
  trustAnchorDer?: Uint8Array;
  now?: Date;
  /** Accept the development AAGUID too (default false: production only). */
  allowDevelopment?: boolean;
}

/** Verify an App Attest object. Throws AppAttestError on any failure; returns a
 *  result with bindsSigningKey=true on success. */
export function verifyAppAttest(
  objectDer: Uint8Array,
  keyId: Uint8Array,
  signingPubkeyRaw: Uint8Array,
  appId: string,
  opts: VerifyAppAttestOptions = {},
): AppAttestResult {
  const now = opts.now ?? new Date();
  const rootDer = opts.trustAnchorDer ?? pemToDer(APPLE_APP_ATTEST_ROOT_CA_PEM);
  const allowDevelopment = opts.allowDevelopment ?? false;

  // --- 1. CBOR-decode. ---
  const obj = decodeAttestationObject(objectDer);
  if (obj.fmt !== "apple-appattest") {
    throw new AppAttestError("bad-fmt", `unexpected fmt ${JSON.stringify(obj.fmt)}`);
  }
  if (obj.x5c.length === 0) {
    throw new AppAttestError("shape", "attStmt.x5c is empty");
  }

  // --- 2. Verify the x5c chain to the App Attest root. ---
  const certs = obj.x5c.map((der, i) => {
    try {
      return new X509Certificate(Buffer.from(der));
    } catch (e) {
      throw new AppAttestError("parse", `parse cert ${i}: ${(e as Error).message}`);
    }
  });
  let root: X509Certificate;
  try {
    root = new X509Certificate(Buffer.from(rootDer));
  } catch (e) {
    throw new AppAttestError("bad-trust-anchor", `parse trust anchor: ${(e as Error).message}`);
  }

  const validAt = (cert: X509Certificate, idx: number): void => {
    const t = now.getTime();
    if (t < new Date(cert.validFrom).getTime() || t > new Date(cert.validTo).getTime()) {
      throw new AppAttestError("not-valid", `cert ${idx} not valid at ${now.toISOString()}`);
    }
  };
  certs.forEach(validAt);
  validAt(root, -1);

  for (let i = 0; i < certs.length - 1; i++) {
    if (!certs[i]!.verify(certs[i + 1]!.publicKey)) {
      throw new AppAttestError("bad-signature", `signature on cert ${i} doesn't verify`);
    }
  }
  const topIdx = certs.length - 1;
  if (!certs[topIdx]!.verify(root.publicKey)) {
    throw new AppAttestError(
      "bad-signature",
      `top of chain (cert ${topIdx}) not signed by trust anchor`,
    );
  }

  // BasicConstraints: leaf is end-entity, issuers are CAs.
  for (let i = 0; i < certs.length; i++) {
    const isCa = certs[i]!.ca;
    if (i === 0 && isCa) {
      throw new AppAttestError("leaf-is-ca", "leaf (credCert) must be an end-entity, not a CA");
    }
    if (i > 0 && !isCa) {
      throw new AppAttestError(
        "non-ca-issuer",
        `chain cert ${i} is not a CA but signs cert ${i - 1}`,
      );
    }
  }

  const credCert = certs[0]!;

  // --- 3. Recompute nonce and check the credCert nonce extension. ---
  const clientDataHash = sha256(signingPubkeyRaw);
  const expectedNonce = sha256(concat(obj.authData, clientDataHash));

  const rawDer = new Uint8Array(
    credCert.raw.buffer,
    credCert.raw.byteOffset,
    credCert.raw.byteLength,
  );
  const nonceExt = parseExtensions(rawDer).find((e) => e.oid === OID_APP_ATTEST_NONCE);
  if (!nonceExt) {
    throw new AppAttestError("no-nonce-extension", "credCert has no nonce extension");
  }
  const gotNonce = parseNonceExtension(nonceExt.value);
  if (!gotNonce) {
    throw new AppAttestError("bad-nonce-extension", "malformed nonce extension");
  }
  if (!ctEq(gotNonce, expectedNonce)) {
    throw new AppAttestError(
      "nonce-mismatch",
      "attestation is not bound to the signing key (nonce mismatch)",
    );
  }

  // --- 4. credCert pubkey → credentialId, cross-check authData + keyId. ---
  const attestedPubkey = uncompressedPoint(credCert);
  if (!attestedPubkey) {
    throw new AppAttestError("shape", "credCert public key is not an uncompressed P-256 point");
  }
  const pubkeyHash = sha256(attestedPubkey);

  // --- 5. Parse authData; validate rpIdHash / AAGUID / credentialId. ---
  const ad = parseAuthData(obj.authData);
  if (!ctEq(ad.rpIdHash, sha256(new TextEncoder().encode(appId)))) {
    throw new AppAttestError("shape", "rpIdHash != sha256(appId)");
  }
  const aaguidOk =
    ctEq(ad.aaguid, AAGUID_PRODUCTION) || (allowDevelopment && ctEq(ad.aaguid, AAGUID_DEVELOPMENT));
  if (!aaguidOk) {
    throw new AppAttestError(
      "bad-aaguid",
      `unrecognized AAGUID ${Buffer.from(ad.aaguid).toString("hex")}`,
    );
  }
  if (!ctEq(ad.credentialId, pubkeyHash)) {
    throw new AppAttestError("cred-id-mismatch", "credentialId != sha256(attested pubkey)");
  }
  if (!ctEq(keyId, pubkeyHash)) {
    throw new AppAttestError("key-id-mismatch", "keyId != credentialId");
  }

  return {
    valid: true,
    attestedPubkeyUncompressed: Buffer.from(attestedPubkey).toString("base64"),
    keyId: Buffer.from(pubkeyHash).toString("base64"),
    aaguid: ad.aaguid,
    rpIdHash: ad.rpIdHash,
    bindsSigningKey: true,
  };
}

/** Decode base64 object/keyId/publicKey and verify. Returns true iff valid AND
 *  bound to publicKeyB64. Never throws — callers that want detail use
 *  verifyAppAttest directly. */
export function verifyAppAttestB64(
  objectB64: string,
  keyIdB64: string,
  publicKeyB64: string,
  appId: string,
  opts: VerifyAppAttestOptions = {},
): boolean {
  try {
    const res = verifyAppAttest(
      Uint8Array.from(Buffer.from(objectB64, "base64")),
      Uint8Array.from(Buffer.from(keyIdB64, "base64")),
      Uint8Array.from(Buffer.from(publicKeyB64, "base64")),
      appId,
      opts,
    );
    return res.valid && res.bindsSigningKey;
  } catch (e) {
    if (e instanceof AppAttestError) return false;
    throw e;
  }
}

// ---- App Attest ASSERTIONS (ADR-0003) --------------------------------
//
// An attestation OBJECT (above) is a one-time proof that a key was generated in
// the Secure Enclave. An ASSERTION is the ongoing signature: DCAppAttestService
// .generateAssertion(keyId, clientDataHash) signs `authenticatorData ‖
// clientDataHash` with the SE key. The SE key can't be exported and can't raw-
// sign arbitrary bytes, so an assertion can only be produced on the physical
// device holding the key. When the confidential identity IS the App Attest key
// (keyId == sha256(uncompressed publicKey)), every record signature becomes an
// assertion over clientDataHash = sha256(canonical message) — and the identity
// can no longer be lifted onto another host.

/** Verify an App Attest assertion over `message`, against the SE key that IS the
 *  signing identity (`publicKeyB64` = the attestation's `publicKey`, raw 64-byte
 *  X‖Y). Checks the ES256 signature over `authenticatorData ‖ sha256(message)`
 *  and that the assertion's rpIdHash == sha256(appId). Resolves false (never
 *  throws) on any shape/verify failure. */
export async function verifyAppAttestAssertion(
  publicKeyB64: string,
  assertionB64: string,
  message: Uint8Array,
  appId: string,
): Promise<boolean> {
  let signature: Uint8Array;
  let authenticatorData: Uint8Array;
  try {
    const top = cborReadValue({ buf: b64ToBytes(assertionB64), pos: 0 });
    if (!(top instanceof Map)) return false;
    const sig = top.get("signature");
    const ad = top.get("authenticatorData");
    if (!(sig instanceof Uint8Array) || !(ad instanceof Uint8Array)) return false;
    signature = sig;
    authenticatorData = ad;
  } catch {
    return false;
  }
  // authenticatorData = rpIdHash(32) ‖ flags(1) ‖ signCount(4); assertions omit
  // attested-credential-data, so 37 bytes is the minimum.
  if (authenticatorData.length < 37) return false;
  const rpIdHash = authenticatorData.slice(0, 32);
  if (!ctEq(rpIdHash, sha256(new TextEncoder().encode(appId)))) return false;

  const clientDataHash = sha256(message);
  const signed = concat(authenticatorData, clientDataHash);
  const sigDerB64 = Buffer.from(signature).toString("base64");
  try {
    return await verifyP256(publicKeyB64, sigDerB64, signed);
  } catch (e) {
    if (e instanceof SignatureVerifyError) return false;
    throw e;
  }
}

/** The residency predicate (ADR-0003): does the App-Attest-attested key EQUAL
 *  the signing key? The attestation OBJECT proves a genuine SE key was attested,
 *  but binds to the signing key only via clientData — so a genuine SE key can
 *  attest a commitment to a SEPARATE (software) signing key, and that object is
 *  still portable. Only when the attested key IS the signing key
 *  (`sha256(uncompressed publicKey) == keyId`) is the signing private key itself
 *  proven non-exportable. `attestedUncompressedB64` is the 65-byte 0x04‖X‖Y from
 *  {@link AppAttestResult.attestedPubkeyUncompressed}; `signingPubKeyB64` is the
 *  attestation's raw 64-byte `publicKey`. */
export function attestedKeyMatchesSigningKey(
  attestedUncompressedB64: string,
  signingPubKeyB64: string,
): boolean {
  try {
    const att = b64ToBytes(attestedUncompressedB64);
    const sig = b64ToBytes(signingPubKeyB64);
    if (att.length !== 65 || sig.length !== 64 || att[0] !== 0x04) return false;
    return ctEq(att.subarray(1), sig);
  } catch {
    return false;
  }
}

// ---- internals -------------------------------------------------------

function b64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(Buffer.from(b64, "base64"));
}

function sha256(data: Uint8Array): Uint8Array {
  return Uint8Array.from(createHash("sha256").update(Buffer.from(data)).digest());
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function ctEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let acc = 0;
  for (let i = 0; i < a.length; i++) acc |= a[i]! ^ b[i]!;
  return acc === 0;
}

function pemToDer(pem: string): Uint8Array {
  const stripped = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  return Uint8Array.from(Buffer.from(stripped, "base64"));
}

/** credCert public key as the uncompressed EC point (0x04‖X‖Y, 65 bytes). */
function uncompressedPoint(cert: X509Certificate): Uint8Array | undefined {
  try {
    const jwk = cert.publicKey.export({ format: "jwk" }) as {
      kty?: string;
      crv?: string;
      x?: string;
      y?: string;
    };
    if (jwk.kty === "EC" && jwk.crv === "P-256" && jwk.x && jwk.y) {
      const x = Buffer.from(jwk.x, "base64url");
      const y = Buffer.from(jwk.y, "base64url");
      if (x.length === 32 && y.length === 32) {
        return Uint8Array.from(Buffer.concat([Buffer.from([0x04]), x, y]));
      }
    }
  } catch {
    // fall through → undefined
  }
  return undefined;
}

interface AuthData {
  rpIdHash: Uint8Array;
  aaguid: Uint8Array;
  credentialId: Uint8Array;
}

function parseAuthData(ad: Uint8Array): AuthData {
  // rpIdHash(32) | flags(1) | signCount(4) | aaguid(16) | credIdLen(2) | credId(L) | cose...
  if (ad.length < 37) {
    throw new AppAttestError("short-auth-data", `authData too short (${ad.length} bytes)`);
  }
  const rpIdHash = ad.slice(0, 32);
  const flags = ad[32]!;
  if ((flags & FLAG_AT) === 0) {
    throw new AppAttestError("no-attested-credential-data", "AT flag not set in authData");
  }
  if (ad.length < 55) {
    throw new AppAttestError("short-auth-data", `authData too short (${ad.length} bytes)`);
  }
  const aaguid = ad.slice(37, 53);
  const credIdLen = (ad[53]! << 8) | ad[54]!;
  const end = 55 + credIdLen;
  if (end > ad.length) {
    throw new AppAttestError(
      "short-auth-data",
      `authData too short for credId (${ad.length} bytes)`,
    );
  }
  const credentialId = ad.slice(55, end);
  return { rpIdHash, aaguid, credentialId };
}

/** The credCert nonce extension extnValue is DER:
 *  SEQUENCE { [1] EXPLICIT OCTET STRING <nonce> }. Walk it strictly. */
function parseNonceExtension(extValue: Uint8Array): Uint8Array | undefined {
  const seq = readTlv(extValue);
  if (!seq || seq.tag !== 0x30) return undefined; // SEQUENCE
  const ctx = readTlv(seq.value);
  if (!ctx || ctx.tag !== 0xa1) return undefined; // [1] constructed
  const oct = readTlv(ctx.value);
  if (!oct || oct.tag !== 0x04) return undefined; // OCTET STRING
  if (oct.value.length !== 32) return undefined; // sha256 nonce
  return oct.value;
}

interface Tlv {
  tag: number;
  value: Uint8Array;
  rest: Uint8Array;
}

/** Minimal strict DER TLV reader (definite lengths only). */
function readTlv(data: Uint8Array): Tlv | undefined {
  if (data.length < 2) return undefined;
  const tag = data[0]!;
  const firstLen = data[1]!;
  let len: number;
  let header: number;
  if ((firstLen & 0x80) === 0) {
    len = firstLen;
    header = 2;
  } else {
    const n = firstLen & 0x7f;
    if (n === 0 || n > 4 || data.length < 2 + n) return undefined;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | data[2 + i]!;
    header = 2 + n;
  }
  const endPos = header + len;
  if (endPos > data.length) return undefined;
  return { tag, value: data.slice(header, endPos), rest: data.slice(endPos) };
}

// ---- minimal CBOR decoder (definite-length maps/arrays/byte+text strings) ---
//
// The App Attest object is a small, well-shaped CBOR map; we only need its top
// level (fmt / attStmt(x5c, receipt) / authData). authData is an opaque byte
// string here (its inner COSE key isn't needed). We support major types 0
// (uint, for lengths), 2 (bytes), 3 (text), 4 (array), 5 (map), and skip 1/6/7
// values we don't traverse. Indefinite lengths are rejected.

interface CborReader {
  buf: Uint8Array;
  pos: number;
}

function cborErr(msg: string): never {
  throw new AppAttestError("cbor", msg);
}

function cborReadHead(r: CborReader): { major: number; info: number } {
  if (r.pos >= r.buf.length) cborErr("unexpected end of CBOR");
  const b = r.buf[r.pos++]!;
  return { major: b >> 5, info: b & 0x1f };
}

function cborReadArg(r: CborReader, info: number): number {
  if (info < 24) return info;
  if (info === 24) {
    if (r.pos + 1 > r.buf.length) cborErr("truncated CBOR arg");
    return r.buf[r.pos++]!;
  }
  if (info === 25) {
    if (r.pos + 2 > r.buf.length) cborErr("truncated CBOR arg");
    const v = (r.buf[r.pos]! << 8) | r.buf[r.pos + 1]!;
    r.pos += 2;
    return v;
  }
  if (info === 26) {
    if (r.pos + 4 > r.buf.length) cborErr("truncated CBOR arg");
    const v =
      r.buf[r.pos]! * 0x1000000 +
      (r.buf[r.pos + 1]! << 16) +
      (r.buf[r.pos + 2]! << 8) +
      r.buf[r.pos + 3]!;
    r.pos += 4;
    return v;
  }
  if (info === 27) {
    // 8-byte length — far larger than any attestation object; reject.
    cborErr("CBOR 64-bit lengths not supported");
  }
  cborErr(`unsupported CBOR additional-info ${info}`);
}

type CborValue = number | string | Uint8Array | CborValue[] | Map<string, CborValue>;

function cborReadValue(r: CborReader): CborValue {
  const { major, info } = cborReadHead(r);
  switch (major) {
    case 0: // unsigned int
      return cborReadArg(r, info);
    case 1: // negative int (not traversed in our shape, but decode it)
      return -1 - cborReadArg(r, info);
    case 2: {
      // byte string
      const len = cborReadArg(r, info);
      if (r.pos + len > r.buf.length) cborErr("truncated CBOR byte string");
      const out = r.buf.slice(r.pos, r.pos + len);
      r.pos += len;
      return out;
    }
    case 3: {
      // text string
      const len = cborReadArg(r, info);
      if (r.pos + len > r.buf.length) cborErr("truncated CBOR text string");
      const out = new TextDecoder("utf-8").decode(r.buf.slice(r.pos, r.pos + len));
      r.pos += len;
      return out;
    }
    case 4: {
      // array
      const len = cborReadArg(r, info);
      const arr: CborValue[] = [];
      for (let i = 0; i < len; i++) arr.push(cborReadValue(r));
      return arr;
    }
    case 5: {
      // map (text keys expected for our shape)
      const len = cborReadArg(r, info);
      const m = new Map<string, CborValue>();
      for (let i = 0; i < len; i++) {
        const key = cborReadValue(r);
        const val = cborReadValue(r);
        if (typeof key !== "string") cborErr("non-text CBOR map key");
        m.set(key, val);
      }
      return m;
    }
    default:
      cborErr(`unsupported CBOR major type ${major}`);
  }
}

interface DecodedObject {
  fmt: string;
  x5c: Uint8Array[];
  authData: Uint8Array;
}

function decodeAttestationObject(objectDer: Uint8Array): DecodedObject {
  const top = cborReadValue({ buf: objectDer, pos: 0 });
  if (!(top instanceof Map)) cborErr("top-level is not a CBOR map");
  const fmt = top.get("fmt");
  if (typeof fmt !== "string") cborErr("missing fmt");
  const attStmt = top.get("attStmt");
  if (!(attStmt instanceof Map)) cborErr("missing attStmt");
  const x5cVal = attStmt.get("x5c");
  if (!Array.isArray(x5cVal)) cborErr("missing attStmt.x5c");
  const x5c = x5cVal.map((c) => {
    if (!(c instanceof Uint8Array)) cborErr("attStmt.x5c[] not bytes");
    return c;
  });
  const authData = top.get("authData");
  if (!(authData instanceof Uint8Array)) cborErr("missing authData");
  return { fmt, x5c, authData };
}
