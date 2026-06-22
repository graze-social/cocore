// Apple Managed Device Attestation cert-chain verification.
//
// Mirror of provider/src/mda.rs in TypeScript so AppViews can
// verify "hardware-attested" trust claims without re-implementing
// cert handling per operator. Uses Node's built-in
// `crypto.X509Certificate` (Node 16+) for parsing + signature
// verification — no third-party X.509 lib required.
//
// What we verify:
//   1. Every cert in the chain was signed by the next cert up
//      (or by the supplied trust anchor for the top of the chain).
//   2. Each cert's NotBefore/NotAfter window covers `now`.
//   3. The Apple-defined OIDs in the leaf parse cleanly.
//
// We do NOT verify revocation; Apple's MDA leaves are short-lived
// (~30 days) and the operational risk is bounded. Mirrors the scope
// of the Rust verifier in `provider/src/mda.rs`.

import { X509Certificate } from "node:crypto";

/// Apple Enterprise Attestation Root CA, P-384, valid 2022 → 2047.
/// Identical bytes to the Rust embed in provider/src/mda.rs.
export const APPLE_ENTERPRISE_ATTESTATION_ROOT_CA_PEM =
  "-----BEGIN CERTIFICATE-----\n" +
  "MIICJDCCAamgAwIBAgIUQsDCuyxyfFxeq/bxpm8frF15hzcwCgYIKoZIzj0EAwMw\n" +
  "UTEtMCsGA1UEAwwkQXBwbGUgRW50ZXJwcmlzZSBBdHRlc3RhdGlvbiBSb290IENB\n" +
  "MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0yMjAyMTYxOTAx\n" +
  "MjRaFw00NzAyMjAwMDAwMDBaMFExLTArBgNVBAMMJEFwcGxlIEVudGVycHJpc2Ug\n" +
  "QXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UE\n" +
  "BhMCVVMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT6Jigq+Ps9Q4CoT8t8q+UnOe2p\n" +
  "oT9nRaUfGhBTbgvqSGXPjVkbYlIWYO+1zPk2Sz9hQ5ozzmLrPmTBgEWRcHjA2/y7\n" +
  "7GEicps9wn2tj+G89l3INNDKETdxSPPIZpPj8VmjQjBAMA8GA1UdEwEB/wQFMAMB\n" +
  "Af8wHQYDVR0OBBYEFPNqTQGd8muBpV5du+UIbVbi+d66MA4GA1UdDwEB/wQEAwIB\n" +
  "BjAKBggqhkjOPQQDAwNpADBmAjEA1xpWmTLSpr1VH4f8Ypk8f3jMUKYz4QPG8mL5\n" +
  "8m9sX/b2+eXpTv2pH4RZgJjucnbcAjEA4ZSB6S45FlPuS/u4pTnzoz632rA+xW/T\n" +
  "ZwFEh9bhKjJ+5VQ9/Do1os0u3LEkgN/r\n" +
  "-----END CERTIFICATE-----\n";

// Apple MDA OID dotted-int strings — Node's X509Certificate exposes
// extensions keyed by these. Same values as provider/src/mda.rs.
const OID_DEVICE_SERIAL_NUMBER = "1.2.840.113635.100.8.9.1";
const OID_DEVICE_UDID = "1.2.840.113635.100.8.9.2";
const OID_OS_VERSION = "1.2.840.113635.100.8.10.1";
const OID_SEP_OS_VERSION = "1.2.840.113635.100.8.10.2";
const OID_LLB_VERSION = "1.2.840.113635.100.8.10.3";
const OID_FRESHNESS_CODE = "1.2.840.113635.100.8.11.1";
const OID_SIP_STATUS = "1.2.840.113635.100.8.13.1";
const OID_SECURE_BOOT_STATUS = "1.2.840.113635.100.8.13.2";
const OID_KEXT_STATUS = "1.2.840.113635.100.8.13.3";

export interface MdaResult {
  valid: boolean;
  error?: string;
  /** The leaf certificate's P-256 public key as base64 of the raw 64-byte
   *  X‖Y point — the SAME encoding as a `dev.cocore.compute.attestation`
   *  record's `publicKey`. A caller BINDS the chain to the signer by
   *  requiring `leafPublicKey === attestation.publicKey`; without that, a
   *  valid Apple chain for one device can be stapled to any signing key. */
  leafPublicKey?: string;
  deviceSerial?: string;
  deviceUdid?: string;
  osVersion?: string;
  sepOsVersion?: string;
  llbVersion?: string;
  freshnessCode?: Uint8Array;
  sipEnabled?: boolean;
  secureBootEnabled?: boolean;
  thirdPartyKexts?: boolean;
}

export class MdaError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "MdaError";
    this.code = code;
  }
}

/** Verify a DER-encoded MDA chain against the embedded Apple Root. */
export function verifyChain(chainDer: Uint8Array[]): MdaResult {
  return verifyChainAgainst(
    chainDer,
    pemToDer(APPLE_ENTERPRISE_ATTESTATION_ROOT_CA_PEM),
    new Date(),
  );
}

/** Verify a DER-encoded MDA chain against a caller-supplied trust
 *  anchor. The cross-lang test path uses this with a synthetic
 *  root produced by the Rust fixture generator. */
export function verifyChainAgainst(
  chainDer: Uint8Array[],
  rootCaDer: Uint8Array,
  now: Date,
): MdaResult {
  if (chainDer.length === 0) {
    throw new MdaError("empty-chain", "empty certificate chain");
  }

  const certs = chainDer.map((der, i) => {
    try {
      return new X509Certificate(Buffer.from(der));
    } catch (e) {
      throw new MdaError("parse", `parse cert ${i}: ${(e as Error).message}`);
    }
  });
  let root: X509Certificate;
  try {
    root = new X509Certificate(Buffer.from(rootCaDer));
  } catch (e) {
    throw new MdaError("bad-trust-anchor", `parse trust anchor: ${(e as Error).message}`);
  }

  const validAt = (cert: X509Certificate, idx: number): void => {
    const nb = new Date(cert.validFrom).getTime();
    const na = new Date(cert.validTo).getTime();
    const t = now.getTime();
    if (t < nb || t > na) {
      throw new MdaError("not-valid", `cert ${idx} not valid at ${now.toISOString()}`);
    }
  };
  certs.forEach(validAt);
  validAt(root, -1);

  // Walk the chain: certs[i] must be signed by certs[i+1].
  for (let i = 0; i < certs.length - 1; i++) {
    if (!certs[i]!.verify(certs[i + 1]!.publicKey)) {
      throw new MdaError("bad-signature", `signature on cert ${i} doesn't verify`);
    }
  }
  // Top of chain must be signed by the trust anchor.
  const topIdx = certs.length - 1;
  if (!certs[topIdx]!.verify(root.publicKey)) {
    throw new MdaError("bad-signature", `top of chain (cert ${topIdx}) not signed by trust anchor`);
  }

  // CA constraints. Every non-leaf cert must be a CA (BasicConstraints
  // cA=true) and the leaf must be an end-entity. Without this, a single
  // Apple-signed leaf can be presented as a forging intermediate
  // ("leaf-as-issuer"): mint a sub-cert under it and present a 2-cert
  // chain that walks cleanly to the Apple root. Node exposes
  // BasicConstraints via `X509Certificate.ca`.
  for (let i = 0; i < certs.length; i++) {
    const isCa = certs[i]!.ca;
    if (i === 0 && isCa) {
      throw new MdaError("leaf-is-ca", "leaf certificate must be an end-entity, not a CA");
    }
    if (i > 0 && !isCa) {
      throw new MdaError("non-ca-issuer", `chain cert ${i} is not a CA but signs cert ${i - 1}`);
    }
  }

  // Extract OIDs from the leaf. Node's X509Certificate gives us a
  // pre-parsed `subject` string and a `raw` DER buffer; for arbitrary
  // OID extensions we have to descend into the DER. We do so via a
  // tiny tag-length-value scanner over the cert's extensions section,
  // which Node exposes through `cert.toLegacyObject()` only on some
  // versions, so we fall back to manual parsing of the leaf DER.
  const leaf = certs[0]!;
  const result: MdaResult = { valid: true };

  // Leaf public key as raw X‖Y (64 bytes), base64 — for the caller's
  // binding check against the attestation's `publicKey`. Node exposes the
  // key as a JWK ({x, y} base64url for P-256); we recombine to the same
  // 64-byte encoding the signer publishes.
  try {
    const jwk = leaf.publicKey.export({ format: "jwk" }) as {
      kty?: string;
      crv?: string;
      x?: string;
      y?: string;
    };
    if (jwk.kty === "EC" && jwk.crv === "P-256" && jwk.x && jwk.y) {
      const x = Buffer.from(jwk.x, "base64url");
      const y = Buffer.from(jwk.y, "base64url");
      if (x.length === 32 && y.length === 32) {
        result.leafPublicKey = Buffer.concat([x, y]).toString("base64");
      }
    }
  } catch {
    // Non-P-256 / unexportable key → leafPublicKey stays undefined and the
    // binding check below fails closed.
  }

  // Subject serialNumber RDN (OID 2.5.4.5) → device serial fallback.
  // Subject string format from Node: "CN=...,serialNumber=C02...".
  const subject = leaf.subject;
  const m = subject.match(/(?:^|[\n,])serialNumber=([^,\n]+)/);
  if (m) result.deviceSerial = m[1]!.trim();

  // Walk extensions in the raw DER and pick the OIDs we care about.
  // Node's `cert.raw` is a NonSharedBuffer; we want a Uint8Array
  // view to feed our minimal DER scanner.
  const rawDer = new Uint8Array(leaf.raw.buffer, leaf.raw.byteOffset, leaf.raw.byteLength);
  const exts = parseExtensions(rawDer);
  for (const { oid, value } of exts) {
    switch (oid) {
      case OID_DEVICE_SERIAL_NUMBER: {
        const s = parseString(value);
        if (s !== undefined) result.deviceSerial = s;
        break;
      }
      case OID_DEVICE_UDID: {
        const s = parseString(value);
        if (s !== undefined) result.deviceUdid = s;
        break;
      }
      case OID_OS_VERSION: {
        const s = parseString(value);
        if (s !== undefined) result.osVersion = s;
        break;
      }
      case OID_SEP_OS_VERSION: {
        const s = parseString(value);
        if (s !== undefined) result.sepOsVersion = s;
        break;
      }
      case OID_LLB_VERSION: {
        const s = parseString(value);
        if (s !== undefined) result.llbVersion = s;
        break;
      }
      case OID_FRESHNESS_CODE:
        result.freshnessCode = value;
        break;
      case OID_SIP_STATUS:
        result.sipEnabled = parseBool(value);
        break;
      case OID_SECURE_BOOT_STATUS:
        result.secureBootEnabled = parseBool(value);
        break;
      case OID_KEXT_STATUS:
        result.thirdPartyKexts = parseBool(value);
        break;
    }
  }
  return result;
}

// ---- internals -------------------------------------------------------

function pemToDer(pem: string): Uint8Array {
  const stripped = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  return Uint8Array.from(Buffer.from(stripped, "base64"));
}

export interface DerExtension {
  oid: string;
  value: Uint8Array;
}

/** Walk an X.509 certificate's DER and yield every extension. We
 *  only need OID + value, which lets us keep the parser minimal.
 *  Exported so the App Attest verifier (`appattest.ts`) can reuse the
 *  same scanner to pull Apple's nonce extension from the credCert. */
export function parseExtensions(certDer: Uint8Array): DerExtension[] {
  // X.509 layout (RFC 5280 §4.1):
  //   Certificate := SEQUENCE { tbs, sigAlg, sigValue }
  //   tbs := SEQUENCE { version, serial, sigAlg, issuer, validity,
  //                     subject, spki, [issuerUniqueID], [subjectUniqueID],
  //                     [extensions:[3] EXPLICIT SEQUENCE OF Extension] }
  // Extensions live inside an EXPLICIT [3] tag (0xa3). We scan the
  // TBS's children, find that tag, then walk the SEQUENCE inside.
  const buf = certDer;
  const reader = new DerReader(buf);
  reader.readSequenceHeader(); // outer Certificate
  const tbsLen = reader.readSequenceHeader(); // TBS
  const tbsEnd = reader.pos + tbsLen;

  while (reader.pos < tbsEnd) {
    const tag = buf[reader.pos]!;
    const start = reader.pos;
    const len = reader.peekHeaderLen();
    if (tag === 0xa3) {
      // Extensions block. Skip the [3] EXPLICIT wrapper and walk
      // the inner SEQUENCE.
      reader.skipHeader();
      const innerLen = reader.readSequenceHeader();
      const innerEnd = reader.pos + innerLen;
      const out: DerExtension[] = [];
      while (reader.pos < innerEnd) {
        const exLen = reader.readSequenceHeader();
        const exEnd = reader.pos + exLen;
        const oid = reader.readOid();
        // Optional BOOLEAN `critical` then OCTET STRING value.
        let valueBytes: Uint8Array;
        if (buf[reader.pos] === 0x01) {
          // BOOLEAN — skip
          reader.skipTagAndContents();
        }
        if (buf[reader.pos] !== 0x04) {
          // Not an OCTET STRING; skip the rest of this extension.
          reader.pos = exEnd;
          continue;
        }
        const _octLen = reader.skipHeader();
        valueBytes = buf.slice(reader.pos, exEnd);
        reader.pos = exEnd;
        out.push({ oid, value: valueBytes });
      }
      return out;
    }
    // Skip this TBS field whatever it is.
    reader.pos = start;
    reader.skipTagAndContents();
    // (`len` is captured for parity with the Rust scanner; we don't
    // use it here because skipTagAndContents handles advancement.)
    void len;
  }
  return [];
}

class DerReader {
  pos = 0;
  buf: Uint8Array;
  constructor(buf: Uint8Array) {
    this.buf = buf;
  }
  /** Read SEQUENCE header at pos, return inner length, advance past header. */
  readSequenceHeader(): number {
    if (this.buf[this.pos] !== 0x30) {
      throw new MdaError(
        "bad-der",
        `expected SEQUENCE at ${this.pos}, got 0x${this.buf[this.pos]?.toString(16)}`,
      );
    }
    this.pos++;
    return this.readLength();
  }
  /** Skip over the tag byte, return the inner length. */
  skipHeader(): number {
    this.pos++;
    return this.readLength();
  }
  /** How many bytes the *header* (tag+length) occupies, without
   *  consuming. Useful for forward-skip planning. */
  peekHeaderLen(): number {
    const lenByte = this.buf[this.pos + 1]!;
    if ((lenByte & 0x80) === 0) return 2;
    return 2 + (lenByte & 0x7f);
  }
  /** Skip past the next TLV entirely. */
  skipTagAndContents(): void {
    this.pos++;
    const len = this.readLength();
    this.pos += len;
  }
  readLength(): number {
    const first = this.buf[this.pos]!;
    this.pos++;
    if ((first & 0x80) === 0) return first;
    const n = first & 0x7f;
    let len = 0;
    for (let i = 0; i < n; i++) {
      len = (len << 8) | this.buf[this.pos]!;
      this.pos++;
    }
    return len;
  }
  /** Decode the next TLV as an OID, return dotted-int string. */
  readOid(): string {
    if (this.buf[this.pos] !== 0x06) {
      throw new MdaError("bad-der", `expected OID at ${this.pos}`);
    }
    this.pos++;
    const len = this.readLength();
    const end = this.pos + len;
    if (this.pos >= end) {
      throw new MdaError("bad-der", "empty OID");
    }
    const first = this.buf[this.pos]!;
    this.pos++;
    const a = Math.floor(first / 40);
    const b = first % 40;
    const components: number[] = [a, b];
    let acc = 0;
    while (this.pos < end) {
      const byte = this.buf[this.pos]!;
      this.pos++;
      acc = (acc << 7) | (byte & 0x7f);
      if ((byte & 0x80) === 0) {
        components.push(acc);
        acc = 0;
      }
    }
    return components.join(".");
  }
}

function parseString(value: Uint8Array): string | undefined {
  // The OCTET STRING contents are typically a UTF8String TLV
  // (tag 0x0c). Fall back to raw bytes if that's not the case.
  if (value.length >= 2 && value[0] === 0x0c) {
    const len = value[1]!;
    if (len + 2 <= value.length) {
      return new TextDecoder("utf-8").decode(value.slice(2, 2 + len));
    }
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(value);
  } catch {
    return undefined;
  }
}

function parseBool(value: Uint8Array): boolean | undefined {
  // Fail CLOSED. These extensions carry security posture (SIP / Secure
  // Boot / third-party kexts) and the leaf is attacker-controlled, so a
  // value that isn't a strict ASN.1 BOOLEAN (0x01 0x01 0x00|0xff) is
  // "unknown" (→ treated as not enabled), NEVER `true`. The old "any
  // non-zero trailing byte == true" fallback let a crafted, non-conforming
  // extension assert SIP/Secure-Boot enabled to this verifier — which is
  // the load-bearing one that grants `hardware-attested`.
  if (value.length === 3 && value[0] === 0x01 && value[1] === 0x01) {
    return value[2] !== 0x00;
  }
  return undefined;
}
