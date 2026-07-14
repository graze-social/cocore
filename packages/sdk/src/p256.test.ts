import { test } from "vitest";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  derToRawSignature,
  verifyP256,
  verifyReceiptSignature,
  verifyAttestationSignature,
} from "./p256.ts";
import { canonicalize } from "./canonical.ts";

test("derToRawSignature: 64 bytes for any P-256 sig", () => {
  // A minimal DER sig: SEQUENCE { INTEGER 0x01, INTEGER 0x02 } padded.
  // Build it programmatically.
  const der = new Uint8Array([
    0x30,
    0x06, // SEQUENCE, len 6
    0x02,
    0x01,
    0x01, // INTEGER r = 1
    0x02,
    0x01,
    0x02, // INTEGER s = 2
  ]);
  const raw = derToRawSignature(der);
  assert.equal(raw.length, 64);
  assert.equal(raw[31], 1);
  assert.equal(raw[63], 2);
});

test("derToRawSignature: strips leading zero padding", () => {
  // INTEGER values whose high bit is set get a 0x00 prefix in DER.
  // r = 0x80 (one byte, but DER renders as 0x00 0x80 = two bytes).
  const der = new Uint8Array([
    0x30,
    0x08,
    0x02,
    0x02,
    0x00,
    0x80, // r = 128 (DER: 00 80)
    0x02,
    0x02,
    0x00,
    0x81, // s = 129
  ]);
  const raw = derToRawSignature(der);
  assert.equal(raw[31], 0x80);
  assert.equal(raw[63], 0x81);
});

test("cross-language fixture: TS verifies a signature produced by Rust", async () => {
  // The Rust integration test in
  // provider/tests/cross_lang_fixture.rs writes this JSON. If you
  // run this test from a fresh clone, run `cargo test --test
  // cross_lang_fixture` in provider/ first.
  const path = findFixture();
  const fixture = JSON.parse(readFileSync(path, "utf-8")) as {
    publicKeyB64: string;
    isHardwareBound: boolean;
    canonicalB64: string;
    receipt: Record<string, unknown> & { enclaveSignature: string };
  };

  // 1. Verify directly: bytes Rust signed, signature Rust produced.
  const message = Uint8Array.from(atob(fixture.canonicalB64), (c) => c.charCodeAt(0));
  const ok = await verifyP256(fixture.publicKeyB64, fixture.receipt.enclaveSignature, message);
  assert.equal(ok, true, "TS must verify Rust-produced ECDSA-P256 DER signature");

  // 2. Verify via the higher-level helper that re-canonicalises the
  //    receipt body. Proves canonical-byte parity end-to-end.
  const ok2 = await verifyReceiptSignature(fixture.receipt, fixture.publicKeyB64);
  assert.equal(ok2, true, "verifyReceiptSignature must re-canonicalise to the same bytes");

  // 3. Sanity: the canonical bytes the TS canonicaliser produces from
  //    the receipt body MUST equal the bytes Rust signed.
  const { enclaveSignature: _drop, ...signed } = fixture.receipt;
  const tsCanon = canonicalize(signed);
  const rustCanon = new TextDecoder().decode(message);
  assert.equal(tsCanon, rustCanon, "TS canonicalisation must equal Rust canonicalisation");
});

test("verifyReceiptSignature: tampered body fails", async () => {
  const path = findFixture();
  const fixture = JSON.parse(readFileSync(path, "utf-8"));
  const tampered = { ...fixture.receipt, model: "mistakes-were-made" };
  const ok = await verifyReceiptSignature(tampered, fixture.publicKeyB64);
  assert.equal(ok, false);
});

test("verifyReceiptSignature: missing signature returns false", async () => {
  const ok = await verifyReceiptSignature(
    { foo: "bar" } as unknown as { enclaveSignature: string },
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  );
  assert.equal(ok, false);
});

test("verifyReceiptSignature: ignores $type lexicon framing (2026-06 stall regression)", async () => {
  // The provider signs the receipt body BEFORE writing it to its PDS, so the
  // signed canonical bytes never include `$type`. The indexed/stored record
  // DOES carry `$type` (atproto adds it), and `$type` sorts to the front of
  // the canonical JSON. The verifier must strip it; otherwise every receipt
  // is rejected the moment it flows through the indexer with `$type`
  // populated — exactly what silently broke settlement in 2026-06.
  //
  // Self-contained (no Rust fixture): mint a P-256 key, sign the body WITHOUT
  // `$type` (as the provider does), then verify the STORED form WITH `$type`.
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)); // 0x04||X||Y
  const pubB64 = btoa(String.fromCharCode(...rawPub.subarray(1))); // X||Y (64 bytes)

  const body = {
    job: { uri: "at://did:plc:req/dev.cocore.compute.job/j1", cid: "bafyjob" },
    requester: "did:plc:req",
    model: "m",
    inputCommitment: "0".repeat(64),
    outputCommitment: "1".repeat(64),
    tokens: { in: 1, out: 2 },
    startedAt: "2026-01-01T00:00:00Z",
    completedAt: "2026-01-01T00:00:01Z",
    price: { amount: 1, currency: "CC" },
    attestation: { uri: "at://did:plc:prov/dev.cocore.compute.attestation/a1", cid: "bafyatt" },
  };
  const msg = new TextEncoder().encode(canonicalize(body));
  const rawSig = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, msg),
  );
  const derB64 = btoa(String.fromCharCode(...rawToDer(rawSig)));

  // The exact signed form (no $type) verifies.
  assert.equal(
    await verifyReceiptSignature({ ...body, enclaveSignature: derB64 }, pubB64),
    true,
    "signed body (no $type) must verify",
  );
  // The STORED form the indexer presents (with $type) must ALSO verify.
  assert.equal(
    await verifyReceiptSignature(
      { $type: "dev.cocore.compute.receipt", ...body, enclaveSignature: derB64 },
      pubB64,
    ),
    true,
    "stored body (with $type) must verify — $type must be stripped",
  );
});

test("verifyAttestationSignature: tolerates legacy signed-vs-stored divergence (2026-06 settlement stall)", async () => {
  // The pre-2026-07 provider signed a canonical attestation body that differed
  // from the record it actually wrote to its PDS in two ways, so every stored
  // attestation failed selfSignature verification — which silently blocked
  // settlement (verifyForChargeStrict checks the attestation selfSig):
  //
  //   1. mdaCertChain — signed as `[]`, but serde's skip_serializing_if dropped
  //      the empty array from the stored record (the self-attested common case).
  //   2. timestamps — signed at seconds precision (RFC3339 SecondsFormat::Secs),
  //      but stored at chrono's default sub-second precision.
  //
  // Those records can't be re-signed (the key is enclave-bound), so the
  // verifier must reconstruct what was signed. This test signs the LEGACY form
  // and verifies the STORED form, exactly as the live records present.
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const pubB64 = btoa(String.fromCharCode(...rawPub.subarray(1)));

  // Fields common to both forms.
  const common = {
    publicKey: pubB64,
    encryptionPubKey: "enc",
    chipName: "Apple M5 Max",
    tier: "best-effort",
    sipEnabled: true,
  };
  // SIGNED form: mdaCertChain present as [], timestamps at seconds precision.
  const signedBody = {
    ...common,
    mdaCertChain: [],
    attestedAt: "2026-06-29T21:21:08Z",
    expiresAt: "2026-06-30T21:21:08Z",
  };
  const msg = new TextEncoder().encode(canonicalize(signedBody));
  const rawSig = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, msg),
  );
  const selfSignature = btoa(String.fromCharCode(...rawToDer(rawSig)));

  // STORED form: mdaCertChain dropped (empty), timestamps at sub-second
  // precision, $type added by atproto. This is what the indexer presents.
  const stored = {
    $type: "dev.cocore.compute.attestation",
    ...common,
    attestedAt: "2026-06-29T21:21:08.384834Z",
    expiresAt: "2026-06-30T21:21:08.384834Z",
    selfSignature,
  };
  assert.equal(
    await verifyAttestationSignature(stored, pubB64),
    true,
    "stored attestation (mdaCertChain dropped, sub-second timestamps) must verify against the legacy signed form",
  );

  // A post-fix attestation that stores exactly what it signs must ALSO verify
  // (the as-stored attempt, no reconstruction needed).
  const postFix = { $type: "dev.cocore.compute.attestation", ...signedBody, selfSignature };
  assert.equal(
    await verifyAttestationSignature(postFix, pubB64),
    true,
    "post-fix attestation (signed bytes == stored bytes) must verify as-stored",
  );

  // Tampering with a signed field must still fail.
  const tampered = { ...stored, tier: "attested-confidential" };
  assert.equal(await verifyAttestationSignature(tampered, pubB64), false);
});

/** Inverse of {@link derToRawSignature}: P-1363 raw r||s (64 bytes, what
 *  WebCrypto's ECDSA sign emits) → DER SEQUENCE{INTEGER r, INTEGER s} (what
 *  verifyP256 expects). Test-only. */
function rawToDer(raw: Uint8Array): Uint8Array {
  const toInt = (b: Uint8Array): number[] => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = Array.from(b.subarray(i));
    if ((v[0]! & 0x80) !== 0) v = [0x00, ...v];
    return [0x02, v.length, ...v];
  };
  const r = toInt(raw.subarray(0, 32));
  const s = toInt(raw.subarray(32, 64));
  const body = [...r, ...s];
  return Uint8Array.from([0x30, body.length, ...body]);
}

function findFixture(): string {
  // packages/sdk/src/ → ../../../target/
  const here = new URL(".", import.meta.url).pathname;
  return join(here, "..", "..", "..", "target", "cross-lang-fixture.json");
}

// --- receipt enclaveSignature as an App Attest assertion (ADR-0003) ---
// When the attestation's sigScheme is 'appattest-assertion', the receipt is
// signed by the same SE identity via an assertion. verifyReceiptSignature must
// dispatch on the sigScheme argument.
test("verifyReceiptSignature: verifies an assertion when sigScheme='appattest-assertion'", async () => {
  const { createHash, generateKeyPairSync, sign: nodeSign } = await import("node:crypto");
  const APP_ID = "4L45P7CP9M.dev.cocore.provider";
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const pubB64 = Buffer.concat([
    Buffer.from(jwk.x, "base64url"),
    Buffer.from(jwk.y, "base64url"),
  ]).toString("base64");
  const sha = (b: Uint8Array): Buffer => createHash("sha256").update(Buffer.from(b)).digest();
  const bstr = (b: Buffer): Buffer =>
    b.length < 24
      ? Buffer.concat([Buffer.from([0x40 | b.length]), b])
      : Buffer.concat([Buffer.from([0x58, b.length]), b]);
  const tstr = (s: string): Buffer =>
    Buffer.concat([Buffer.from([0x60 | Buffer.from(s).length]), Buffer.from(s)]);
  const assertionOver = (msg: Uint8Array): string => {
    const authData = Buffer.concat([
      sha(new TextEncoder().encode(APP_ID)),
      Buffer.from([0, 0, 0, 0, 1]),
    ]);
    const signature = nodeSign("SHA256", Buffer.concat([authData, sha(msg)]), privateKey);
    return Buffer.concat([
      Buffer.from([0xa2]),
      tstr("signature"),
      bstr(signature),
      tstr("authenticatorData"),
      bstr(authData),
    ]).toString("base64");
  };

  const body = {
    job: { uri: "at://did:plc:req/dev.cocore.compute.job/j1", cid: "bafyjob" },
    requester: "did:plc:req",
    model: "m",
    inputCommitment: "0".repeat(64),
    outputCommitment: "1".repeat(64),
    tokens: { in: 1, out: 2 },
    startedAt: "2026-01-01T00:00:00Z",
    completedAt: "2026-01-01T00:00:01Z",
    price: { amount: 1, currency: "CC" },
    attestation: { uri: "at://did:plc:prov/dev.cocore.compute.attestation/a1", cid: "bafyatt" },
  };
  const enclaveSignature = assertionOver(new TextEncoder().encode(canonicalize(body)));
  const receipt = { $type: "dev.cocore.compute.receipt", ...body, enclaveSignature };

  // With the scheme → verifies.
  assert.equal(await verifyReceiptSignature(receipt, pubB64, "appattest-assertion"), true);
  // Without the scheme it's treated as raw p256 → the assertion CBOR is not a
  // valid DER sig, so it fails closed rather than false-accepting.
  assert.equal(await verifyReceiptSignature(receipt, pubB64), false);
  // Tampered body → assertion clientDataHash differs → fails.
  assert.equal(
    await verifyReceiptSignature({ ...receipt, model: "evil" }, pubB64, "appattest-assertion"),
    false,
  );
});
