import { test } from "vitest";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { createHash, generateKeyPairSync, sign as nodeSign } from "node:crypto";
import {
  APPLE_APP_ATTEST_ROOT_CA_PEM,
  AppAttestError,
  attestedKeyMatchesSigningKey,
  verifyAppAttest,
  verifyAppAttestAssertion,
  verifyAppAttestB64,
} from "./appattest.ts";

interface Fixture {
  objectB64: string;
  keyIdB64: string;
  publicKeyB64: string;
  appId: string;
  rootDerB64: string;
  appleRootPem: string;
}

function loadFixture(): Fixture {
  const here = new URL(".", import.meta.url).pathname;
  const path = join(here, "..", "..", "..", "target", "appattest-cross-lang-fixture.json");
  return JSON.parse(readFileSync(path, "utf-8"));
}

function b64(s: string): Uint8Array {
  return Uint8Array.from(Buffer.from(s, "base64"));
}

test("cross-language App Attest fixture: TS verifies an object produced by Rust", () => {
  const f = loadFixture();
  const res = verifyAppAttest(b64(f.objectB64), b64(f.keyIdB64), b64(f.publicKeyB64), f.appId, {
    trustAnchorDer: b64(f.rootDerB64),
  });
  assert.equal(res.valid, true);
  assert.equal(res.bindsSigningKey, true);
  // keyId is sha256(attested pubkey) → 32 bytes; equals the fixture's keyId.
  assert.equal(Buffer.from(res.keyId, "base64").length, 32);
  assert.equal(res.keyId, f.keyIdB64);
});

test("App Attest bound to a different signing key is rejected (nonce mismatch)", () => {
  const f = loadFixture();
  const otherKey = Buffer.alloc(64, 9).toString("base64");
  assert.throws(
    () =>
      verifyAppAttest(b64(f.objectB64), b64(f.keyIdB64), b64(otherKey), f.appId, {
        trustAnchorDer: b64(f.rootDerB64),
      }),
    (e: unknown) => e instanceof AppAttestError && e.code === "nonce-mismatch",
  );
});

test("synthetic App Attest object rejected against the real Apple App Attest root", () => {
  const f = loadFixture();
  assert.throws(
    () =>
      verifyAppAttest(b64(f.objectB64), b64(f.keyIdB64), b64(f.publicKeyB64), f.appId, {
        // pull the Apple PEM from the fixture (the exact Rust-embedded bytes)
        trustAnchorDer: pemToDer(f.appleRootPem),
      }),
    (e: unknown) => e instanceof AppAttestError && e.code === "bad-signature",
  );
});

test("wrong appId is rejected (rpIdHash mismatch)", () => {
  const f = loadFixture();
  assert.throws(
    () =>
      verifyAppAttest(
        b64(f.objectB64),
        b64(f.keyIdB64),
        b64(f.publicKeyB64),
        "4L45P7CP9M.com.evil.fork",
        { trustAnchorDer: b64(f.rootDerB64) },
      ),
    (e: unknown) => e instanceof AppAttestError && e.code === "shape",
  );
});

test("verifyAppAttestB64 returns true for the bound fixture, false for a bad object", () => {
  const f = loadFixture();
  assert.equal(
    verifyAppAttestB64(f.objectB64, f.keyIdB64, f.publicKeyB64, f.appId, {
      trustAnchorDer: b64(f.rootDerB64),
    }),
    true,
  );
  // Garbage object → false, never throws.
  assert.equal(
    verifyAppAttestB64(
      Buffer.from("not-cbor").toString("base64"),
      f.keyIdB64,
      f.publicKeyB64,
      f.appId,
      { trustAnchorDer: b64(f.rootDerB64) },
    ),
    false,
  );
});

test("embedded Apple App Attest root PEM is byte-identical to the Rust embed", () => {
  const f = loadFixture();
  assert.equal(APPLE_APP_ATTEST_ROOT_CA_PEM, f.appleRootPem);
});

function pemToDer(pem: string): Uint8Array {
  const stripped = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  return Uint8Array.from(Buffer.from(stripped, "base64"));
}

// ---- App Attest ASSERTION verification (ADR-0003) --------------------
// Self-contained: synthesize an assertion the way DCAppAttestService would (a
// P-256 SE key signs `authenticatorData ‖ sha256(clientData)`), no device or
// Rust fixture needed. The "SE key" here is a plain P-256 key standing in for
// the non-exportable one; the crypto path the verifier checks is identical.

const APP_ID = "4L45P7CP9M.dev.cocore.provider";

function sha256(b: Uint8Array): Buffer {
  return createHash("sha256").update(Buffer.from(b)).digest();
}

/** Minimal CBOR encode of `{ signature, authenticatorData }` (2-entry map,
 *  short text keys, byte-string values ≤ 65535). */
function encodeAssertion(signature: Buffer, authData: Buffer): Buffer {
  const bstr = (b: Buffer): Buffer =>
    b.length < 24
      ? Buffer.concat([Buffer.from([0x40 | b.length]), b])
      : b.length < 256
        ? Buffer.concat([Buffer.from([0x58, b.length]), b])
        : Buffer.concat([Buffer.from([0x59, b.length >> 8, b.length & 0xff]), b]);
  const tstr = (s: string): Buffer => {
    const b = Buffer.from(s, "utf8");
    return Buffer.concat([Buffer.from([0x60 | b.length]), b]); // len < 24
  };
  return Buffer.concat([
    Buffer.from([0xa2]),
    tstr("signature"),
    bstr(signature),
    tstr("authenticatorData"),
    bstr(authData),
  ]);
}

function makeIdentity(): { pubB64: string; privateKey: import("node:crypto").KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const pubB64 = Buffer.concat([
    Buffer.from(jwk.x, "base64url"),
    Buffer.from(jwk.y, "base64url"),
  ]).toString("base64");
  return { pubB64, privateKey };
}

function signAssertion(
  privateKey: import("node:crypto").KeyObject,
  message: Uint8Array,
  appId = APP_ID,
): string {
  const authData = Buffer.concat([
    sha256(new TextEncoder().encode(appId)),
    Buffer.from([0x00, 0, 0, 0, 1]),
  ]);
  const signed = Buffer.concat([authData, sha256(message)]);
  const signature = nodeSign("SHA256", signed, privateKey);
  return encodeAssertion(signature, authData).toString("base64");
}

test("verifyAppAttestAssertion accepts a valid assertion over the message", async () => {
  const { pubB64, privateKey } = makeIdentity();
  const message = new TextEncoder().encode("canonical record bytes");
  const assertion = signAssertion(privateKey, message);
  assert.equal(await verifyAppAttestAssertion(pubB64, assertion, message, APP_ID), true);
});

test("verifyAppAttestAssertion rejects a tampered message, wrong key, and wrong appId", async () => {
  const { pubB64, privateKey } = makeIdentity();
  const message = new TextEncoder().encode("canonical record bytes");
  const assertion = signAssertion(privateKey, message);

  // Tampered message → clientDataHash differs → signature fails.
  assert.equal(
    await verifyAppAttestAssertion(pubB64, assertion, new TextEncoder().encode("tampered"), APP_ID),
    false,
  );
  // Wrong verifying key.
  const other = makeIdentity();
  assert.equal(await verifyAppAttestAssertion(other.pubB64, assertion, message, APP_ID), false);
  // Wrong appId → rpIdHash mismatch.
  assert.equal(
    await verifyAppAttestAssertion(pubB64, assertion, message, "9Z9Z9Z9Z9Z.dev.cocore.provider"),
    false,
  );
  // An assertion whose authData was signed for a DIFFERENT appId is rejected too.
  const crossApp = signAssertion(privateKey, message, "9Z9Z9Z9Z9Z.dev.cocore.provider");
  assert.equal(await verifyAppAttestAssertion(pubB64, crossApp, message, APP_ID), false);
});

test("attestedKeyMatchesSigningKey: true iff attested == 0x04 || signingKey", () => {
  const { pubB64 } = makeIdentity();
  const raw = Buffer.from(pubB64, "base64"); // 64-byte X||Y
  const uncompressed = Buffer.concat([Buffer.from([0x04]), raw]).toString("base64");
  assert.equal(attestedKeyMatchesSigningKey(uncompressed, pubB64), true);
  // A different key doesn't match.
  const other = makeIdentity();
  const otherUncompressed = Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(other.pubB64, "base64"),
  ]).toString("base64");
  assert.equal(attestedKeyMatchesSigningKey(otherUncompressed, pubB64), false);
  // Missing / wrong 0x04 prefix doesn't match.
  assert.equal(attestedKeyMatchesSigningKey(pubB64, pubB64), false);
});
