import { test } from "vitest";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  APPLE_APP_ATTEST_ROOT_CA_PEM,
  AppAttestError,
  verifyAppAttest,
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
