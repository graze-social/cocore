import { test } from "vitest";
import assert from "node:assert/strict";
import type { webcrypto } from "node:crypto";
import {
  deriveKey,
  ecdhRawX,
  eciesOpenReply,
  eciesSeal,
  openWithKey,
  sealWithIv,
} from "./ecies.ts";

// The cross-language golden vector — IDENTICAL fixed inputs to the Rust
// `crypto::ecies_golden_vector` test and the Python `test_ecies.py`. All three
// implementations must derive the same Z, AES key, and sealed blob.
//   K (recipient) priv = 0x01..=0x20, E (sender ephemeral) priv = 0x21..=0x40,
//   iv = 0x000102..0b, plaintext = "cocore-ecies-golden".
const K_PUB =
  "515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354";
const E_PRIV = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40";
const E_PUB =
  "1f140146bfb1b251f84f4ddbe0d4cdcfd77afd984a9520e35794021f8312bb9eec995a08b1fa7704df3dcc0b50a9665263fb7711f95f9f8a449c5096e47c892b";
const GOLDEN_Z = "4fe243908f378aa1c2a69538822e6ed908c3225d8692575507c649901245150a";
const GOLDEN_BLOB =
  "000102030405060708090a0b18d935a95421e46242ea5aac5e58adf5ca4a6ec3cf3fdfdec85ba2f014b13c83cf0958";
const IV = "000102030405060708090a0b";
const PLAINTEXT = "cocore-ecies-golden";

function hex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function b64url(b: Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}

/** Import the fixed sender ephemeral E as an ECDH private key via JWK
 *  (d + the public x,y), so we can reproduce the exact golden Z. */
async function importFixedEcdhPriv(privHex: string, pubHex: string): Promise<webcrypto.CryptoKey> {
  const pub = hex(pubHex);
  const jwk: webcrypto.JsonWebKey = {
    kty: "EC",
    crv: "P-256",
    d: b64url(hex(privHex)),
    x: b64url(pub.subarray(0, 32)),
    y: b64url(pub.subarray(32, 64)),
    ext: true,
  };
  return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
}

test("ecies ECDH derives the golden Z (cross-language with Rust/Python/SE)", async () => {
  const ePriv = await importFixedEcdhPriv(E_PRIV, E_PUB);
  const z = await ecdhRawX(ePriv, hex(K_PUB));
  assert.equal(Buffer.from(z).toString("hex"), GOLDEN_Z, "shared secret Z drifted");
});

test("ecies HKDF+AES-GCM reproduces the golden blob and opens it", async () => {
  const key = await deriveKey(hex(GOLDEN_Z));
  const blob = await sealWithIv(key, hex(IV), new TextEncoder().encode(PLAINTEXT));
  assert.equal(Buffer.from(blob).toString("hex"), GOLDEN_BLOB, "sealed blob drifted");

  const opened = await openWithKey(key, hex(GOLDEN_BLOB));
  assert.ok(opened, "golden blob failed to open");
  assert.equal(new TextDecoder().decode(opened!), PLAINTEXT);
});

test("ecies seal → the same Z opens it (round-trip)", async () => {
  // Seal to K_PUB with a fresh ephemeral, then open using the ephemeral's
  // private + K_PUB (the reply-direction symmetry the provider relies on).
  const { blob, ephemeralPrivate } = await eciesSeal(hex(K_PUB), new TextEncoder().encode("hi"));
  const opened = await eciesOpenReply(ephemeralPrivate, hex(K_PUB), blob);
  assert.ok(opened);
  assert.equal(new TextDecoder().decode(opened!), "hi");
});

test("ecies open rejects a tampered blob", async () => {
  const key = await deriveKey(hex(GOLDEN_Z));
  const bad = hex(GOLDEN_BLOB);
  const last = bad.length - 1;
  bad[last] = (bad[last] ?? 0) ^ 0xff; // flip a tag byte
  assert.equal(await openWithKey(key, bad), null);
});
