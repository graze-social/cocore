import { test } from "vitest";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import nacl from "tweetnacl";
import {
  ConfidentialUnavailableError,
  openFromProvider,
  sealConfidential,
  sealToProvider,
} from "./seal.ts";
import type { AttestationRecord } from "./types.ts";

test("seal/open round-trips (matches the crypto_box wire format)", () => {
  const sender = nacl.box.keyPair();
  const recipient = nacl.box.keyPair();
  const msg = new TextEncoder().encode("a very secret prompt");
  const framed = sealToProvider(msg, recipient.publicKey, sender.secretKey);
  const opened = openFromProvider(framed, sender.publicKey, recipient.secretKey);
  assert.deepEqual(opened, msg);
});

test("open fails (null) on a tampered ciphertext", () => {
  const sender = nacl.box.keyPair();
  const recipient = nacl.box.keyPair();
  const framed = sealToProvider(
    new TextEncoder().encode("hi"),
    recipient.publicKey,
    sender.secretKey,
  );
  framed[framed.length - 1]! ^= 0xff;
  assert.equal(openFromProvider(framed, sender.publicKey, recipient.secretKey), null);
});

test("sealConfidential FAILS CLOSED on a non-confidential provider", async () => {
  // A bare attestation (no chain, no posture) can't earn confidential.
  const att = {
    publicKey: "x",
    encryptionPubKey: "y",
    selfSignature: "",
  } as unknown as AttestationRecord;
  await assert.rejects(
    () =>
      sealConfidential(new TextEncoder().encode("secret"), att, undefined, {
        knownGoodCdHashes: [],
      }),
    (e: unknown) => e instanceof ConfidentialUnavailableError,
  );
});

const CONF_FIXTURE = join(
  new URL(".", import.meta.url).pathname,
  "..",
  "..",
  "..",
  "target",
  "confidential-attestation-fixture.json",
);

test.skipIf(!existsSync(CONF_FIXTURE))(
  "sealConfidential seals to the attested key on a verified confidential provider",
  async () => {
    const f = JSON.parse(readFileSync(CONF_FIXTURE, "utf-8"));
    const att = f.attestation as AttestationRecord;
    const sealed = await sealConfidential(
      new TextEncoder().encode("private prompt"),
      att,
      att.mdaCertChain,
      {
        knownGoodCdHashes: [f.knownGoodCdHash],
        knownGoodMetallibHashes: [f.knownGoodMetallibHash],
        knownGoodEngineLibHashes: [f.knownGoodEngineLibHash],
        osFloor: f.osFloor,
        trustAnchorDer: Uint8Array.from(Buffer.from(f.rootDerB64, "base64")),
        // Offline fixture (no live advisor): opt out of the APNs code-identity
        // leg, which is asserted separately (see the 0.9.23 secure default).
        requireCodeAttested: false,
        // MDA-freshness fixture predates the App Attest residency gate (ADR-0003),
        // which now caps MDA-only at hardware-attested. This test exercises the
        // seal mechanics, not residency policy, so opt out of the residency gate.
        requireHardwareBoundKey: false,
        now: () => new Date(),
      },
    );
    assert.equal(sealed.tier, "attested-confidential");
    // No session key supplied → sealed to the selfSignature-authenticated key.
    assert.equal(sealed.sealedToKey, att.encryptionPubKey);
    assert.ok(sealed.ciphertext.length > 24);
    assert.ok(sealed.senderPublicKey.length > 0);
  },
);
