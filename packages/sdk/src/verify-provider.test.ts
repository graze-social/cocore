import { test } from "vitest";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createHash, generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { canonicalize } from "./canonical.ts";
import {
  compareOsVersion,
  freshnessBindsKey,
  type SessionKey,
  sessionKeyMessage,
  verifyProviderForSeal,
} from "./verify-provider.ts";
import type { AttestationRecord } from "./types.ts";

// A P-256 signer that produces DER signatures (node:crypto default) and a raw
// 64-byte X‖Y base64 public key — the exact encoding attestation.publicKey
// uses, so the same key serves as the attestation signing key, the
// selfSignature signer, and the session signer.
function makeSigner(): { pubB64: string; signDerB64: (msg: Uint8Array) => string } {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");
  const pubB64 = Buffer.concat([x, y]).toString("base64");
  const signDerB64 = (msg: Uint8Array): string =>
    nodeSign("SHA256", Buffer.from(msg), privateKey).toString("base64");
  return { pubB64, signDerB64 };
}

const CDHASH = "a".repeat(40);
const METALLIB = "c".repeat(64);
const NONCE = "f".repeat(32);
const ATT_CID = "bafyattestationcid";

// A confidential-eligible attestation EXCEPT it carries no MDA chain (supplied
// separately). publicKey is the caller's signer so selfSignature + session
// signatures verify.
function goodAttestation(pubB64: string): AttestationRecord {
  return {
    publicKey: pubB64,
    encryptionPubKey: "ZW5jcnlwdGlvbktleQ==",
    chipName: "Apple M3 Max",
    hardwareModel: "Mac15,8",
    serialNumberHash: "0".repeat(64),
    osVersion: "macOS 14.6.1",
    binaryHash: "1".repeat(64),
    cdHash: CDHASH,
    teamId: "TEAM123456",
    hardenedRuntime: true,
    libraryValidation: true,
    getTaskAllow: false,
    metallibHash: METALLIB,
    inProcessBackend: true,
    antiDebug: true,
    coreDumpsDisabled: true,
    envScrubbed: true,
    sipEnabled: true,
    secureBootEnabled: true,
    secureEnclaveAvailable: true,
    authenticatedRootEnabled: true,
    selfSignature: "",
    attestedAt: "2026-06-19T00:00:00Z",
    expiresAt: "2026-06-20T00:00:00Z",
  };
}

/** Sign an attestation's selfSignature over its canonical body (matching the
 *  Rust producer + the SDK's verifyAttestationSignature). Sign AFTER any patch
 *  so the signature honestly covers the (possibly insecure) posture — the
 *  attack model is a provider that validly signs a weak attestation. */
function signAtt(att: AttestationRecord, signDerB64: (m: Uint8Array) => string): AttestationRecord {
  const { selfSignature: _omit, ...rest } = att;
  // Drop undefined-valued keys so the canonical body matches the wire, where
  // absent optional fields are skip-serialized (never present as `undefined`).
  const body: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(rest)) if (v !== undefined) body[k] = v;
  const sig = signDerB64(new TextEncoder().encode(canonicalize(body)));
  return { ...body, selfSignature: sig } as AttestationRecord;
}

/** Build + patch + sign an attestation in one go. */
function mkAtt(
  pubB64: string,
  signDerB64: (m: Uint8Array) => string,
  patch: Partial<AttestationRecord> = {},
): AttestationRecord {
  return signAtt({ ...goodAttestation(pubB64), ...patch }, signDerB64);
}

function freshSessionKey(signDerB64: (m: Uint8Array) => string): SessionKey {
  const base = { ephemeralPubKey: "ZXBoZW1lcmFsUHViS2V5", nonce: NONCE, attestationCid: ATT_CID };
  return { ...base, signature: signDerB64(sessionKeyMessage(base)) };
}

const NOW = () => new Date("2026-06-19T12:00:00Z");

function codes(findings: { code: string }[]): string[] {
  return findings.map((f) => f.code);
}

// ---- fail-closed core ------------------------------------------------------

test("a self-attested provider (no MDA chain) is best-effort, not confidential", async () => {
  const { pubB64, signDerB64 } = makeSigner();
  const r = await verifyProviderForSeal(mkAtt(pubB64, signDerB64), undefined, {
    knownGoodCdHashes: [CDHASH],
    nonce: NONCE,
    attestationCid: ATT_CID,
    sessionKey: freshSessionKey(signDerB64),
    now: NOW,
  });
  assert.equal(r.tier, "best-effort");
  assert.equal(r.ok, true); // best-effort acceptable when not demanded
  assert.ok(codes(r.findings).includes("no-mda-chain"));
  assert.ok(r.findings.every((f) => f.severity === "warn"));
  assert.equal(r.sealToKey, undefined);
});

test("requireCodeAttested gates on the advisor's APNs code-identity standing", async () => {
  const { pubB64, signDerB64 } = makeSigner();
  const att = mkAtt(pubB64, signDerB64);
  const base = {
    knownGoodCdHashes: [CDHASH],
    nonce: NONCE,
    attestationCid: ATT_CID,
    sessionKey: freshSessionKey(signDerB64),
    now: NOW,
  };
  // Required but not code-attested → the specific blocker appears.
  const missing = await verifyProviderForSeal(att, undefined, {
    ...base,
    requireCodeAttested: true,
  });
  assert.ok(codes(missing.findings).includes("code-not-attested"));
  // Required and code-attested → that blocker is gone.
  const ok = await verifyProviderForSeal(att, undefined, {
    ...base,
    requireCodeAttested: true,
    codeAttested: true,
  });
  assert.ok(!codes(ok.findings).includes("code-not-attested"));
  // SECURE DEFAULT (0.9.23): code-attestation is REQUIRED by default, so a
  // confidential seal blocks when not code-attested even without opting in.
  const def = await verifyProviderForSeal(att, undefined, base);
  assert.ok(codes(def.findings).includes("code-not-attested"));
  // Explicit opt-out (non-APNs advisor) → no longer blocks.
  const off = await verifyProviderForSeal(att, undefined, {
    ...base,
    requireCodeAttested: false,
  });
  assert.ok(!codes(off.findings).includes("code-not-attested"));
});

test("requireSecureEnclaveKey (ADR-0005) gates on attestation.secureEnclaveAvailable", async () => {
  const { pubB64, signDerB64 } = makeSigner();
  const base = {
    knownGoodCdHashes: [CDHASH],
    nonce: NONCE,
    attestationCid: ATT_CID,
    sessionKey: freshSessionKey(signDerB64),
    now: NOW,
  };
  // Default OFF: an SE-less machine is NOT blocked on the SE code (soft cutover).
  const swAtt = mkAtt(pubB64, signDerB64, { secureEnclaveAvailable: false });
  const def = await verifyProviderForSeal(swAtt, undefined, base);
  assert.ok(!codes(def.findings).includes("se-key-not-available"));
  // Enforced + software key → the specific blocker appears (fail-closed).
  const blocked = await verifyProviderForSeal(swAtt, undefined, {
    ...base,
    requireSecureEnclaveKey: true,
  });
  assert.ok(codes(blocked.findings).includes("se-key-not-available"));
  // Enforced + SE key → no SE blocker.
  const seAtt = mkAtt(pubB64, signDerB64, { secureEnclaveAvailable: true });
  const ok = await verifyProviderForSeal(seAtt, undefined, {
    ...base,
    requireSecureEnclaveKey: true,
  });
  assert.ok(!codes(ok.findings).includes("se-key-not-available"));
});

test("requireConfidential fails closed when the chain is missing", async () => {
  const { pubB64, signDerB64 } = makeSigner();
  const r = await verifyProviderForSeal(mkAtt(pubB64, signDerB64), undefined, {
    requireConfidential: true,
    knownGoodCdHashes: [CDHASH],
    nonce: NONCE,
    attestationCid: ATT_CID,
    sessionKey: freshSessionKey(signDerB64),
    now: NOW,
  });
  assert.equal(r.tier, "best-effort");
  assert.equal(r.ok, false);
  assert.ok(r.findings.some((f) => f.severity === "error" && f.code === "no-mda-chain"));
  assert.equal(r.sealToKey, undefined);
});

// ---- the attestation self-signature is load-bearing ------------------------

test("a tampered attestation (invalid selfSignature) is rejected", async () => {
  const { pubB64, signDerB64 } = makeSigner();
  // Sign a clean attestation, then flip a posture field WITHOUT re-signing —
  // exactly the forge-the-posture attack the selfSignature gate defends.
  const att = mkAtt(pubB64, signDerB64);
  const forged = { ...att, getTaskAllow: true };
  const r = await verifyProviderForSeal(forged, undefined, {
    requireConfidential: true,
    knownGoodCdHashes: [CDHASH],
    nonce: NONCE,
    attestationCid: ATT_CID,
    sessionKey: freshSessionKey(signDerB64),
    now: NOW,
  });
  assert.ok(codes(r.findings).includes("attestation-signature-invalid"));
  assert.equal(r.ok, false);
});

test("an honestly-signed but INSECURE attestation still fails confidential", async () => {
  // The signature is valid (signed after the patch) but reports getTaskAllow.
  const { pubB64, signDerB64 } = makeSigner();
  const att = mkAtt(pubB64, signDerB64, { getTaskAllow: true });
  const r = await verifyProviderForSeal(att, undefined, {
    requireConfidential: true,
    knownGoodCdHashes: [CDHASH],
    now: NOW,
  });
  // selfSignature is fine; the posture gate is what rejects it.
  assert.ok(!codes(r.findings).includes("attestation-signature-invalid"));
  assert.ok(codes(r.findings).includes("get-task-allow"));
  assert.equal(r.ok, false);
});

// ---- each posture gate blocks confidential ---------------------------------

const POSTURE_CASES: Array<[string, Partial<AttestationRecord>, string]> = [
  ["SIP off", { sipEnabled: false }, "sip-off"],
  ["Secure Boot off", { secureBootEnabled: false }, "secure-boot-off"],
  ["no hardened runtime", { hardenedRuntime: false }, "no-hardened-runtime"],
  ["no library validation", { libraryValidation: false }, "no-library-validation"],
  ["get-task-allow true", { getTaskAllow: true }, "get-task-allow"],
  ["get-task-allow absent (unsafe default)", { getTaskAllow: undefined }, "get-task-allow"],
  ["cdHash absent", { cdHash: undefined }, "no-cdhash"],
  ["subprocess backend", { inProcessBackend: false }, "not-in-process"],
  ["in-process absent (unsafe default)", { inProcessBackend: undefined }, "not-in-process"],
  ["anti-debug off", { antiDebug: false }, "no-anti-debug"],
  ["core dumps enabled", { coreDumpsDisabled: false }, "core-dumps-enabled"],
  ["env not scrubbed", { envScrubbed: false }, "env-not-scrubbed"],
];

for (const [name, patch, expectedCode] of POSTURE_CASES) {
  test(`posture gate: ${name} blocks confidential`, async () => {
    const { pubB64, signDerB64 } = makeSigner();
    const att = mkAtt(pubB64, signDerB64, patch);
    const r = await verifyProviderForSeal(att, undefined, {
      requireConfidential: true,
      knownGoodCdHashes: [CDHASH],
      nonce: NONCE,
      attestationCid: ATT_CID,
      sessionKey: freshSessionKey(signDerB64),
      now: NOW,
    });
    assert.equal(r.tier, "best-effort");
    assert.equal(r.ok, false);
    assert.ok(codes(r.findings).includes(expectedCode), `expected finding ${expectedCode}`);
  });
}

test("cdHash not in the known-good set blocks confidential", async () => {
  const { pubB64, signDerB64 } = makeSigner();
  const r = await verifyProviderForSeal(mkAtt(pubB64, signDerB64), undefined, {
    requireConfidential: true,
    knownGoodCdHashes: ["b".repeat(40)],
    nonce: NONCE,
    attestationCid: ATT_CID,
    sessionKey: freshSessionKey(signDerB64),
    now: NOW,
  });
  assert.ok(codes(r.findings).includes("cdhash-unknown"));
});

test("empty known-good set means no build can be trusted", async () => {
  const { pubB64, signDerB64 } = makeSigner();
  const r = await verifyProviderForSeal(mkAtt(pubB64, signDerB64), undefined, {
    requireConfidential: true,
    knownGoodCdHashes: [],
    nonce: NONCE,
    attestationCid: ATT_CID,
    sessionKey: freshSessionKey(signDerB64),
    now: NOW,
  });
  assert.ok(codes(r.findings).includes("no-known-good-set"));
});

test("metallib hash not in the known-good set blocks confidential", async () => {
  const { pubB64, signDerB64 } = makeSigner();
  const r = await verifyProviderForSeal(mkAtt(pubB64, signDerB64), undefined, {
    requireConfidential: true,
    knownGoodCdHashes: [CDHASH],
    knownGoodMetallibHashes: ["d".repeat(64)],
    now: NOW,
  });
  assert.ok(codes(r.findings).includes("metallib-unknown"));
});

test("osVersion below floor blocks confidential", async () => {
  const { pubB64, signDerB64 } = makeSigner();
  const att = mkAtt(pubB64, signDerB64, { osVersion: "macOS 14.4.0" });
  const r = await verifyProviderForSeal(att, undefined, {
    requireConfidential: true,
    knownGoodCdHashes: [CDHASH],
    osFloor: "14.6.0",
    now: NOW,
  });
  assert.ok(codes(r.findings).includes("os-below-floor"));
});

test("expired attestation blocks confidential", async () => {
  const { pubB64, signDerB64 } = makeSigner();
  const r = await verifyProviderForSeal(mkAtt(pubB64, signDerB64), undefined, {
    requireConfidential: true,
    knownGoodCdHashes: [CDHASH],
    now: () => new Date("2026-06-21T00:00:00Z"), // past expiresAt
  });
  assert.ok(codes(r.findings).includes("attestation-expired"));
});

// ---- session-key handshake (optional, advisor-trustless freshness) ---------

test("a valid session signature produces no session findings", async () => {
  const { pubB64, signDerB64 } = makeSigner();
  const r = await verifyProviderForSeal(mkAtt(pubB64, signDerB64), undefined, {
    knownGoodCdHashes: [CDHASH],
    nonce: NONCE,
    attestationCid: ATT_CID,
    sessionKey: freshSessionKey(signDerB64),
    now: NOW,
  });
  assert.ok(!codes(r.findings).some((c) => c.startsWith("session-")));
});

test("tampered session signature is rejected", async () => {
  const { pubB64, signDerB64 } = makeSigner();
  const sk = freshSessionKey(signDerB64);
  const forged: SessionKey = { ...sk, ephemeralPubKey: "dGFtcGVyZWRLZXk=" };
  const r = await verifyProviderForSeal(mkAtt(pubB64, signDerB64), undefined, {
    requireConfidential: true,
    knownGoodCdHashes: [CDHASH],
    nonce: NONCE,
    attestationCid: ATT_CID,
    sessionKey: forged,
    now: NOW,
  });
  assert.ok(codes(r.findings).includes("session-signature-invalid"));
  assert.equal(r.ok, false);
});

test("stale nonce (replayed session key) is rejected", async () => {
  const { pubB64, signDerB64 } = makeSigner();
  const r = await verifyProviderForSeal(mkAtt(pubB64, signDerB64), undefined, {
    requireConfidential: true,
    knownGoodCdHashes: [CDHASH],
    nonce: "e".repeat(32),
    attestationCid: ATT_CID,
    sessionKey: freshSessionKey(signDerB64),
    now: NOW,
  });
  assert.ok(codes(r.findings).includes("session-nonce-mismatch"));
});

test("session key bound to a different attestation is rejected", async () => {
  const { pubB64, signDerB64 } = makeSigner();
  const r = await verifyProviderForSeal(mkAtt(pubB64, signDerB64), undefined, {
    requireConfidential: true,
    knownGoodCdHashes: [CDHASH],
    nonce: NONCE,
    attestationCid: "bafiSOMEOTHERcid",
    sessionKey: freshSessionKey(signDerB64),
    now: NOW,
  });
  assert.ok(codes(r.findings).includes("session-attestation-mismatch"));
});

test("no session key is fine by default (seal to bound encryptionPubKey)", async () => {
  const { pubB64, signDerB64 } = makeSigner();
  const att = mkAtt(pubB64, signDerB64);
  const r = await verifyProviderForSeal(att, undefined, {
    knownGoodCdHashes: [CDHASH],
    now: NOW,
  });
  // No MDA chain so still best-effort, but the absence of a session key is NOT
  // itself a blocker in the default (advisor-vouched) mode.
  assert.ok(!codes(r.findings).includes("no-session-key"));
});

test("requireSessionKey demands a session key", async () => {
  const { pubB64, signDerB64 } = makeSigner();
  const r = await verifyProviderForSeal(mkAtt(pubB64, signDerB64), undefined, {
    requireConfidential: true,
    requireSessionKey: true,
    knownGoodCdHashes: [CDHASH],
    now: NOW,
  });
  assert.ok(codes(r.findings).includes("no-session-key"));
});

// ---- osVersion comparator --------------------------------------------------

test("compareOsVersion handles prefixes and component counts", () => {
  assert.equal(compareOsVersion("macOS 14.6.1", "14.6.1"), 0);
  assert.ok(compareOsVersion("14.6.1", "14.6.0") > 0);
  assert.ok(compareOsVersion("14.5.9", "14.6.0") < 0);
  assert.ok(compareOsVersion("15.0", "14.9.9") > 0);
  assert.ok(compareOsVersion("14.6", "14.6.0") === 0);
  assert.ok(compareOsVersion("unknown", "14.0.0") < 0);
});

// ---- cross-language confidential PASS (Rust producer → TS verifier) ---------
//
// The definitive parity test: a fully-signed confidential attestation produced
// by the Rust fixture generator (one P-256 key as MDA leaf + attestation
// publicKey + selfSignature signer + session signer) must verify, end-to-end,
// as attested-confidential through every gate. Skipped if the fixture hasn't
// been generated (the Rust `cross_lang_fixture` test writes it).

const CONF_FIXTURE = join(
  new URL(".", import.meta.url).pathname,
  "..",
  "..",
  "..",
  "target",
  "confidential-attestation-fixture.json",
);

const CONF_APPATTEST_FIXTURE = join(
  new URL(".", import.meta.url).pathname,
  "..",
  "..",
  "..",
  "target",
  "confidential-appattest-fixture.json",
);

// The MDM-free parity test: a confidential attestation whose hardware
// attestation is an App Attest object (no MDA chain) must ALSO verify as
// attested-confidential, with the App Attest object bound to the signing key.
test.skipIf(!existsSync(CONF_APPATTEST_FIXTURE))(
  "cross-language: a Rust App-Attest confidential attestation verifies as attested-confidential",
  async () => {
    const f = JSON.parse(readFileSync(CONF_APPATTEST_FIXTURE, "utf-8"));
    const appAttestRootDer = Uint8Array.from(Buffer.from(f.appAttestRootDerB64, "base64"));
    const att = f.attestation as AttestationRecord;

    // No MDA chain at all — hardware attestation comes solely from att.appAttest.
    const noKey = await verifyProviderForSeal(att, undefined, {
      requireConfidential: true,
      requireCodeAttested: false,
      // This fixture's App Attest object binds via clientData to a SEPARATE
      // signing key (keyId != sha256(publicKey)) — the pointer form, which
      // ADR-0003's residency gate now rejects for confidential. The test
      // exercises object verification, not the residency identity, so opt out.
      requireHardwareBoundKey: false,
      knownGoodCdHashes: [f.knownGoodCdHash],
      knownGoodMetallibHashes: [f.knownGoodMetallibHash],
      knownGoodEngineLibHashes: [f.knownGoodEngineLibHash],
      osFloor: f.osFloor,
      appAttestTrustAnchorDer: appAttestRootDer,
      now: () => new Date(),
    });
    assert.equal(
      noKey.tier,
      "attested-confidential",
      `unexpected findings: ${JSON.stringify(noKey.findings)}`,
    );
    assert.equal(noKey.ok, true);
    assert.equal(noKey.sealToKey, att.encryptionPubKey);

    // App Attest is load-bearing: verify the SAME (untampered) attestation but
    // against the real Apple App Attest root, which did not sign the synthetic
    // object → it fails to verify, doesn't bind, and with no MDA fallback the
    // result drops to best-effort. selfSignature still passes (publicKey is
    // unchanged), so the only blocker is the missing hardware attestation.
    const downgraded = await verifyProviderForSeal(att, undefined, {
      requireConfidential: false, // observe the downgrade rather than throw
      requireCodeAttested: false,
      knownGoodCdHashes: [f.knownGoodCdHash],
      // omit appAttestTrustAnchorDer → uses the embedded real Apple root
      now: () => new Date(),
    });
    assert.equal(downgraded.tier, "best-effort");
    assert.ok(codes(downgraded.findings).includes("no-mda-chain"));
    assert.ok(!codes(downgraded.findings).includes("attestation-signature-invalid"));
  },
);

test.skipIf(!existsSync(CONF_FIXTURE))(
  "cross-language: a Rust confidential attestation verifies as attested-confidential",
  async () => {
    const f = JSON.parse(readFileSync(CONF_FIXTURE, "utf-8"));
    const rootDer = Uint8Array.from(Buffer.from(f.rootDerB64, "base64"));
    const att = f.attestation as AttestationRecord;
    const chain: string[] = att.mdaCertChain!;

    // (a) advisor-trustless mode: full chain + session key → seal to the
    // enclave-signed ephemeral key.
    const withKey = await verifyProviderForSeal(att, chain, {
      requireConfidential: true,
      requireSessionKey: true,
      // This fixture exercises the OFFLINE crypto (Rust-signed attestation +
      // MDA chain + session key); the live APNs code-identity leg is asserted
      // separately by the advisor, so opt out of it here.
      requireCodeAttested: false,
      // This fixture predates the App Attest key-residency gate (ADR-0003) and
      // binds via the MDA freshness path, which now caps at hardware-attested.
      // Its purpose is cross-language signing parity, not residency policy, so
      // opt out of the residency gate to keep exercising the crypto it tests.
      requireHardwareBoundKey: false,
      knownGoodCdHashes: [f.knownGoodCdHash],
      knownGoodMetallibHashes: [f.knownGoodMetallibHash],
      knownGoodEngineLibHashes: [f.knownGoodEngineLibHash],
      osFloor: f.osFloor,
      trustAnchorDer: rootDer,
      attestationCid: f.attestationCid,
      nonce: f.nonce,
      sessionKey: f.sessionKey,
      now: () => new Date(),
    });
    assert.equal(
      withKey.tier,
      "attested-confidential",
      `unexpected findings: ${JSON.stringify(withKey.findings)}`,
    );
    assert.equal(withKey.ok, true);
    assert.equal(withKey.sealToKey, f.sessionKey.ephemeralPubKey);

    // (b) advisor-vouched mode: no session key → seal to the
    // selfSignature-authenticated long-lived encryptionPubKey.
    const noKey = await verifyProviderForSeal(att, chain, {
      requireConfidential: true,
      requireCodeAttested: false,
      // MDA-freshness fixture — opt out of the ADR-0003 residency gate (see above).
      requireHardwareBoundKey: false,
      knownGoodCdHashes: [f.knownGoodCdHash],
      knownGoodMetallibHashes: [f.knownGoodMetallibHash],
      osFloor: f.osFloor,
      trustAnchorDer: rootDer,
      now: () => new Date(),
    });
    assert.equal(
      noKey.tier,
      "attested-confidential",
      `unexpected findings: ${JSON.stringify(noKey.findings)}`,
    );
    assert.equal(noKey.sealToKey, att.encryptionPubKey);

    // (c) tamper the signed posture → selfSignature gate catches it.
    const tampered = { ...att, getTaskAllow: true };
    const bad = await verifyProviderForSeal(tampered, chain, {
      requireConfidential: true,
      knownGoodCdHashes: [f.knownGoodCdHash],
      trustAnchorDer: rootDer,
      now: () => new Date(),
    });
    assert.ok(codes(bad.findings).includes("attestation-signature-invalid"));
    assert.equal(bad.ok, false);
  },
);

// --- Option-B freshness-code binding (cross-language parity with mda.rs + py) ---
test("freshnessBindsKey: binds iff freshness == sha256(publicKey), wrapper-tolerant", async () => {
  const pubRaw = Buffer.alloc(64, 7); // raw 64-byte P-256 X‖Y
  const pubB64 = pubRaw.toString("base64");
  const good = createHash("sha256").update(pubRaw).digest(); // 32 bytes

  // Raw 32-byte freshness == sha256(pubkey) → binds.
  assert.equal(await freshnessBindsKey(new Uint8Array(good), pubB64), true);

  // Same value inside its DER OCTET STRING wrapper (04 20 ‖ 32) → binds.
  const wrapped = new Uint8Array([0x04, 0x20, ...good]);
  assert.equal(await freshnessBindsKey(wrapped, pubB64), true);

  // Freshness for a DIFFERENT key → does not bind.
  const other = createHash("sha256").update(Buffer.alloc(64, 9)).digest();
  assert.equal(await freshnessBindsKey(new Uint8Array(other), pubB64), false);

  // Missing/empty freshness → false, never throws.
  assert.equal(await freshnessBindsKey(undefined, pubB64), false);
  assert.equal(await freshnessBindsKey(new Uint8Array(0), pubB64), false);
});

// --- sigScheme dispatch: selfSignature as an App Attest assertion (ADR-0003) ---
// A provider whose signing identity IS the SE App Attest key signs the record
// with an assertion, not raw ECDSA. Gate #0 must verify it as an assertion when
// sigScheme says so — and still catch a tamper (the assertion commits to the
// canonical body via clientDataHash).
test("sigScheme 'appattest-assertion': selfSignature verifies as an assertion, tamper still caught", async () => {
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
  const tstr = (s: string): Buffer => {
    const b = Buffer.from(s, "utf8");
    return Buffer.concat([Buffer.from([0x60 | b.length]), b]);
  };
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

  const base: Record<string, unknown> = {
    ...goodAttestation(pubB64),
    sigScheme: "appattest-assertion",
  };
  delete base.selfSignature;
  const message = new TextEncoder().encode(canonicalize(base));
  const att = { ...base, selfSignature: assertionOver(message) } as unknown as AttestationRecord;

  const ok = await verifyProviderForSeal(att, undefined, { requireConfidential: false, now: NOW });
  assert.ok(
    !codes(ok.findings).includes("attestation-signature-invalid"),
    `assertion selfSignature should verify: ${JSON.stringify(ok.findings)}`,
  );

  // Tamper a signed posture field after signing → clientDataHash differs → fail.
  const tampered = { ...att, getTaskAllow: true } as AttestationRecord;
  const bad = await verifyProviderForSeal(tampered, undefined, {
    requireConfidential: false,
    now: NOW,
  });
  assert.ok(codes(bad.findings).includes("attestation-signature-invalid"));
});
