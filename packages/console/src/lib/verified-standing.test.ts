// Pure tests for the trust-floor logic that gates the verified path. The
// network/crypto half (fetch attestation + run the SDK verifier) is exercised
// by the SDK's own verifier tests; here we pin the floor semantics: a
// hardware-attested floor accepts EITHER verified tier, confidential is strict.

import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { describe, expect, it } from "vitest";

import { canonicalize } from "@cocore/sdk/canonical";
import type { AttestationRecord } from "@cocore/sdk/types";
import { verifyProviderForSeal } from "@cocore/sdk/verify-provider";

import { HARDWARE_BLOCKER_CODES, meetsFloor, parseTrustFloor } from "./verified-standing.server.ts";

describe("parseTrustFloor", () => {
  it("maps the accepted aliases", () => {
    expect(parseTrustFloor("hardware-attested")).toBe("hardware-attested");
    expect(parseTrustFloor("hardware")).toBe("hardware-attested");
    expect(parseTrustFloor("confidential")).toBe("attested-confidential");
    expect(parseTrustFloor("attested-confidential")).toBe("attested-confidential");
    expect(parseTrustFloor(" Confidential ")).toBe("attested-confidential");
  });

  it("rejects unknown / non-string values (caller 400s instead of downgrading)", () => {
    expect(parseTrustFloor("best-effort")).toBeNull();
    expect(parseTrustFloor("")).toBeNull();
    expect(parseTrustFloor(undefined)).toBeNull();
    expect(parseTrustFloor(42)).toBeNull();
  });
});

describe("meetsFloor", () => {
  it("hardware-attested floor accepts either verified tier, not best-effort", () => {
    expect(meetsFloor("hardware-attested", "hardware-attested")).toBe(true);
    expect(meetsFloor("attested-confidential", "hardware-attested")).toBe(true);
    expect(meetsFloor("best-effort", "hardware-attested")).toBe(false);
  });

  it("confidential floor is strict — only attested-confidential passes", () => {
    expect(meetsFloor("attested-confidential", "attested-confidential")).toBe(true);
    expect(meetsFloor("hardware-attested", "attested-confidential")).toBe(false);
    expect(meetsFloor("best-effort", "attested-confidential")).toBe(false);
  });
});

// Regression: HARDWARE_BLOCKER_CODES is matched against the SDK verifier's
// finding codes by NAME. If the two drift (as they did when this set listed
// "no-hardware-attestation" but the SDK emits "no-mda-chain"), a self-attested
// record with no MDA chain and no App Attest — e.g. every Linux provider,
// which has no Apple attestation framework to call — passes through
// unblocked and offlineHardwareTier() wrongly reports "hardware-attested".
describe("HARDWARE_BLOCKER_CODES tracks the SDK's actual finding codes", () => {
  it("flags a self-attested record with no MDA chain and no App Attest", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
    const pubB64 = Buffer.concat([
      Buffer.from(jwk.x, "base64url"),
      Buffer.from(jwk.y, "base64url"),
    ]).toString("base64");
    const sign = (msg: Uint8Array): string =>
      nodeSign("SHA256", Buffer.from(msg), privateKey).toString("base64");

    const unsigned: Omit<AttestationRecord, "selfSignature"> = {
      publicKey: pubB64,
      encryptionPubKey: "ZW5jcnlwdGlvbktleQ==",
      chipName: "generic-linux",
      hardwareModel: "linux",
      serialNumberHash: "0".repeat(64),
      osVersion: "Linux 6.12",
      binaryHash: "1".repeat(64),
      cdHash: "a".repeat(40),
      teamId: "TEAM123456",
      hardenedRuntime: false,
      libraryValidation: false,
      getTaskAllow: true,
      inProcessBackend: true,
      antiDebug: false,
      coreDumpsDisabled: false,
      envScrubbed: false,
      sipEnabled: false,
      secureBootEnabled: false,
      secureEnclaveAvailable: false,
      authenticatedRootEnabled: false,
      attestedAt: "2026-06-19T00:00:00Z",
      expiresAt: "2026-06-20T00:00:00Z",
    };
    const attestation: AttestationRecord = {
      ...unsigned,
      selfSignature: sign(new TextEncoder().encode(canonicalize(unsigned))),
    };

    const result = await verifyProviderForSeal(attestation, undefined, {
      now: () => new Date("2026-06-19T12:00:00Z"),
    });

    const codes = result.findings.map((f) => f.code);
    expect(codes).toContain("no-mda-chain");
    expect(codes.some((c) => HARDWARE_BLOCKER_CODES.has(c))).toBe(true);
  });
});

// Key residency (ADR-0003): confidential requires a Secure-Enclave-resident
// signing key (a bound App Attest object). A record without one is flagged with
// `key-not-hardware-bound`, but that code must DOWNGRADE confidential to
// hardware-attested — never drop the machine to best-effort — so it must NOT be
// a hardware blocker.
describe("key-not-hardware-bound residency gate", () => {
  function signedRecord(): AttestationRecord {
    const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
    const pubB64 = Buffer.concat([
      Buffer.from(jwk.x, "base64url"),
      Buffer.from(jwk.y, "base64url"),
    ]).toString("base64");
    const unsigned: Omit<AttestationRecord, "selfSignature"> = {
      publicKey: pubB64,
      encryptionPubKey: "ZW5jcnlwdGlvbktleQ==",
      chipName: "generic-linux",
      hardwareModel: "linux",
      serialNumberHash: "0".repeat(64),
      osVersion: "Linux 6.12",
      binaryHash: "1".repeat(64),
      cdHash: "a".repeat(40),
      teamId: "TEAM123456",
      hardenedRuntime: true,
      libraryValidation: true,
      getTaskAllow: false,
      inProcessBackend: true,
      antiDebug: true,
      coreDumpsDisabled: true,
      envScrubbed: true,
      sipEnabled: true,
      secureBootEnabled: true,
      secureEnclaveAvailable: false,
      authenticatedRootEnabled: false,
      attestedAt: "2026-06-19T00:00:00Z",
      expiresAt: "2026-06-20T00:00:00Z",
    };
    return {
      ...unsigned,
      selfSignature: nodeSign(
        "SHA256",
        Buffer.from(new TextEncoder().encode(canonicalize(unsigned))),
        privateKey,
      ).toString("base64"),
    };
  }

  it("`key-not-hardware-bound` is NOT a hardware blocker (caps confidential, keeps hardware-attested)", () => {
    expect(HARDWARE_BLOCKER_CODES.has("key-not-hardware-bound")).toBe(false);
  });

  it("emits the finding under requireHardwareBoundKey:true, absent by default (ADR-0004 retired it)", async () => {
    const rec = signedRecord();
    const now = () => new Date("2026-06-19T12:00:00Z");

    // Opt-in (a future confidential-compute backend) → the gate fires.
    const on = await verifyProviderForSeal(rec, undefined, { now, requireHardwareBoundKey: true });
    expect(on.findings.map((f) => f.code)).toContain("key-not-hardware-bound");

    // ADR-0004 default: App Attest is retired for the Mac tier, so the gate is
    // off unless explicitly requested.
    const off = await verifyProviderForSeal(rec, undefined, { now });
    expect(off.findings.map((f) => f.code)).not.toContain("key-not-hardware-bound");
  });
});
