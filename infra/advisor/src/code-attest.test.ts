// APNs code-identity: sender crypto + verify + the confidential-eligibility gate.
import crypto, { webcrypto } from "node:crypto";
import { describe, expect, it } from "vitest";

import nacl from "tweetnacl";

import { buildApnsJwt, loadApnsConfig, sealCodeChallenge } from "./apns.ts";
import { codeSignedPayloadFor, makeCodeNonce, verifyCodeAttestation } from "./attest.ts";
import { KnownGoodSet } from "./known-good.ts";
import type { CodeAttestationResponse, Register } from "./protocol.ts";
import { ProviderRegistry } from "./registry.ts";

// --- helpers (P-256 sign → DER, like attest.test.ts) -----------------------
function bytesToBase64(b: Uint8Array): string {
  let bin = "";
  for (const byte of b) bin += String.fromCharCode(byte);
  return btoa(bin);
}
function trimLeadingZeros(b: Uint8Array): Uint8Array {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0x00) i++;
  return b.slice(i);
}
function encodeInteger(b: Uint8Array): Uint8Array {
  const needsPad = (b[0] ?? 0) & 0x80;
  const inner = needsPad ? new Uint8Array([0x00, ...b]) : b;
  return new Uint8Array([0x02, inner.length, ...inner]);
}
function rawSigToDer(raw: Uint8Array): Uint8Array {
  const r = encodeInteger(trimLeadingZeros(raw.slice(0, 32)));
  const s = encodeInteger(trimLeadingZeros(raw.slice(32, 64)));
  return new Uint8Array([0x30, r.length + s.length, ...r, ...s]);
}
async function p256KeyPair(): Promise<{ key: webcrypto.CryptoKey; pubB64: string }> {
  const kp = (await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
  ])) as webcrypto.CryptoKeyPair;
  const raw = new Uint8Array(await webcrypto.subtle.exportKey("raw", kp.publicKey));
  return { key: kp.privateKey, pubB64: bytesToBase64(raw.slice(1)) };
}
async function signDer(key: webcrypto.CryptoKey, msg: Uint8Array): Promise<number[]> {
  const raw = new Uint8Array(
    await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, msg),
  );
  return [...rawSigToDer(raw)];
}

function register(over: Partial<Register> = {}): Register {
  return {
    provider_did: "did:plc:test",
    machine_id: "rkey-1",
    machine_label: "Test",
    chip: "M3",
    ram_gb: 16,
    supported_models: ["m"],
    encryption_pub_key: bytesToBase64(nacl.box.keyPair().publicKey),
    attestation_pub_key: "x".repeat(40),
    attestation_uri: "at://x",
    ...over,
  };
}

describe("apns sender", () => {
  it("loadApnsConfig is null unless all four vars present", () => {
    expect(loadApnsConfig({})).toBeNull();
    expect(loadApnsConfig({ APNS_AUTH_KEY: "k", APNS_KEY_ID: "i", APNS_TEAM_ID: "t" })).toBeNull();
    const cfg = loadApnsConfig({
      APNS_AUTH_KEY: "k",
      APNS_KEY_ID: "i",
      APNS_TEAM_ID: "t",
      APNS_TOPIC: "dev.cocore.provider",
    });
    expect(cfg).toEqual({ authKeyPem: "k", keyId: "i", teamId: "t", topic: "dev.cocore.provider" });
  });

  it("buildApnsJwt makes a verifiable ES256 token with the right claims", () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const jwt = buildApnsJwt(
      { authKeyPem: pem, keyId: "KEY1234567", teamId: "TEAM123456", topic: "dev.cocore.provider" },
      1_700_000_000_000,
      {},
    );
    const [h, p, sig] = jwt.split(".");
    const header = JSON.parse(Buffer.from(h!, "base64url").toString());
    const payload = JSON.parse(Buffer.from(p!, "base64url").toString());
    expect(header).toEqual({ alg: "ES256", kid: "KEY1234567" });
    expect(payload).toEqual({ iss: "TEAM123456", iat: 1_700_000_000 });
    // Signature verifies over `${h}.${p}` with the public key (raw r||s form).
    const ok = crypto.verify(
      "SHA256",
      Buffer.from(`${h}.${p}`),
      { key: publicKey, dsaEncoding: "ieee-p1363" },
      Buffer.from(sig!, "base64url"),
    );
    expect(ok).toBe(true);
  });

  it("sealCodeChallenge seals to K so only K's holder recovers the nonce", async () => {
    const recipient = nacl.box.keyPair();
    const nonce = makeCodeNonce();
    // Omit encScheme → the X25519 default (an old software-key agent).
    const { epk, n } = await sealCodeChallenge(nonce, bytesToBase64(recipient.publicKey));
    // The provider opens it: framed = boxNonce(24) || box.
    const framed = new Uint8Array(Buffer.from(n, "base64"));
    const boxNonce = framed.slice(0, nacl.box.nonceLength);
    const body = framed.slice(nacl.box.nonceLength);
    const epkPub = new Uint8Array(Buffer.from(epk, "base64"));
    const opened = nacl.box.open(body, boxNonce, epkPub, recipient.secretKey);
    expect(opened).not.toBeNull();
    expect(new TextDecoder().decode(opened!)).toBe(nonce);
    // A different key cannot open it.
    const wrong = nacl.box.keyPair();
    expect(nacl.box.open(body, boxNonce, epkPub, wrong.secretKey)).toBeNull();
  });
});

describe("verifyCodeAttestation", () => {
  it("accepts a valid SE signature over {nonce} and rejects tampering", async () => {
    const { key, pubB64 } = await p256KeyPair();
    const nonce = makeCodeNonce();
    const sig = await signDer(key, codeSignedPayloadFor(nonce));
    const resp: CodeAttestationResponse = { nonce, signature: sig };

    expect(await verifyCodeAttestation(resp, nonce, pubB64)).toBe(true);
    // Wrong expected nonce → reject (someone replayed an old response).
    expect(await verifyCodeAttestation(resp, makeCodeNonce(), pubB64)).toBe(false);
    // Tampered signature → reject.
    const bad = { ...resp, signature: [...sig.slice(0, -1), (sig.at(-1)! ^ 1) & 0xff] };
    expect(await verifyCodeAttestation(bad, nonce, pubB64)).toBe(false);
  });

  it("BINDS the cdHash (0.9.23): a {cdHash,nonce} signature verifies only against the same cdHash", async () => {
    const { key, pubB64 } = await p256KeyPair();
    const nonce = makeCodeNonce();
    const cd = "57bd6dfa8daf45c187249a4c70a2b6c396ab9fc0";
    // Agent signs over {cdHash, nonce} (its measured cdHash).
    const sig = await signDer(key, codeSignedPayloadFor(nonce, cd));
    const resp: CodeAttestationResponse = { nonce, signature: sig };

    // Advisor reconstructs with the SAME (registered) cdHash → verifies.
    expect(await verifyCodeAttestation(resp, nonce, pubB64, cd)).toBe(true);
    // A different registered cdHash → reject (the proof is bound to the measurement).
    expect(await verifyCodeAttestation(resp, nonce, pubB64, "deadbeef")).toBe(false);
    // Reconstructing as nonce-only (legacy) also rejects a bound proof.
    expect(await verifyCodeAttestation(resp, nonce, pubB64)).toBe(false);
  });
});

describe("confidential gate is per-machine earned — ALWAYS requires code-attestation", () => {
  const cd = "a".repeat(64);
  const reg = register({ cd_hash: cd, tier: "attested-confidential", apns_device_token: "tok" });

  it("gated false until code-attested, true after, false when dropped", () => {
    const r = new ProviderRegistry(new KnownGoodSet([cd]));
    r.upsert(
      reg,
      () => {},
      () => {},
      async () => true,
    );
    r.recordChallengeSip(reg.provider_did, reg.machine_id!, true);
    expect(r.get(reg.provider_did, reg.machine_id!)!.confidentialEligible).toBe(false);
    r.markCodeAttested(reg.provider_did, reg.machine_id!);
    expect(r.get(reg.provider_did, reg.machine_id!)!.confidentialEligible).toBe(true);
    // A dropped code-attestation revokes it.
    r.dropCodeAttested(reg.provider_did, reg.machine_id!);
    expect(r.get(reg.provider_did, reg.machine_id!)!.confidentialEligible).toBe(false);
  });

  it("never confidential without code-attestation, even with known-good cdHash + SIP", () => {
    // No global "enforcement off" escape: cdHash ∈ known-good + SIP verified is
    // NOT enough — a self-reported cdHash is forgeable. The machine must answer
    // the live code-identity challenge. (Without APNs configured it never can,
    // so confidential is simply unavailable — fail-closed.)
    const r = new ProviderRegistry(new KnownGoodSet([cd]));
    r.upsert(
      reg,
      () => {},
      () => {},
      async () => true,
    );
    r.recordChallengeSip(reg.provider_did, reg.machine_id!, true);
    expect(r.get(reg.provider_did, reg.machine_id!)!.confidentialEligible).toBe(false);
  });
});
