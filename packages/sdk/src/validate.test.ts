import { test } from "vitest";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

import { canonicalize } from "./canonical.ts";
import {
  verifyForChargeStrict,
  verifyReceipt,
  verifyReceiptStrict,
  verifySettlementChain,
} from "./validate.ts";
import type {
  AttestationRecord,
  JobRecord,
  PaymentAuthorizationRecord,
  ReceiptRecord,
  SettlementRecord,
} from "./types.ts";

const { subtle } = webcrypto;

function fixtureJob(overrides: Partial<JobRecord> = {}): JobRecord {
  return {
    model: "llama-3.1-70b",
    inputCommitment: "a".repeat(64),
    maxTokensOut: 1000,
    priceCeiling: { amount: 100, currency: "USD" },
    acceptedTrustLevel: "self-attested",
    paymentAuthorization: { uri: "at://did:plc:r/auth/1", cid: "bafycid" },
    expiresAt: "2026-05-07T13:00:00Z",
    createdAt: "2026-05-07T12:00:00Z",
    ...overrides,
  };
}

function fixtureAttestation(overrides: Partial<AttestationRecord> = {}): AttestationRecord {
  return {
    publicKey: "AAAA",
    encryptionPubKey: "BBBB",
    chipName: "Apple M3 Max",
    hardwareModel: "Mac15,8",
    serialNumberHash: "d".repeat(64),
    osVersion: "15.0",
    binaryHash: "e".repeat(64),
    sipEnabled: true,
    secureBootEnabled: true,
    secureEnclaveAvailable: true,
    authenticatedRootEnabled: true,
    rdmaDisabled: true,
    selfSignature: "sigsig",
    attestedAt: "2026-05-07T11:00:00Z",
    expiresAt: "2026-05-08T11:00:00Z",
    ...overrides,
  };
}

function fixtureReceipt(overrides: Partial<ReceiptRecord> = {}): ReceiptRecord {
  return {
    job: { uri: "at://did:plc:r/job/1", cid: "bafycid" },
    requester: "did:plc:r",
    model: "llama-3.1-70b",
    inputCommitment: "a".repeat(64),
    outputCommitment: "b".repeat(64),
    tokens: { in: 32, out: 128 },
    startedAt: "2026-05-07T12:00:00Z",
    completedAt: "2026-05-07T12:00:03Z",
    price: { amount: 50, currency: "USD" },
    attestation: { uri: "at://did:plc:p/attest/1", cid: "bafyatt" },
    enclaveSignature: "sigsig",
    ...overrides,
  };
}

test("happy path receipt verifies", () => {
  const r = verifyReceipt(fixtureReceipt(), fixtureJob(), fixtureAttestation());
  assert.equal(r.ok, true, JSON.stringify(r.findings));
});

test("price over ceiling fails", () => {
  const r = verifyReceipt(
    fixtureReceipt({ price: { amount: 500, currency: "USD" } }),
    fixtureJob(),
    fixtureAttestation(),
  );
  assert.equal(r.ok, false);
  assert.ok(r.findings.some((f) => f.code === "price-over-ceiling"));
});

test("commitment mismatch fails", () => {
  const r = verifyReceipt(
    fixtureReceipt({ inputCommitment: "z".repeat(64) }),
    fixtureJob(),
    fixtureAttestation(),
  );
  assert.equal(r.ok, false);
  assert.ok(r.findings.some((f) => f.code === "commitment-mismatch"));
});

test("expired attestation fails", () => {
  const r = verifyReceipt(
    fixtureReceipt(),
    fixtureJob(),
    fixtureAttestation({
      attestedAt: "2026-04-01T00:00:00Z",
      expiresAt: "2026-04-02T00:00:00Z",
    }),
  );
  assert.equal(r.ok, false);
  assert.ok(r.findings.some((f) => f.code === "attestation-stale"));
});

test("missing signature fails", () => {
  const r = verifyReceipt(
    fixtureReceipt({ enclaveSignature: "" }),
    fixtureJob(),
    fixtureAttestation(),
  );
  assert.equal(r.ok, false);
  assert.ok(r.findings.some((f) => f.code === "no-signature"));
});

test("pro-bono receipt with zero price and zero tokens verifies", () => {
  // The carve-out for explicitly unlimited usage: free + unmetered.
  const r = verifyReceipt(
    fixtureReceipt({
      proBono: true,
      price: { amount: 0, currency: "USD" },
      tokens: { in: 0, out: 0 },
    }),
    fixtureJob(),
    fixtureAttestation(),
  );
  assert.equal(r.ok, true, JSON.stringify(r.findings));
});

test("pro-bono receipt that still charges is rejected", () => {
  // A provider can't fly the pro-bono flag while billing.
  const r = verifyReceipt(
    fixtureReceipt({
      proBono: true,
      price: { amount: 50, currency: "USD" },
      tokens: { in: 0, out: 0 },
    }),
    fixtureJob(),
    fixtureAttestation(),
  );
  assert.equal(r.ok, false);
  assert.ok(r.findings.some((f) => f.code === "pro-bono-nonzero-price"));
});

test("pro-bono receipt that still meters tokens is rejected", () => {
  const r = verifyReceipt(
    fixtureReceipt({
      proBono: true,
      price: { amount: 0, currency: "USD" },
      tokens: { in: 32, out: 128 },
    }),
    fixtureJob(),
    fixtureAttestation(),
  );
  assert.equal(r.ok, false);
  assert.ok(r.findings.some((f) => f.code === "pro-bono-nonzero-tokens"));
});

const fixtureAuth = (
  overrides: Partial<PaymentAuthorizationRecord> = {},
): PaymentAuthorizationRecord => ({
  exchange: "did:web:exchange.example",
  ceiling: { amount: 100, currency: "USD" },
  scope: "singleJob",
  nonce: "a".repeat(32),
  expiresAt: "2026-05-07T13:00:00Z",
  createdAt: "2026-05-07T12:00:00Z",
  ...overrides,
});

const fixtureSettlement = (overrides: Partial<SettlementRecord> = {}): SettlementRecord => ({
  receipt: { uri: "at://did:plc:p/receipt/1", cid: "bafyrcpt" },
  requesterAuthorization: { uri: "at://did:plc:r/auth/1", cid: "bafyauth" },
  amountCharged: { amount: 50, currency: "USD" },
  providerPayout: { amount: 45, currency: "USD" },
  exchangeFee: { amount: 5, currency: "USD" },
  processorReference: "cmVm",
  status: "settled",
  settledAt: "2026-05-07T12:00:10Z",
  ...overrides,
});

test("happy settlement verifies", () => {
  const r = verifySettlementChain(
    fixtureSettlement(),
    fixtureReceipt(),
    fixtureAuth(),
    "did:web:exchange.example",
  );
  assert.equal(r.ok, true, JSON.stringify(r.findings));
});

test("settlement from wrong exchange fails", () => {
  const r = verifySettlementChain(
    fixtureSettlement(),
    fixtureReceipt(),
    fixtureAuth(),
    "did:web:other.example",
  );
  assert.equal(r.ok, false);
  assert.ok(r.findings.some((f) => f.code === "wrong-exchange"));
});

test("settlement over ceiling fails", () => {
  const r = verifySettlementChain(
    fixtureSettlement({
      amountCharged: { amount: 200, currency: "USD" },
      providerPayout: { amount: 180, currency: "USD" },
      exchangeFee: { amount: 20, currency: "USD" },
    }),
    fixtureReceipt({ price: { amount: 200, currency: "USD" } }),
    fixtureAuth(),
    "did:web:exchange.example",
  );
  assert.equal(r.ok, false);
  assert.ok(r.findings.some((f) => f.code === "over-ceiling"));
});

test("split mismatch fails", () => {
  const r = verifySettlementChain(
    fixtureSettlement({
      amountCharged: { amount: 50, currency: "USD" },
      providerPayout: { amount: 45, currency: "USD" },
      exchangeFee: { amount: 10, currency: "USD" }, // 45 + 10 != 50
    }),
    fixtureReceipt(),
    fixtureAuth(),
    "did:web:exchange.example",
  );
  assert.equal(r.ok, false);
  assert.ok(r.findings.some((f) => f.code === "split-mismatch"));
});

// ---- strict ES256 sig verification ---------------------------------

function base64Encode(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** Convert WebCrypto's raw r||s ECDSA output into the DER form
 *  verifyP256 expects on the wire. Mirrors how a real provider
 *  would sign with `p256::ecdsa::Signer` (Rust default = DER). */
function rawSigToDer(raw: Uint8Array): Uint8Array {
  if (raw.length !== 64) throw new Error(`expected 64-byte raw sig, got ${raw.length}`);
  const r = stripLeadingZeros(raw.slice(0, 32));
  const s = stripLeadingZeros(raw.slice(32, 64));
  // 0x02 INTEGER tag, length, value (with optional 0x00 sign byte)
  const rEnc = encodeDerInteger(r);
  const sEnc = encodeDerInteger(s);
  const seqLen = rEnc.length + sEnc.length;
  const out = new Uint8Array(2 + seqLen);
  out[0] = 0x30;
  out[1] = seqLen;
  out.set(rEnc, 2);
  out.set(sEnc, 2 + rEnc.length);
  return out;
}

function stripLeadingZeros(b: Uint8Array): Uint8Array {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0x00) i++;
  return b.slice(i);
}

function encodeDerInteger(b: Uint8Array): Uint8Array {
  // Prepend 0x00 when high bit is set so the value isn't read as negative.
  const needsPad = (b[0]! & 0x80) !== 0;
  const len = b.length + (needsPad ? 1 : 0);
  const out = new Uint8Array(2 + len);
  out[0] = 0x02;
  out[1] = len;
  if (needsPad) {
    out[2] = 0x00;
    out.set(b, 3);
  } else {
    out.set(b, 2);
  }
  return out;
}

interface KeyPair {
  publicKeyB64: string; // 64 raw bytes, base64-encoded
  signRaw: (msg: Uint8Array) => Promise<Uint8Array>; // returns DER
}

async function genP256Keypair(): Promise<KeyPair> {
  const pair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const jwk = (await subtle.exportKey("jwk", pair.publicKey)) as { x: string; y: string };
  const xRaw = b64urlDecode(jwk.x);
  const yRaw = b64urlDecode(jwk.y);
  const pubRaw = new Uint8Array(64);
  pubRaw.set(xRaw, 0);
  pubRaw.set(yRaw, 32);
  return {
    publicKeyB64: base64Encode(pubRaw),
    async signRaw(msg) {
      const raw = new Uint8Array(
        await subtle.sign({ name: "ECDSA", hash: { name: "SHA-256" } }, pair.privateKey, msg),
      );
      return rawSigToDer(raw);
    },
  };
}

function b64urlDecode(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

async function signedReceipt(
  attestPubKeyB64: string,
  signRaw: (msg: Uint8Array) => Promise<Uint8Array>,
  overrides: Partial<ReceiptRecord> = {},
): Promise<ReceiptRecord> {
  const draft: ReceiptRecord = { ...fixtureReceipt(overrides), enclaveSignature: "" };
  const { enclaveSignature: _omit, ...signable } = draft;
  const msg = new TextEncoder().encode(canonicalize(signable));
  const sig = await signRaw(msg);
  return { ...draft, enclaveSignature: base64Encode(sig) };
}

/** An attestation whose `selfSignature` actually verifies against `publicKey`
 *  (H1: verifyForChargeStrict now authenticates the attestation, not just the
 *  receipt). */
async function signedAttestation(
  kp: { publicKeyB64: string; signRaw: (msg: Uint8Array) => Promise<Uint8Array> },
  overrides: Partial<AttestationRecord> = {},
): Promise<AttestationRecord> {
  const draft = fixtureAttestation({
    publicKey: kp.publicKeyB64,
    selfSignature: "",
    ...overrides,
  });
  const {
    selfSignature: _omit,
    $type: _t,
    ...signable
  } = draft as unknown as Record<string, unknown>;
  const msg = new TextEncoder().encode(canonicalize(signable));
  const sig = await kp.signRaw(msg);
  return { ...draft, selfSignature: base64Encode(sig) };
}

test("verifyReceiptStrict: valid signature passes", async () => {
  const kp = await genP256Keypair();
  const att = fixtureAttestation({ publicKey: kp.publicKeyB64 });
  const receipt = await signedReceipt(kp.publicKeyB64, kp.signRaw);
  const r = await verifyReceiptStrict(receipt, fixtureJob(), att);
  assert.equal(r.ok, true, JSON.stringify(r.findings));
});

test("verifyReceiptStrict: tampered receipt fails with signature-invalid", async () => {
  const kp = await genP256Keypair();
  const att = fixtureAttestation({ publicKey: kp.publicKeyB64 });
  const receipt = await signedReceipt(kp.publicKeyB64, kp.signRaw);
  // Tamper after signing.
  const tampered = { ...receipt, outputCommitment: "f".repeat(64) };
  const r = await verifyReceiptStrict(tampered, fixtureJob(), att);
  assert.equal(r.ok, false);
  assert.ok(
    r.findings.some((f) => f.code === "signature-invalid"),
    JSON.stringify(r.findings),
  );
});

test("verifyReceiptStrict: missing signature fails the cheap check, no crypto error fires", async () => {
  const kp = await genP256Keypair();
  const att = fixtureAttestation({ publicKey: kp.publicKeyB64 });
  const r = await verifyReceiptStrict(fixtureReceipt({ enclaveSignature: "" }), fixtureJob(), att);
  assert.equal(r.ok, false);
  assert.ok(r.findings.some((f) => f.code === "no-signature"));
  assert.ok(!r.findings.some((f) => f.code === "signature-invalid"));
  assert.ok(!r.findings.some((f) => f.code === "signature-verify-error"));
});

test("verifyReceiptStrict: malformed publicKey surfaces signature-verify-error", async () => {
  // Generate a real signature, then verify against a too-short pubkey.
  const kp = await genP256Keypair();
  const receipt = await signedReceipt(kp.publicKeyB64, kp.signRaw);
  const att = fixtureAttestation({ publicKey: "AAAA" }); // 3 bytes — wrong
  const r = await verifyReceiptStrict(receipt, fixtureJob(), att);
  // verifyReceiptSignature swallows SignatureVerifyError + returns
  // false → we surface as signature-invalid, not -error. The
  // -error path fires only on non-SignatureVerifyError throws,
  // which is currently unreachable.
  assert.equal(r.ok, false);
  assert.ok(r.findings.some((f) => f.code === "signature-invalid"));
});

test("verifyForChargeStrict: appends a sig check on top of verifyForCharge", async () => {
  const kp = await genP256Keypair();
  const att = await signedAttestation(kp);
  const receipt = await signedReceipt(kp.publicKeyB64, kp.signRaw);
  const job = fixtureJob();
  const auth = fixtureAuth();
  const r = await verifyForChargeStrict(
    {
      exchangeDid: "did:web:exchange.example",
      settledReceipts: new Set(),
      now: () => new Date("2026-05-07T12:00:01Z"),
    },
    {
      receipt,
      receiptUri: "at://did:plc:p/receipt/1",
      job,
      jobOwnerDid: "did:plc:r",
      authorization: auth,
      authorizationUri: { uri: "at://did:plc:r/auth/1", cid: "bafycid" },
    },
    att,
  );
  assert.equal(r.ok, true, JSON.stringify(r.findings));
});

test("verifyForChargeStrict: bad sig fails before charging", async () => {
  const kp = await genP256Keypair();
  const att = await signedAttestation(kp);
  const receipt = await signedReceipt(kp.publicKeyB64, kp.signRaw);
  // Tamper with the price after signing — the sig is now stale.
  const tampered = { ...receipt, price: { amount: 99, currency: "USD" } };
  const r = await verifyForChargeStrict(
    {
      exchangeDid: "did:web:exchange.example",
      settledReceipts: new Set(),
      now: () => new Date("2026-05-07T12:00:01Z"),
    },
    {
      receipt: tampered,
      receiptUri: "at://did:plc:p/receipt/1",
      job: fixtureJob(),
      jobOwnerDid: "did:plc:r",
      authorization: fixtureAuth(),
      authorizationUri: { uri: "at://did:plc:r/auth/1", cid: "bafycid" },
    },
    att,
  );
  assert.equal(r.ok, false);
  assert.ok(r.findings.some((f) => f.code === "signature-invalid"));
});
