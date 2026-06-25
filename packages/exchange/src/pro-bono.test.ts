// Exercises the real `Exchange.onReceipt` pro-bono path end to end —
// not the fake exchange the pipeline test uses. The point is to cover
// the `isProBono` short-circuit in `exchange.ts`: a `proBono: true`
// receipt must settle to all-zero amounts even when the fee policy has
// a non-zero `minMinor` floor, which on a zero-price receipt would
// otherwise drive `providerShare` negative (amountCharged 0, fee 5 →
// payout -5) and break the `amountCharged = payout + fee` invariant.
//
// The receipt + attestation are really ES256-signed so the receipt
// clears `verifyForChargeStrict` before settlement — the same gate the
// production exchange runs. Crypto helpers mirror validate.test.ts.

import { describe, expect, it } from "vitest";
import { webcrypto } from "node:crypto";

import { canonicalize } from "@cocore/sdk/canonical";
import type { IndexedRecord } from "@cocore/sdk";
import type {
  AttestationRecord,
  JobRecord,
  PaymentAuthorizationRecord,
  ReceiptRecord,
} from "@cocore/sdk/types";

import { Exchange } from "./exchange.ts";
import { SettlementPublisher } from "./publisher.ts";

const { subtle } = webcrypto;

const EX_DID = "did:web:exchange.example";
const PROVIDER_DID = "did:plc:provider";
const REQUESTER_DID = "did:plc:requester";

// ── ES256 signing helpers (raw r||s → DER, mirroring a Rust signer) ──

function base64Encode(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function stripLeadingZeros(b: Uint8Array): Uint8Array {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0x00) i++;
  return b.slice(i);
}

function encodeDerInteger(b: Uint8Array): Uint8Array {
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

function rawSigToDer(raw: Uint8Array): Uint8Array {
  const r = stripLeadingZeros(raw.slice(0, 32));
  const s = stripLeadingZeros(raw.slice(32, 64));
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

function b64urlDecode(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

interface KeyPair {
  publicKeyB64: string;
  signRaw: (msg: Uint8Array) => Promise<Uint8Array>;
}

async function genP256Keypair(): Promise<KeyPair> {
  const pair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const jwk = (await subtle.exportKey("jwk", pair.publicKey)) as { x: string; y: string };
  const pubRaw = new Uint8Array(64);
  pubRaw.set(b64urlDecode(jwk.x), 0);
  pubRaw.set(b64urlDecode(jwk.y), 32);
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

// ── fixtures ─────────────────────────────────────────────────────────

function fixtureJob(): JobRecord {
  return {
    model: "stub",
    inputCommitment: "a".repeat(64),
    maxTokensOut: 1000,
    priceCeiling: { amount: 100, currency: "CC" },
    acceptedTrustLevel: "self-attested",
    paymentAuthorization: { uri: `at://${REQUESTER_DID}/auth/1`, cid: "bafyauth" },
    expiresAt: "2026-05-07T13:00:00Z",
    createdAt: "2026-05-07T12:00:00Z",
  };
}

function fixtureAuth(): PaymentAuthorizationRecord {
  return {
    exchange: EX_DID,
    ceiling: { amount: 100, currency: "CC" },
    scope: "singleJob",
    nonce: "a".repeat(32),
    expiresAt: "2099-01-01T00:00:00Z",
    createdAt: "2026-05-07T12:00:00Z",
  };
}

function baseReceipt(overrides: Partial<ReceiptRecord>): ReceiptRecord {
  return {
    job: { uri: `at://${REQUESTER_DID}/job/1`, cid: "bafyjob" },
    requester: REQUESTER_DID,
    model: "stub",
    inputCommitment: "a".repeat(64),
    outputCommitment: "b".repeat(64),
    tokens: { in: 32, out: 128 },
    startedAt: "2026-05-07T12:00:00Z",
    completedAt: "2026-05-07T12:00:03Z",
    price: { amount: 50, currency: "CC" },
    attestation: { uri: `at://${PROVIDER_DID}/attest/1`, cid: "bafyatt" },
    enclaveSignature: "",
    ...overrides,
  };
}

async function signReceipt(kp: KeyPair, overrides: Partial<ReceiptRecord>): Promise<ReceiptRecord> {
  const draft = baseReceipt(overrides);
  const { enclaveSignature: _omit, ...signable } = draft;
  const sig = await kp.signRaw(new TextEncoder().encode(canonicalize(signable)));
  return { ...draft, enclaveSignature: base64Encode(sig) };
}

async function signAttestation(kp: KeyPair): Promise<AttestationRecord> {
  const draft = {
    publicKey: kp.publicKeyB64,
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
    attestedAt: "2026-05-07T11:00:00Z",
    expiresAt: "2026-05-08T11:00:00Z",
    selfSignature: "",
  } as unknown as AttestationRecord;
  const { selfSignature: _omit, ...signable } = draft as unknown as Record<string, unknown>;
  const sig = await kp.signRaw(new TextEncoder().encode(canonicalize(signable)));
  return { ...draft, selfSignature: base64Encode(sig) };
}

function indexed<T>(uri: string, repo: string, collection: string, body: T): IndexedRecord<T> {
  return {
    uri,
    cid: `bafy-${uri.split("/").pop()}`,
    collection,
    repo,
    rkey: uri.split("/").pop() ?? "",
    body,
  } as IndexedRecord<T>;
}

// A fee policy WITH a non-zero floor — the case the isProBono guard
// protects against. On a zero-price receipt, computeFee would return
// max(0, 5) = 5, and providerShare would be 0 - 5 = -5 without the guard.
const FEE_POLICY = { bps: 500, minMinor: 5 };

describe("Exchange pro-bono settlement", () => {
  it("settles a pro-bono receipt to an all-zero split despite a non-zero fee floor", async () => {
    // Inspect the SettlementRecord the exchange hands the publisher by
    // intercepting build() — the strongest assertion that the isProBono
    // branch produced a conserved all-zero split rather than a negative one.
    const kp = await genP256Keypair();
    const receipt = await signReceipt(kp, {
      proBono: true,
      price: { amount: 0, currency: "CC" },
      tokens: { in: 0, out: 0 },
    });
    const attestation = await signAttestation(kp);

    const records = new Map<string, IndexedRecord>([
      [
        `at://${REQUESTER_DID}/job/1`,
        indexed(
          `at://${REQUESTER_DID}/job/1`,
          REQUESTER_DID,
          "dev.cocore.compute.job",
          fixtureJob(),
        ),
      ],
      [
        `at://${REQUESTER_DID}/auth/1`,
        indexed(
          `at://${REQUESTER_DID}/auth/1`,
          REQUESTER_DID,
          "dev.cocore.compute.paymentAuthorization",
          fixtureAuth(),
        ),
      ],
      [
        `at://${PROVIDER_DID}/attest/1`,
        indexed(
          `at://${PROVIDER_DID}/attest/1`,
          PROVIDER_DID,
          "dev.cocore.compute.attestation",
          attestation,
        ),
      ],
    ]);

    const publisher = new SettlementPublisher(EX_DID);
    const builtSplits: Array<{ charged: number; payout: number; fee: number }> = [];
    const origBuild = publisher.build.bind(publisher);
    publisher.build = (inputs) => {
      builtSplits.push({
        charged: inputs.amountCharged.amount,
        payout: inputs.providerPayout.amount,
        fee: inputs.exchangeFee.amount,
      });
      return origBuild(inputs);
    };

    const exchange = new Exchange({
      exchangeDid: EX_DID,
      feePolicy: FEE_POLICY,
      publisher,
      resolveRecord: async (uri: string) => records.get(uri) ?? null,
    });

    const outcome = await exchange.onReceipt(
      indexed(
        `at://${PROVIDER_DID}/dev.cocore.compute.receipt/pb2`,
        PROVIDER_DID,
        "dev.cocore.compute.receipt",
        receipt,
      ),
    );

    expect(outcome.kind).toBe("settled");
    expect(builtSplits).toHaveLength(1);
    // The whole point: zero charged, zero payout, zero fee — NOT charged 0
    // with fee 5 and payout -5 (which the minMinor floor would have produced
    // without the isProBono short-circuit). Split conserves: 0 = 0 + 0.
    expect(builtSplits[0]).toEqual({ charged: 0, payout: 0, fee: 0 });
  });

  it("still charges the fee floor on a normal (non-pro-bono) receipt", async () => {
    // Proves the floor is actually active under this policy, so the
    // all-zero pro-bono result above is the guard's doing, not a no-op.
    const kp = await genP256Keypair();
    const receipt = await signReceipt(kp, {
      price: { amount: 50, currency: "CC" },
      tokens: { in: 32, out: 128 },
    });
    const attestation = await signAttestation(kp);

    const records = new Map<string, IndexedRecord>([
      [
        `at://${REQUESTER_DID}/job/1`,
        indexed(
          `at://${REQUESTER_DID}/job/1`,
          REQUESTER_DID,
          "dev.cocore.compute.job",
          fixtureJob(),
        ),
      ],
      [
        `at://${REQUESTER_DID}/auth/1`,
        indexed(
          `at://${REQUESTER_DID}/auth/1`,
          REQUESTER_DID,
          "dev.cocore.compute.paymentAuthorization",
          fixtureAuth(),
        ),
      ],
      [
        `at://${PROVIDER_DID}/attest/1`,
        indexed(
          `at://${PROVIDER_DID}/attest/1`,
          PROVIDER_DID,
          "dev.cocore.compute.attestation",
          attestation,
        ),
      ],
    ]);

    const publisher = new SettlementPublisher(EX_DID);
    const builtSplits: Array<{ charged: number; payout: number; fee: number }> = [];
    const origBuild = publisher.build.bind(publisher);
    publisher.build = (inputs) => {
      builtSplits.push({
        charged: inputs.amountCharged.amount,
        payout: inputs.providerPayout.amount,
        fee: inputs.exchangeFee.amount,
      });
      return origBuild(inputs);
    };

    const exchange = new Exchange({
      exchangeDid: EX_DID,
      feePolicy: FEE_POLICY,
      publisher,
      resolveRecord: async (uri: string) => records.get(uri) ?? null,
    });

    const outcome = await exchange.onReceipt(
      indexed(
        `at://${PROVIDER_DID}/dev.cocore.compute.receipt/normal1`,
        PROVIDER_DID,
        "dev.cocore.compute.receipt",
        receipt,
      ),
    );

    expect(outcome.kind).toBe("settled");
    // 50 CC at 500 bps = 2 by bps, floored up to minMinor 5 → fee 5, payout 45.
    expect(builtSplits[0]).toEqual({ charged: 50, payout: 45, fee: 5 });
  });
});
