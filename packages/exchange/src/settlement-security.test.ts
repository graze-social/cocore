// Security regressions for the settlement path:
//
//   H1  a second receipt spending the SAME singleJob authorization is
//       rejected (single-use / nonce enforced); a session authorization
//       cannot be charged past its sessionBudget.
//   H2  a receipt whose job points at an authorization owned by someone
//       other than the receipt's requester is rejected.
//   M4  settlement idempotency is durable — it survives a simulated
//       process restart (a fresh Exchange over the same sqlite db).
//   M5  a fee floor above a small price clamps so providerShare never
//       goes negative.
//
// Receipts + attestations are really ES256-signed so they clear
// verifyForChargeStrict — the same gate production runs. The crypto
// helpers mirror pro-bono.test.ts.

import { describe, expect, it } from "vitest";
import { webcrypto } from "node:crypto";
import Database from "better-sqlite3";

import { canonicalize } from "@cocore/sdk/canonical";
import type { IndexedRecord } from "@cocore/sdk";
import type {
  AttestationRecord,
  JobRecord,
  PaymentAuthorizationRecord,
  ReceiptRecord,
} from "@cocore/sdk/types";

import { Exchange, type ExchangeConfig } from "./exchange.ts";
import { SettlementPublisher } from "./publisher.ts";

const { subtle } = webcrypto;

const EX_DID = "did:web:exchange.example";
const PROVIDER_DID = "did:plc:provider";
const REQUESTER_DID = "did:plc:requester";
const OTHER_DID = "did:plc:someoneelse";

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

function fixtureJob(overrides: Partial<JobRecord> = {}): JobRecord {
  return {
    model: "stub",
    inputCommitment: "a".repeat(64),
    maxTokensOut: 1000,
    priceCeiling: { amount: 100, currency: "CC" },
    acceptedTrustLevel: "self-attested",
    paymentAuthorization: { uri: `at://${REQUESTER_DID}/auth/1`, cid: "bafyauth" },
    expiresAt: "2099-05-07T13:00:00Z",
    createdAt: "2026-05-07T12:00:00Z",
    ...overrides,
  };
}

function fixtureAuth(
  overrides: Partial<PaymentAuthorizationRecord> = {},
): PaymentAuthorizationRecord {
  return {
    exchange: EX_DID,
    ceiling: { amount: 100, currency: "CC" },
    scope: "singleJob",
    nonce: "a".repeat(32),
    expiresAt: "2099-01-01T00:00:00Z",
    createdAt: "2026-05-07T12:00:00Z",
    ...overrides,
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
    expiresAt: "2099-05-08T11:00:00Z",
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

function receiptIndexed(uri: string, body: ReceiptRecord): IndexedRecord<ReceiptRecord> {
  return indexed(uri, PROVIDER_DID, "dev.cocore.compute.receipt", body);
}

/** Build a records map + an Exchange over a (fresh or shared) db. */
function makeExchange(opts: {
  records: Map<string, IndexedRecord>;
  db?: Database.Database;
  feePolicy?: { bps: number; minMinor: number };
}): { exchange: Exchange; splits: Array<{ charged: number; payout: number; fee: number }> } {
  const publisher = new SettlementPublisher(EX_DID);
  const splits: Array<{ charged: number; payout: number; fee: number }> = [];
  const origBuild = publisher.build.bind(publisher);
  publisher.build = (inputs) => {
    splits.push({
      charged: inputs.amountCharged.amount,
      payout: inputs.providerPayout.amount,
      fee: inputs.exchangeFee.amount,
    });
    return origBuild(inputs);
  };
  const cfg: ExchangeConfig = {
    exchangeDid: EX_DID,
    feePolicy: opts.feePolicy ?? { bps: 500, minMinor: 0 },
    publisher,
    resolveRecord: async (uri: string) => opts.records.get(uri) ?? null,
    ...(opts.db ? { db: opts.db } : {}),
  };
  return { exchange: new Exchange(cfg), splits };
}

function baseRecords(
  auth: PaymentAuthorizationRecord,
  attestation: AttestationRecord,
  job: JobRecord = fixtureJob(),
  authOwner: string = REQUESTER_DID,
): Map<string, IndexedRecord> {
  return new Map<string, IndexedRecord>([
    [
      `at://${REQUESTER_DID}/job/1`,
      indexed(`at://${REQUESTER_DID}/job/1`, REQUESTER_DID, "dev.cocore.compute.job", job),
    ],
    [
      job.paymentAuthorization.uri,
      indexed(
        job.paymentAuthorization.uri,
        authOwner,
        "dev.cocore.compute.paymentAuthorization",
        auth,
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
}

// ── H1: single-use authorization ─────────────────────────────────────

describe("H1 single-use payment authorization", () => {
  it("rejects a second receipt spending the same singleJob authorization", async () => {
    const kp = await genP256Keypair();
    const attestation = await signAttestation(kp);
    const records = baseRecords(fixtureAuth({ scope: "singleJob" }), attestation);
    const db = new Database(":memory:");
    const { exchange } = makeExchange({ records, db });

    const r1 = await signReceipt(kp, { price: { amount: 50, currency: "CC" } });
    const first = await exchange.onReceipt(
      receiptIndexed(`at://${PROVIDER_DID}/dev.cocore.compute.receipt/rk1`, r1),
    );
    expect(first.kind).toBe("settled");

    // Distinct rkey, SAME job → SAME authorization (nonce). This is the
    // double-charge the fix closes.
    const r2 = await signReceipt(kp, { price: { amount: 50, currency: "CC" } });
    const second = await exchange.onReceipt(
      receiptIndexed(`at://${PROVIDER_DID}/dev.cocore.compute.receipt/rk2`, r2),
    );
    expect(second.kind).toBe("rejected");
    if (second.kind === "rejected") {
      expect(second.report.findings[0]?.code).toBe("authorization-already-consumed");
    }
  });

  it("enforces sessionBudget across settlements under one session authorization", async () => {
    const kp = await genP256Keypair();
    const attestation = await signAttestation(kp);
    // session scope, budget 120: two 50-charges fit (100), a third (150)
    // would exceed and must be rejected.
    const auth = fixtureAuth({
      scope: "session",
      sessionBudget: { amount: 120, currency: "CC" },
    });
    // Two distinct jobs, both pointing at the same session authorization.
    const jobA = fixtureJob();
    const records = baseRecords(auth, attestation, jobA);
    const db = new Database(":memory:");
    const { exchange } = makeExchange({ records, db });

    const mk = async (rk: string) => {
      const r = await signReceipt(kp, { price: { amount: 50, currency: "CC" } });
      return exchange.onReceipt(
        receiptIndexed(`at://${PROVIDER_DID}/dev.cocore.compute.receipt/${rk}`, r),
      );
    };
    expect((await mk("s1")).kind).toBe("settled"); // cumulative 50
    expect((await mk("s2")).kind).toBe("settled"); // cumulative 100
    const third = await mk("s3"); // would be 150 > 120
    expect(third.kind).toBe("rejected");
    if (third.kind === "rejected") {
      expect(third.report.findings[0]?.code).toBe("session-budget-exceeded");
    }
  });
});

// ── H2: authorization not owned by the requester ─────────────────────

describe("H2 authorization requester binding", () => {
  it("rejects when the authorization is owned by a DID other than the requester", async () => {
    const kp = await genP256Keypair();
    const attestation = await signAttestation(kp);
    // The authorization record's owning repo is OTHER_DID, but the
    // receipt/job's requester is REQUESTER_DID.
    const records = baseRecords(fixtureAuth(), attestation, fixtureJob(), OTHER_DID);
    const db = new Database(":memory:");
    const { exchange } = makeExchange({ records, db });

    const r = await signReceipt(kp, { price: { amount: 50, currency: "CC" } });
    const outcome = await exchange.onReceipt(
      receiptIndexed(`at://${PROVIDER_DID}/dev.cocore.compute.receipt/h2`, r),
    );
    expect(outcome.kind).toBe("rejected");
    if (outcome.kind === "rejected") {
      expect(outcome.report.findings[0]?.code).toBe("authorization-owner-mismatch");
    }
  });
});

// ── M4: durable idempotency across restart ───────────────────────────

describe("M4 durable settlement idempotency", () => {
  it("rejects a re-observed receipt after a simulated process restart", async () => {
    const kp = await genP256Keypair();
    const attestation = await signAttestation(kp);
    const records = baseRecords(fixtureAuth(), attestation);
    const db = new Database(":memory:");

    // Process life #1 settles the receipt.
    const { exchange: ex1 } = makeExchange({ records, db });
    const r = await signReceipt(kp, { price: { amount: 50, currency: "CC" } });
    const first = await ex1.onReceipt(
      receiptIndexed(`at://${PROVIDER_DID}/dev.cocore.compute.receipt/m4`, r),
    );
    expect(first.kind).toBe("settled");

    // Simulate a restart: a brand-new Exchange (empty in-memory Map)
    // over the SAME db. The durable settled_receipt row must still block
    // a re-charge.
    const { exchange: ex2 } = makeExchange({ records, db });
    const again = await ex2.onReceipt(
      receiptIndexed(`at://${PROVIDER_DID}/dev.cocore.compute.receipt/m4`, r),
    );
    expect(again.kind).not.toBe("settled");
    if (again.kind === "rejected") {
      expect(again.report.findings[0]?.code).toBe("already-settled");
    }
  });
});

// ── M5: small-price fee clamp ────────────────────────────────────────

describe("M5 fee floor clamp", () => {
  it("clamps the fee to the price so providerShare is never negative", async () => {
    const kp = await genP256Keypair();
    const attestation = await signAttestation(kp);
    const records = baseRecords(fixtureAuth(), attestation);
    const db = new Database(":memory:");
    // minMinor 5 on a price-of-3 receipt would produce fee 5, payout -3
    // without the clamp. With the clamp: fee = min(5, 3) = 3, payout 0.
    const { exchange, splits } = makeExchange({
      records,
      db,
      feePolicy: { bps: 500, minMinor: 5 },
    });

    const r = await signReceipt(kp, { price: { amount: 3, currency: "CC" } });
    const outcome = await exchange.onReceipt(
      receiptIndexed(`at://${PROVIDER_DID}/dev.cocore.compute.receipt/m5`, r),
    );
    expect(outcome.kind).toBe("settled");
    expect(splits[0]).toEqual({ charged: 3, payout: 0, fee: 3 });
    expect(splits[0]!.payout).toBeGreaterThanOrEqual(0);
  });
});
