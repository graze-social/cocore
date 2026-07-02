import { afterEach, beforeEach, test, vi } from "vitest";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { __resetHydrateCacheForTests } from "../bsky-hydrate.ts";
import { Store } from "../store.ts";
import { buildAppviewApp } from "./server.ts";
import { withAppviewServer } from "./http-app.ts";
import { canonicalize } from "@cocore/sdk/canonical";

let originalFetch: typeof fetch;
beforeEach(() => {
  originalFetch = globalThis.fetch;
  __resetHydrateCacheForTests();
  // Default mock: every bsky-appview lookup 404s. Tests that need
  // positive hits replace fetch via mockBskyAppview. Without this
  // default, the hydration path would hit the live public bsky
  // appview during tests — slow + flaky + DNS-dependent.
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url.includes("public.api.bsky.app")) {
      return new Response("not found", { status: 404 });
    }
    return originalFetch(input);
  }) as unknown as typeof fetch;
});
afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.clearAllMocks();
});

/** Mock the public bsky appview so hydration paths don't make real
 *  network calls. Each test that hits hydration sets up its own
 *  fixture map keyed by DID. Non-bsky URLs pass through to the
 *  original fetch (so the test's loopback calls to its own server
 *  still work). */
function mockBskyAppview(
  profiles: Record<string, { handle: string; displayName?: string; avatar?: string }>,
): void {
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (!url.includes("public.api.bsky.app")) {
      return originalFetch(input);
    }
    const actor = new URL(url).searchParams.get("actor") ?? "";
    const hit = profiles[actor];
    if (!hit) {
      return new Response("not found", { status: 404 });
    }
    return new Response(
      JSON.stringify({
        did: actor,
        handle: hit.handle,
        displayName: hit.displayName,
        avatar: hit.avatar,
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }) as unknown as typeof fetch;
}

/** Generate a real P-256 keypair, sign the canonical bytes of the
 *  receipt body (minus enclaveSignature), and return everything the
 *  AppView's /verifyReceipt route needs to actually verify. */
async function signedReceiptFixture() {
  const RECEIPT_URI = "at://did:plc:p/dev.cocore.compute.receipt/1";
  const JOB_URI = "at://did:plc:r/dev.cocore.compute.job/1";
  const ATT_URI = "at://did:plc:p/dev.cocore.compute.attestation/1";

  const job = {
    model: "m",
    inputCommitment: "a".repeat(64),
    maxTokensOut: 100,
    priceCeiling: { amount: 100, currency: "USD" },
    acceptedTrustLevel: "self-attested",
    paymentAuthorization: { uri: "x", cid: "y" },
    expiresAt: "2026-05-07T13:00:00Z",
    createdAt: "2026-05-07T12:00:00Z",
  };

  // Real P-256 keypair, sign-then-export so we can stuff the public
  // key bytes into the attestation record exactly as the AppView
  // would receive it from a provider's PDS.
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  // 'raw' export is uncompressed: 0x04 || X || Y. Strip the 0x04 to
  // match the lexicon's 64-byte X||Y publicKey field.
  const pubB64 = btoa(String.fromCharCode(...rawPub.slice(1)));

  const receiptUnsigned = {
    job: { uri: JOB_URI, cid: "bafyreigh2akiscaildc5sgz5wybizysiehxiv4dhpwwqouytxnvgkpkcaq" },
    requester: "did:plc:r",
    model: "m",
    inputCommitment: "a".repeat(64),
    outputCommitment: "b".repeat(64),
    tokens: { in: 1, out: 1 },
    startedAt: "2026-05-07T12:00:00Z",
    completedAt: "2026-05-07T12:00:03Z",
    price: { amount: 50, currency: "USD" },
    attestation: {
      uri: ATT_URI,
      cid: "bafyreidqs7iyhjmkkdiekz5wlerpcjzmifgl2hpvgflzbcjfjsljbjlhmm",
    },
  };
  const message = new TextEncoder().encode(canonicalize(receiptUnsigned));
  // WebCrypto's sign returns IEEE P1363 raw r||s — convert to DER
  // before publishing so it matches the on-the-wire format that
  // CryptoKit/the Rust p256 crate produce.
  const rawSig = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, message),
  );
  const derSig = rawToDer(rawSig);
  const sigB64 = btoa(String.fromCharCode(...derSig));

  // Build the attestation body WITHOUT its selfSignature, then sign the
  // canonical bytes with the same enclave key — the AppView's verifyReceipt now
  // authenticates the attestation's own selfSignature (H4/H1), so the fixture
  // must carry a real one, not the receipt's signature.
  const attUnsigned = {
    publicKey: pubB64,
    encryptionPubKey: "B",
    chipName: "M3",
    hardwareModel: "Mac15,8",
    serialNumberHash: "d".repeat(64),
    osVersion: "15",
    binaryHash: "e".repeat(64),
    sipEnabled: true,
    secureBootEnabled: true,
    secureEnclaveAvailable: true,
    authenticatedRootEnabled: true,
    rdmaDisabled: true,
    attestedAt: "2026-05-07T11:00:00Z",
    expiresAt: "2026-05-08T11:00:00Z",
  };
  const attMessage = new TextEncoder().encode(canonicalize(attUnsigned));
  const attRawSig = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, attMessage),
  );
  const attSelfSigB64 = btoa(String.fromCharCode(...rawToDer(attRawSig)));
  const att = { ...attUnsigned, selfSignature: attSelfSigB64 };
  const receipt = { ...receiptUnsigned, enclaveSignature: sigB64 };
  return { RECEIPT_URI, JOB_URI, ATT_URI, job, att, receipt };
}

function rawToDer(rawSig: Uint8Array): Uint8Array {
  // P-256 raw is r||s, 32 bytes each.
  const r = rawSig.slice(0, 32);
  const s = rawSig.slice(32, 64);
  return new Uint8Array([0x30, ...lenAndInts(r, s)]);
}
function lenAndInts(r: Uint8Array, s: Uint8Array): number[] {
  const rEnc = encodeInteger(r);
  const sEnc = encodeInteger(s);
  return [rEnc.length + sEnc.length, ...rEnc, ...sEnc];
}
function encodeInteger(b: Uint8Array): number[] {
  // Strip leading zeros, then add a single 0x00 if the high bit is
  // set so DER doesn't read it as negative.
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  const trimmed = b.slice(i);
  const needsPad = (trimmed[0]! & 0x80) !== 0;
  return [0x02, trimmed.length + (needsPad ? 1 : 0), ...(needsPad ? [0x00] : []), ...trimmed];
}

async function withServer<T>(
  fn: (base: string, ctx: Awaited<ReturnType<typeof signedReceiptFixture>>) => Promise<T>,
): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), "cocore-api-"));
  const store = new Store(join(dir, "appview.db"));
  const ctx = await signedReceiptFixture();

  store.upsert({
    uri: ctx.JOB_URI,
    cid: "bafyreigh2akiscaildc5sgz5wybizysiehxiv4dhpwwqouytxnvgkpkcaq",
    collection: "dev.cocore.compute.job",
    repo: "did:plc:r",
    rkey: "1",
    body: ctx.job,
  });
  store.upsert({
    uri: ctx.ATT_URI,
    cid: "bafyreidqs7iyhjmkkdiekz5wlerpcjzmifgl2hpvgflzbcjfjsljbjlhmm",
    collection: "dev.cocore.compute.attestation",
    repo: "did:plc:p",
    rkey: "1",
    body: ctx.att,
  });
  store.upsert({
    uri: ctx.RECEIPT_URI,
    cid: "rcid",
    collection: "dev.cocore.compute.receipt",
    repo: "did:plc:p",
    rkey: "1",
    body: ctx.receipt,
  });

  return withAppviewServer(buildAppviewApp(store), async (base) => fn(base, ctx));
}

test("verifyReceipt happy path returns ok=true with real P-256 signature", async () => {
  await withServer(async (base, ctx) => {
    const url = `${base}/xrpc/dev.cocore.compute.verifyReceipt?uri=${encodeURIComponent(ctx.RECEIPT_URI)}`;
    const res = await fetch(url);
    assert.equal(res.status, 200);
    const body = (await res.json()) as { ok: boolean; findings: { code: string }[] };
    assert.equal(body.ok, true, JSON.stringify(body.findings));
    assert.ok(!body.findings.some((f) => f.code === "signature-invalid"));
  });
});

test("verifyReceipt rejects a tampered receipt at the signature check", async () => {
  // We can't reach into withServer's store, so we rebuild the
  // fixture standalone, mutate before upsert, and stand up a
  // throw-away server for the assertion.
  const dir = mkdtempSync(join(tmpdir(), "cocore-api-tamp-"));
  const store = new Store(join(dir, "appview.db"));
  const ctx = await signedReceiptFixture();
  // Flip a field that's covered by the signature but still passes
  // structural rules (model name; price + currency are unchanged).
  const tampered = { ...ctx.receipt, model: "mistakes-were-made" };
  store.upsert({
    uri: ctx.JOB_URI,
    cid: "bafyreigh2akiscaildc5sgz5wybizysiehxiv4dhpwwqouytxnvgkpkcaq",
    collection: "dev.cocore.compute.job",
    repo: "did:plc:r",
    rkey: "1",
    body: ctx.job,
  });
  store.upsert({
    uri: ctx.ATT_URI,
    cid: "bafyreidqs7iyhjmkkdiekz5wlerpcjzmifgl2hpvgflzbcjfjsljbjlhmm",
    collection: "dev.cocore.compute.attestation",
    repo: "did:plc:p",
    rkey: "1",
    body: ctx.att,
  });
  store.upsert({
    uri: ctx.RECEIPT_URI,
    cid: "rcid",
    collection: "dev.cocore.compute.receipt",
    repo: "did:plc:p",
    rkey: "1",
    body: tampered,
  });

  await withAppviewServer(buildAppviewApp(store), async (base) => {
    const res = await fetch(
      `${base}/xrpc/dev.cocore.compute.verifyReceipt?uri=${encodeURIComponent(ctx.RECEIPT_URI)}`,
    );
    assert.equal(res.status, 200);
    const body = (await res.json()) as { ok: boolean; findings: { code: string }[] };
    assert.equal(body.ok, false, "tampered receipt must fail verification");
    assert.ok(
      body.findings.some((f) => f.code === "signature-invalid"),
      `expected signature-invalid finding, got ${JSON.stringify(body.findings)}`,
    );
    // Also confirm: we'd have passed without the crypto check (the
    // structural rules don't catch a model-name swap — the lexicon
    // doesn't pin model — so the only thing rejecting this is the
    // P-256 verify).
    const onlyStructuralCodes = body.findings.filter((f) => f.code !== "signature-invalid");
    assert.equal(
      onlyStructuralCodes.length,
      1,
      `unexpected structural failures: ${JSON.stringify(onlyStructuralCodes)}`,
    );
    assert.equal(onlyStructuralCodes[0]!.code, "model-mismatch");
  });
});

test("H4: verifyReceipt rejects an attestation owned by a different repo than the receipt provider", async () => {
  // The attestation is authentic (real selfSignature) but lives in a DIFFERENT
  // repo than the receipt's provider — a borrowed/laundered attestation. The
  // AppView must bind attestation-owner to receipt-provider (the same tie the
  // exchange enforces) and report ok=false with attestation-owner-mismatch.
  const dir = mkdtempSync(join(tmpdir(), "cocore-api-owner-"));
  const store = new Store(join(dir, "appview.db"));
  const ctx = await signedReceiptFixture();
  store.upsert({
    uri: ctx.JOB_URI,
    cid: "bafyreigh2akiscaildc5sgz5wybizysiehxiv4dhpwwqouytxnvgkpkcaq",
    collection: "dev.cocore.compute.job",
    repo: "did:plc:r",
    rkey: "1",
    body: ctx.job,
  });
  // Attestation indexed under a foreign repo (did:plc:other), not the receipt
  // provider (did:plc:p).
  store.upsert({
    uri: ctx.ATT_URI,
    cid: "bafyreidqs7iyhjmkkdiekz5wlerpcjzmifgl2hpvgflzbcjfjsljbjlhmm",
    collection: "dev.cocore.compute.attestation",
    repo: "did:plc:other",
    rkey: "1",
    body: ctx.att,
  });
  store.upsert({
    uri: ctx.RECEIPT_URI,
    cid: "rcid",
    collection: "dev.cocore.compute.receipt",
    repo: "did:plc:p",
    rkey: "1",
    body: ctx.receipt,
  });

  await withAppviewServer(buildAppviewApp(store), async (base) => {
    const res = await fetch(
      `${base}/xrpc/dev.cocore.compute.verifyReceipt?uri=${encodeURIComponent(ctx.RECEIPT_URI)}`,
    );
    assert.equal(res.status, 200);
    const body = (await res.json()) as { ok: boolean; findings: { code: string }[] };
    assert.equal(body.ok, false, "borrowed attestation must fail verification");
    assert.ok(
      body.findings.some((f) => f.code === "attestation-owner-mismatch"),
      `expected attestation-owner-mismatch, got ${JSON.stringify(body.findings)}`,
    );
  });
});

test("verifyReceipt returns 404 for unknown URI", async () => {
  await withServer(async (base) => {
    const res = await fetch(`${base}/xrpc/dev.cocore.compute.verifyReceipt?uri=at%3A%2F%2Funknown`);
    assert.equal(res.status, 404);
  });
});

test("listProviders returns indexed providers", async () => {
  await withServer(async (base) => {
    const res = await fetch(`${base}/xrpc/dev.cocore.compute.listProviders`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as { providers: unknown[] };
    assert.equal(Array.isArray(body.providers), true);
  });
});

test("getReceipts filters by provider", async () => {
  await withServer(async (base) => {
    const res = await fetch(`${base}/xrpc/dev.cocore.compute.listReceipts?provider=did%3Aplc%3Ap`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as { receipts: unknown[] };
    assert.equal(body.receipts.length, 1);
  });
});

test("latency endpoint derives stats from receipt startedAt/completedAt", async () => {
  // The signed receipt fixture spans 12:00:00 → 12:00:03 = 3000ms.
  await withServer(async (base) => {
    const res = await fetch(`${base}/xrpc/dev.cocore.compute.latency`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as {
      overall: { sampleCount: number; p50Ms: number | null; lastMs: number | null };
      byProvider: Array<{ did: string; stats: { p50Ms: number | null } }>;
      byModel: Array<{ modelId: string; stats: { p50Ms: number | null } }>;
    };
    assert.equal(body.overall.sampleCount, 1);
    assert.equal(body.overall.p50Ms, 3000);
    assert.equal(body.overall.lastMs, 3000);
    const provider = body.byProvider.find((p) => p.did === "did:plc:p");
    assert.ok(provider, "expected a per-provider latency row for did:plc:p");
    assert.equal(provider!.stats.p50Ms, 3000);
    const model = body.byModel.find((m) => m.modelId === "m");
    assert.ok(model, "expected a per-model latency row for model 'm'");
    assert.equal(model!.stats.p50Ms, 3000);
  });
});

test("getProfile includes provider latency derived from receipts", async () => {
  const dir = mkdtempSync(join(tmpdir(), "cocore-latency-profile-"));
  const store = new Store(join(dir, "appview.db"));
  store.upsert({
    uri: "at://did:plc:alice/dev.cocore.account.tokenGrant/self",
    cid: "g",
    collection: "dev.cocore.account.tokenGrant",
    repo: "did:plc:alice",
    rkey: "self",
    body: { createdAt: "2026-05-01T00:00:00Z" },
  });
  // Two timed receipts: 1000ms and 3000ms → p50 over the 2-sample
  // window lands on 3000 (nearest-rank ceil), avg 2000.
  store.upsert({
    uri: "at://did:plc:alice/dev.cocore.compute.receipt/0",
    cid: "r0",
    collection: "dev.cocore.compute.receipt",
    repo: "did:plc:alice",
    rkey: "0",
    body: { model: "m", startedAt: "2026-05-07T12:00:00Z", completedAt: "2026-05-07T12:00:01Z" },
  });
  store.upsert({
    uri: "at://did:plc:alice/dev.cocore.compute.receipt/1",
    cid: "r1",
    collection: "dev.cocore.compute.receipt",
    repo: "did:plc:alice",
    rkey: "1",
    body: { model: "m", startedAt: "2026-05-07T12:00:00Z", completedAt: "2026-05-07T12:00:03Z" },
  });
  await withAppviewServer(buildAppviewApp(store), async (base) => {
    const res = await fetch(`${base}/xrpc/dev.cocore.account.getProfile?did=did:plc:alice`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as {
      profile: { latency: { sampleCount: number; avgMs: number | null } };
    };
    assert.equal(body.profile.latency.sampleCount, 2);
    assert.equal(body.profile.latency.avgMs, 2000);
  });
});

test("getJobs filters by requester repo", async () => {
  await withServer(async (base) => {
    const ok = await fetch(`${base}/xrpc/dev.cocore.compute.listJobs?requester=did%3Aplc%3Ar`);
    assert.equal(ok.status, 200);
    const body = (await ok.json()) as { jobs: { uri: string }[] };
    assert.equal(body.jobs.length, 1);
    assert.equal(body.jobs[0]!.uri, "at://did:plc:r/dev.cocore.compute.job/1");
    const miss = await fetch(
      `${base}/xrpc/dev.cocore.compute.listJobs?requester=did%3Aplc%3Aother`,
    );
    assert.equal(miss.status, 200);
    const empty = (await miss.json()) as { jobs: unknown[] };
    assert.equal(empty.jobs.length, 0);
  });
});

interface AccountSummaryWire {
  did: string;
  handle: string | null;
  displayName: string | null;
  avatarUrl: string | null;
  joinedAt: string;
  lastActivityAt: string;
  providerCount: number;
  isProvider: boolean;
}

/** Build a small AppView store pre-seeded with N synthetic signed-up
 *  DIDs. Each DID gets a tokenGrant (so it's in the directory),
 *  optionally a profile + provider records. Used by the listAccounts
 *  test suite. */
async function withAccountsStore(
  seed: Array<{
    did: string;
    handle?: string;
    displayName?: string;
    isProvider?: boolean;
  }>,
  fn: (base: string) => Promise<void>,
  friendEdges?: Array<{ friender: string; subject: string }>,
): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "cocore-api-accts-"));
  const store = new Store(join(dir, "appview.db"));
  for (const s of seed) {
    store.upsert({
      uri: `at://${s.did}/dev.cocore.account.tokenGrant/self`,
      cid: `cid-${s.did}-grant`,
      collection: "dev.cocore.account.tokenGrant",
      repo: s.did,
      rkey: "self",
      body: { createdAt: "2026-05-01T00:00:00Z" },
    });
    if (s.handle || s.displayName) {
      store.upsert({
        uri: `at://${s.did}/dev.cocore.account.profile/self`,
        cid: `cid-${s.did}-profile`,
        collection: "dev.cocore.account.profile",
        repo: s.did,
        rkey: "self",
        body: {
          handle: s.handle ?? null,
          displayName: s.displayName ?? null,
          createdAt: "2026-05-01T00:00:00Z",
        },
      });
    }
    if (s.isProvider) {
      store.upsert({
        uri: `at://${s.did}/dev.cocore.compute.provider/m1`,
        cid: `cid-${s.did}-provider`,
        collection: "dev.cocore.compute.provider",
        repo: s.did,
        rkey: "m1",
        body: { machineLabel: "test" },
      });
    }
  }
  for (const e of friendEdges ?? []) {
    const rk = `f${e.subject.replace(/[^a-z0-9]/gi, "")}`;
    store.upsert({
      uri: `at://${e.friender}/dev.cocore.account.friend/${rk}`,
      cid: `cid-friend-${e.friender}-${rk}`,
      collection: "dev.cocore.account.friend",
      repo: e.friender,
      rkey: rk,
      body: { subject: e.subject, createdAt: "2026-05-01T00:00:00Z" },
    });
  }
  await withAppviewServer(buildAppviewApp(store), fn);
}

test("listAccounts returns every signed-up DID with denormalized profile", async () => {
  await withAccountsStore(
    [
      { did: "did:plc:alice", handle: "alice.bsky.social", displayName: "Alice" },
      { did: "did:plc:bob", handle: "bob.bsky.social", isProvider: true },
    ],
    async (base) => {
      const res = await fetch(`${base}/xrpc/dev.cocore.account.listAccounts`);
      assert.equal(res.status, 200);
      const body = (await res.json()) as {
        accounts: AccountSummaryWire[];
        total: number;
        sortBy: string;
      };
      assert.equal(body.total, 2);
      assert.equal(body.sortBy, "recent");
      const byDid = Object.fromEntries(body.accounts.map((a) => [a.did, a]));
      assert.ok(byDid["did:plc:alice"]);
      assert.equal(byDid["did:plc:alice"]!.handle, "alice.bsky.social");
      assert.equal(byDid["did:plc:alice"]!.displayName, "Alice");
      assert.equal(byDid["did:plc:alice"]!.isProvider, false);
      assert.equal(byDid["did:plc:bob"]!.isProvider, true);
      assert.equal(byDid["did:plc:bob"]!.providerCount, 1);
    },
  );
});

test("listAccounts q= filters accounts by profile handle or DID substring", async () => {
  await withAccountsStore(
    [
      { did: "did:plc:alice", handle: "alice.bsky.social", displayName: "Alice" },
      { did: "did:plc:bob99", handle: "other.social", displayName: "Bob" },
    ],
    async (base) => {
      const byHandle = await fetch(
        `${base}/xrpc/dev.cocore.account.listAccounts?q=${encodeURIComponent("alice")}`,
      );
      assert.equal(byHandle.status, 200);
      const hBody = (await byHandle.json()) as {
        accounts: AccountSummaryWire[];
        total: number;
        q?: string;
      };
      assert.equal(hBody.q, "alice");
      assert.equal(hBody.total, 1);
      assert.equal(hBody.accounts.length, 1);
      assert.equal(hBody.accounts[0]!.did, "did:plc:alice");

      const byDid = await fetch(
        `${base}/xrpc/dev.cocore.account.listAccounts?q=${encodeURIComponent("bob99")}`,
      );
      const dBody = (await byDid.json()) as { accounts: AccountSummaryWire[]; total: number };
      assert.equal(dBody.total, 1);
      assert.equal(dBody.accounts[0]!.did, "did:plc:bob99");

      const noHit = await fetch(
        `${base}/xrpc/dev.cocore.account.listAccounts?q=${encodeURIComponent("zzz")}`,
      );
      const zBody = (await noHit.json()) as { accounts: AccountSummaryWire[]; total: number };
      assert.equal(zBody.total, 0);
      assert.equal(zBody.accounts.length, 0);
    },
  );
});

test("listAccounts viewerDid filter excludes self from the directory", async () => {
  await withAccountsStore(
    [{ did: "did:plc:alice" }, { did: "did:plc:bob" }, { did: "did:plc:carol" }],
    async (base) => {
      const res = await fetch(
        `${base}/xrpc/dev.cocore.account.listAccounts?viewerDid=${encodeURIComponent("did:plc:bob")}`,
      );
      const body = (await res.json()) as { accounts: AccountSummaryWire[]; total: number };
      assert.equal(body.total, 2);
      assert.equal(
        body.accounts.find((a) => a.did === "did:plc:bob"),
        undefined,
      );
    },
  );
});

test("listAccounts excludeViewerFriends omits DIDs the viewer has friended", async () => {
  await withAccountsStore(
    [{ did: "did:plc:alice" }, { did: "did:plc:bob" }, { did: "did:plc:carol" }],
    async (base) => {
      const all = await fetch(
        `${base}/xrpc/dev.cocore.account.listAccounts?viewerDid=${encodeURIComponent("did:plc:alice")}`,
      );
      const allBody = (await all.json()) as { accounts: AccountSummaryWire[]; total: number };
      assert.equal(allBody.total, 2);

      const filtered = await fetch(
        `${base}/xrpc/dev.cocore.account.listAccounts?viewerDid=${encodeURIComponent("did:plc:alice")}&excludeViewerFriends=true`,
      );
      const fBody = (await filtered.json()) as { accounts: AccountSummaryWire[]; total: number };
      assert.equal(fBody.total, 1);
      assert.equal(fBody.accounts.length, 1);
      assert.equal(fBody.accounts[0]!.did, "did:plc:carol");
    },
    [{ friender: "did:plc:alice", subject: "did:plc:bob" }],
  );
});

test("listAccounts providersOnly=true filters to DIDs with provider records", async () => {
  await withAccountsStore(
    [
      { did: "did:plc:requester" },
      { did: "did:plc:provider-a", isProvider: true },
      { did: "did:plc:provider-b", isProvider: true },
    ],
    async (base) => {
      const all = await fetch(`${base}/xrpc/dev.cocore.account.listAccounts`);
      const allBody = (await all.json()) as { total: number };
      assert.equal(allBody.total, 3);

      const onlyProviders = await fetch(
        `${base}/xrpc/dev.cocore.account.listAccounts?providersOnly=true`,
      );
      const opBody = (await onlyProviders.json()) as {
        accounts: AccountSummaryWire[];
        total: number;
      };
      assert.equal(opBody.total, 2);
      assert.ok(opBody.accounts.every((a) => a.isProvider));
    },
  );
});

test("listAccounts limit + offset paginate deterministically", async () => {
  await withAccountsStore(
    [
      { did: "did:plc:a" },
      { did: "did:plc:b" },
      { did: "did:plc:c" },
      { did: "did:plc:d" },
      { did: "did:plc:e" },
    ],
    async (base) => {
      const page1 = await fetch(`${base}/xrpc/dev.cocore.account.listAccounts?limit=2&offset=0`);
      const p1 = (await page1.json()) as { accounts: AccountSummaryWire[]; total: number };
      const page2 = await fetch(`${base}/xrpc/dev.cocore.account.listAccounts?limit=2&offset=2`);
      const p2 = (await page2.json()) as { accounts: AccountSummaryWire[]; total: number };
      assert.equal(p1.total, 5);
      assert.equal(p2.total, 5);
      assert.equal(p1.accounts.length, 2);
      assert.equal(p2.accounts.length, 2);
      // No DID appears on both pages.
      const overlap = p1.accounts
        .map((a) => a.did)
        .filter((d) => p2.accounts.some((b) => b.did === d));
      assert.equal(overlap.length, 0);
    },
  );
});

test("listAccounts limit caps at 100 even when a huge limit is requested", async () => {
  await withAccountsStore([{ did: "did:plc:a" }], async (base) => {
    const res = await fetch(`${base}/xrpc/dev.cocore.account.listAccounts?limit=99999`);
    const body = (await res.json()) as { limit: number };
    assert.equal(body.limit, 100);
  });
});

test("listAccounts includes DIDs whose only cocore footprint is a profile record (= OAuth'd in but no tokenGrant yet)", async () => {
  // Seed: alice has ONLY a profile record (the auto-provisioned
  // record from her first OAuth callback). No tokenGrant, no
  // compute records. Pre-fix this would have left her out of the
  // directory — post-fix she shows up because the source is "any
  // dev.cocore.* record under her repo."
  const dir = mkdtempSync(join(tmpdir(), "cocore-oauth-only-"));
  const store = new Store(join(dir, "appview.db"));
  store.upsert({
    uri: "at://did:plc:alice/dev.cocore.account.profile/self",
    cid: "cid-alice-profile",
    collection: "dev.cocore.account.profile",
    repo: "did:plc:alice",
    rkey: "self",
    body: {
      handle: "alice.bsky.social",
      displayName: "Alice",
      createdAt: "2026-05-01T00:00:00Z",
    },
  });
  await withAppviewServer(buildAppviewApp(store), async (base) => {
    const res = await fetch(`${base}/xrpc/dev.cocore.account.listAccounts`);
    const body = (await res.json()) as {
      accounts: AccountSummaryWire[];
      total: number;
    };
    assert.equal(body.total, 1);
    assert.equal(body.accounts[0]!.did, "did:plc:alice");
    assert.equal(body.accounts[0]!.handle, "alice.bsky.social");
  });
});

test("listAccounts hydrates handle + displayName from bsky when no local profile record exists", async () => {
  // Seed: alice OAuth'd in (has a profile) but bob only ever
  // dispatched a job — no profile record. The directory should
  // still surface bob's handle by hydrating through the public
  // bsky appview.
  const dir = mkdtempSync(join(tmpdir(), "cocore-hydrate-"));
  const store = new Store(join(dir, "appview.db"));
  store.upsert({
    uri: "at://did:plc:alice/dev.cocore.account.profile/self",
    cid: "cid-alice-profile",
    collection: "dev.cocore.account.profile",
    repo: "did:plc:alice",
    rkey: "self",
    body: {
      handle: "alice.bsky.social",
      displayName: "Alice",
      createdAt: "2026-05-01T00:00:00Z",
    },
  });
  store.upsert({
    uri: "at://did:plc:bob/dev.cocore.compute.job/3l1",
    cid: "cid-bob-job",
    collection: "dev.cocore.compute.job",
    repo: "did:plc:bob",
    rkey: "3l1",
    body: { model: "stub" },
  });

  mockBskyAppview({
    "did:plc:bob": { handle: "bob.bsky.social", displayName: "Bob" },
    // Alice is in the bsky appview too but we shouldn't ask — she
    // has a local profile already.
    "did:plc:alice": { handle: "WRONG_HANDLE_DO_NOT_USE" },
  });

  await withAppviewServer(buildAppviewApp(store), async (base) => {
    const res = await fetch(`${base}/xrpc/dev.cocore.account.listAccounts`);
    const body = (await res.json()) as { accounts: AccountSummaryWire[]; total: number };
    const byDid = Object.fromEntries(body.accounts.map((a) => [a.did, a]));
    // alice's local profile wins — bsky was not consulted.
    assert.equal(byDid["did:plc:alice"]!.handle, "alice.bsky.social");
    assert.equal(byDid["did:plc:alice"]!.displayName, "Alice");
    // bob's was hydrated from the bsky appview.
    assert.equal(byDid["did:plc:bob"]!.handle, "bob.bsky.social");
    assert.equal(byDid["did:plc:bob"]!.displayName, "Bob");
  });
});

test("listAccounts also includes DIDs whose only footprint is a compute record (API-direct users)", async () => {
  // Power user dispatched a job via the API before ever opening
  // the console. No profile, no grant — just a job record under
  // their repo. They should still show up in the directory.
  const dir = mkdtempSync(join(tmpdir(), "cocore-api-only-"));
  const store = new Store(join(dir, "appview.db"));
  store.upsert({
    uri: "at://did:plc:power/dev.cocore.compute.job/3lk5",
    cid: "cid-power-job",
    collection: "dev.cocore.compute.job",
    repo: "did:plc:power",
    rkey: "3lk5",
    body: { model: "stub", createdAt: "2026-05-01T00:00:00Z" },
  });
  await withAppviewServer(buildAppviewApp(store), async (base) => {
    const res = await fetch(`${base}/xrpc/dev.cocore.account.listAccounts`);
    const body = (await res.json()) as { accounts: AccountSummaryWire[]; total: number };
    assert.equal(body.total, 1);
    assert.equal(body.accounts[0]!.did, "did:plc:power");
    // No profile so handle is null.
    assert.equal(body.accounts[0]!.handle, null);
  });
});

interface ProfileWire {
  did: string;
  handle: string | null;
  displayName: string | null;
  bio: string | null;
  avatarUrl: string | null;
  joinedAt: string | null;
  lastActivityAt: string | null;
  machines: Array<{ rkey: string; machineLabel: string | null; supportedModels: string[] }>;
  jobCount: number;
  receiptCount: number;
  incomingFriendsCount: number;
  weekSeries: {
    oldestWeekStart: string;
    jobsDispatched: number[];
    receiptsServed: number[];
    machinesIndexedCumulative: number[];
    tokensIndexed: number[];
    trustedByNew: number[];
  };
}

test("getProfile returns 404 for a DID with no cocore footprint", async () => {
  await withAccountsStore([], async (base) => {
    const res = await fetch(
      `${base}/xrpc/dev.cocore.account.getProfile?did=${encodeURIComponent("did:plc:ghost")}`,
    );
    assert.equal(res.status, 404);
  });
});

test("getProfile returns 400 when did param is missing or malformed", async () => {
  await withAccountsStore([{ did: "did:plc:alice" }], async (base) => {
    const missing = await fetch(`${base}/xrpc/dev.cocore.account.getProfile`);
    assert.equal(missing.status, 400);
    const malformed = await fetch(`${base}/xrpc/dev.cocore.account.getProfile?did=not-a-did`);
    assert.equal(malformed.status, 400);
  });
});

test("getProfile aggregates profile + machines + activity counts for a signed-up DID", async () => {
  const dir = mkdtempSync(join(tmpdir(), "cocore-profile-"));
  const store = new Store(join(dir, "appview.db"));
  // Seed: alice signed up, has a profile, runs two machines, has
  // dispatched 3 jobs and produced 2 receipts. Two other DIDs
  // have friended her.
  store.upsert({
    uri: "at://did:plc:alice/dev.cocore.account.tokenGrant/self",
    cid: "g",
    collection: "dev.cocore.account.tokenGrant",
    repo: "did:plc:alice",
    rkey: "self",
    body: { createdAt: "2026-05-01T00:00:00Z" },
  });
  store.upsert({
    uri: "at://did:plc:alice/dev.cocore.account.profile/self",
    cid: "p",
    collection: "dev.cocore.account.profile",
    repo: "did:plc:alice",
    rkey: "self",
    body: {
      handle: "alice.bsky.social",
      displayName: "Alice",
      bio: "Building cocore",
      createdAt: "2026-05-01T00:00:00Z",
    },
  });
  for (let i = 0; i < 2; i += 1) {
    store.upsert({
      uri: `at://did:plc:alice/dev.cocore.compute.provider/m${i}`,
      cid: `mc${i}`,
      collection: "dev.cocore.compute.provider",
      repo: "did:plc:alice",
      rkey: `m${i}`,
      body: {
        machineLabel: `mac-${i}`,
        chip: "M4",
        ramGB: 64,
        supportedModels: ["stub", "qwen-3b"],
      },
    });
  }
  for (let i = 0; i < 3; i += 1) {
    store.upsert({
      uri: `at://did:plc:alice/dev.cocore.compute.job/${i}`,
      cid: `jc${i}`,
      collection: "dev.cocore.compute.job",
      repo: "did:plc:alice",
      rkey: `${i}`,
      body: { model: "stub" },
    });
  }
  for (let i = 0; i < 2; i += 1) {
    store.upsert({
      uri: `at://did:plc:alice/dev.cocore.compute.receipt/${i}`,
      cid: `rc${i}`,
      collection: "dev.cocore.compute.receipt",
      repo: "did:plc:alice",
      rkey: `${i}`,
      body: { model: "stub" },
    });
  }
  for (const friender of ["did:plc:bob", "did:plc:carol"]) {
    store.upsert({
      uri: `at://${friender}/dev.cocore.account.friend/x`,
      cid: `f-${friender}`,
      collection: "dev.cocore.account.friend",
      repo: friender,
      rkey: "x",
      body: { subject: "did:plc:alice", createdAt: "2026-05-10T00:00:00Z" },
    });
  }

  await withAppviewServer(buildAppviewApp(store), async (base) => {
    const res = await fetch(`${base}/xrpc/dev.cocore.account.getProfile?did=did:plc:alice`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as { profile: ProfileWire };
    assert.equal(body.profile.did, "did:plc:alice");
    assert.equal(body.profile.handle, "alice.bsky.social");
    assert.equal(body.profile.displayName, "Alice");
    assert.equal(body.profile.bio, "Building cocore");
    assert.equal(body.profile.machines.length, 2);
    assert.equal(body.profile.jobCount, 3);
    assert.equal(body.profile.receiptCount, 2);
    assert.equal(body.profile.incomingFriendsCount, 2);
    assert.equal(body.profile.weekSeries.jobsDispatched.length, 52);
    assert.equal(body.profile.weekSeries.receiptsServed.length, 52);
    const jobSum = body.profile.weekSeries.jobsDispatched.reduce((a, b) => a + b, 0);
    assert.equal(jobSum, 3);
    const receiptSum = body.profile.weekSeries.receiptsServed.reduce((a, b) => a + b, 0);
    assert.equal(receiptSum, 2);
    assert.equal(
      body.profile.weekSeries.trustedByNew.reduce((a, b) => a + b, 0),
      2,
    );
  });
});

test("listIncomingFriends returns DIDs that named the queried DID as subject", async () => {
  const dir = mkdtempSync(join(tmpdir(), "cocore-inbound-"));
  const store = new Store(join(dir, "appview.db"));
  // Three friend records targeting did:plc:alice (the viewer), one
  // unrelated friend record for noise.
  for (const friender of ["did:plc:bob", "did:plc:carol", "did:plc:dave"]) {
    store.upsert({
      uri: `at://${friender}/dev.cocore.account.friend/x`,
      cid: `f-${friender}`,
      collection: "dev.cocore.account.friend",
      repo: friender,
      rkey: "x",
      body: { subject: "did:plc:alice", createdAt: "2026-05-10T00:00:00Z" },
    });
  }
  store.upsert({
    uri: `at://did:plc:eve/dev.cocore.account.friend/y`,
    cid: `f-eve`,
    collection: "dev.cocore.account.friend",
    repo: "did:plc:eve",
    rkey: "y",
    body: { subject: "did:plc:someone-else", createdAt: "2026-05-10T00:00:00Z" },
  });

  await withAppviewServer(buildAppviewApp(store), async (base) => {
    const res = await fetch(
      `${base}/xrpc/dev.cocore.account.listIncomingFriends?did=did:plc:alice`,
    );
    assert.equal(res.status, 200);
    const body = (await res.json()) as {
      friends: Array<{ friender: string }>;
      total: number;
    };
    assert.equal(body.total, 3);
    const frienders = body.friends.map((f) => f.friender).sort();
    assert.deepEqual(frienders, ["did:plc:bob", "did:plc:carol", "did:plc:dave"]);
  });
});

test("listIncomingFriends collapses duplicate records from the same friender into one row", async () => {
  // Bob (the friender) rapid-fired the Friend button before the
  // post-write dedup in addFriend landed, ending up with three
  // friend records on his PDS all naming alice as subject. The
  // AppView's read path should fold them back into one row.
  const dir = mkdtempSync(join(tmpdir(), "cocore-inbound-dedup-"));
  const store = new Store(join(dir, "appview.db"));
  const timestamps = ["2026-05-10T00:00:00Z", "2026-05-10T00:00:01Z", "2026-05-10T00:00:02Z"];
  for (let i = 0; i < timestamps.length; i += 1) {
    store.upsert({
      uri: `at://did:plc:bob/dev.cocore.account.friend/dup${i}`,
      cid: `f-bob-${i}`,
      collection: "dev.cocore.account.friend",
      repo: "did:plc:bob",
      rkey: `dup${i}`,
      body: { subject: "did:plc:alice", createdAt: timestamps[i] },
    });
  }
  // One legit friend from a different DID — should still show.
  store.upsert({
    uri: `at://did:plc:carol/dev.cocore.account.friend/legit`,
    cid: "f-carol",
    collection: "dev.cocore.account.friend",
    repo: "did:plc:carol",
    rkey: "legit",
    body: { subject: "did:plc:alice", createdAt: "2026-05-11T00:00:00Z" },
  });

  await withAppviewServer(buildAppviewApp(store), async (base) => {
    const res = await fetch(
      `${base}/xrpc/dev.cocore.account.listIncomingFriends?did=did:plc:alice`,
    );
    const body = (await res.json()) as {
      friends: Array<{ friender: string; createdAt: string }>;
      total: number;
    };
    // Two frienders total — bob (collapsed from 3) + carol.
    assert.equal(body.total, 2);
    const bob = body.friends.find((f) => f.friender === "did:plc:bob");
    assert.ok(bob, "bob should appear once");
    // The OLDEST timestamp wins so the trust-started-on date is
    // stable across page refreshes.
    assert.equal(bob!.createdAt, "2026-05-10T00:00:00Z");
  });
});

test("getProfile.incomingFriendsCount counts distinct frienders, not raw records", async () => {
  const dir = mkdtempSync(join(tmpdir(), "cocore-inbound-count-"));
  const store = new Store(join(dir, "appview.db"));
  // Alice needs a tokenGrant so getProfile doesn't 404.
  store.upsert({
    uri: "at://did:plc:alice/dev.cocore.account.tokenGrant/self",
    cid: "g",
    collection: "dev.cocore.account.tokenGrant",
    repo: "did:plc:alice",
    rkey: "self",
    body: { createdAt: "2026-05-01T00:00:00Z" },
  });
  // Bob has three duplicate friend records targeting alice.
  for (let i = 0; i < 3; i += 1) {
    store.upsert({
      uri: `at://did:plc:bob/dev.cocore.account.friend/dup${i}`,
      cid: `f-bob-${i}`,
      collection: "dev.cocore.account.friend",
      repo: "did:plc:bob",
      rkey: `dup${i}`,
      body: { subject: "did:plc:alice", createdAt: "2026-05-10T00:00:00Z" },
    });
  }

  await withAppviewServer(buildAppviewApp(store), async (base) => {
    const res = await fetch(`${base}/xrpc/dev.cocore.account.getProfile?did=did:plc:alice`);
    const body = (await res.json()) as { profile: { incomingFriendsCount: number } };
    // One DISTINCT friender even with three records.
    assert.equal(body.profile.incomingFriendsCount, 1);
  });
});

test("indexer accepts dev.cocore.account.* records (not just compute.*)", async () => {
  // Direct integration test for the indexer's allowlist broadening:
  // a friend record should land in the store the same way a receipt
  // does.
  const { Indexer } = await import("../indexer/index.ts");
  const dir = mkdtempSync(join(tmpdir(), "cocore-ingest-"));
  const store = new Store(join(dir, "appview.db"));
  const indexer = new Indexer(store);
  const ok = indexer.ingest({
    uri: "at://did:plc:alice/dev.cocore.account.friend/abc",
    cid: "ff",
    collection: "dev.cocore.account.friend",
    repo: "did:plc:alice",
    rkey: "abc",
    record: { subject: "did:plc:bob", createdAt: "2026-05-10T00:00:00Z" },
  });
  assert.equal(ok, true);
  // And a non-cocore record should still be rejected.
  const nope = indexer.ingest({
    uri: "at://did:plc:alice/app.bsky.feed.post/abc",
    cid: "pp",
    collection: "app.bsky.feed.post",
    repo: "did:plc:alice",
    rkey: "abc",
    record: { text: "hi" },
  });
  assert.equal(nope, false);
});

test("listFriendEdges returns directed trust edges, excluding self-edges", async () => {
  await withAccountsStore(
    [
      { did: "did:plc:alice", handle: "alice.test" },
      { did: "did:plc:bob", handle: "bob.test", isProvider: true },
      { did: "did:plc:carol", handle: "carol.test", isProvider: true },
    ],
    async (base) => {
      const res = await fetch(`${base}/xrpc/dev.cocore.account.listFriendEdges`);
      assert.equal(res.status, 200);
      const body = (await res.json()) as {
        edges: Array<{ friender: string; subject: string; createdAt: string }>;
        total: number;
      };
      // alice→bob, bob→alice, carol→bob survive; alice→alice (self) is dropped.
      assert.equal(body.total, 3);
      const pairs = new Set(body.edges.map((e) => `${e.friender}>${e.subject}`));
      assert.ok(pairs.has("did:plc:alice>did:plc:bob"));
      assert.ok(pairs.has("did:plc:bob>did:plc:alice"));
      assert.ok(pairs.has("did:plc:carol>did:plc:bob"));
      assert.ok(!pairs.has("did:plc:alice>did:plc:alice"), "self-edge excluded");
      for (const e of body.edges) assert.equal(typeof e.createdAt, "string");
    },
    [
      { friender: "did:plc:alice", subject: "did:plc:bob" },
      { friender: "did:plc:bob", subject: "did:plc:alice" },
      { friender: "did:plc:carol", subject: "did:plc:bob" },
      { friender: "did:plc:alice", subject: "did:plc:alice" },
    ],
  );
});
