// Synthetic provider for the docker-compose stack.
//
// Every `COCORE_TICK_MS` ms (default 5s), publishes a fresh
// (paymentAuthorization, job, attestation, receipt) tuple into the
// bridge. The exchange picks up the receipt, charges via
// MockAdapter, and emits a settlement record back into the
// firehose. The AppView indexes everything; the smoke test asserts
// the chain closed.

import type { IndexedRecord } from "@cocore/sdk";

const BRIDGE = process.env["COCORE_BRIDGE_URL"] ?? "http://localhost:8080";
const TICK_MS = Number(process.env["COCORE_TICK_MS"] ?? 5000);
const EXCHANGE_DID = process.env["COCORE_EXCHANGE_DID"] ?? "did:web:exchange.local";
const PROVIDER_DID = process.env["COCORE_PROVIDER_DID"] ?? "did:plc:mock-provider";
const REQUESTER_DID = process.env["COCORE_REQUESTER_DID"] ?? "did:plc:mock-requester";

let attCount = 0;

async function publish(rec: IndexedRecord): Promise<void> {
  const res = await fetch(`${BRIDGE}/xrpc/dev.cocore.bridge.publish`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(process.env["COCORE_INTERNAL_API_KEY"]
        ? { authorization: `Bearer ${process.env["COCORE_INTERNAL_API_KEY"]}` }
        : {}),
    },
    body: JSON.stringify(rec),
  });
  if (!res.ok) {
    console.error(`publish failed: ${res.status} ${await res.text()}`);
  }
}

function rkey(): string {
  return [...crypto.getRandomValues(new Uint8Array(8))]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hash(_bytes: string): string {
  // SHA-like: 64 hex chars derived from a counter so receipts have
  // distinct commitments. The exchange doesn't validate the hash;
  // the canonical bytes are what matter.
  return [...crypto.getRandomValues(new Uint8Array(32))]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function publishAttestationIfNeeded(): Promise<{ uri: string; cid: string }> {
  // One attestation per process boot is enough for synthetic
  // receipts; in production a provider re-attests every 23h.
  if (attCount === 0) {
    attCount = 1;
    const k = rkey();
    const uri = `at://${PROVIDER_DID}/dev.cocore.compute.attestation/${k}`;
    const cid = `bafy-att-${k}`;
    await publish({
      uri,
      cid,
      collection: "dev.cocore.compute.attestation",
      repo: PROVIDER_DID,
      rkey: k,
      body: {
        publicKey: "AAAA",
        encryptionPubKey: "XXXX",
        chipName: "Apple M-mock",
        hardwareModel: "Mac-mock",
        serialNumberHash: hash("serial"),
        osVersion: "15.0",
        binaryHash: hash("binary"),
        sipEnabled: true,
        secureBootEnabled: true,
        secureEnclaveAvailable: true,
        authenticatedRootEnabled: true,
        selfSignature: "sigsig",
        attestedAt: new Date(Date.now() - 60_000).toISOString(),
        expiresAt: new Date(Date.now() + 23 * 3600 * 1000).toISOString(),
      },
    });
    return { uri, cid };
  }
  // Reuse the most recent — record fetch from store in a real
  // provider; here we just keep it in-process.
  return cachedAtt!;
}

let cachedAtt: { uri: string; cid: string } | null = null;

async function tick(): Promise<void> {
  if (!cachedAtt) cachedAtt = await publishAttestationIfNeeded();

  const authRkey = rkey();
  const authUri = `at://${REQUESTER_DID}/dev.cocore.compute.paymentAuthorization/${authRkey}`;
  await publish({
    uri: authUri,
    cid: `bafy-auth-${authRkey}`,
    collection: "dev.cocore.compute.paymentAuthorization",
    repo: REQUESTER_DID,
    rkey: authRkey,
    body: {
      exchange: EXCHANGE_DID,
      ceiling: { amount: 100, currency: "USD" },
      scope: "singleJob",
      nonce: rkey() + rkey(),
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      createdAt: new Date().toISOString(),
    },
  });

  const jobRkey = rkey();
  const jobUri = `at://${REQUESTER_DID}/dev.cocore.compute.job/${jobRkey}`;
  const inputCommit = hash("prompt");
  await publish({
    uri: jobUri,
    cid: `bafy-job-${jobRkey}`,
    collection: "dev.cocore.compute.job",
    repo: REQUESTER_DID,
    rkey: jobRkey,
    body: {
      model: "mock-model",
      inputCommitment: inputCommit,
      maxTokensOut: 1000,
      priceCeiling: { amount: 100, currency: "USD" },
      acceptedTrustLevel: "self-attested",
      paymentAuthorization: { uri: authUri, cid: `bafy-auth-${authRkey}` },
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      createdAt: new Date().toISOString(),
    },
  });

  const receiptRkey = rkey();
  const receiptUri = `at://${PROVIDER_DID}/dev.cocore.compute.receipt/${receiptRkey}`;
  const startedAt = new Date(Date.now() - 3000).toISOString();
  const completedAt = new Date().toISOString();
  await publish({
    uri: receiptUri,
    cid: `bafy-rcpt-${receiptRkey}`,
    collection: "dev.cocore.compute.receipt",
    repo: PROVIDER_DID,
    rkey: receiptRkey,
    body: {
      job: { uri: jobUri, cid: `bafy-job-${jobRkey}` },
      requester: REQUESTER_DID,
      model: "mock-model",
      inputCommitment: inputCommit,
      outputCommitment: hash("output"),
      tokens: { in: 32, out: 128 },
      startedAt,
      completedAt,
      price: { amount: 50, currency: "USD" },
      attestation: cachedAtt,
      enclaveSignature: "sigsig",
    },
  });

  console.error(`mock-provider: published receipt ${receiptUri}`);
}

async function main() {
  console.error(`mock-provider: bridge=${BRIDGE} tick=${TICK_MS}ms`);
  // Wait for bridge readiness.
  for (let i = 0; i < 30; i++) {
    try {
      const r = await fetch(`${BRIDGE}/healthz`);
      if (r.ok) break;
    } catch {
      /* not ready */
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  while (true) {
    try {
      await tick();
    } catch (e) {
      console.error(`tick error: ${(e as Error).message}`);
    }
    await new Promise((r) => setTimeout(r, TICK_MS));
  }
}

main();
