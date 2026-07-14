import { test } from "vitest";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../store.ts";
import { AccountStore } from "../operational/account-store.ts";
import { buildAppviewApp } from "./server.ts";
import { withAppviewServer } from "./http-app.ts";

const APPVIEW_DID = "did:web:appview.test";

/** Stand up a stub advisor whose `/providers` returns `rows`, run `fn` with its
 *  base URL, then tear it down. Mirrors the real advisor's response shape. */
async function withStubAdvisor(
  rows: unknown[],
  fn: (advisorUrl: string) => Promise<void>,
): Promise<void> {
  const server = createServer((req, res) => {
    if (req.url?.startsWith("/providers")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(rows));
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

interface ConfidentialStatusBody {
  confidentialVerified: boolean;
  confidentialDesired: boolean;
  confidentialBlockedReason: string | null;
  needsReauth: boolean;
}

function setup(): { store: Store; accountStore: AccountStore } {
  const dir = mkdtempSync(join(tmpdir(), "cocore-agent-status-"));
  return {
    store: new Store(join(dir, "appview.db")),
    accountStore: new AccountStore(join(dir, "account.db")),
  };
}

interface StatusBody {
  did: string;
  currency: string;
  balance: number | null;
  earned24h: number;
  trustLevel: string | null;
  agentVersion: string | null;
}

test("GET /api/agent/status: 401 without a bearer key", async () => {
  const { store, accountStore } = setup();
  await withAppviewServer(
    buildAppviewApp(store, { accountStore, appviewDid: APPVIEW_DID }),
    async (base) => {
      const res = await fetch(`${base}/api/agent/status`);
      assert.equal(res.status, 401);
    },
  );
});

test("GET /api/agent/status: 401 for an unknown key", async () => {
  const { store, accountStore } = setup();
  await withAppviewServer(
    buildAppviewApp(store, { accountStore, appviewDid: APPVIEW_DID }),
    async (base) => {
      const res = await fetch(`${base}/api/agent/status`, {
        headers: { authorization: "Bearer cocore-totally-bogus" },
      });
      assert.equal(res.status, 401);
    },
  );
});

test("GET /api/agent/status: resolves an AppView-minted key and reports provider status", async () => {
  const { store, accountStore } = setup();
  const did = "did:plc:provider1";
  const { secret } = accountStore.createKey({ did, name: "test machine" });
  store.upsert({
    uri: `at://${did}/dev.cocore.compute.provider/m1`,
    cid: "cid-prov",
    collection: "dev.cocore.compute.provider",
    repo: did,
    rkey: "m1",
    body: { trustLevel: "hardware-attested", binaryVersion: "1.2.3" },
  });
  await withAppviewServer(
    buildAppviewApp(store, { accountStore, appviewDid: APPVIEW_DID }),
    async (base) => {
      const res = await fetch(`${base}/api/agent/status`, {
        headers: { authorization: `Bearer ${secret}` },
      });
      assert.equal(res.status, 200);
      const body = (await res.json()) as StatusBody;
      assert.equal(body.did, did);
      assert.equal(body.currency, "credits");
      assert.equal(body.trustLevel, "hardware-attested");
      assert.equal(body.agentVersion, "1.2.3");
      // No bridgeUrl wired in the test → ledger reads degrade, not throw.
      assert.equal(body.earned24h, 0);
      assert.equal(body.balance, null);
    },
  );
});

test("confidential-desired machine registered unauthenticated ⇒ 'sign in again', not 'not connected'", async () => {
  const { store, accountStore } = setup();
  const did = "did:plc:reauth";
  const { secret } = accountStore.createKey({ did, name: "The Cauldron" });
  // Owner opted into confidential (desiredTier on the provider record).
  store.upsert({
    uri: `at://${did}/dev.cocore.compute.provider/m1`,
    cid: "cid-prov",
    collection: "dev.cocore.compute.provider",
    repo: did,
    rkey: "m1",
    body: { desiredTier: "attested-confidential", binaryVersion: "0.9.41" },
  });
  // The machine IS live on the advisor, but its registration didn't prove the
  // DID (dead OAuth session ⇒ no service-auth JWT). Legs are irrelevant here.
  const rows = [
    {
      did,
      confidentialEligible: false,
      registrationAuthenticated: false,
      confidentialLegs: {
        selfTierConfidential: false,
        cdHashKnownGood: false,
        challengeVerifiedSip: true,
        codeAttested: false,
      },
    },
  ];
  await withStubAdvisor(rows, async (advisorUrl) => {
    await withAppviewServer(
      buildAppviewApp(store, { accountStore, appviewDid: APPVIEW_DID, advisorUrl }),
      async (base) => {
        const res = await fetch(`${base}/api/agent/status`, {
          headers: { authorization: `Bearer ${secret}` },
        });
        assert.equal(res.status, 200);
        const body = (await res.json()) as ConfidentialStatusBody;
        assert.equal(body.confidentialVerified, false);
        assert.equal(body.confidentialDesired, true);
        assert.equal(body.needsReauth, true);
        assert.match(body.confidentialBlockedReason ?? "", /sign in again/i);
        assert.doesNotMatch(
          body.confidentialBlockedReason ?? "",
          /connected to the co\/core network/i,
        );
      },
    );
  });
});

test("authenticated-but-still-attesting machine shows the per-leg reason, not re-auth", async () => {
  const { store, accountStore } = setup();
  const did = "did:plc:attesting";
  const { secret } = accountStore.createKey({ did, name: "machine" });
  store.upsert({
    uri: `at://${did}/dev.cocore.compute.provider/m1`,
    cid: "cid-prov",
    collection: "dev.cocore.compute.provider",
    repo: did,
    rkey: "m1",
    body: { desiredTier: "attested-confidential", binaryVersion: "0.9.41" },
  });
  // Authenticated registration, confidential worker up, SIP + cdHash fine, but
  // the code-identity challenge hasn't landed yet.
  const rows = [
    {
      did,
      confidentialEligible: false,
      registrationAuthenticated: true,
      confidentialLegs: {
        selfTierConfidential: true,
        cdHashKnownGood: true,
        challengeVerifiedSip: true,
        codeAttested: false,
      },
    },
  ];
  await withStubAdvisor(rows, async (advisorUrl) => {
    await withAppviewServer(
      buildAppviewApp(store, { accountStore, appviewDid: APPVIEW_DID, advisorUrl }),
      async (base) => {
        const res = await fetch(`${base}/api/agent/status`, {
          headers: { authorization: `Bearer ${secret}` },
        });
        const body = (await res.json()) as ConfidentialStatusBody;
        assert.equal(body.needsReauth, false);
        assert.match(body.confidentialBlockedReason ?? "", /code-identity challenge/i);
      },
    );
  });
});

test("GET /agent/status (no /api prefix) is also served", async () => {
  const { store, accountStore } = setup();
  const did = "did:plc:provider2";
  const { secret } = accountStore.createKey({ did, name: "test machine" });
  await withAppviewServer(
    buildAppviewApp(store, { accountStore, appviewDid: APPVIEW_DID }),
    async (base) => {
      const res = await fetch(`${base}/agent/status`, {
        headers: { authorization: `Bearer ${secret}` },
      });
      assert.equal(res.status, 200);
      const body = (await res.json()) as StatusBody;
      assert.equal(body.did, did);
      assert.equal(body.trustLevel, null);
      assert.equal(body.agentVersion, null);
    },
  );
});
