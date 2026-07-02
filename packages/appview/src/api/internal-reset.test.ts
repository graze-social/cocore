import { describe, expect, it } from "vitest";

import { Store } from "../store.ts";
import { AccountStore } from "../operational/account-store.ts";
import { buildAppviewApp } from "./server.ts";
import { withAppviewServer } from "./http-app.ts";

// Exercises POST /internal/account/reset-did — the AppView half of the
// console's "reset connection" repair flow. The route is gated on the
// shared internal secret (console<->AppView trust boundary), so we build
// the app with one and present it via the x-cocore-internal-secret header.

// >= 32 chars: the AppView refuses to mount /internal/* behind a weaker
// secret (H5), so the test secret must clear that bar.
const SECRET = "test-internal-secret-0123456789abcdef";
const ALICE = "did:plc:alice";
const BOB = "did:plc:bob";

/** Stand up the AppView app (with the internal secret enabled) on an
 *  ephemeral port and hand the test the base URL + the backing store. */
function withReset(
  fn: (ctx: { base: string; accountStore: AccountStore }) => Promise<void>,
): Promise<void> {
  const store = new Store(":memory:");
  const accountStore = new AccountStore(":memory:");
  const app = buildAppviewApp(store, {
    accountStore,
    appviewDid: "did:web:appview.test",
    internalSecret: SECRET,
  });
  return withAppviewServer(app, (base) => fn({ base, accountStore }));
}

function resetReq(base: string, body: unknown, secret: string | null): Promise<Response> {
  return fetch(`${base}/internal/account/reset-did`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(secret ? { "x-cocore-internal-secret": secret } : {}),
    },
    body: JSON.stringify(body),
  });
}

function resolveKeyReq(base: string, body: unknown, secret: string | null): Promise<Response> {
  return fetch(`${base}/internal/account/resolve-key`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(secret ? { "x-cocore-internal-secret": secret } : {}),
    },
    body: JSON.stringify(body),
  });
}

describe("POST /internal/account/reset-did", () => {
  it("rejects a missing/wrong secret with 403", async () => {
    await withReset(async ({ base }) => {
      expect((await resetReq(base, { did: ALICE }, null)).status).toBe(403);
      expect((await resetReq(base, { did: ALICE }, "wrong")).status).toBe(403);
    });
  });

  it("requires a did", async () => {
    await withReset(async ({ base }) => {
      expect((await resetReq(base, {}, SECRET)).status).toBe(400);
      expect((await resetReq(base, { did: "not-a-did" }, SECRET)).status).toBe(400);
    });
  });

  it("revokes the DID's keys + drops its session, leaving other DIDs intact", async () => {
    await withReset(async ({ base, accountStore }) => {
      const a = accountStore.createKey({ did: ALICE, name: "laptop" });
      accountStore.putOAuthSession(ALICE, '{"dpop":"v1"}');
      const b = accountStore.createKey({ did: BOB, name: "desktop" });
      accountStore.putOAuthSession(BOB, '{"dpop":"v1"}');

      const res = await resetReq(base, { did: ALICE }, SECRET);
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ ok: true, keysRevoked: 1 });

      // Alice is fully reset.
      expect(accountStore.resolveBearerKey(a.secret)).toBeNull();
      expect(accountStore.getOAuthSession(ALICE)).toBeNull();

      // Bob is untouched.
      expect(accountStore.resolveBearerKey(b.secret)?.did).toBe(BOB);
      expect(accountStore.getOAuthSession(BOB)).toBe('{"dpop":"v1"}');
    });
  });
});

// The console's inference path calls this so an AppView-minted key (which
// lands in account.db, not console.db) still authenticates at
// cocore.dev/v1/chat/completions.
describe("POST /internal/account/resolve-key", () => {
  it("rejects a missing/wrong secret with 403", async () => {
    await withReset(async ({ base }) => {
      expect((await resolveKeyReq(base, { key: "x" }, null)).status).toBe(403);
      expect((await resolveKeyReq(base, { key: "x" }, "wrong")).status).toBe(403);
    });
  });

  it("requires a key", async () => {
    await withReset(async ({ base }) => {
      expect((await resolveKeyReq(base, {}, SECRET)).status).toBe(400);
      expect((await resolveKeyReq(base, { key: "" }, SECRET)).status).toBe(400);
    });
  });

  it("resolves a live key to its owning DID", async () => {
    await withReset(async ({ base, accountStore }) => {
      const a = accountStore.createKey({ did: ALICE, name: "laptop" });
      const res = await resolveKeyReq(base, { key: a.secret }, SECRET);
      expect(res.status).toBe(200);
      expect(await res.json()).toMatchObject({ did: ALICE, name: "laptop" });
    });
  });

  it("404s an unknown or revoked key", async () => {
    await withReset(async ({ base, accountStore }) => {
      expect((await resolveKeyReq(base, { key: "cocore-nope" }, SECRET)).status).toBe(404);
      const a = accountStore.createKey({ did: ALICE, name: "laptop" });
      accountStore.revokeAllKeysForDid(ALICE);
      expect((await resolveKeyReq(base, { key: a.secret }, SECRET)).status).toBe(404);
    });
  });
});
