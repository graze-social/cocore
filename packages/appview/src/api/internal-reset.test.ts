import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Server } from "node:http";

import { Store } from "../store.ts";
import { AccountStore } from "../operational/account-store.ts";
import { buildServer } from "./server.ts";

// Exercises POST /internal/account/reset-did — the AppView half of the
// console's "reset connection" repair flow. The route is gated on the
// shared internal secret (console<->AppView trust boundary), so we build
// the server with one and present it via the x-cocore-internal-secret
// header.

const SECRET = "test-internal-secret";
const ALICE = "did:plc:alice";
const BOB = "did:plc:bob";

let server: Server | undefined;
let base = "";
let accountStore: AccountStore;

function startServer(): Promise<{ base: string; server: Server }> {
  const store = new Store(":memory:");
  accountStore = new AccountStore(":memory:");
  const srv = buildServer(store, {
    accountStore,
    appviewDid: "did:web:appview.test",
    internalSecret: SECRET,
  });
  return new Promise((resolve) => {
    srv.listen(0, () => {
      const addr = srv.address();
      if (typeof addr === "string" || !addr) throw new Error("no address");
      resolve({ base: `http://127.0.0.1:${addr.port}`, server: srv });
    });
  });
}

beforeEach(async () => {
  const s = await startServer();
  server = s.server;
  base = s.base;
});

afterEach(() => {
  server?.close();
  server = undefined;
});

function resetReq(body: unknown, secret: string | null): Promise<Response> {
  return fetch(`${base}/internal/account/reset-did`, {
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
    expect((await resetReq({ did: ALICE }, null)).status).toBe(403);
    expect((await resetReq({ did: ALICE }, "wrong")).status).toBe(403);
  });

  it("requires a did", async () => {
    expect((await resetReq({}, SECRET)).status).toBe(400);
    expect((await resetReq({ did: "not-a-did" }, SECRET)).status).toBe(400);
  });

  it("revokes the DID's keys + drops its session, leaving other DIDs intact", async () => {
    const a = accountStore.createKey({ did: ALICE, name: "laptop" });
    accountStore.putOAuthSession(ALICE, '{"dpop":"v1"}');
    const b = accountStore.createKey({ did: BOB, name: "desktop" });
    accountStore.putOAuthSession(BOB, '{"dpop":"v1"}');

    const res = await resetReq({ did: ALICE }, SECRET);
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
