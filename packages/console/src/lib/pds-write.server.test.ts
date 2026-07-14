// Regression test for the single-owner OAuth cutover.
//
// The bug: `pdsGetServiceAuth` restored the DID's OAuth session LOCALLY on the
// console on every call. The agent re-mints a service-auth token on every
// advisor registration (~every 14 min), and a local restore refreshes the
// session — rotating the single-use DPoP refresh token out from under the
// AppView, which is the designated single owner/refresher. Two refreshers
// cannibalize one token → the session dies every few hours (browser logouts +
// agent 401s + `registrationAuthenticated` dropping → confidential/Secure off).
//
// The fix: when forwarding is configured, mint the token through the
// AppView-backed session (which replays via the AppView's owned session and
// refreshes nothing on the console). These tests lock that: with the forward
// configured the local restore is NEVER called; without it the legacy local
// path is preserved unchanged.

import { beforeEach, describe, expect, it, vi } from "vitest";

const state = {
  forwardConfigured: true,
  did: "did:plc:owner" as string,
  restoreCalls: 0,
  backedHandleCalls: 0,
};

vi.mock("@/lib/api-keys.server.ts", () => ({
  resolveBearerKey: (_bearer: string) => ({ did: state.did }),
}));

vi.mock("@/lib/appview-pds-forward.server.ts", () => ({
  isAppviewForwardConfigured: () => state.forwardConfigured,
  // unused on the getServiceAuth path but imported at module load
  forwardPdsWrite: async () => new Response("{}", { status: 200 }),
}));

vi.mock("@/lib/appview-backed-session.server.ts", () => ({
  appviewBackedSession: (did: string) => ({
    did,
    handle: async (_path: string, _init?: unknown) => {
      state.backedHandleCalls += 1;
      return new Response(JSON.stringify({ token: "appview-minted-token" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  }),
}));

vi.mock("@/integrations/auth/atproto.server.ts", async () => {
  const { Effect } = await import("effect");
  return {
    lastRestoreError: () => undefined,
    // If this ever runs while the forward is configured, the cannibalizing
    // second refresher is back — the test asserts it does NOT.
    restoreAtprotoSessionEffect: () =>
      Effect.sync(() => {
        state.restoreCalls += 1;
        return {
          did: state.did,
          handle: async () =>
            new Response(JSON.stringify({ token: "local-minted-token" }), {
              status: 200,
              headers: { "content-type": "application/json" },
            }),
        };
      }),
  };
});

async function callGetServiceAuth() {
  const { pdsGetServiceAuth } = await import("./pds-write.server.ts");
  const req = new Request("https://console.example/api/pds/getServiceAuth", {
    method: "POST",
    headers: { authorization: "Bearer k", "content-type": "application/json" },
    body: JSON.stringify({ aud: "did:web:advisor.cocore.dev", lxm: "dev.cocore.compute.register" }),
  });
  return pdsGetServiceAuth(req);
}

describe("pdsGetServiceAuth single-owner cutover", () => {
  beforeEach(() => {
    state.forwardConfigured = true;
    state.did = "did:plc:owner";
    state.restoreCalls = 0;
    state.backedHandleCalls = 0;
    delete process.env["COCORE_ADVISOR_DID"];
  });

  it("mints via the AppView-backed session and never restores locally when forwarding is configured", async () => {
    const res = await callGetServiceAuth();
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ token: "appview-minted-token" });
    expect(state.backedHandleCalls).toBe(1);
    expect(state.restoreCalls).toBe(0); // the cannibalizing second refresher stays dormant
  });

  it("falls back to the legacy local restore when forwarding is NOT configured", async () => {
    state.forwardConfigured = false;
    const res = await callGetServiceAuth();
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ token: "local-minted-token" });
    expect(state.restoreCalls).toBe(1);
    expect(state.backedHandleCalls).toBe(0);
  });
});
