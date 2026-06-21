import { describe, expect, it } from "vitest";
import { HttpRouter } from "@effect/platform";

import { AccountStore } from "../operational/account-store.ts";
import type { AppviewOAuthClient } from "../auth/oauth-client.ts";
import { withAppviewServer } from "../api/http-app.ts";
import { buildInternalPdsRouter, buildPdsRouter, buildProxyAliasRouter } from "./write.ts";

const ALICE = "did:plc:alice";
const INTERNAL_SECRET = "test-internal-secret";

/** A fake OAuth client whose restored session echoes the repo call it
 *  received, so tests can assert what would have hit the PDS. `restore`
 *  returns null for `nullFor` DIDs (simulates an expired session). */
function fakeOauth(
  opts: {
    reply?: (path: string, payload: unknown) => { status: number; body: unknown };
    nullFor?: Set<string>;
  } = {},
): AppviewOAuthClient {
  const reply =
    opts.reply ??
    ((path, payload) => {
      const p = payload as { collection?: string; rkey?: string };
      if (path.endsWith("createRecord")) {
        return {
          status: 200,
          body: {
            uri: `at://${ALICE}/${p.collection}/rk`,
            cid: "bafycid",
            commit: { cid: "c", rev: "r" },
          },
        };
      }
      if (path.endsWith("putRecord")) {
        return {
          status: 200,
          body: { uri: `at://${ALICE}/${p.collection}/${p.rkey}`, cid: "bafycid" },
        };
      }
      return { status: 200, body: {} };
    });
  return {
    restore: async (did: string) => {
      if (opts.nullFor?.has(did)) throw new Error("no session");
      return {
        handle: async (path: string, init: { body?: string }) => {
          const payload = init.body ? JSON.parse(init.body) : {};
          const { status, body } = reply(path, payload);
          return new Response(JSON.stringify(body), {
            status,
            headers: { "content-type": "application/json" },
          });
        },
      };
    },
  } as unknown as AppviewOAuthClient;
}

/** Build an in-memory AccountStore + router and hand the running server's
 *  base URL (and the minted bearer secret) to `fn`. The server is torn
 *  down when `fn` resolves. */
async function withServer(
  oauth: AppviewOAuthClient | undefined,
  fn: (base: string, secret: string) => Promise<void>,
): Promise<void> {
  const accounts = new AccountStore(":memory:");
  const { secret } = accounts.createKey({ did: ALICE, name: "agent" });
  const ctx = { accounts, oauth: oauth ?? fakeOauth() };
  const proxyAlias = buildProxyAliasRouter(ctx);
  const router = HttpRouter.empty.pipe(
    HttpRouter.concat(buildPdsRouter(ctx)),
    HttpRouter.concat(buildInternalPdsRouter(ctx, INTERNAL_SECRET)),
    // Mirror server.ts: the deprecated proxy alias is served bare and under /api.
    HttpRouter.concat(proxyAlias),
    HttpRouter.concat(proxyAlias.pipe(HttpRouter.prefixAll("/api"))),
  );
  await withAppviewServer(router, (base) => fn(base, secret));
}

function post(base: string, path: string, secret: string | null, body: unknown): Promise<Response> {
  return fetch(`${base}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(secret ? { authorization: `Bearer ${secret}` } : {}),
    },
    body: JSON.stringify(body),
  });
}

describe("/pds/* write endpoints", () => {
  it("createRecord writes via the session and returns uri/cid/commit", async () => {
    await withServer(undefined, async (base, secret) => {
      const r = await post(base, "/pds/createRecord", secret, {
        collection: "dev.cocore.compute.receipt",
        record: { foo: 1 },
      });
      expect(r.status).toBe(200);
      expect((await r.json()) as unknown).toMatchObject({ cid: "bafycid", commit: { rev: "r" } });
    });
  });

  it("putRecord requires an rkey and echoes it back", async () => {
    await withServer(undefined, async (base, secret) => {
      const ok = await post(base, "/pds/putRecord", secret, {
        collection: "dev.cocore.compute.provider",
        rkey: "self",
        record: { a: 1 },
      });
      expect(((await ok.json()) as { uri: string }).uri).toContain("/self");

      const noRkey = await post(base, "/pds/putRecord", secret, {
        collection: "dev.cocore.compute.provider",
        record: {},
      });
      expect(noRkey.status).toBe(400);
    });
  });

  it("deleteRecord returns the uri", async () => {
    await withServer(undefined, async (base, secret) => {
      const r = await post(base, "/pds/deleteRecord", secret, {
        collection: "dev.cocore.account.profile",
        rkey: "self",
      });
      expect(r.status).toBe(200);
      expect(((await r.json()) as { uri: string }).uri).toBe(
        `at://${ALICE}/dev.cocore.account.profile/self`,
      );
    });
  });

  it("401s without a valid bearer key", async () => {
    await withServer(undefined, async (base) => {
      expect((await post(base, "/pds/createRecord", null, {})).status).toBe(401);
      expect((await post(base, "/pds/createRecord", "cocore-bogus", {})).status).toBe(401);
    });
  });

  it("401s when the OAuth session can't be restored", async () => {
    await withServer(fakeOauth({ nullFor: new Set([ALICE]) }), async (base, secret) => {
      const r = await post(base, "/pds/createRecord", secret, {
        collection: "dev.cocore.compute.job",
        record: {},
      });
      expect(r.status).toBe(401);
    });
  });

  it("400s a collection outside dev.cocore.*", async () => {
    await withServer(undefined, async (base, secret) => {
      const r = await post(base, "/pds/createRecord", secret, {
        collection: "app.bsky.feed.post",
        record: {},
      });
      expect(r.status).toBe(400);
    });
  });

  it("405s on the wrong method", async () => {
    await withServer(undefined, async (base) => {
      expect((await fetch(`${base}/pds/createRecord`)).status).toBe(405);
    });
  });
});

describe("deprecated dev.cocore.proxy.* aliases", () => {
  // These are the exact paths older agents (apiBase → AppView) still POST to;
  // they were 404ing before the alias was mounted. Same auth + cores as /pds/*.
  it("putRecord works at /api/xrpc/dev.cocore.proxy.putRecord (the live 404 path)", async () => {
    await withServer(undefined, async (base, secret) => {
      const r = await post(base, "/api/xrpc/dev.cocore.proxy.putRecord", secret, {
        collection: "dev.cocore.compute.provider",
        rkey: "self",
        record: { a: 1 },
      });
      expect(r.status).toBe(200);
      expect(((await r.json()) as { uri: string }).uri).toContain("/self");
    });
  });

  it("createRecord + deleteRecord are served under the proxy alias", async () => {
    await withServer(undefined, async (base, secret) => {
      const created = await post(base, "/api/xrpc/dev.cocore.proxy.createRecord", secret, {
        collection: "dev.cocore.compute.receipt",
        record: { foo: 1 },
      });
      expect(created.status).toBe(200);

      const deleted = await post(base, "/api/xrpc/dev.cocore.proxy.deleteRecord", secret, {
        collection: "dev.cocore.account.profile",
        rkey: "self",
      });
      expect(deleted.status).toBe(200);
    });
  });

  it("still enforces bearer auth on the alias", async () => {
    await withServer(undefined, async (base) => {
      const r = await post(base, "/api/xrpc/dev.cocore.proxy.putRecord", null, {
        collection: "dev.cocore.compute.provider",
        rkey: "self",
        record: {},
      });
      expect(r.status).toBe(401);
    });
  });
});

describe("/internal/pds/* (trusted-DID write)", () => {
  function ipost(base: string, path: string, secret: string | null, b: unknown): Promise<Response> {
    return fetch(`${base}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(secret ? { "x-cocore-internal-secret": secret } : {}),
      },
      body: JSON.stringify(b),
    });
  }

  it("writes with the secret + an asserted did", async () => {
    await withServer(undefined, async (base) => {
      const r = await ipost(base, "/internal/pds/createRecord", INTERNAL_SECRET, {
        did: ALICE,
        collection: "dev.cocore.compute.receipt",
        record: { x: 1 },
      });
      expect(r.status).toBe(200);
      expect((await r.json()) as unknown).toMatchObject({ cid: "bafycid" });
    });
  });

  it("403 without the internal secret", async () => {
    await withServer(undefined, async (base) => {
      const r = await ipost(base, "/internal/pds/createRecord", null, {
        did: ALICE,
        collection: "dev.cocore.compute.job",
        record: {},
      });
      expect(r.status).toBe(403);
    });
  });

  it("400 without an asserted did", async () => {
    await withServer(undefined, async (base) => {
      const r = await ipost(base, "/internal/pds/createRecord", INTERNAL_SECRET, {
        collection: "dev.cocore.compute.job",
        record: {},
      });
      expect(r.status).toBe(400);
    });
  });

  it("401 when the session can't restore", async () => {
    await withServer(fakeOauth({ nullFor: new Set([ALICE]) }), async (base) => {
      const r = await ipost(base, "/internal/pds/createRecord", INTERNAL_SECRET, {
        did: ALICE,
        collection: "dev.cocore.compute.job",
        record: {},
      });
      expect(r.status).toBe(401);
    });
  });
});
