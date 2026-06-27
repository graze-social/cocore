// Unit coverage for the AppView account-store key fallback. The console's
// inference path calls this after a local console.db miss so a key minted
// via the documented AppView createApiKey still authenticates.

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { resolveBearerKeyViaAppview } from "./api-keys-appview.server.ts";

const BASE = "http://appview.internal";
const SECRET = "shh-internal";

beforeEach(() => {
  process.env["COCORE_APPVIEW_INTERNAL_URL"] = BASE;
  process.env["COCORE_INTERNAL_SECRET"] = SECRET;
});

afterEach(() => {
  delete process.env["COCORE_APPVIEW_INTERNAL_URL"];
  delete process.env["COCORE_INTERNAL_SECRET"];
  vi.unstubAllGlobals();
});

describe("resolveBearerKeyViaAppview", () => {
  test("returns null without making a call when the channel is unconfigured", async () => {
    delete process.env["COCORE_APPVIEW_INTERNAL_URL"];
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    expect(await resolveBearerKeyViaAppview("cocore-abc")).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test("skips the round-trip for a non-cocore bearer (e.g. a JWT)", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    expect(await resolveBearerKeyViaAppview("header.payload.sig")).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test("resolves a key, forwarding the internal secret + key body", async () => {
    const fetchSpy = vi.fn(async (_url: string, init: RequestInit) => {
      expect((init.headers as Record<string, string>)["x-cocore-internal-secret"]).toBe(SECRET);
      expect(JSON.parse(init.body as string)).toEqual({ key: "cocore-good" });
      return new Response(JSON.stringify({ id: "k1", did: "did:plc:abc", name: "laptop" }), {
        status: 200,
      });
    });
    vi.stubGlobal("fetch", fetchSpy);
    expect(await resolveBearerKeyViaAppview("cocore-good")).toEqual({
      id: "k1",
      did: "did:plc:abc",
      name: "laptop",
    });
    expect(fetchSpy).toHaveBeenCalledWith(
      `${BASE}/internal/account/resolve-key`,
      expect.objectContaining({ method: "POST" }),
    );
  });

  test("returns null on a 404 (unknown/revoked/expired key)", async () => {
    vi.stubGlobal("fetch", async () => new Response("{}", { status: 404 }));
    expect(await resolveBearerKeyViaAppview("cocore-missing")).toBeNull();
  });

  test("returns null when the AppView is unreachable", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new Error("ECONNREFUSED");
    });
    expect(await resolveBearerKeyViaAppview("cocore-blip")).toBeNull();
  });

  test("returns null when the response omits a did", async () => {
    vi.stubGlobal(
      "fetch",
      async () => new Response(JSON.stringify({ name: "x" }), { status: 200 }),
    );
    expect(await resolveBearerKeyViaAppview("cocore-weird")).toBeNull();
  });
});
