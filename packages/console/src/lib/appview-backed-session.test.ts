// Unit tests for the AppView-backed session shim. Pure (mocked fetch) — no
// SQLite — so it validates the console half of the single-owner cutover:
// the proxy envelope it builds, the Response it reconstructs, and the
// session-info liveness signal. The integration path (real AppView owning
// the session) is covered by the appview package's internal-pds tests.

import type { Did } from "@atcute/lexicons";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  appviewBackedSession,
  appviewSessionInfo,
  resetAppviewSessionInfoCache,
} from "./appview-backed-session.server.ts";

const DID = "did:plc:abc123" as Did;
const BASE = "http://appview.internal:8081";
const SECRET = "shh";

type ShimLike = {
  did: string;
  handle: (
    path: string,
    init?: { method?: string; headers?: HeadersInit; body?: BodyInit },
  ) => Promise<Response>;
  getTokenInfo: () => Promise<{ aud: string }>;
};

function shim(): ShimLike {
  return appviewBackedSession(DID) as unknown as ShimLike;
}

/** Capture the single fetch call + return a canned proxy/session-info reply. */
function mockFetch(reply: { ok?: boolean; status?: number; json: unknown }) {
  const calls: Array<{ url: string; init: RequestInit | undefined }> = [];
  const fn = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    return {
      ok: reply.ok ?? true,
      status: reply.status ?? 200,
      json: async () => reply.json,
      text: async () => JSON.stringify(reply.json),
    } as unknown as Response;
  });
  vi.stubGlobal("fetch", fn);
  return calls;
}

beforeEach(() => {
  process.env["COCORE_APPVIEW_INTERNAL_URL"] = BASE;
  process.env["COCORE_INTERNAL_SECRET"] = SECRET;
  // session-info is memoized per DID; every case here reuses DID, so without
  // this the second case would read the first one's answer.
  resetAppviewSessionInfoCache();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  delete process.env["COCORE_APPVIEW_INTERNAL_URL"];
  delete process.env["COCORE_INTERNAL_SECRET"];
  resetAppviewSessionInfoCache();
});

describe("AppviewBackedSession.handle", () => {
  it("forwards a JSON write as a bodyText envelope and rebuilds the upstream Response", async () => {
    const calls = mockFetch({ json: { status: 200, bodyText: JSON.stringify({ uri: "at://x" }) } });

    const body = JSON.stringify({ repo: DID, collection: "dev.cocore.account.profile" });
    const res = await shim().handle("/xrpc/com.atproto.repo.putRecord", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });

    // One proxy call, secret + did + verbatim body in the envelope.
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(`${BASE}/internal/pds/proxy`);
    expect((calls[0]!.init!.headers as Record<string, string>)["x-cocore-internal-secret"]).toBe(
      SECRET,
    );
    const env = JSON.parse(calls[0]!.init!.body as string);
    expect(env).toMatchObject({
      did: DID,
      path: "/xrpc/com.atproto.repo.putRecord",
      method: "POST",
      bodyText: body,
      contentType: "application/json",
    });
    expect(env.blobB64).toBeUndefined();

    // Reconstructed Response carries the UPSTREAM status + body.
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ uri: "at://x" });
  });

  it("base64-encodes a binary uploadBlob body", async () => {
    const calls = mockFetch({ json: { status: 200, bodyText: "{}" } });
    const bytes = new Uint8Array([1, 2, 3, 4]);

    await shim().handle("/xrpc/com.atproto.repo.uploadBlob", {
      method: "POST",
      headers: { "Content-Type": "image/png" },
      body: bytes as BodyInit,
    });

    const env = JSON.parse(calls[0]!.init!.body as string);
    expect(env.blobB64).toBe(Buffer.from(bytes).toString("base64"));
    expect(env.bodyText).toBeUndefined();
    expect(env.contentType).toBe("image/png");
  });

  it("propagates an upstream 404 as a 404 Response (not an error)", async () => {
    mockFetch({ json: { status: 404, bodyText: JSON.stringify({ error: "RecordNotFound" }) } });
    const res = await shim().handle("/xrpc/com.atproto.repo.getRecord?rkey=self", {
      method: "GET",
    });
    expect(res.status).toBe(404);
    expect(res.ok).toBe(false);
  });

  it("throws when the internal proxy layer itself fails (dead transport)", async () => {
    mockFetch({ ok: false, status: 502, json: { error: "SessionRestoreFailed" } });
    await expect(
      shim().handle("/xrpc/com.atproto.repo.getRecord?rkey=self", { method: "GET" }),
    ).rejects.toThrow(/internal 502/);
  });
});

describe("appviewSessionInfo", () => {
  it("reports checked+present and the aud on a 200", async () => {
    mockFetch({ json: { present: true, aud: "https://pds.example" } });
    expect(await appviewSessionInfo(DID)).toEqual({
      checked: true,
      present: true,
      aud: "https://pds.example",
    });
  });

  it("reports checked but absent when the AppView says present:false", async () => {
    mockFetch({ json: { present: false, aud: null } });
    expect(await appviewSessionInfo(DID)).toEqual({ checked: true, present: false, aud: null });
  });

  it("reports NOT checked on a transport error (never logs the user out on a blip)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("ECONNREFUSED");
      }),
    );
    expect(await appviewSessionInfo(DID)).toEqual({ checked: false, present: false, aud: null });
  });

  it("is a no-op (unchecked) when forwarding is not configured", async () => {
    delete process.env["COCORE_APPVIEW_INTERNAL_URL"];
    const f = vi.fn();
    vi.stubGlobal("fetch", f);
    expect(await appviewSessionInfo(DID)).toEqual({ checked: false, present: false, aud: null });
    expect(f).not.toHaveBeenCalled();
  });
});

describe("appviewSessionInfo memoization", () => {
  it("asks the AppView once when the same DID is read twice", async () => {
    // Rendering one signed-in page reads session-info twice: once for
    // liveness in `atprotoSessionForRequestEffect`, once for `.aud` via
    // `getPdsUrl` → `getTokenInfo()`. Both are serial and on the critical
    // path, so the second was pure duplicated latency.
    const calls = mockFetch({ json: { present: true, aud: "https://pds.example" } });

    const first = await appviewSessionInfo(DID);
    const second = await appviewSessionInfo(DID);

    expect(calls).toHaveLength(1);
    expect(first).toEqual({ checked: true, present: true, aud: "https://pds.example" });
    expect(second).toEqual(first);
  });

  it("does not let one DID's answer serve another", async () => {
    const calls = mockFetch({ json: { present: true, aud: "https://pds.example" } });

    await appviewSessionInfo(DID);
    await appviewSessionInfo("did:plc:someoneelse");

    expect(calls).toHaveLength(2);
  });

  it("re-reads once the TTL lapses, so a dead session is still noticed", async () => {
    vi.useFakeTimers();
    const calls = mockFetch({ json: { present: true, aud: "https://pds.example" } });

    await expect(appviewSessionInfo(DID)).resolves.toMatchObject({ present: true });
    vi.advanceTimersByTime(5_001);
    await appviewSessionInfo(DID);

    expect(calls).toHaveLength(2);
  });

  it("never caches a transient failure, so a blip can't mask a live session", async () => {
    // `checked: false` means "couldn't reach the AppView", which callers must
    // not act on. Remembering it would strand the user on a non-answer.
    let attempt = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        attempt += 1;
        if (attempt === 1) throw new Error("ECONNREFUSED");
        return {
          ok: true,
          status: 200,
          json: async () => ({ present: true, aud: "https://pds.example" }),
        } as unknown as Response;
      }),
    );

    await expect(appviewSessionInfo(DID)).resolves.toEqual({
      checked: false,
      present: false,
      aud: null,
    });
    await expect(appviewSessionInfo(DID)).resolves.toMatchObject({ checked: true, present: true });
    expect(attempt).toBe(2);
  });

  it("treats a non-OK AppView response as a blip, not a definitive absence", async () => {
    let attempt = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        attempt += 1;
        return attempt === 1
          ? ({ ok: false, status: 503, json: async () => ({}) } as unknown as Response)
          : ({
              ok: true,
              status: 200,
              json: async () => ({ present: true, aud: "https://pds.example" }),
            } as unknown as Response);
      }),
    );

    await expect(appviewSessionInfo(DID)).resolves.toMatchObject({ checked: false });
    await expect(appviewSessionInfo(DID)).resolves.toMatchObject({ checked: true });
    expect(attempt).toBe(2);
  });
});
