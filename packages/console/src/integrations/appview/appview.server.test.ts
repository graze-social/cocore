// Regression coverage for the AppView read client's failure handling.
//
// The case that matters here is a body read that aborts *after* the response
// headers arrive. `AbortSignal.timeout` fires on the whole exchange, so a slow
// body leaves us holding a Response whose `text()` rejects with a DOMException
// TimeoutError. That rejection used to escape the client entirely and kill the
// console process (Node exits on an unhandled rejection), crash-looping
// cocore.dev on 2026-08-11. It must surface as a transient AppviewFetchError
// instead, so the retry + stale-cache fallback can absorb it.

import { Effect } from "effect";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { AppviewClient, AppviewFetchError, appviewListProvidersEffect } from "./appview.server.ts";

const BASE = "http://appview.internal";

/** Run an AppView effect against a fresh client (fresh stale-cache). */
function run<A, E>(effect: Effect.Effect<A, E, AppviewClient>) {
  return Effect.runPromise(Effect.either(Effect.provide(effect, AppviewClient.Default)));
}

/** A Response whose headers are fine but whose body never finishes — exactly
 *  what undici hands back when the abort lands mid-stream. */
function bodyAbortsResponse(): Response {
  return {
    ok: true,
    status: 200,
    text: () =>
      Promise.reject(new DOMException("The operation was aborted due to timeout", "TimeoutError")),
  } as unknown as Response;
}

function jsonResponse(body: unknown): Response {
  return {
    ok: true,
    status: 200,
    text: () => Promise.resolve(JSON.stringify(body)),
  } as unknown as Response;
}

let unhandled: unknown[] = [];
const captureUnhandled = (reason: unknown) => unhandled.push(reason);

beforeEach(() => {
  process.env["COCORE_APPVIEW_URL"] = BASE;
  unhandled = [];
  process.on("unhandledRejection", captureUnhandled);
});

afterEach(() => {
  process.off("unhandledRejection", captureUnhandled);
  delete process.env["COCORE_APPVIEW_URL"];
  vi.unstubAllGlobals();
});

describe("AppviewClient.get", () => {
  test("a mid-body abort fails transiently instead of escaping as an unhandled rejection", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(() => Promise.resolve(bodyAbortsResponse())),
    );

    const result = await run(appviewListProvidersEffect);

    expect(result._tag).toBe("Left");
    if (result._tag !== "Left") return;
    expect(result.left).toBeInstanceOf(AppviewFetchError);
    // status 0 == transient, so `isTransient` retries and the stale cache applies.
    expect(result.left.status).toBe(0);
    expect(result.left.message).toContain("aborted due to timeout");
    expect(result.left.message).toContain(`GET ${BASE}`);

    // Let any escaped rejection reach the process handler before asserting.
    await new Promise((r) => setImmediate(r));
    expect(unhandled).toEqual([]);
  });

  test("a mid-body abort is retried, so a body that lands on a later attempt still succeeds", async () => {
    const fetchSpy = vi
      .fn()
      .mockImplementationOnce(() => Promise.resolve(bodyAbortsResponse()))
      .mockImplementation(() => Promise.resolve(jsonResponse({ providers: [] })));
    vi.stubGlobal("fetch", fetchSpy);

    const result = await run(appviewListProvidersEffect);

    expect(result._tag).toBe("Right");
    if (result._tag !== "Right") return;
    expect(result.right).toEqual({ providers: [] });
    expect(fetchSpy.mock.calls.length).toBeGreaterThan(1);
    expect(unhandled).toEqual([]);
  });

  test("a connect-level failure still reports the undici cause code and the URL", async () => {
    const err = Object.assign(new TypeError("fetch failed"), {
      cause: { code: "ECONNREFUSED" },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(() => Promise.reject(err)),
    );

    const result = await run(appviewListProvidersEffect);

    expect(result._tag).toBe("Left");
    if (result._tag !== "Left") return;
    expect(result.left.status).toBe(0);
    expect(result.left.message).toContain("ECONNREFUSED");
  });

  test("a 4xx is a real answer, not transient — it is not retried", async () => {
    const fetchSpy = vi.fn().mockImplementation(() =>
      Promise.resolve({
        ok: false,
        status: 404,
        text: () => Promise.resolve("not found"),
      } as unknown as Response),
    );
    vi.stubGlobal("fetch", fetchSpy);

    const result = await run(appviewListProvidersEffect);

    expect(result._tag).toBe("Left");
    if (result._tag !== "Left") return;
    expect(result.left.status).toBe(404);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
});
