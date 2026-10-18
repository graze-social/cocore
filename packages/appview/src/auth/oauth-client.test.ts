// Tests for the OAuth resilience helpers added after the 2026-06 incident:
//   * classifyRestoreError — turns a swallowed restore failure into a coarse,
//     alertable reason (needs_reauth vs transient).
//   * startServiceSessionKeepAlive — keeps a long-lived service session warm
//     so it can't lapse from disuse and 401 every write under it.

import { describe, expect, it, vi } from "vitest";

import {
  classifyRestoreError,
  restoreSession,
  startServiceSessionKeepAlive,
  type AppviewOAuthClient,
} from "./oauth-client.ts";

const fakeClient = {} as unknown as AppviewOAuthClient;

describe("classifyRestoreError", () => {
  it("flags spent/expired/revoked grants as needs_reauth", () => {
    expect(classifyRestoreError(new Error("invalid_grant"))).toBe("needs_reauth");
    expect(classifyRestoreError(new Error("refresh token has expired"))).toBe("needs_reauth");
    expect(classifyRestoreError(new Error("token was revoked"))).toBe("needs_reauth");
  });

  it("flags network / 5xx / timeouts as transient", () => {
    expect(classifyRestoreError(new Error("fetch failed"))).toBe("transient");
    expect(classifyRestoreError(new Error("ECONNREFUSED 127.0.0.1:443"))).toBe("transient");
    expect(classifyRestoreError(new Error("503 Service Unavailable"))).toBe("transient");
    expect(classifyRestoreError(new Error("socket hang up"))).toBe("transient");
  });

  it("defaults to unknown for unrecognized errors", () => {
    expect(classifyRestoreError(new Error("something odd"))).toBe("unknown");
    expect(classifyRestoreError("not even an error")).toBe("unknown");
  });
});

describe("startServiceSessionKeepAlive", () => {
  it("is a no-op for an empty or all-invalid DID list", () => {
    const restore = vi.fn();
    const stop = startServiceSessionKeepAlive({
      client: fakeClient,
      dids: ["", "not-a-did"],
      intervalMs: 1000,
      restore,
      log: () => {},
    });
    stop();
    expect(restore).not.toHaveBeenCalled();
  });

  it("warms each service DID on the eager tick and again on the interval", async () => {
    vi.useFakeTimers();
    try {
      const restore = vi.fn().mockResolvedValue({});
      const stop = startServiceSessionKeepAlive({
        client: fakeClient,
        dids: ["did:plc:exchange", "did:web:foo"],
        intervalMs: 60_000,
        restore,
        log: () => {},
      });

      await vi.advanceTimersByTimeAsync(5_000); // eager warm-up
      expect(restore).toHaveBeenCalledTimes(2);

      await vi.advanceTimersByTimeAsync(60_000); // one interval
      expect(restore).toHaveBeenCalledTimes(4);

      stop();
      await vi.advanceTimersByTimeAsync(120_000); // stopped → no more
      expect(restore).toHaveBeenCalledTimes(4);
    } finally {
      vi.useRealTimers();
    }
  });

  it("skips non-did entries", async () => {
    vi.useFakeTimers();
    try {
      const restore = vi.fn().mockResolvedValue({});
      startServiceSessionKeepAlive({
        client: fakeClient,
        dids: ["", "nope", "did:plc:x"],
        intervalMs: 60_000,
        restore,
        log: () => {},
      });
      await vi.advanceTimersByTimeAsync(5_000);
      expect(restore).toHaveBeenCalledTimes(1);
      expect(restore).toHaveBeenCalledWith(fakeClient, "did:plc:x");
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("restoreSession onNeedsReauth", () => {
  const did = "did:plc:abc123" as Parameters<typeof restoreSession>[1];
  const failingWith = (msg: string) =>
    ({
      restore: async () => {
        throw new Error(msg);
      },
    }) as unknown as AppviewOAuthClient;

  it("drops the stored session on a definitive needs_reauth failure", async () => {
    const onNeedsReauth = vi.fn();
    const out = await restoreSession(failingWith("invalid_grant"), did, { onNeedsReauth });
    expect(out).toBeNull();
    expect(onNeedsReauth).toHaveBeenCalledWith(did);
  });

  it("never drops the session on a transient or unknown failure", async () => {
    const onNeedsReauth = vi.fn();
    expect(await restoreSession(failingWith("fetch failed"), did, { onNeedsReauth })).toBeNull();
    expect(await restoreSession(failingWith("something odd"), did, { onNeedsReauth })).toBeNull();
    expect(onNeedsReauth).not.toHaveBeenCalled();
  });

  it("still returns null if the drop callback throws", async () => {
    const out = await restoreSession(failingWith("invalid_grant"), did, {
      onNeedsReauth: () => {
        throw new Error("db locked");
      },
    });
    expect(out).toBeNull();
  });
});
