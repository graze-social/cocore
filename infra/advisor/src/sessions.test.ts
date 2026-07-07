// Pins the long-job idle-timeout behavior: a keepalive keeps a slow-but-
// alive job from being killed as silent; a job that streamed real tokens
// before stalling is reported as `streamed` (so the advisor doesn't penalize
// a merely-slow machine); the pre-first-chunk (prefill) budget is separate
// from the steady-state idle budget.

import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { SessionManager } from "./sessions.ts";

function fakeRes() {
  return {
    statusCode: 0,
    writableEnded: false,
    headers: {} as Record<string, string>,
    chunks: [] as string[],
    setHeader(k: string, v: string) {
      this.headers[k] = v;
    },
    flushHeaders() {},
    write(s: string) {
      this.chunks.push(s);
      return true;
    },
    end() {
      this.writableEnded = true;
    },
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const asRes = (r: ReturnType<typeof fakeRes>) => r as any;

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

test("a keepalive resets the idle timer — a slow-but-alive job survives", () => {
  const fired: boolean[] = [];
  const sm = new SessionManager({
    idleTimeoutMs: 1_000,
    onIdleTimeout: (_did, _machine, streamed) => fired.push(streamed),
  });
  const res = fakeRes();
  sm.open("s1", "did:plc:p", "machine-1", "did:plc:r", asRes(res));
  // It produced a token, so we're now on the steady-state idle budget.
  sm.write("s1", { type: "chunk", sessionId: "s1", seq: 0, ciphertext: [1] });

  // Keepalives every 600ms hold it open well past several idle budgets.
  for (let i = 0; i < 6; i++) {
    vi.advanceTimersByTime(600);
    sm.keepalive("s1");
  }
  expect(fired).toHaveLength(0);
  expect(sm.has("s1")).toBe(true);

  // Stop keepalives → the idle budget elapses → timeout fires, and because
  // it had streamed a token, `streamed` is true.
  vi.advanceTimersByTime(1_000);
  expect(fired).toEqual([true]);
  expect(res.writableEnded).toBe(true);
  expect(sm.has("s1")).toBe(false);
});

test("a job that never sent a chunk times out as streamed=false (silent)", () => {
  const fired: boolean[] = [];
  const sm = new SessionManager({
    idleTimeoutMs: 1_000,
    firstChunkTimeoutMs: 1_000,
    onIdleTimeout: (_did, _machine, streamed) => fired.push(streamed),
  });
  sm.open("s2", "did:plc:p", "machine-1", "did:plc:r", asRes(fakeRes()));
  vi.advanceTimersByTime(1_001);
  expect(fired).toEqual([false]);
});

test("the first-chunk (prefill) budget is independent of the steady-state idle budget", () => {
  const fired: boolean[] = [];
  const sm = new SessionManager({
    idleTimeoutMs: 1_000,
    firstChunkTimeoutMs: 5_000,
    onIdleTimeout: (_did, _machine, streamed) => fired.push(streamed),
  });
  sm.open("s3", "did:plc:p", "machine-1", "did:plc:r", asRes(fakeRes()));

  // Past the steady-state budget but still within the prefill budget.
  vi.advanceTimersByTime(1_500);
  expect(fired).toHaveLength(0);

  // Past the prefill budget → fires, streamed=false (never produced a token).
  vi.advanceTimersByTime(3_600);
  expect(fired).toEqual([false]);
});

test("closeForMachine drains only the target machine's sessions and clears their idle timers", () => {
  const fired: string[] = [];
  const sm = new SessionManager({
    idleTimeoutMs: 1_000,
    firstChunkTimeoutMs: 1_000,
    onIdleTimeout: (_did, machine) => fired.push(machine),
  });
  const bad1 = fakeRes();
  const bad2 = fakeRes();
  const other = fakeRes();
  // Two in-flight sessions on the bad machine, one on a sibling.
  sm.open("b1", "did:plc:p", "bad", "did:plc:r", asRes(bad1));
  sm.open("b2", "did:plc:p", "bad", "did:plc:r", asRes(bad2));
  sm.open("o1", "did:plc:p", "other", "did:plc:r", asRes(other));

  const closed = sm.closeForMachine("did:plc:p", "bad", "provider-disconnected");
  expect(closed).toBe(2);

  // Both bad sessions ended with a final error event carrying the reason; the
  // sibling's session is untouched.
  expect(bad1.writableEnded).toBe(true);
  expect(bad2.writableEnded).toBe(true);
  expect(other.writableEnded).toBe(false);
  expect(bad1.chunks.join("")).toContain("provider-disconnected");
  expect(sm.has("b1")).toBe(false);
  expect(sm.has("b2")).toBe(false);
  expect(sm.has("o1")).toBe(true);

  // The drained sessions' idle timers were cleared: advancing well past every
  // budget fires onIdleTimeout only for the still-open sibling.
  vi.advanceTimersByTime(5_000);
  expect(fired).toEqual(["other"]);
});
