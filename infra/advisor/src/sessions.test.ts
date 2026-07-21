// Pins the long-job idle-timeout behavior: a keepalive keeps a slow-but-
// alive job from being killed as silent; a job that streamed real tokens
// before stalling is reported as `streamed` (so the advisor doesn't penalize
// a merely-slow machine); the pre-first-chunk (prefill) budget is separate
// from the steady-state idle budget.

import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { ProviderRegistry, resumeExpiredHandler } from "./registry.ts";
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

test("resume reattaches the same invocation and suppresses replayed chunks", () => {
  const sm = new SessionManager({ idleTimeoutMs: 10_000, resumeGraceMs: 2_000 });
  const res = fakeRes();
  sm.open("s", "did:plc:p", "m", "did:plc:r", asRes(res), undefined, "secret");

  expect(
    sm.acceptChunk("s", 0, { type: "chunk", sessionId: "s", seq: 0, ciphertext: [1] }),
  ).toEqual({ nextSeq: 1, resumeToken: "secret" });
  expect(sm.detachForMachine("did:plc:p", "m")).toEqual({ detached: 1, closed: 0 });
  expect(sm.resume("s", "did:plc:p", "m", "secret", 2)).toEqual({
    status: "resume",
    nextSeq: 1,
  });

  // Replay of seq=0 is acknowledged but not written twice; seq=1 lands once.
  const before = res.chunks.length;
  expect(
    sm.acceptChunk("s", 0, { type: "chunk", sessionId: "s", seq: 0, ciphertext: [1] }),
  ).toEqual({ nextSeq: 1, resumeToken: "secret" });
  expect(res.chunks).toHaveLength(before);
  sm.acceptChunk("s", 1, { type: "chunk", sessionId: "s", seq: 1, ciphertext: [2] });
  expect(sm.complete("s", { tokensIn: 1, tokensOut: 2, receiptUri: "at://r" }, 2)).toEqual({
    accepted: true,
    nextSeq: 2,
    resumeToken: "secret",
  });
  expect(res.chunks.join("").match(/"type":"complete"/g)).toHaveLength(1);
  expect(sm.resume("s", "did:plc:p", "m", "secret", 2)).toEqual({
    status: "completed",
    nextSeq: 2,
  });
});

test("complete rejects a finalSeq that races ahead of a missing chunk", () => {
  // A resumable completion is valid only after every produced chunk was
  // accepted: finalSeq must equal the advisor's nextSeq. A mismatch is
  // rejected without writing the SSE completion or closing the session, so the
  // provider must replay the missing chunk before it can complete.
  const sm = new SessionManager({ idleTimeoutMs: 10_000, resumeGraceMs: 2_000 });
  const res = fakeRes();
  sm.open("s", "did:plc:p", "m", "did:plc:r", asRes(res), undefined, "secret");
  sm.acceptChunk("s", 0, { type: "chunk", sessionId: "s", seq: 0, ciphertext: [1] });
  // nextSeq is now 1; a completion claiming finalSeq=0 (behind) is rejected.
  expect(sm.complete("s", { tokensIn: 1, tokensOut: 1, receiptUri: "at://r" }, 0)).toEqual({
    accepted: false,
    nextSeq: 1,
    resumeToken: "secret",
  });
  // No completion was written and the session is still live.
  expect(res.chunks.join("")).not.toContain('"type":"complete"');
  expect(sm.has("s")).toBe(true);
  // The matching finalSeq completes cleanly.
  expect(sm.complete("s", { tokensIn: 1, tokensOut: 1, receiptUri: "at://r" }, 1)).toEqual({
    accepted: true,
    nextSeq: 1,
    resumeToken: "secret",
  });
});

test("a conflicting duplicate sequence terminates instead of corrupting output", () => {
  const sm = new SessionManager();
  const res = fakeRes();
  sm.open("s", "did:plc:p", "m", "did:plc:r", asRes(res), undefined, "secret");
  sm.acceptChunk("s", 0, { type: "chunk", sessionId: "s", seq: 0, ciphertext: [1] });
  expect(
    sm.acceptChunk("s", 0, { type: "chunk", sessionId: "s", seq: 0, ciphertext: [9] }),
  ).toBeNull();
  expect(res.chunks.join("")).toContain("resume-sequence-conflict");
  expect(sm.has("s")).toBe(false);
});

test("resume rejects a foreign machine or stale token without consuming the grace", () => {
  const sm = new SessionManager({ resumeGraceMs: 2_000 });
  sm.open("s", "did:plc:p", "m", "did:plc:r", asRes(fakeRes()), undefined, "secret");
  sm.detachForMachine("did:plc:p", "m");
  expect(sm.resume("s", "did:plc:p", "other", "secret", 0).status).toBe("rejected");
  expect(sm.resume("s", "did:plc:p", "m", "stale", 0).status).toBe("rejected");
  expect(sm.resume("s", "did:plc:p", "m", "secret", 0).status).toBe("resume");
});

test("resume grace expiry emits one bounded terminal error", () => {
  const expired: string[] = [];
  const sm = new SessionManager({
    resumeGraceMs: 1_000,
    onResumeExpired: (_did, machine) => expired.push(machine),
  });
  const res = fakeRes();
  sm.open("s", "did:plc:p", "m", "did:plc:r", asRes(res), undefined, "secret");
  sm.detachForMachine("did:plc:p", "m");
  vi.advanceTimersByTime(1_001);
  expect(expired).toEqual(["m"]);
  expect(res.chunks.join("").match(/resume-expired/g)).toHaveLength(1);
  expect(sm.has("s")).toBe(false);
});

test("repeated detach does not restart the grace timer", () => {
  // A same-(did,machine) replacement socket that never presents the resume
  // token must not perpetually extend grace by restarting the timer. Only the
  // first detach arms expiry; repeated detachForMachine is a no-op on an
  // already-detached session.
  const expired: string[] = [];
  const sm = new SessionManager({
    resumeGraceMs: 1_000,
    onResumeExpired: (_did, machine) => expired.push(machine),
  });
  const res = fakeRes();
  sm.open("s", "did:plc:p", "m", "did:plc:r", asRes(res), undefined, "secret");
  sm.detachForMachine("did:plc:p", "m");
  // Repeated replacement re-registers (without a resume) several times during
  // the grace window — none of these should restart the timer.
  for (let i = 0; i < 5; i++) sm.detachForMachine("did:plc:p", "m");
  vi.advanceTimersByTime(999);
  expect(expired).toEqual([]);
  // The ORIGINAL grace elapses on schedule.
  vi.advanceTimersByTime(2);
  expect(expired).toEqual(["m"]);
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

test("a forward sequence gap is not accepted — the ack's high-water asks for a replay", () => {
  const sm = new SessionManager({ idleTimeoutMs: 60_000, resumeGraceMs: 30_000 });
  const res = fakeRes();
  sm.open("s-gap", "did:plc:p", "m", "did:plc:r", asRes(res), undefined, "tok");
  // seq 2 arrives while nextSeq is 0 (frames 0–1 lost in flight): nothing is
  // written, nothing advances, and the returned high-water tells the provider
  // to replay from 0. The session stays live.
  expect(
    sm.acceptChunk("s-gap", 2, { type: "chunk", sessionId: "s-gap", seq: 2, ciphertext: [3] }),
  ).toEqual({ nextSeq: 0, resumeToken: "tok" });
  expect(res.chunks.join("")).not.toContain('"seq":2');
  expect(sm.has("s-gap")).toBe(true);
  // The replay from 0 then lands normally.
  expect(
    sm.acceptChunk("s-gap", 0, { type: "chunk", sessionId: "s-gap", seq: 0, ciphertext: [1] }),
  ).toEqual({ nextSeq: 1, resumeToken: "tok" });
});

test("resume replays a multi-chunk gap in order until completion", () => {
  // A long detach can lose several chunks at once (not just one): the
  // provider reports producedSeq far ahead of the advisor's high-water and
  // must replay every missing frame in order before it can complete.
  const sm = new SessionManager({ idleTimeoutMs: 60_000, resumeGraceMs: 30_000 });
  const res = fakeRes();
  sm.open("s-multi", "did:plc:p", "m", "did:plc:r", asRes(res), undefined, "tok");
  expect(sm.detachForMachine("did:plc:p", "m")).toEqual({ detached: 1, closed: 0 });
  expect(sm.resume("s-multi", "did:plc:p", "m", "tok", 3)).toEqual({
    status: "resume",
    nextSeq: 0,
  });
  for (let seq = 0; seq < 3; seq++) {
    expect(
      sm.acceptChunk("s-multi", seq, {
        type: "chunk",
        sessionId: "s-multi",
        seq,
        ciphertext: [seq],
      }),
    ).toEqual({ nextSeq: seq + 1, resumeToken: "tok" });
  }
  expect(sm.complete("s-multi", { tokensIn: 1, tokensOut: 3, receiptUri: "at://r" }, 3)).toEqual({
    accepted: true,
    nextSeq: 3,
    resumeToken: "tok",
  });
  const sse = res.chunks.join("");
  expect(sse.match(/"type":"chunk"/g)).toHaveLength(3);
  expect(sse.match(/"type":"complete"/g)).toHaveLength(1);
});

test("resume grace expiry records a machine failure via the production handler", () => {
  // Component-level check of main.ts's actual onResumeExpired wiring
  // (resumeExpiredHandler): a lapsed reconnect grace lands in the registry's
  // failure ledger for that machine.
  const registry = new ProviderRegistry();
  const spy = vi.spyOn(registry, "recordFailure");
  const sm = new SessionManager({
    idleTimeoutMs: 60_000,
    resumeGraceMs: 1_000,
    onResumeExpired: resumeExpiredHandler(registry),
  });
  const res = fakeRes();
  sm.open("s-exp", "did:plc:p", "m", "did:plc:r", asRes(res), undefined, "tok");
  sm.detachForMachine("did:plc:p", "m");
  vi.advanceTimersByTime(1_000);
  expect(spy).toHaveBeenCalledWith("did:plc:p", "m", "resume-expired");
  expect(sm.has("s-exp")).toBe(false);
});
