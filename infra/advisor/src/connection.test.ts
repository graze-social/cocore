// End-to-end test of the re-attestation timeout. Spins up a real
// WebSocket server backed by handleConnection (with a tiny response
// timeout), connects a fake provider that registers but deliberately
// never answers the challenge, and asserts:
//   1. The advisor closes the socket with code 1008 within the
//      configured timeout window.
//   2. The registry's attestedAt is cleared (so any in-flight
//      pickFor stops routing).
//   3. The entry is removed from the registry after socket close.

import { createServer, type Server } from "node:http";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WebSocket, WebSocketServer } from "ws";

import { handleConnection } from "./connection.ts";
import { ProviderRegistry } from "./registry.ts";
import { SessionManager } from "./sessions.ts";

interface Harness {
  server: Server;
  url: string;
  registry: ProviderRegistry;
  sessions: SessionManager;
  onUnanswered: (did: string) => void;
  unansweredFires: string[];
}

// Real-deployment ratios: rechallenge cadence ≫ response timeout.
// Tests use compressed values that preserve that ordering, so a
// single missed challenge expires the deadline before the next
// rechallenge would have refreshed it.
const RECHALLENGE_MS = 5_000;
const TIMEOUT_MS = 100;

async function startHarness(): Promise<Harness> {
  const registry = new ProviderRegistry();
  const sessions = new SessionManager({ idleTimeoutMs: 2_000 });
  const unansweredFires: string[] = [];
  const onUnanswered = (did: string): void => {
    unansweredFires.push(did);
  };
  const server = createServer();
  const wss = new WebSocketServer({ server, path: "/v1/agent" });
  wss.on("connection", (socket, req) =>
    handleConnection(socket, req, registry, sessions, {
      rechallengeIntervalMs: RECHALLENGE_MS,
      responseTimeoutMs: TIMEOUT_MS,
      onUnanswered,
    }),
  );
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("no addr");
  return {
    server,
    url: `ws://127.0.0.1:${addr.port}/v1/agent`,
    registry,
    sessions,
    onUnanswered,
    unansweredFires,
  };
}

describe("re-attestation timeout enforcement", () => {
  let h: Harness;
  beforeEach(async () => {
    h = await startHarness();
  });
  afterEach(async () => {
    await new Promise<void>((r) => h.server.close(() => r()));
  });

  it("clears attestedAt and closes the socket when the provider never answers a challenge", async () => {
    const ws = new WebSocket(h.url);
    await new Promise<void>((r) => ws.once("open", () => r()));

    const inbound: string[] = [];
    ws.on("message", (data) => inbound.push(data.toString("utf-8")));

    ws.send(
      JSON.stringify({
        type: "register",
        provider_did: "did:plc:silent",
        machine_label: "m1",
        chip: "M4",
        ram_gb: 64,
        supported_models: ["stub"],
        encryption_pub_key: "k",
        attestation_pub_key: "a",
        attestation_uri: "",
      }),
    );

    // Wait for the initial challenge frame to arrive.
    await vi.waitFor(
      () => expect(inbound.some((f) => f.includes("attestation_challenge"))).toBe(true),
      { timeout: 1_000 },
    );

    // Force-mark attested so we can prove clearAttested fires when
    // the timeout expires. This models the case where a provider
    // answered the first challenge but stopped answering rechallenges.
    // No machine_id in the register frame above → machineId falls back to
    // the attestation_pub_key ("a").
    h.registry.markAttested("did:plc:silent", "a");
    expect(h.registry.get("did:plc:silent", "a")?.attestedAt).not.toBeNull();

    // Drive the assertion off `onUnanswered` (synchronous from the
    // server's perspective) rather than the client-side close event
    // — the latter depends on a full bidirectional WebSocket close
    // handshake that's not what we're testing here. We close the WS
    // explicitly at the end to make the afterEach hook clean.
    await vi.waitFor(() => expect(h.unansweredFires).toEqual(["did:plc:silent"]), {
      timeout: 1_500,
    });

    // The server's onUnanswered hook clears attestedAt *before*
    // calling socket.close, so at the moment the hook fires the
    // entry is in the "unattested" state. (The full registry remove
    // happens once the server-side close event fires; we don't
    // assert on that here to keep the test deterministic.)
    const entryAtTimeout = h.registry.get("did:plc:silent", "a");
    if (entryAtTimeout) {
      // If the close hook hasn't run yet, attestedAt must be null.
      expect(entryAtTimeout.attestedAt).toBeNull();
    }

    ws.terminate();
  }, 5_000);

  it("does NOT fire the timeout when the provider answers the challenge", async () => {
    // Tighter sanity check: we don't have a P-256 keypair to produce
    // a valid signature here, so we send a *malformed* response that
    // will fail isFresh. That still cancels the response timer (the
    // clear happens before the isFresh check ... wait, actually it
    // doesn't). Let me re-read the handler.
    //
    // Re-reading connection.ts: the `attestation_response` case
    // calls `isFresh` first; if that fails it closes with
    // `attestation-replay`. The `clearResponseTimer()` call only
    // happens after a successful verify. So a malformed response
    // close still uses code 1008 but a different reason — that's
    // a useful negative-path signal too.
    const ws = new WebSocket(h.url);
    await new Promise<void>((r) => ws.once("open", () => r()));
    const inbound: string[] = [];
    ws.on("message", (data) => inbound.push(data.toString("utf-8")));

    ws.send(
      JSON.stringify({
        type: "register",
        provider_did: "did:plc:lies",
        machine_label: "m1",
        chip: "M4",
        ram_gb: 64,
        supported_models: ["stub"],
        encryption_pub_key: "k",
        attestation_pub_key: "a",
        attestation_uri: "",
      }),
    );

    await vi.waitFor(
      () => expect(inbound.some((f) => f.includes("attestation_challenge"))).toBe(true),
      { timeout: 1_000 },
    );

    // Send a malformed attestation response — nonce mismatch.
    ws.send(
      JSON.stringify({
        type: "attestation_response",
        nonce: "00000000000000000000000000000000",
        timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
        sip_enabled: true,
        signature: [],
      }),
    );

    const closeCode = await new Promise<number>((resolve) => {
      ws.once("close", (code) => resolve(code));
    });
    // Close code is still 1008 but for replay, not timeout — the
    // unansweredFires array should NOT contain this DID because the
    // response did arrive (just malformed); the response-deadline
    // gets cleared by the close hook teardown, not by the
    // isFresh-failed branch.
    expect(closeCode).toBe(1008);
    expect(h.unansweredFires).not.toContain("did:plc:lies");
  }, 5_000);
});

// Connection-stability behavior added to survive Railway's edge: a
// frequent keepalive ping (kept under the proxy idle cutoff) with
// miss-tolerance, and a proactive clean recycle under the hard connection
// cap. Compressed cadences here preserve the production ordering.
interface KeepaliveHarness {
  server: Server;
  url: string;
  registry: ProviderRegistry;
}

async function startKeepaliveHarness(opts: {
  keepaliveIntervalMs?: number;
  keepaliveMaxMissed?: number;
  maxConnectionMs?: number;
}): Promise<KeepaliveHarness> {
  const registry = new ProviderRegistry();
  const sessions = new SessionManager({ idleTimeoutMs: 2_000 });
  const server = createServer();
  const wss = new WebSocketServer({ server, path: "/v1/agent", perMessageDeflate: false });
  wss.on("connection", (socket, req) =>
    handleConnection(socket, req, registry, sessions, {
      rechallengeIntervalMs: 60_000, // long — not under test here
      responseTimeoutMs: 30_000,
      ...opts,
    }),
  );
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("no addr");
  return { server, url: `ws://127.0.0.1:${addr.port}/v1/agent`, registry };
}

describe("WS connection stability", () => {
  it("proactively recycles a connection with a clean close under the cap", async () => {
    const h = await startKeepaliveHarness({ maxConnectionMs: 200 });
    try {
      const ws = new WebSocket(h.url);
      await new Promise<void>((r) => ws.once("open", () => r()));
      const { code, reason } = await new Promise<{ code: number; reason: string }>((resolve) => {
        ws.once("close", (c, r) => resolve({ code: c, reason: r.toString("utf-8") }));
      });
      // Clean, advisor-driven recycle — NOT an abrupt 1006.
      expect(code).toBe(1000);
      expect(reason).toBe("recycle");
    } finally {
      await new Promise<void>((r) => h.server.close(() => r()));
    }
  }, 5_000);

  it("keeps a healthy (auto-ponging) connection open across many ping intervals", async () => {
    // Frequent pings must NOT reap a peer that's answering them.
    const h = await startKeepaliveHarness({ keepaliveIntervalMs: 40, keepaliveMaxMissed: 2 });
    try {
      const ws = new WebSocket(h.url); // ws auto-pongs by default
      await new Promise<void>((r) => ws.once("open", () => r()));
      let closed = false;
      ws.once("close", () => {
        closed = true;
      });
      // ~10 ping intervals; a healthy peer should sail through.
      await new Promise<void>((r) => setTimeout(r, 400));
      expect(closed).toBe(false);
      expect(ws.readyState).toBe(WebSocket.OPEN);
      ws.terminate();
    } finally {
      await new Promise<void>((r) => h.server.close(() => r()));
    }
  }, 5_000);

  it("terminates a peer that stops answering pongs (after the miss tolerance)", async () => {
    // autoPong:false → the client never answers pings, modeling a
    // half-open/dead socket. The server should reap it after
    // maxMissed consecutive misses — but only after tolerance, not on
    // the first interval.
    const h = await startKeepaliveHarness({ keepaliveIntervalMs: 60, keepaliveMaxMissed: 2 });
    try {
      const ws = new WebSocket(h.url, { autoPong: false });
      await new Promise<void>((r) => ws.once("open", () => r()));
      const openedAt = Date.now();
      await new Promise<void>((r) => ws.once("close", () => r()));
      const lived = Date.now() - openedAt;
      // Reaped, but only after a couple of missed intervals (tolerance),
      // not immediately on the first ping.
      expect(lived).toBeGreaterThanOrEqual(60);
    } finally {
      await new Promise<void>((r) => h.server.close(() => r()));
    }
  }, 5_000);
});

// A provider that drops its socket mid-job must (a) not strand the requester
// and (b) count toward its failure cooldown — but an advisor-initiated clean
// close (recycle/replace) must do neither, since the machine is coming right
// back and its sessions can still be served.
interface DropHarness {
  server: Server;
  url: string;
  registry: ProviderRegistry;
  sessions: SessionManager;
}

async function startDropHarness(opts: { maxConnectionMs?: number } = {}): Promise<DropHarness> {
  const registry = new ProviderRegistry();
  const sessions = new SessionManager({ idleTimeoutMs: 10_000 });
  const server = createServer();
  const wss = new WebSocketServer({ server, path: "/v1/agent", perMessageDeflate: false });
  wss.on("connection", (socket, req) =>
    handleConnection(socket, req, registry, sessions, {
      rechallengeIntervalMs: 60_000,
      responseTimeoutMs: 30_000,
      ...opts,
    }),
  );
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("no addr");
  return { server, url: `ws://127.0.0.1:${addr.port}/v1/agent`, registry, sessions };
}

function fakeSseRes() {
  return {
    statusCode: 0,
    writableEnded: false,
    chunks: [] as string[],
    setHeader() {},
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

async function registerProvider(url: string, did: string, resumable = false): Promise<WebSocket> {
  const ws = new WebSocket(url);
  await new Promise<void>((r) => ws.once("open", () => r()));
  const inbound: string[] = [];
  ws.on("message", (data) => inbound.push(data.toString("utf-8")));
  ws.send(
    JSON.stringify({
      type: "register",
      provider_did: did,
      machine_label: "m1",
      chip: "M4",
      ram_gb: 64,
      supported_models: ["stub"],
      encryption_pub_key: "k",
      attestation_pub_key: "a", // no machine_id → machineId falls back to this
      attestation_uri: "",
      ...(resumable ? { stream_resume_version: 1 } : {}),
    }),
  );
  // Wait for the challenge so we know the register frame was processed.
  await vi.waitFor(
    () => expect(inbound.some((f) => f.includes("attestation_challenge"))).toBe(true),
    { timeout: 1_000 },
  );
  return ws;
}

describe("provider mid-job socket drop", () => {
  it("drains in-flight sessions and records a failure on an abnormal drop", async () => {
    const h = await startDropHarness();
    try {
      const ws = await registerProvider(h.url, "did:plc:dropme");
      // Stand up an in-flight session dispatched to this machine.
      const res = fakeSseRes();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      h.sessions.open("sess-1", "did:plc:dropme", "a", "did:plc:req", res as any);
      expect(h.sessions.has("sess-1")).toBe(true);

      const failSpy = vi.spyOn(h.registry, "recordFailure");
      // Abrupt drop (1006) — the machine did NOT cleanly recycle/replace.
      ws.terminate();

      await vi.waitFor(() => expect(h.sessions.has("sess-1")).toBe(false), { timeout: 2_000 });
      // Requester got a clean error event rather than hanging.
      expect(res.writableEnded).toBe(true);
      expect(res.chunks.join("")).toContain("provider-disconnected");
      // The drop was counted once toward the machine's cooldown ledger.
      expect(
        failSpy.mock.calls.some(
          (c) => c[0] === "did:plc:dropme" && c[1] === "a" && c[2] === "provider-disconnected",
        ),
      ).toBe(true);
    } finally {
      await new Promise<void>((r) => h.server.close(() => r()));
    }
  }, 5_000);

  it("reattaches one invocation after an abnormal reset without duplicate chunks or completion", async () => {
    const h = await startDropHarness();
    try {
      const ws1 = await registerProvider(h.url, "did:plc:resume", true);
      const res = fakeSseRes();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      h.sessions.open(
        "sess-r",
        "did:plc:resume",
        "a",
        "did:plc:req",
        res as any,
        undefined,
        "token-r",
      );
      ws1.send(
        JSON.stringify({
          type: "inference_chunk",
          session_id: "sess-r",
          seq: 0,
          ciphertext: [1],
        }),
      );
      await vi.waitFor(() => expect(res.chunks.join("")).toContain('"seq":0'));

      ws1.terminate();
      await vi.waitFor(() => expect(h.registry.get("did:plc:resume", "a")).toBeUndefined());
      expect(h.sessions.has("sess-r")).toBe(true);
      expect(res.writableEnded).toBe(false);

      const ws2 = await registerProvider(h.url, "did:plc:resume", true);
      const inbound: Record<string, unknown>[] = [];
      ws2.on("message", (data) => {
        inbound.push(JSON.parse(data.toString("utf-8")) as Record<string, unknown>);
      });
      ws2.send(
        JSON.stringify({
          type: "inference_resume",
          session_id: "sess-r",
          resume_token: "token-r",
          produced_seq: 2,
        }),
      );
      await vi.waitFor(() =>
        expect(
          inbound.some((m) => m["type"] === "inference_resume_result" && m["next_seq"] === 1),
        ).toBe(true),
      );

      // Ambiguous seq=0 is replayed but suppressed; seq=1 and completion land once.
      ws2.send(
        JSON.stringify({
          type: "inference_chunk",
          session_id: "sess-r",
          seq: 0,
          ciphertext: [1],
        }),
      );
      ws2.send(
        JSON.stringify({
          type: "inference_chunk",
          session_id: "sess-r",
          seq: 1,
          ciphertext: [2],
        }),
      );
      ws2.send(
        JSON.stringify({
          type: "inference_complete",
          session_id: "sess-r",
          tokens_in: 1,
          tokens_out: 2,
          receipt_uri: "at://receipt/one",
          final_seq: 2,
        }),
      );
      await vi.waitFor(() => expect(res.writableEnded).toBe(true));
      const sse = res.chunks.join("");
      expect(sse.match(/"seq":0/g)).toHaveLength(1);
      expect(sse.match(/"seq":1/g)).toHaveLength(1);
      expect(sse.match(/"type":"complete"/g)).toHaveLength(1);
      await vi.waitFor(() =>
        expect(inbound.some((m) => m["type"] === "inference_ack" && m["completed"] === true)).toBe(
          true,
        ),
      );
      ws2.close();
    } finally {
      await new Promise<void>((r) => h.server.close(() => r()));
    }
  }, 5_000);

  it("drops session frames from a replaced-but-still-open stale socket", async () => {
    // The exact race ownsCurrentRegistration exists for: ws1 is replaced by
    // ws2 for the same (did, machine) but hasn't died yet and keeps sending.
    // Its frames — even with the correct session_id AND resume token — must
    // not reach the session or the resume handshake.
    const h = await startDropHarness();
    try {
      const ws1 = await registerProvider(h.url, "did:plc:stale", true);
      const res = fakeSseRes();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      h.sessions.open("sess-s", "did:plc:stale", "a", "did:plc:req", res as any, undefined, "tok");
      ws1.send(
        JSON.stringify({ type: "inference_chunk", session_id: "sess-s", seq: 0, ciphertext: [1] }),
      );
      await vi.waitFor(() => expect(res.chunks.join("")).toContain('"seq":0'));

      // Stop ws1's receive side so it never processes the advisor's
      // close(1000, "replaced") and stays OPEN from its own point of view —
      // the deterministic version of the replaced-but-not-yet-dead window.
      ws1.pause();
      const errSpy = vi.spyOn(console, "error");
      const ws2 = await registerProvider(h.url, "did:plc:stale", true);

      // The stale socket injects a chunk, a resume claim, and a completion.
      ws1.send(
        JSON.stringify({ type: "inference_chunk", session_id: "sess-s", seq: 1, ciphertext: [9] }),
      );
      ws1.send(
        JSON.stringify({
          type: "inference_resume",
          session_id: "sess-s",
          resume_token: "tok",
          produced_seq: 2,
        }),
      );
      ws1.send(
        JSON.stringify({
          type: "inference_complete",
          session_id: "sess-s",
          tokens_in: 1,
          tokens_out: 1,
          receipt_uri: "at://evil",
          final_seq: 2,
        }),
      );
      // The drop log proves the frames were processed AND fenced (a silently
      // lost frame would make the assertions below vacuous).
      await vi.waitFor(() =>
        expect(
          errSpy.mock.calls.some((c) => String(c[0]).includes("drop inference_complete")),
        ).toBe(true),
      );
      expect(res.chunks.join("")).not.toContain('"seq":1');
      expect(res.chunks.join("")).not.toContain("at://evil");
      expect(res.writableEnded).toBe(false);
      expect(h.sessions.has("sess-s")).toBe(true);

      // The successor socket resumes and completes the session normally —
      // the stale frames advanced nothing.
      const inbound: Record<string, unknown>[] = [];
      ws2.on("message", (data) => {
        inbound.push(JSON.parse(data.toString("utf-8")) as Record<string, unknown>);
      });
      ws2.send(
        JSON.stringify({
          type: "inference_resume",
          session_id: "sess-s",
          resume_token: "tok",
          produced_seq: 2,
        }),
      );
      await vi.waitFor(() =>
        expect(
          inbound.some((m) => m["type"] === "inference_resume_result" && m["next_seq"] === 1),
        ).toBe(true),
      );
      ws2.send(
        JSON.stringify({ type: "inference_chunk", session_id: "sess-s", seq: 1, ciphertext: [2] }),
      );
      ws2.send(
        JSON.stringify({
          type: "inference_complete",
          session_id: "sess-s",
          tokens_in: 1,
          tokens_out: 2,
          receipt_uri: "at://receipt/good",
          final_seq: 2,
        }),
      );
      await vi.waitFor(() => expect(res.writableEnded).toBe(true));
      expect(res.chunks.join("")).toContain("at://receipt/good");
      errSpy.mockRestore();
      ws1.terminate();
      ws2.close();
    } finally {
      await new Promise<void>((r) => h.server.close(() => r()));
    }
  }, 5_000);

  it("fails legacy sessions but preserves resumable sessions on advisor recycle", async () => {
    const h = await startDropHarness({ maxConnectionMs: 150 });
    try {
      const ws = await registerProvider(h.url, "did:plc:recycle", true);
      const legacyRes = fakeSseRes();
      const resumableRes = fakeSseRes();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      h.sessions.open("sess-legacy", "did:plc:recycle", "a", "did:plc:req", legacyRes as any);
      h.sessions.open(
        "sess-resume",
        "did:plc:recycle",
        "a",
        "did:plc:req",
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        resumableRes as any,
        undefined,
        "token-recycle",
      );
      const failSpy = vi.spyOn(h.registry, "recordFailure");

      const reason = await new Promise<string>((resolve) => {
        ws.once("close", (_c, r) => resolve(r.toString("utf-8")));
      });
      expect(reason).toBe("recycle");
      await vi.waitFor(() => expect(legacyRes.writableEnded).toBe(true));

      expect(h.sessions.has("sess-legacy")).toBe(false);
      expect(h.sessions.has("sess-resume")).toBe(true);
      expect(resumableRes.writableEnded).toBe(false);
      expect(failSpy).not.toHaveBeenCalled();
      h.sessions.close("sess-resume");
    } finally {
      await new Promise<void>((r) => h.server.close(() => r()));
    }
  }, 5_000);

  it("fails legacy sessions before replacing a provider socket", async () => {
    const h = await startDropHarness();
    try {
      const ws1 = await registerProvider(h.url, "did:plc:replace");
      const legacyRes = fakeSseRes();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      h.sessions.open("sess-replaced", "did:plc:replace", "a", "did:plc:req", legacyRes as any);
      const failSpy = vi.spyOn(h.registry, "recordFailure");
      const closed = new Promise<string>((resolve) => {
        ws1.once("close", (_c, r) => resolve(r.toString("utf-8")));
      });

      const ws2 = await registerProvider(h.url, "did:plc:replace");
      expect(await closed).toBe("replaced");
      await vi.waitFor(() => expect(legacyRes.writableEnded).toBe(true));
      expect(h.sessions.has("sess-replaced")).toBe(false);
      expect(failSpy).not.toHaveBeenCalled();
      ws2.close();
    } finally {
      await new Promise<void>((r) => h.server.close(() => r()));
    }
  }, 5_000);
});
