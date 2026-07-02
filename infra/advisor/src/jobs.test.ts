// Integration-style tests for `POST /jobs`. We stand up the real
// HTTP server + WebSocket bits and drive both sides over loopback:
// a fake "provider" connects, registers, attests against a
// generated key, and the test dispatches a job by curl-ing
// /jobs and asserting the SSE relay carries the chunk + complete
// frames the fake provider emits.

import { createServer, type Server } from "node:http";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WebSocket, WebSocketServer } from "ws";

import { renderSseEvent } from "./events.ts";
import { handleJobsRequest } from "./jobs.ts";
import type { AdvisorMessage } from "./protocol.ts";
import { CRASH_LOOP_THRESHOLD, ProviderRegistry } from "./registry.ts";
import { SessionManager } from "./sessions.ts";

interface Harness {
  server: Server;
  url: string;
  registry: ProviderRegistry;
  sessions: SessionManager;
}

async function startHarness(
  opts: { attestationMaxAgeMs?: number; onDispatched?: (ms: number) => void } = {},
): Promise<Harness> {
  const registry = new ProviderRegistry();
  const sessions = new SessionManager({ idleTimeoutMs: 2_000 });
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    if (url.pathname === "/jobs" && req.method === "POST") {
      void handleJobsRequest(req, res, {
        registry,
        sessions,
        generateId: () => "test-session",
        attestationMaxAgeMs: opts.attestationMaxAgeMs,
        onDispatched: opts.onDispatched,
      });
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("no addr");
  return {
    server,
    url: `http://127.0.0.1:${addr.port}`,
    registry,
    sessions,
  };
}

/** Synthesize a "provider" entry directly in the registry — for
 *  pure HTTP-side tests we don't need a real WebSocket; we just
 *  capture the frames the advisor would have sent. */
function fakeProvider(
  registry: ProviderRegistry,
  did: string,
  encryptionPubKey: string,
  /** Whether this provider "answers" the preflight ping. Defaults to
   *  true; pass false to simulate a wedged/unresponsive machine. */
  alive = true,
  /** Per-machine id. Defaults to one derived from the DID; pass an
   *  explicit value to stand up two machines under the SAME did. */
  machineId = `${did}#m`,
): { sent: AdvisorMessage[]; machineId: string; close: () => void } {
  const sent: AdvisorMessage[] = [];
  registry.upsert(
    {
      provider_did: did,
      machine_id: machineId,
      machine_label: "fake",
      chip: "fake-chip",
      ram_gb: 8,
      // Advertise the model the /jobs tests dispatch ("stub"). Empty
      // supportedModels no longer matches any requested model (M2 —
      // empty is not a wildcard), so an explicit advertisement is required
      // for the open-pool path to route these fake providers.
      supported_models: ["stub"],
      encryption_pub_key: encryptionPubKey,
      attestation_pub_key: "fake-attest",
      attestation_uri: "",
    },
    () => {},
    (msg) => {
      sent.push(msg);
    },
    () => Promise.resolve(alive),
  );
  registry.markAttested(did, machineId);
  return { sent, machineId, close: () => registry.remove(did, machineId) };
}

async function readSseLines(url: string, body: object): Promise<string[]> {
  const resp = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "text/event-stream" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status}: ${await resp.text()}`);
  }
  if (!resp.body) throw new Error("no body");
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  const lines: string[] = [];
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buf.indexOf("\n\n")) !== -1) {
      lines.push(buf.slice(0, idx));
      buf = buf.slice(idx + 2);
    }
  }
  return lines;
}

describe("POST /jobs", () => {
  let h: Harness;
  beforeEach(async () => {
    h = await startHarness();
  });
  afterEach(async () => {
    await new Promise<void>((r) => h.server.close(() => r()));
  });

  it("400s on missing fields", async () => {
    const resp = await fetch(`${h.url}/jobs`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jobUri: "at://x" }),
    });
    expect(resp.status).toBe(400);
    const j = (await resp.json()) as { error: string };
    expect(j.error).toMatch(/missing field: requesterDid/);
  });

  it("503s when no providers are connected", async () => {
    const resp = await fetch(`${h.url}/jobs`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jobUri: "at://x",
        requesterDid: "did:plc:requester",
        requesterPubKey: "abcd",
        model: "stub",
        maxTokensOut: 10,
        ciphertext: "QQ==",
      }),
    });
    expect(resp.status).toBe(503);
  });

  it("503s when targeted provider is not connected", async () => {
    fakeProvider(h.registry, "did:plc:online", "pub-online");
    const resp = await fetch(`${h.url}/jobs`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jobUri: "at://x",
        requesterDid: "did:plc:requester",
        requesterPubKey: "abcd",
        model: "stub",
        maxTokensOut: 10,
        ciphertext: "QQ==",
        targetProviderDid: "did:plc:not-here",
      }),
    });
    expect(resp.status).toBe(503);
  });

  it("503s pickFor when the only provider's attestation is stale", async () => {
    // Tear down the default harness; rebuild one with a tight
    // staleness ceiling and backdate the provider's attestedAt.
    await new Promise<void>((r) => h.server.close(() => r()));
    h = await startHarness({ attestationMaxAgeMs: 1_000 });
    const fp = fakeProvider(h.registry, "did:plc:stale", "pub-stale");
    // markAttested defaults to Date.now(); force it to a moment well
    // outside the 1-second ceiling.
    const entry = h.registry.get("did:plc:stale", fp.machineId);
    if (!entry) throw new Error("missing entry");
    entry.attestedAt = Date.now() - 60_000;

    const resp = await fetch(`${h.url}/jobs`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jobUri: "at://x",
        requesterDid: "did:plc:requester",
        requesterPubKey: "abcd",
        model: "stub",
        maxTokensOut: 10,
        ciphertext: "QQ==",
      }),
    });
    expect(resp.status).toBe(503);
    const j = (await resp.json()) as { error: string };
    expect(j.error).toMatch(/no attested providers available/);
  });

  it("503s targeted dispatch when the named provider's attestation is stale", async () => {
    // The targetProviderDid path bypasses pickFor's pre-filter, so
    // this verifies the explicit secondary check in jobs.ts.
    await new Promise<void>((r) => h.server.close(() => r()));
    h = await startHarness({ attestationMaxAgeMs: 1_000 });
    const fp = fakeProvider(h.registry, "did:plc:pinned", "pub-pinned");
    const entry = h.registry.get("did:plc:pinned", fp.machineId);
    if (!entry) throw new Error("missing entry");
    entry.attestedAt = Date.now() - 60_000;

    const resp = await fetch(`${h.url}/jobs`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jobUri: "at://x",
        requesterDid: "did:plc:requester",
        requesterPubKey: "abcd",
        model: "stub",
        maxTokensOut: 10,
        ciphertext: "QQ==",
        targetProviderDid: "did:plc:pinned",
      }),
    });
    expect(resp.status).toBe(503);
    const j = (await resp.json()) as { error: string };
    // The pinned path now filters that DID's machines by the same eligibility
    // the open pool uses; a stale-attestation machine leaves none available.
    expect(j.error).toMatch(/no attested, healthy machine available/);
  });

  it("dispatches and relays the chunk + complete the provider emits", async () => {
    const fp = fakeProvider(h.registry, "did:plc:p1", "pub-p1");

    // Kick off the request — it'll block on the SSE stream until
    // we synthesize provider replies below.
    const linesP = readSseLines(`${h.url}/jobs`, {
      jobUri: "at://job",
      requesterDid: "did:plc:requester",
      requesterPubKey: "req-pub",
      model: "stub",
      maxTokensOut: 32,
      ciphertext: [1, 2, 3],
    });

    // Wait for the inference_request frame to land in the provider's
    // outbound queue, then push back a chunk + complete.
    await vi.waitFor(() => expect(fp.sent.length).toBeGreaterThan(0), { timeout: 1_000 });
    const sent = fp.sent[0];
    expect(sent?.type).toBe("inference_request");
    if (!sent || sent.type !== "inference_request") throw new Error("unreachable");
    expect(sent.session_id).toBe("test-session");
    expect(sent.requester_did).toBe("did:plc:requester");

    // Synthesize the provider's replies by writing to the session
    // through the SessionManager (the WS message handler in main.ts
    // does the same when frames arrive on the socket).
    h.sessions.write("test-session", {
      type: "chunk",
      sessionId: "test-session",
      seq: 0,
      ciphertext: [4, 5, 6],
    });
    h.sessions.complete("test-session", { tokensIn: 1, tokensOut: 2, receiptUri: "at://receipt" });

    const lines = await linesP;
    // Three events: open, chunk, complete.
    expect(lines.length).toBe(3);
    expect(lines[0]).toBe(
      renderSseEvent({ type: "open", sessionId: "test-session", providerDid: "did:plc:p1" }).trim(),
    );
    expect(lines[1]).toContain("event: chunk");
    expect(lines[1]).toContain('"seq":0');
    expect(lines[2]).toContain("event: complete");
    expect(lines[2]).toContain('"receiptUri":"at://receipt"');
  });

  it("fires onDispatched (time-to-ack) once the inference_request is handed off", async () => {
    await new Promise<void>((r) => h.server.close(() => r()));
    const acks: number[] = [];
    h = await startHarness({ onDispatched: (ms) => acks.push(ms) });
    const fp = fakeProvider(h.registry, "did:plc:ack", "pub-ack");

    const linesP = readSseLines(`${h.url}/jobs`, {
      jobUri: "at://job",
      requesterDid: "did:plc:requester",
      requesterPubKey: "req-pub",
      model: "stub",
      maxTokensOut: 32,
      ciphertext: [1, 2, 3],
    });

    // The ack fires the instant the frame lands in the provider's queue —
    // before any chunk is relayed, proving it measures handoff, not TTFT.
    await vi.waitFor(() => expect(fp.sent.length).toBeGreaterThan(0), { timeout: 1_000 });
    expect(acks.length).toBe(1);
    expect(acks[0]).toBeGreaterThanOrEqual(0);
    expect(acks[0]).toBeLessThan(2_000);

    // Drain the stream so the request completes cleanly.
    h.sessions.complete("test-session", { tokensIn: 1, tokensOut: 0, receiptUri: "at://receipt" });
    await linesP;
  });

  it("preflights and fails over from an unresponsive provider to a live one", async () => {
    // A wedged machine (doesn't answer the preflight ping) that's the
    // freshest candidate, plus a healthy one.
    const dead = fakeProvider(h.registry, "did:plc:dead", "pub-dead", false);
    const live = fakeProvider(h.registry, "did:plc:live", "pub-live", true);
    // Make the dead one the freshest so it's preflighted first.
    h.registry.get("did:plc:dead", dead.machineId)!.lastSeen = Date.now() + 10_000;

    const linesP = readSseLines(`${h.url}/jobs`, {
      jobUri: "at://job",
      requesterDid: "did:plc:requester",
      requesterPubKey: "req-pub",
      model: "stub",
      maxTokensOut: 32,
      ciphertext: [1, 2, 3],
    });

    // The job transparently lands on the live provider, not the dead one.
    await vi.waitFor(
      () => expect(live.sent.some((m) => m.type === "inference_request")).toBe(true),
      { timeout: 2_000 },
    );
    expect(dead.sent.some((m) => m.type === "inference_request")).toBe(false);
    // The dead one was told it's in bad standing, asked to self-right, and
    // marked unhealthy.
    expect(dead.sent.some((m) => m.type === "health_notice" && m.standing === "bad")).toBe(true);
    expect(dead.sent.some((m) => m.type === "recover_request")).toBe(true);
    expect(h.registry.get("did:plc:dead", dead.machineId)!.unhealthyAt).not.toBeNull();
    expect(h.registry.get("did:plc:live", live.machineId)!.unhealthyAt).toBeNull();

    h.sessions.complete("test-session", { tokensIn: 1, tokensOut: 2, receiptUri: "at://r" });
    await linesP;
  });

  it("does not route to a crash-looping provider when a healthy one exists", async () => {
    // A crash-looping machine (crash.count >= threshold) that's the freshest
    // candidate, plus a healthy one. Both answer the preflight ping, so the
    // only thing keeping the job off the looping machine is the crash-loop
    // exclusion in pickCandidates.
    const looping = fakeProvider(h.registry, "did:plc:looping", "pub-looping", true);
    const healthy = fakeProvider(h.registry, "did:plc:healthy", "pub-healthy", true);
    // Make the looping one the freshest so, absent the crash exclusion, it
    // would rank first.
    h.registry.get("did:plc:looping", looping.machineId)!.lastSeen = Date.now() + 10_000;
    h.registry.setCrash("did:plc:looping", looping.machineId, { count: CRASH_LOOP_THRESHOLD });

    const linesP = readSseLines(`${h.url}/jobs`, {
      jobUri: "at://job",
      requesterDid: "did:plc:requester",
      requesterPubKey: "req-pub",
      model: "stub",
      maxTokensOut: 32,
      ciphertext: [1, 2, 3],
    });

    await vi.waitFor(
      () => expect(healthy.sent.some((m) => m.type === "inference_request")).toBe(true),
      { timeout: 2_000 },
    );
    expect(looping.sent.some((m) => m.type === "inference_request")).toBe(false);

    h.sessions.complete("test-session", { tokensIn: 1, tokensOut: 2, receiptUri: "at://r" });
    await linesP;
  });

  it("fails over to a healthy sibling machine under the SAME did", async () => {
    // One owner (one DID), two machines: a wedged laptop and a live desktop.
    const laptop = fakeProvider(h.registry, "did:plc:owner", "pub-l", false, "laptop");
    const desktop = fakeProvider(h.registry, "did:plc:owner", "pub-d", true, "desktop");
    // Make the wedged laptop the freshest so it's preflighted first.
    h.registry.get("did:plc:owner", "laptop")!.lastSeen = Date.now() + 10_000;

    const linesP = readSseLines(`${h.url}/jobs`, {
      jobUri: "at://job",
      requesterDid: "did:plc:requester",
      requesterPubKey: "req-pub",
      model: "stub",
      maxTokensOut: 32,
      ciphertext: [1, 2, 3],
    });

    // The job lands on the live desktop; the laptop is flagged, not the DID.
    await vi.waitFor(
      () => expect(desktop.sent.some((m) => m.type === "inference_request")).toBe(true),
      { timeout: 2_000 },
    );
    expect(laptop.sent.some((m) => m.type === "inference_request")).toBe(false);
    expect(h.registry.get("did:plc:owner", "laptop")!.unhealthyAt).not.toBeNull();
    expect(h.registry.get("did:plc:owner", "desktop")!.unhealthyAt).toBeNull();

    h.sessions.complete("test-session", { tokensIn: 1, tokensOut: 2, receiptUri: "at://r" });
    await linesP;
  });

  it("spreads a burst across an owner's capable machines instead of piling onto the freshest", async () => {
    // One owner, two healthy machines — the real-world setup that surfaced
    // this: two Macs under one DID, both able to serve the model. Requests
    // arrive in a burst (e.g. a load test / the console's live probes).
    const a = fakeProvider(h.registry, "did:plc:owner", "pub-a", true, "machine-a");
    const b = fakeProvider(h.registry, "did:plc:owner", "pub-b", true, "machine-b");
    // Make A the freshest so, under the old freshest-wins rule, BOTH jobs
    // would have concentrated on A while B sat idle.
    h.registry.get("did:plc:owner", "machine-a")!.lastSeen = Date.now() + 10_000;

    // Job 1 lands on the freshest (A) and stays in-flight (no complete yet).
    const job1 = readSseLines(`${h.url}/jobs`, {
      jobUri: "at://job1",
      requesterDid: "did:plc:requester",
      requesterPubKey: "req-pub",
      model: "stub",
      maxTokensOut: 32,
      ciphertext: [1, 2, 3],
      sessionId: "s1",
    });
    await vi.waitFor(() => expect(a.sent.some((m) => m.type === "inference_request")).toBe(true), {
      timeout: 2_000,
    });

    // Job 2: A now carries an in-flight session, so the least-loaded rule
    // routes it to B even though A is still the freshest heartbeat.
    const job2 = readSseLines(`${h.url}/jobs`, {
      jobUri: "at://job2",
      requesterDid: "did:plc:requester",
      requesterPubKey: "req-pub",
      model: "stub",
      maxTokensOut: 32,
      ciphertext: [1, 2, 3],
      sessionId: "s2",
    });
    await vi.waitFor(() => expect(b.sent.some((m) => m.type === "inference_request")).toBe(true), {
      timeout: 2_000,
    });

    // The burst fanned out: one request each, not two on A.
    expect(a.sent.filter((m) => m.type === "inference_request").length).toBe(1);
    expect(b.sent.filter((m) => m.type === "inference_request").length).toBe(1);

    h.sessions.complete("s1", { tokensIn: 1, tokensOut: 2, receiptUri: "at://r1" });
    h.sessions.complete("s2", { tokensIn: 1, tokensOut: 2, receiptUri: "at://r2" });
    await Promise.all([job1, job2]);
  });

  it("targetMachineId pins dispatch to one specific machine under a did", async () => {
    const laptop = fakeProvider(h.registry, "did:plc:owner", "pub-l", true, "laptop");
    const desktop = fakeProvider(h.registry, "did:plc:owner", "pub-d", true, "desktop");

    const linesP = readSseLines(`${h.url}/jobs`, {
      jobUri: "at://job",
      requesterDid: "did:plc:requester",
      requesterPubKey: "req-pub",
      model: "stub",
      maxTokensOut: 32,
      ciphertext: [1, 2, 3],
      targetProviderDid: "did:plc:owner",
      targetMachineId: "desktop",
    });

    await vi.waitFor(
      () => expect(desktop.sent.some((m) => m.type === "inference_request")).toBe(true),
      { timeout: 2_000 },
    );
    // The laptop, though healthy, was never in the candidate set.
    expect(laptop.sent.some((m) => m.type === "inference_request")).toBe(false);

    h.sessions.complete("test-session", { tokensIn: 1, tokensOut: 2, receiptUri: "at://r" });
    await linesP;
  });

  it("503s when every provider fails preflight", async () => {
    const dead = fakeProvider(h.registry, "did:plc:dead-only", "pub", false);
    const resp = await fetch(`${h.url}/jobs`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jobUri: "at://x",
        requesterDid: "did:plc:requester",
        requesterPubKey: "abcd",
        model: "stub",
        maxTokensOut: 10,
        ciphertext: "QQ==",
      }),
    });
    expect(resp.status).toBe(503);
    const j = (await resp.json()) as { error: string };
    expect(j.error).toMatch(/no responsive providers/);
    expect(dead.sent.some((m) => m.type === "health_notice" && m.standing === "bad")).toBe(true);
  });
});

describe("WebSocket round-trip (smoke)", () => {
  it("provider WS frames flow into the registry's send hook", async () => {
    const server = createServer();
    const wss = new WebSocketServer({ server, path: "/v1/agent" });
    const registry = new ProviderRegistry();

    wss.on("connection", (sock) => {
      sock.on("message", (data) => {
        const m = JSON.parse(data.toString("utf8")) as AdvisorMessage;
        if (m.type === "register") {
          registry.upsert(
            m,
            () => sock.close(),
            (msg) => sock.send(JSON.stringify(msg)),
            () => Promise.resolve(true),
          );
          registry.markAttested(m.provider_did, ProviderRegistry.machineIdOf(m));
        }
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const addr = server.address();
    if (!addr || typeof addr === "string") throw new Error("no addr");

    const inbound: AdvisorMessage[] = [];
    const ws = new WebSocket(`ws://127.0.0.1:${addr.port}/v1/agent`);
    await new Promise<void>((r) => ws.once("open", () => r()));
    ws.on("message", (data) => {
      inbound.push(JSON.parse(data.toString("utf8")) as AdvisorMessage);
    });

    ws.send(
      JSON.stringify({
        type: "register",
        provider_did: "did:plc:roundtrip",
        machine_label: "x",
        chip: "y",
        ram_gb: 1,
        supported_models: [],
        encryption_pub_key: "k",
        attestation_pub_key: "a",
        attestation_uri: "",
      }),
    );

    await vi.waitFor(() => expect(registry.size()).toBe(1), { timeout: 1_000 });
    // No machine_id in the register frame → machineId falls back to the
    // attestation_pub_key ("a").
    const entry = registry.get("did:plc:roundtrip", "a");
    if (!entry) throw new Error("missing entry");

    // Push a frame through the registry.send hook — should land at
    // the WS client.
    entry.send({ type: "heartbeat", load: 0, queue_depth: 0, at: new Date().toISOString() });
    await vi.waitFor(() => expect(inbound.length).toBe(1), { timeout: 1_000 });
    expect(inbound[0]?.type).toBe("heartbeat");

    ws.close();
    await new Promise<void>((r) => server.close(() => r()));
  });
});
