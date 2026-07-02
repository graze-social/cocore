// Security tests for the advisor connection handler:
//   C1 — DID-bound registration (auth_jwt must bind to provider_did).
//   C2 — a malformed frame closes the socket cleanly (no process crash).
//   H6b — a socket that isn't a session's assigned provider can't complete or
//         inject chunks for it.

import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import { WebSocket, WebSocketServer } from "ws";

import { P256PrivateKeyExportable } from "@atcute/crypto";

import { handleConnection, type ConnectionConfig } from "./connection.ts";
import { type DidDocumentResolver, LXM_REGISTER } from "./did-auth.ts";
import { ProviderRegistry } from "./registry.ts";
import { SessionManager } from "./sessions.ts";
import type { SseResponse } from "./sessions.ts";

const ADVISOR_DID = "did:web:advisor.cocore.dev";

// --- JWT + stub-resolver helpers (mirrors did-auth.test.ts) --------
function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlJson(obj: unknown): string {
  return b64url(new TextEncoder().encode(JSON.stringify(obj)));
}
async function mintJwt(
  key: P256PrivateKeyExportable,
  claims: { iss: string; aud: string; lxm: string },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "ES256", typ: "JWT" };
  const payload = { exp: now + 60, ...claims };
  const signingInput = `${b64urlJson(header)}.${b64urlJson(payload)}`;
  const sig = await key.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${b64url(sig)}`;
}
async function keyAndResolver(
  did: string,
): Promise<{ key: P256PrivateKeyExportable; resolver: DidDocumentResolver }> {
  const key = await P256PrivateKeyExportable.createKeypair();
  const multikey = await key.exportPublicKey("multikey");
  const resolver: DidDocumentResolver = {
    resolve(reqDid) {
      if (reqDid !== did) return Promise.reject(new Error("unknown did"));
      return Promise.resolve({
        id: did,
        verificationMethod: [
          { id: `${did}#atproto`, type: "Multikey", controller: did, publicKeyMultibase: multikey },
        ],
      });
    },
  };
  return { key, resolver };
}

interface Harness {
  server: Server;
  url: string;
  registry: ProviderRegistry;
  sessions: SessionManager;
}
async function startHarness(config: Partial<ConnectionConfig>): Promise<Harness> {
  const registry = new ProviderRegistry();
  const sessions = new SessionManager({ idleTimeoutMs: 2_000 });
  const server = createServer();
  const wss = new WebSocketServer({ server, path: "/v1/agent" });
  wss.on("connection", (socket, req) =>
    handleConnection(socket, req, registry, sessions, {
      rechallengeIntervalMs: 60_000,
      responseTimeoutMs: 30_000,
      ...config,
    }),
  );
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("no addr");
  return { server, url: `ws://127.0.0.1:${addr.port}/v1/agent`, registry, sessions };
}

function registerFrame(providerDid: string, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    type: "register",
    provider_did: providerDid,
    machine_label: "m1",
    chip: "M4",
    ram_gb: 64,
    supported_models: ["stub"],
    encryption_pub_key: "k",
    attestation_pub_key: "a",
    attestation_uri: "",
    ...extra,
  });
}

describe("C1 — DID-bound registration", () => {
  let h: Harness;
  afterEach(async () => {
    if (h) await new Promise<void>((r) => h.server.close(() => r()));
  });

  it("accepts a register whose JWT iss matches provider_did", async () => {
    const did = "did:plc:good";
    const { key, resolver } = await keyAndResolver(did);
    h = await startHarness({ advisorDid: ADVISOR_DID, requireAuth: true, didResolver: resolver });
    const jwt = await mintJwt(key, { iss: did, aud: ADVISOR_DID, lxm: LXM_REGISTER });
    const ws = new WebSocket(h.url);
    await new Promise<void>((r) => ws.once("open", () => r()));
    ws.send(registerFrame(did, { auth_jwt: jwt }));
    // A challenge frame means the register was accepted.
    const got = await new Promise<string>((resolve, reject) => {
      const t = setTimeout(() => reject(new Error("no challenge")), 1500);
      ws.on("message", (d) => {
        clearTimeout(t);
        resolve(d.toString("utf8"));
      });
    });
    expect(got).toContain("attestation_challenge");
    expect(h.registry.get(did, "a")).toBeDefined();
    ws.terminate();
  }, 5_000);

  it("rejects a register whose JWT iss != provider_did (impersonation)", async () => {
    const victim = "did:plc:victim";
    const attacker = "did:plc:attacker";
    // The attacker holds a valid JWT for ITS OWN did, but registers as the victim.
    const { key, resolver } = await keyAndResolver(attacker);
    h = await startHarness({ advisorDid: ADVISOR_DID, requireAuth: true, didResolver: resolver });
    const jwt = await mintJwt(key, { iss: attacker, aud: ADVISOR_DID, lxm: LXM_REGISTER });
    const ws = new WebSocket(h.url);
    await new Promise<void>((r) => ws.once("open", () => r()));
    ws.send(registerFrame(victim, { auth_jwt: jwt }));
    const code = await new Promise<number>((resolve) => ws.once("close", (c) => resolve(c)));
    expect(code).toBe(1008);
    expect(h.registry.get(victim, "a")).toBeUndefined();
  }, 5_000);

  it("rejects a register with no JWT when requireAuth is on", async () => {
    const { resolver } = await keyAndResolver("did:plc:whoever");
    h = await startHarness({ advisorDid: ADVISOR_DID, requireAuth: true, didResolver: resolver });
    const ws = new WebSocket(h.url);
    await new Promise<void>((r) => ws.once("open", () => r()));
    ws.send(registerFrame("did:plc:noauth"));
    const code = await new Promise<number>((resolve) => ws.once("close", (c) => resolve(c)));
    expect(code).toBe(1008);
    expect(h.registry.get("did:plc:noauth", "a")).toBeUndefined();
  }, 5_000);

  it("accepts a register with no JWT when requireAuth is off (staged rollout)", async () => {
    const { resolver } = await keyAndResolver("did:plc:whoever");
    h = await startHarness({ advisorDid: ADVISOR_DID, requireAuth: false, didResolver: resolver });
    const ws = new WebSocket(h.url);
    await new Promise<void>((r) => ws.once("open", () => r()));
    ws.send(registerFrame("did:plc:legacy"));
    const got = await new Promise<string>((resolve, reject) => {
      const t = setTimeout(() => reject(new Error("no challenge")), 1500);
      ws.on("message", (d) => {
        clearTimeout(t);
        resolve(d.toString("utf8"));
      });
    });
    expect(got).toContain("attestation_challenge");
    expect(h.registry.get("did:plc:legacy", "a")).toBeDefined();
    ws.terminate();
  }, 5_000);
});

describe("C2 — malformed frames don't crash the process", () => {
  let h: Harness;
  afterEach(async () => {
    if (h) await new Promise<void>((r) => h.server.close(() => r()));
  });

  it("closes the socket with 1008 on a register frame missing required fields", async () => {
    h = await startHarness({});
    const ws = new WebSocket(h.url);
    await new Promise<void>((r) => ws.once("open", () => r()));
    // `{"type":"register"}` — would hit msg.supported_models.length before the fix.
    ws.send(JSON.stringify({ type: "register" }));
    const { code, reason } = await new Promise<{ code: number; reason: string }>((resolve) =>
      ws.once("close", (c, r) => resolve({ code: c, reason: r.toString("utf8") })),
    );
    expect(code).toBe(1008);
    expect(reason).toBe("bad-frame");
  }, 5_000);

  it("closes on an attestation_response missing signature (no deep throw)", async () => {
    h = await startHarness({});
    const ws = new WebSocket(h.url);
    await new Promise<void>((r) => ws.once("open", () => r()));
    ws.send(
      JSON.stringify({
        type: "attestation_response",
        nonce: "00000000000000000000000000000000",
        timestamp: "2026-01-01T00:00:00Z",
        sip_enabled: true,
        // signature omitted → bytesToBase64(undefined) used to throw deep.
      }),
    );
    const { code, reason } = await new Promise<{ code: number; reason: string }>((resolve) =>
      ws.once("close", (c, r) => resolve({ code: c, reason: r.toString("utf8") })),
    );
    expect(code).toBe(1008);
    expect(reason).toBe("bad-frame");
  }, 5_000);
});

describe("H6b — session frames are bound to the assigned provider", () => {
  let h: Harness;
  afterEach(async () => {
    if (h) await new Promise<void>((r) => h.server.close(() => r()));
  });

  /** A minimal SSE sink capturing the events the SessionManager writes. */
  function fakeSink(): { events: string[]; sink: SseResponse } {
    const events: string[] = [];
    const sink: SseResponse = {
      statusCode: 200,
      setHeader() {},
      flushHeaders() {},
      write(chunk: string) {
        events.push(chunk);
        return true;
      },
      end() {},
      get writableEnded() {
        return false;
      },
    };
    return { events, sink };
  }

  it("drops an inference_complete from a socket that isn't the session's provider", async () => {
    h = await startHarness({});
    // Provider A (the assigned one) and attacker B both connect + register.
    const wsA = new WebSocket(h.url);
    await new Promise<void>((r) => wsA.once("open", () => r()));
    wsA.send(registerFrame("did:plc:provA", { machine_id: "mA", attestation_pub_key: "kA" }));

    const wsB = new WebSocket(h.url);
    await new Promise<void>((r) => wsB.once("open", () => r()));
    wsB.send(registerFrame("did:plc:attacker", { machine_id: "mB", attestation_pub_key: "kB" }));

    // Wait for both to be registered.
    await vi.waitFor(() => {
      expect(h.registry.get("did:plc:provA", "mA")).toBeDefined();
      expect(h.registry.get("did:plc:attacker", "mB")).toBeDefined();
    });

    // Open a session dispatched to provider A.
    const { events, sink } = fakeSink();
    h.sessions.open("sess-1", "did:plc:provA", "mA", "did:plc:req", sink);
    events.length = 0; // drop the `open` event

    // Attacker B completes the session it doesn't own — must be ignored.
    wsB.send(
      JSON.stringify({
        type: "inference_complete",
        session_id: "sess-1",
        tokens_in: 1,
        tokens_out: 1,
        receipt_uri: "at://attacker/evil",
      }),
    );

    // Give the frame time to be processed, then assert the session is intact
    // and no complete/chunk leaked to the requester.
    await new Promise<void>((r) => setTimeout(r, 200));
    expect(h.sessions.has("sess-1")).toBe(true);
    expect(events.join("")).not.toContain("attacker/evil");
    // And the attacker didn't get its own bad standing cleared via recordCompletion.
    expect(h.registry.get("did:plc:attacker", "mB")?.completed).toBe(0);

    // The genuine provider A CAN complete it.
    wsA.send(
      JSON.stringify({
        type: "inference_complete",
        session_id: "sess-1",
        tokens_in: 2,
        tokens_out: 3,
        receipt_uri: "at://provA/good",
      }),
    );
    await vi.waitFor(() => expect(h.sessions.has("sess-1")).toBe(false));
    expect(events.join("")).toContain("provA/good");

    wsA.terminate();
    wsB.terminate();
  }, 5_000);
});
