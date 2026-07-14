// Idempotency of the DeviceInformation attestation enqueue.
//
// NanoMDM's per-device command queue is FIFO with no clear API. Re-enqueuing a
// DeviceInformation command for a key we already requested piles stale commands
// ahead of the real one AND hammers Apple's rate-limited DeviceAttestation into
// returning a CACHED (old-key) chain — which #178 then discards forever. So a
// repeat request for the SAME key must NOT enqueue again; it only re-pushes the
// command already queued. A key change must still enqueue immediately.
//
// The store is mocked (no better-sqlite3), and fetch is stubbed so we can assert
// exactly which NanoMDM endpoints are hit.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const store = { pending: null as { pubkey: string; requestedAt: string } | null };

vi.mock("./mdm-chain-store.server.ts", () => ({
  getExpectedAttestation: () => store.pending,
  getExpectedAttestationKey: () => store.pending?.pubkey ?? null,
  putExpectedAttestationKey: (serial: string, pubkey: string, requestedAt: string) => {
    store.pending = { pubkey, requestedAt };
  },
  getAttestationChain: () => null,
  putAttestationChain: () => {},
}));

import { requestDeviceInformationAttestation } from "./mdm-coordinator.server.ts";

const SERIAL = "H2WHW38LQ6NV";
const UDID = "A1B2C3D4-1111-2222-3333-444455556666";
const KEY_A = Buffer.alloc(64, 1).toString("base64");
const KEY_B = Buffer.alloc(64, 2).toString("base64");

let calls: string[] = [];

beforeEach(() => {
  store.pending = null;
  calls = [];
  process.env["COCORE_NANOMDM_URL"] = "https://nano.example";
  process.env["COCORE_NANOMDM_API_KEY"] = "k";
  vi.stubGlobal("fetch", async (url: string) => {
    calls.push(String(url));
    return { ok: true, status: 200, text: async () => "" } as Response;
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env["COCORE_NANOMDM_URL"];
  delete process.env["COCORE_NANOMDM_API_KEY"];
});

const enqueued = () => calls.some((u) => u.includes("/v1/enqueue/"));
const pushed = () => calls.some((u) => u.includes("/v1/push/"));

describe("requestDeviceInformationAttestation idempotency", () => {
  it("first request for a key enqueues + pushes", async () => {
    await requestDeviceInformationAttestation(SERIAL, UDID, KEY_A);
    expect(enqueued()).toBe(true);
    expect(pushed()).toBe(true);
    expect(store.pending?.pubkey).toBe(KEY_A);
  });

  it("a repeat request for the SAME key re-pushes but does NOT enqueue again", async () => {
    store.pending = { pubkey: KEY_A, requestedAt: new Date().toISOString() };
    const r = await requestDeviceInformationAttestation(SERIAL, UDID, KEY_A);
    expect(enqueued()).toBe(false); // no duplicate command piled onto the queue
    expect(pushed()).toBe(true); // but the queued command is nudged
    expect(r.detail).toMatch(/already requested/i);
  });

  it("a KEY CHANGE enqueues immediately (bypasses dedup)", async () => {
    store.pending = { pubkey: KEY_A, requestedAt: new Date().toISOString() };
    await requestDeviceInformationAttestation(SERIAL, UDID, KEY_B);
    expect(enqueued()).toBe(true);
    expect(store.pending?.pubkey).toBe(KEY_B);
  });

  it("a STALE same-key request (past the dedup window) enqueues a fresh command", async () => {
    store.pending = {
      pubkey: KEY_A,
      requestedAt: new Date(Date.now() - 7 * 60 * 60_000).toISOString(), // 7h ago > 6h window
    };
    await requestDeviceInformationAttestation(SERIAL, UDID, KEY_A);
    expect(enqueued()).toBe(true);
  });
});
