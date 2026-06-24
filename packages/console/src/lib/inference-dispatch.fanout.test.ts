// Unit tests for the multi-image fan-out machine enumeration. The full
// runMultiImageDispatch path runs the real runDispatch (publish + seal +
// stream), so here we cover the pure-ish selection logic: listModelMachines
// filters to attested machines serving the model, dedupes by composite
// (did, machineId) key, and orders freshest-first.

import { afterEach, describe, expect, test } from "vitest";

import { listModelMachines, machineKey } from "./inference-dispatch.server.ts";

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

function providersResponse(rows: unknown[]): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(rows), {
      status: 200,
      headers: { "content-type": "application/json" },
    })) as unknown as typeof fetch;
}

describe("machineKey", () => {
  test("distinguishes two machines under one DID", () => {
    expect(machineKey({ did: "did:plc:a", machineId: "m1" })).not.toBe(
      machineKey({ did: "did:plc:a", machineId: "m2" }),
    );
  });
});

describe("listModelMachines", () => {
  test("returns distinct attested machines serving the model, freshest-first", async () => {
    globalThis.fetch = providersResponse([
      {
        did: "did:plc:a",
        machineId: "m1",
        attestedAt: "t",
        lastSeen: "2026-01-01T00:00:01Z",
        supportedModels: ["stub-flux"],
        encryptionPubKey: "k",
      },
      {
        did: "did:plc:a",
        machineId: "m2",
        attestedAt: "t",
        lastSeen: "2026-01-01T00:00:03Z",
        supportedModels: ["stub-flux"],
        encryptionPubKey: "k",
      },
      {
        did: "did:plc:b",
        machineId: "m1",
        attestedAt: "t",
        lastSeen: "2026-01-01T00:00:02Z",
        supportedModels: [],
        encryptionPubKey: "k",
      },
      // Not attested — excluded.
      {
        did: "did:plc:c",
        machineId: "m1",
        attestedAt: null,
        lastSeen: "2026-01-01T00:00:09Z",
        supportedModels: ["stub-flux"],
        encryptionPubKey: "k",
      },
      // Doesn't serve the model — excluded.
      {
        did: "did:plc:d",
        machineId: "m1",
        attestedAt: "t",
        lastSeen: "2026-01-01T00:00:09Z",
        supportedModels: ["other"],
        encryptionPubKey: "k",
      },
    ]);

    const machines = await listModelMachines("http://advisor", "stub-flux");
    // a/m2 (freshest), b/m1, a/m1 — distinct (did,machineId), freshest-first.
    expect(machines).toEqual([
      { did: "did:plc:a", machineId: "m2" },
      { did: "did:plc:b", machineId: "m1" },
      { did: "did:plc:a", machineId: "m1" },
    ]);
  });

  test("constrains to the allowed DID set when given", async () => {
    globalThis.fetch = providersResponse([
      {
        did: "did:plc:a",
        machineId: "m1",
        attestedAt: "t",
        lastSeen: "2026-01-01T00:00:01Z",
        supportedModels: ["stub-flux"],
        encryptionPubKey: "k",
      },
      {
        did: "did:plc:b",
        machineId: "m1",
        attestedAt: "t",
        lastSeen: "2026-01-01T00:00:02Z",
        supportedModels: ["stub-flux"],
        encryptionPubKey: "k",
      },
    ]);
    const machines = await listModelMachines("http://advisor", "stub-flux", new Set(["did:plc:b"]));
    expect(machines).toEqual([{ did: "did:plc:b", machineId: "m1" }]);
  });
});
