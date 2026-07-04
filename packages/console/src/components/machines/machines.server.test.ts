// Unit tests for recentlyActiveModels — the "did a model serve a job in
// the last few minutes" signal that flips a machine from idle → running.

import assert from "node:assert/strict";
import { test } from "vitest";

import type { AppviewIndexedRecord } from "@/integrations/appview/appview.server.ts";

import {
  aggregateReceiptsByMachine,
  aggregateReceiptsForDid,
  applyAdvisorStanding,
  providerRowsToMachines,
  pubkeyToRkeyMap,
  recentlyActiveModels,
} from "./machines.server.ts";
import type {
  AdvisorStandingResult,
  FleetReceiptStats,
  MachineReceiptStats,
} from "./machines.server.ts";
import { advisorUnreachable, machineNetworkStanding, type Machine } from "./machines-data.ts";

const NOW = Date.UTC(2026, 5, 11, 12, 0, 0); // fixed "now"
const minsAgo = (m: number) => new Date(NOW - m * 60_000).toISOString();

function receipt(
  model: string | undefined,
  completedAt?: string,
  indexedAt?: string,
): AppviewIndexedRecord {
  return {
    uri: `at://did:plc:x/dev.cocore.compute.receipt/${Math.random().toString(36).slice(2)}`,
    cid: "bafy",
    collection: "dev.cocore.compute.receipt",
    repo: "did:plc:x",
    rkey: "r",
    body: { ...(model !== undefined ? { model } : {}), ...(completedAt ? { completedAt } : {}) },
    ...(indexedAt ? { indexedAt } : {}),
  };
}

test("includes models with a receipt completed inside the window", () => {
  const set = recentlyActiveModels(
    [receipt("model-a", minsAgo(2)), receipt("model-b", minsAgo(4))],
    NOW,
  );
  assert.ok(set.has("model-a"));
  assert.ok(set.has("model-b"));
});

test("excludes models whose last receipt is older than the window", () => {
  const set = recentlyActiveModels([receipt("stale", minsAgo(10))], NOW);
  assert.equal(set.has("stale"), false);
  assert.equal(set.size, 0);
});

test("a model is active if ANY of its receipts is recent", () => {
  const set = recentlyActiveModels(
    [receipt("m", minsAgo(30)), receipt("m", minsAgo(1)), receipt("m", minsAgo(20))],
    NOW,
  );
  assert.ok(set.has("m"));
});

test("receipts without a model are ignored", () => {
  const set = recentlyActiveModels([receipt(undefined, minsAgo(1))], NOW);
  assert.equal(set.size, 0);
});

test("falls back to indexedAt when completedAt is absent", () => {
  const set = recentlyActiveModels([receipt("m", undefined, minsAgo(1))], NOW);
  assert.ok(set.has("m"));
});

test("the boundary is exclusive-old / inclusive-recent at 5 min", () => {
  const within = recentlyActiveModels([receipt("edge", minsAgo(4.9))], NOW);
  assert.ok(within.has("edge"));
  const outside = recentlyActiveModels([receipt("edge", minsAgo(5.1))], NOW);
  assert.equal(outside.has("edge"), false);
});

test("a custom window is honored", () => {
  const set = recentlyActiveModels([receipt("m", minsAgo(8))], NOW, 10 * 60_000);
  assert.ok(set.has("m"));
});

// --- aggregateReceiptsForDid: token (CC) accounting ---

/** A receipt priced in `currency` at `amount` minor units. */
function priced(amount: number, currency: string, completedAt: string): AppviewIndexedRecord {
  return {
    uri: `at://did:plc:x/dev.cocore.compute.receipt/${Math.random().toString(36).slice(2)}`,
    cid: "bafy",
    collection: "dev.cocore.compute.receipt",
    repo: "did:plc:x",
    rkey: "r",
    body: { model: "m", price: { amount, currency }, completedAt },
  };
}

test("CC-priced receipts are counted as tokens (regression: the USD filter dropped them)", () => {
  // The provider only ever publishes CC receipts; the old filter required
  // currency === "USD", so every real receipt was silently skipped and all
  // metrics read 0 despite the machine serving jobs.
  const stats = aggregateReceiptsForDid(
    [priced(46, "CC", minsAgo(2)), priced(90, "CC", minsAgo(30))],
    NOW,
  );
  assert.equal(stats.jobs24h, 2);
  assert.equal(stats.earn24hTokens, 136);
  assert.equal(stats.jobsLifetime, 2);
  assert.equal(stats.earnLifetimeTokens, 136);
});

test("the CC token amount is summed raw (no /100 minor-unit division)", () => {
  const stats = aggregateReceiptsForDid([priced(46, "CC", minsAgo(1))], NOW);
  assert.equal(stats.earn24hTokens, 46);
});

test("non-CC (legacy USD) receipts are not counted toward the token total", () => {
  const stats = aggregateReceiptsForDid([priced(500, "USD", minsAgo(1))], NOW);
  assert.equal(stats.jobs24h, 0);
  assert.equal(stats.earn24hTokens, 0);
});

test("receipts without a price are ignored by the aggregate", () => {
  const stats = aggregateReceiptsForDid([receipt("m", minsAgo(1))], NOW);
  assert.equal(stats.jobsLifetime, 0);
  assert.equal(stats.earnLifetimeTokens, 0);
});

// --- engineFault mapping (provider record → Machine) ---

const ZERO_STATS: FleetReceiptStats = {
  earn24hTokens: 0,
  earn7dTokens: 0,
  earn30dTokens: 0,
  earnLifetimeTokens: 0,
  jobs24h: 0,
  jobs7d: 0,
  jobs30d: 0,
  jobsLifetime: 0,
  hourlyEarnTokens: [],
  hourlyActivityPct: [],
  dailyEarnTokens7d: [],
  dailyEarnTokens30d: [],
  dailyActivityPct7d: [],
  dailyActivityPct30d: [],
};

function providerRow(body: Record<string, unknown>): AppviewIndexedRecord {
  return {
    uri: "at://did:plc:x/dev.cocore.compute.provider/p",
    cid: "bafy",
    collection: "dev.cocore.compute.provider",
    repo: "did:plc:x",
    rkey: "p",
    body: { machineLabel: "mac.lan", chip: "Apple M2", ramGB: 24, ...body },
  };
}

test("engineFault is mapped onto the machine when the record carries it", () => {
  const m = providerRowsToMachines(
    [
      providerRow({
        supportedModels: ["stub"],
        engineFault: {
          code: "model-load-failed",
          message: "The inference engine for [qwen] did not come online after 3 attempts.",
          models: ["qwen"],
        },
      }),
    ],
    ZERO_STATS,
    new Map(),
  )[0]!;
  assert.equal(m.faultCode, "model-load-failed");
  assert.match(m.faultReason ?? "", /did not come online/);
  assert.deepEqual(m.faultModels, ["qwen"]);
});

test("a healthy record produces no fault fields", () => {
  const m = providerRowsToMachines(
    [providerRow({ supportedModels: ["qwen"] })],
    ZERO_STATS,
    new Map(),
  )[0]!;
  assert.equal(m.faultCode, undefined);
  assert.equal(m.faultReason, undefined);
  assert.equal(m.faultModels, undefined);
});

test("a fault without a human-readable message is ignored (no empty alert)", () => {
  const m = providerRowsToMachines(
    [providerRow({ supportedModels: ["stub"], engineFault: { code: "model-load-failed" } })],
    ZERO_STATS,
    new Map(),
  )[0]!;
  assert.equal(m.faultReason, undefined);
  assert.equal(m.faultCode, undefined);
});

test("serving=false reads as offline rather than idle", () => {
  const m = providerRowsToMachines(
    [providerRow({ supportedModels: ["qwen"], serving: false })],
    ZERO_STATS,
    new Map(),
  )[0]!;
  assert.equal(m.state, "offline");
});

test("absent serving stays idle (back-compat with pre-2026-06 records)", () => {
  const m = providerRowsToMachines(
    [providerRow({ supportedModels: ["qwen"] })],
    ZERO_STATS,
    new Map(),
  )[0]!;
  assert.equal(m.state, "idle");
});

test("provisioning wins over serving=false", () => {
  const m = providerRowsToMachines(
    [providerRow({ supportedModels: ["qwen"], provisioning: true, serving: false })],
    ZERO_STATS,
    new Map(),
  )[0]!;
  assert.equal(m.state, "provisioning");
});

// --- per-machine attribution (receipt → attestation pubkey → machine) ---

/** A CC receipt attributed to attestation `attUri`. */
function attributed(amount: number, attUri: string, completedAt: string): AppviewIndexedRecord {
  return {
    uri: `at://did:plc:x/dev.cocore.compute.receipt/${Math.random().toString(36).slice(2)}`,
    cid: "bafy",
    collection: "dev.cocore.compute.receipt",
    repo: "did:plc:x",
    rkey: "r",
    body: {
      model: "m",
      price: { amount, currency: "CC" },
      completedAt,
      attestation: { uri: attUri, cid: "bafyatt" },
    },
  };
}

function machineRow(rkey: string, label: string, attestationPubKey: string): AppviewIndexedRecord {
  return {
    uri: `at://did:plc:x/dev.cocore.compute.provider/${rkey}`,
    cid: "bafy",
    collection: "dev.cocore.compute.provider",
    repo: "did:plc:x",
    rkey,
    body: { machineLabel: label, chip: "Apple M2", ramGB: 24, attestationPubKey },
  };
}

const ATT_A = "at://did:plc:x/dev.cocore.compute.attestation/aaa";
const ATT_A2 = "at://did:plc:x/dev.cocore.compute.attestation/aaa2"; // same machine, later session
const ATT_B = "at://did:plc:x/dev.cocore.compute.attestation/bbb";
// attestation URI → publicKey, and publicKey → machine rkey
const ATT_URI_TO_PUBKEY = new Map([
  [ATT_A, "PUBKEY_A"],
  [ATT_A2, "PUBKEY_A"],
  [ATT_B, "PUBKEY_B"],
]);
const PUBKEY_TO_RKEY = new Map([
  ["PUBKEY_A", "machine-a"],
  ["PUBKEY_B", "machine-b"],
]);

test("aggregateReceiptsByMachine attributes receipts to the serving machine, not an even split", () => {
  const byMachine = aggregateReceiptsByMachine(
    [
      attributed(46, ATT_A, minsAgo(2)),
      attributed(90, ATT_A2, minsAgo(3)), // same machine, different session
      attributed(46, ATT_B, minsAgo(4)),
    ],
    ATT_URI_TO_PUBKEY,
    PUBKEY_TO_RKEY,
    NOW,
  );
  assert.equal(byMachine.get("machine-a")?.earn24hTokens, 136);
  assert.equal(byMachine.get("machine-a")?.jobsLifetime, 2);
  assert.equal(byMachine.get("machine-b")?.earn24hTokens, 46);
  assert.equal(byMachine.get("machine-b")?.jobsLifetime, 1);
});

test("receipts whose attestation maps to no current machine are left unattributed", () => {
  const byMachine = aggregateReceiptsByMachine(
    [attributed(50, "at://did:plc:x/dev.cocore.compute.attestation/retired", minsAgo(1))],
    ATT_URI_TO_PUBKEY,
    PUBKEY_TO_RKEY,
    NOW,
  );
  assert.equal(byMachine.size, 0);
});

test("pubkeyToRkeyMap maps each provider record's attestationPubKey to its rkey", () => {
  const m = pubkeyToRkeyMap([
    machineRow("machine-a", "mac.lan", "PUBKEY_A"),
    machineRow("machine-b", "mini", "PUBKEY_B"),
  ]);
  assert.equal(m.get("PUBKEY_A"), "machine-a");
  assert.equal(m.get("PUBKEY_B"), "machine-b");
});

test("providerRowsToMachines uses per-machine attribution when provided (no even split)", () => {
  const perMachine = new Map<string, MachineReceiptStats>([
    [
      "machine-a",
      { earn24hTokens: 5000, earn7dTokens: 5000, earnLifetimeTokens: 5000, jobsLifetime: 24 },
    ],
    [
      "machine-b",
      { earn24hTokens: 2007, earn7dTokens: 2007, earnLifetimeTokens: 2007, jobsLifetime: 18 },
    ],
  ]);
  const rows = [
    machineRow("machine-a", "mac.lan", "PUBKEY_A"),
    machineRow("machine-b", "mini", "PUBKEY_B"),
  ];
  const repoCounts = new Map([["did:plc:x", 2]]);
  const machines = providerRowsToMachines(rows, ZERO_STATS, repoCounts, new Set(), perMachine);
  const a = machines.find((m) => m.id === "machine-a")!;
  const b = machines.find((m) => m.id === "machine-b")!;
  assert.equal(a.earnings24h, 5000);
  assert.equal(a.jobsCompleted, 24);
  assert.equal(b.earnings24h, 2007);
  assert.equal(b.jobsCompleted, 18);
});

test("providerRowsToMachines falls back to the even split when attribution is null", () => {
  const stats: FleetReceiptStats = { ...ZERO_STATS, earn24hTokens: 7000, jobsLifetime: 42 };
  const rows = [
    machineRow("machine-a", "mac.lan", "PUBKEY_A"),
    machineRow("machine-b", "mini", "PUBKEY_B"),
  ];
  const repoCounts = new Map([["did:plc:x", 2]]);
  const machines = providerRowsToMachines(rows, stats, repoCounts, new Set(), null);
  // Even split: 7000/2 each, 42 jobs split 21/21.
  assert.equal(machines[0]!.earnings24h, 3500);
  assert.equal(machines[1]!.earnings24h, 3500);
  assert.equal(machines[0]!.jobsCompleted, 21);
  assert.equal(machines[1]!.jobsCompleted, 21);
});

// --- applyAdvisorStanding: live-standing overlay -----------------------

function machineStub(id: string): Machine {
  return {
    id,
    alias: id,
    state: "idle",
    gpu: "Apple M4",
    vram: 24,
    ram: 24,
    pairedAt: "today",
    earnings24h: 0,
    earnings7d: 0,
    earningsLifetime: 0,
    jobsCompleted: 0,
  };
}

test("applyAdvisorStanding flags an unhealthy machine and marks standing known", () => {
  const machines = [machineStub("rkey-laptop"), machineStub("rkey-desktop")];
  const standing: AdvisorStandingResult = {
    reachable: true,
    byMachineId: new Map([
      [
        "rkey-laptop",
        {
          unhealthy: true,
          unhealthyReason: "preflight-no-response",
          silentFailure: false,
          verifiedTier: "best-effort" as const,
        },
      ],
      [
        "rkey-desktop",
        {
          unhealthy: false,
          unhealthyReason: null,
          silentFailure: false,
          verifiedTier: "hardware-attested" as const,
        },
      ],
    ]),
  };
  const [laptop, desktop] = applyAdvisorStanding(machines, standing);
  assert.equal(laptop!.unhealthy, true);
  assert.equal(laptop!.unhealthyReason, "preflight-no-response");
  assert.equal(laptop!.standingKnown, true);
  assert.equal(laptop!.advisorConnected, true);
  assert.equal(desktop!.unhealthy, false);
  assert.equal(desktop!.advisorConnected, true);
  assert.equal(laptop!.verifiedTier, "best-effort");
  assert.equal(desktop!.verifiedTier, "hardware-attested");
});

test("applyAdvisorStanding marks a machine absent from the advisor list as not connected", () => {
  const machines = [machineStub("rkey-offline")];
  const standing: AdvisorStandingResult = { reachable: true, byMachineId: new Map() };
  const [m] = applyAdvisorStanding(machines, standing);
  assert.equal(m!.standingKnown, true);
  assert.equal(m!.advisorConnected, false);
  assert.equal(m!.unhealthy, false); // not connected ≠ unhealthy
});

test("applyAdvisorStanding never fabricates health when the advisor is unreachable", () => {
  const machines = [machineStub("rkey-1")];
  const standing: AdvisorStandingResult = { reachable: false, byMachineId: new Map() };
  const [m] = applyAdvisorStanding(machines, standing);
  assert.equal(m!.standingKnown, false);
  // unhealthy / advisorConnected stay UNDEFINED — unknown, not a green claim.
  assert.equal(m!.unhealthy, undefined);
  assert.equal(m!.advisorConnected, undefined);
});

// --- advisorFault: "serving locally, invisible to the network" ---------

test("advisorFault is mapped onto the machine when the record carries it", () => {
  const m = providerRowsToMachines(
    [
      providerRow({
        supportedModels: ["qwen"],
        serving: true,
        advisorFault: {
          code: "upgrade-blocked",
          message: "WebSocket connections are being filtered on this network.",
          observedAt: "2026-07-04T01:52:00Z",
        },
      }),
    ],
    ZERO_STATS,
    new Map(),
  )[0]!;
  assert.equal(m.advisorFaultCode, "upgrade-blocked");
  assert.match(m.advisorFaultReason ?? "", /filtered/);
  assert.equal(m.advisorFaultAt, "2026-07-04T01:52:00Z");
  // Independent of the engine fault surface.
  assert.equal(m.faultReason, undefined);
});

test("an advisorFault without a message is ignored (no empty alert)", () => {
  const m = providerRowsToMachines(
    [providerRow({ supportedModels: ["qwen"], advisorFault: { code: "dns-failure" } })],
    ZERO_STATS,
    new Map(),
  )[0]!;
  assert.equal(m.advisorFaultCode, undefined);
  assert.equal(m.advisorFaultReason, undefined);
});

test("advisorUnreachable: fault on an idle machine ⇒ unreachable, even without live standing", () => {
  const m: Machine = {
    ...machineStub("rkey-1"),
    advisorFaultCode: "upgrade-blocked",
    advisorFaultReason: "WebSocket connections are being filtered on this network.",
  };
  assert.equal(advisorUnreachable(m), true);
  assert.equal(machineNetworkStanding(m), "not-reachable");
});

test("advisorUnreachable: serving on PDS but absent from the advisor ⇒ unreachable (the Jesse Beck case)", () => {
  // Agent 0.9.40 published a healthy record but its WS never arrived — no
  // fault field yet (old agent), but the advisor join says "not connected".
  const [m] = applyAdvisorStanding([machineStub("rkey-1")], {
    reachable: true,
    byMachineId: new Map(),
  });
  assert.equal(advisorUnreachable(m!), true);
  assert.equal(machineNetworkStanding(m!), "not-reachable");
});

test("applyAdvisorStanding joins by attestation pubkey when the advisor has no rkey (dead-session agent)", () => {
  // An agent whose PDS session died can't publish at boot, so it registers
  // with no machine_id and the advisor keys it by its attestation pubkey.
  // The machine is LIVE on the network — the pubkey fallback must find it.
  const pubkey = "BFakeUncompressedP256PointBase64==";
  const machines = [{ ...machineStub("rkey-mini"), attestationPubKey: pubkey }];
  const [m] = applyAdvisorStanding(machines, {
    reachable: true,
    byMachineId: new Map([
      [
        pubkey,
        {
          unhealthy: false,
          unhealthyReason: null,
          silentFailure: false,
          verifiedTier: "attested-confidential" as const,
        },
      ],
    ]),
  });
  assert.equal(m!.standingKnown, true);
  assert.equal(m!.advisorConnected, true);
  assert.equal(m!.verifiedTier, "attested-confidential");
  assert.equal(advisorUnreachable(m!), false);
  assert.equal(machineNetworkStanding(m!), "on-network");
});

test("applyAdvisorStanding prefers the rkey join over the pubkey fallback", () => {
  // Same machine present under BOTH keys (e.g. a race across reconnects):
  // the rkey entry is the agent's own claim of identity — it wins.
  const pubkey = "BFakeUncompressedP256PointBase64==";
  const entry = (reason: string) => ({
    unhealthy: true,
    unhealthyReason: reason,
    silentFailure: false,
    verifiedTier: "best-effort" as const,
  });
  const machines = [{ ...machineStub("rkey-mini"), attestationPubKey: pubkey }];
  const [m] = applyAdvisorStanding(machines, {
    reachable: true,
    byMachineId: new Map([
      ["rkey-mini", entry("via-rkey")],
      [pubkey, entry("via-pubkey")],
    ]),
  });
  assert.equal(m!.unhealthyReason, "via-rkey");
});

test("providerRowsToMachines carries the record's attestationPubKey onto the machine", () => {
  const withKey = providerRowsToMachines(
    [providerRow({ attestationPubKey: "BSomeKey==" })],
    ZERO_STATS,
    new Map(),
  )[0]!;
  assert.equal(withKey.attestationPubKey, "BSomeKey==");
  const withoutKey = providerRowsToMachines([providerRow({})], ZERO_STATS, new Map())[0]!;
  assert.equal(withoutKey.attestationPubKey, undefined);
});

test("advisorUnreachable: a live advisor connection outranks a stale fault", () => {
  const machines = [
    {
      ...machineStub("rkey-1"),
      advisorFaultCode: "connect-timeout",
      advisorFaultReason: "stale — the agent just reconnected and hasn't cleared it yet",
    },
  ];
  const [m] = applyAdvisorStanding(machines, {
    reachable: true,
    byMachineId: new Map([
      [
        "rkey-1",
        {
          unhealthy: false,
          unhealthyReason: null,
          silentFailure: false,
          verifiedTier: "best-effort" as const,
        },
      ],
    ]),
  });
  assert.equal(advisorUnreachable(m!), false);
  assert.equal(machineNetworkStanding(m!), "on-network");
});

test("advisorUnreachable: never claimed for a paused/offline/provisioning machine", () => {
  for (const state of ["paused", "offline", "provisioning"] as const) {
    const m: Machine = {
      ...machineStub("rkey-1"),
      state,
      advisorFaultCode: "dns-failure",
      advisorFaultReason: "lingering fault on a stopped machine",
      standingKnown: true,
      advisorConnected: false,
    };
    assert.equal(advisorUnreachable(m), false, state);
    assert.equal(machineNetworkStanding(m), null, state);
  }
});

test("advisorUnreachable: unknown standing with no fault makes no claim", () => {
  const [m] = applyAdvisorStanding([machineStub("rkey-1")], {
    reachable: false,
    byMachineId: new Map(),
  });
  assert.equal(advisorUnreachable(m!), false);
  assert.equal(machineNetworkStanding(m!), null);
});
