import assert from "node:assert/strict";
import { describe, test } from "vitest";

import {
  buildSupplyDemand,
  supplyBlockerFor,
  windowFullyCovered,
  HOT_REQUESTS_PER_MACHINE_HOUR,
  SMOKE_TEST_MODEL_ID,
  SUPPLY_DEMAND_WINDOWS,
  WINDOW_HOURS,
  type AdvisorSupplyRow,
  type DemandInput,
  type ModelSupplyDemandRow,
  type SupplyDemandWindow,
} from "./model-supply-demand.ts";

/** One advisor `/providers` row. Healthy unless a flag says otherwise. */
function machine(
  did: string,
  machineId: string,
  models: string[],
  extra: Partial<AdvisorSupplyRow> = {},
): AdvisorSupplyRow {
  return { did, machineId, supportedModels: models, active: true, ...extra };
}

function demand(
  entries: Array<{ modelId: string; day?: [number, number]; week?: [number, number] }>,
): DemandInput {
  return {
    models: entries.map((e) => ({
      modelId: e.modelId,
      totals: {
        ...(e.day ? { day: { requests: e.day[0], tokens: e.day[1] } } : {}),
        ...(e.week ? { week: { requests: e.week[0], tokens: e.week[1] } } : {}),
      },
    })),
  };
}

function build(
  providers: AdvisorSupplyRow[] | null,
  d: DemandInput | null,
  window: SupplyDemandWindow = "day",
) {
  return buildSupplyDemand({ providers, demand: d, window });
}

function row(snapshot: { rows: ModelSupplyDemandRow[] }, modelId: string): ModelSupplyDemandRow {
  const found = snapshot.rows.find((r) => r.modelId === modelId);
  assert.ok(found, `expected a row for ${modelId}`);
  return found;
}

describe("supplyBlockerFor", () => {
  test("a machine with no flags set is routable", () => {
    assert.equal(supplyBlockerFor({ did: "did:plc:a" }), null);
    assert.equal(supplyBlockerFor(machine("did:plc:a", "m1", [])), null);
  });

  test("an engine fault outranks every other blocker", () => {
    assert.equal(
      supplyBlockerFor({
        engineFault: { code: "native-model-missing" },
        active: false,
        unhealthy: true,
        coolingDown: true,
      }),
      "engineFault",
    );
  });

  test("each flag maps to its own blocker", () => {
    assert.equal(supplyBlockerFor({ active: false }), "paused");
    assert.equal(supplyBlockerFor({ unhealthy: true }), "unhealthy");
    assert.equal(supplyBlockerFor({ coolingDown: true }), "coolingDown");
  });

  test("an explicitly null engineFault is not a fault", () => {
    assert.equal(supplyBlockerFor({ engineFault: null }), null);
  });

  test("a missing flag never invents a problem, and never hides a reported one", () => {
    // An older advisor omits fields entirely — absence is not a claim.
    assert.equal(supplyBlockerFor({}), null);
    assert.equal(supplyBlockerFor({ active: undefined, unhealthy: undefined }), null);
    // Only an explicit `false` pauses; only an explicit `true` faults.
    assert.equal(supplyBlockerFor({ active: true }), null);
    assert.equal(supplyBlockerFor({ unhealthy: false, coolingDown: false }), null);
  });
});

describe("buildSupplyDemand supply counting", () => {
  test("counts machines advertising each model, and how many are routable", () => {
    const snapshot = build(
      [
        machine("did:plc:a", "m1", ["qwen", SMOKE_TEST_MODEL_ID]),
        machine("did:plc:b", "m2", ["qwen", SMOKE_TEST_MODEL_ID]),
        machine("did:plc:c", "m3", ["qwen", SMOKE_TEST_MODEL_ID], { unhealthy: true }),
      ],
      null,
    );
    const qwen = row(snapshot, "qwen");
    assert.equal(qwen.advertising, 3);
    assert.equal(qwen.healthy, 2);
    assert.deepEqual(qwen.blocked, { engineFault: 0, paused: 0, unhealthy: 1, coolingDown: 0 });
  });

  test("a machine with an engine fault is zero supply for everything it still lists", () => {
    // The agent already dropped the models its engine couldn't load, so this
    // box advertises only the smoke test — and that isn't capacity either.
    const snapshot = build(
      [
        machine("did:plc:broken", "m1", [SMOKE_TEST_MODEL_ID], {
          engineFault: { code: "native-model-missing", message: "…", at: "2026-09-17T00:00:00Z" },
        }),
        machine("did:plc:ok", "m2", ["qwen", SMOKE_TEST_MODEL_ID]),
      ],
      null,
    );
    const stub = row(snapshot, SMOKE_TEST_MODEL_ID);
    assert.equal(stub.advertising, 2);
    assert.equal(stub.healthy, 1);
    assert.equal(stub.blocked.engineFault, 1);
    assert.equal(snapshot.totals.healthyMachines, 1);
    assert.equal(snapshot.totals.machines, 2);
  });

  test("a blocked machine is counted once, under its highest-priority blocker", () => {
    const snapshot = build(
      [machine("did:plc:a", "m1", ["qwen"], { unhealthy: true, coolingDown: true })],
      null,
    );
    const qwen = row(snapshot, "qwen");
    assert.equal(qwen.advertising, 1);
    assert.equal(qwen.healthy, 0);
    assert.deepEqual(qwen.blocked, { engineFault: 0, paused: 0, unhealthy: 1, coolingDown: 0 });
    // The breakdown always accounts for exactly the non-routable machines.
    const blockedTotal = Object.values(qwen.blocked).reduce((a, b) => a + b, 0);
    assert.equal(blockedTotal, qwen.advertising - qwen.healthy);
  });

  test("one DID running several machines counts as several machines", () => {
    const snapshot = build(
      [
        machine("did:plc:owner", "laptop", ["qwen"]),
        machine("did:plc:owner", "desktop", ["qwen"]),
        machine("did:plc:other", "mini", ["qwen"]),
      ],
      null,
    );
    const qwen = row(snapshot, "qwen");
    assert.equal(qwen.healthy, 3);
    // …but only two distinct operators are behind that capacity.
    assert.equal(qwen.operators, 2);
    assert.equal(snapshot.totals.machines, 3);
  });

  test("a duplicate advisor row for one machine is not double-counted", () => {
    const snapshot = build(
      [machine("did:plc:a", "m1", ["qwen"]), machine("did:plc:a", "m1", ["qwen"])],
      null,
    );
    assert.equal(row(snapshot, "qwen").healthy, 1);
    assert.equal(snapshot.totals.machines, 1);
  });

  test("a legacy row with no machineId is keyed by its DID alone", () => {
    const snapshot = build(
      [
        { did: "did:plc:legacy", supportedModels: ["qwen"], active: true },
        { did: "did:plc:legacy", supportedModels: ["qwen"], active: true },
      ],
      null,
    );
    assert.equal(row(snapshot, "qwen").healthy, 1);
  });

  test("a model repeated within one machine's list counts once", () => {
    const snapshot = build([machine("did:plc:a", "m1", ["qwen", "qwen"])], null);
    assert.equal(row(snapshot, "qwen").advertising, 1);
  });

  test("ignores rows with no DID and non-array or non-string model lists", () => {
    const snapshot = build(
      [
        { supportedModels: ["ghost"], active: true },
        machine("did:plc:a", "m1", [] as string[], {
          supportedModels: "qwen" as unknown as string[],
        }),
        { did: "did:plc:b", machineId: "m2", supportedModels: [null, 3, "", "qwen"], active: true },
      ] as AdvisorSupplyRow[],
      null,
    );
    assert.deepEqual(
      snapshot.rows.map((r) => r.modelId),
      ["qwen"],
    );
    assert.equal(row(snapshot, "qwen").healthy, 1);
    // The DID-less row contributed nothing; the string-valued list is skipped
    // but its machine still exists on the network.
    assert.equal(snapshot.totals.machines, 2);
  });

  test("silent failures are advisory, not a blocker — the advisor still routes there", () => {
    const snapshot = build(
      [machine("did:plc:a", "m1", ["qwen"], { silentFailure: true })],
      demand([{ modelId: "qwen", day: [10, 100] }]),
    );
    const qwen = row(snapshot, "qwen");
    assert.equal(qwen.healthy, 1);
    assert.equal(qwen.silent, 1);
    assert.equal(qwen.unserved, false);
  });
});

describe("buildSupplyDemand demand counting", () => {
  test("reads the requested window and ignores the others", () => {
    const d = demand([{ modelId: "qwen", day: [24, 2_400], week: [700, 70_000] }]);
    assert.equal(row(build(null, d, "day"), "qwen").requests, 24);
    assert.equal(row(build(null, d, "week"), "qwen").requests, 700);
    assert.equal(row(build(null, d, "week"), "qwen").tokens, 70_000);
  });

  test("a window the AppView didn't report reads as zero demand, not as missing", () => {
    const snapshot = build([machine("did:plc:a", "m1", ["qwen"])], demand([{ modelId: "qwen" }]));
    const qwen = row(snapshot, "qwen");
    assert.equal(qwen.requests, 0);
    assert.equal(qwen.state, "idle");
  });

  test("negative or non-numeric counts are clamped to zero", () => {
    const snapshot = build(null, {
      models: [
        { modelId: "a", totals: { day: { requests: -5, tokens: Number.NaN } } },
        {
          modelId: "b",
          totals: { day: { requests: "7" as unknown as number, tokens: 10 } },
        },
      ],
    });
    assert.equal(row(snapshot, "a").requests, 0);
    assert.equal(row(snapshot, "b").requests, 0);
    assert.equal(row(snapshot, "b").tokens, 10);
  });

  test("a model id repeated in the demand input is summed, never overwritten", () => {
    const snapshot = build(
      null,
      demand([
        { modelId: "qwen", day: [3, 30] },
        { modelId: "qwen", day: [4, 40] },
      ]),
    );
    assert.equal(row(snapshot, "qwen").requests, 7);
    assert.equal(row(snapshot, "qwen").tokens, 70);
  });

  test("demand entries with no usable model id are dropped", () => {
    const snapshot = build(null, {
      models: [
        { modelId: "", totals: { day: { requests: 5, tokens: 5 } } },
        { modelId: 7 as unknown as string, totals: { day: { requests: 5, tokens: 5 } } },
        { modelId: "qwen", totals: { day: { requests: 1, tokens: 1 } } },
      ],
    });
    assert.deepEqual(
      snapshot.rows.map((r) => r.modelId),
      ["qwen"],
    );
  });
});

describe("buildSupplyDemand pressure", () => {
  test("pressure is demand divided by healthy machines, not by advertised ones", () => {
    const snapshot = build(
      [
        machine("did:plc:a", "m1", ["qwen"]),
        machine("did:plc:b", "m2", ["qwen"]),
        machine("did:plc:c", "m3", ["qwen"], { coolingDown: true }),
      ],
      demand([{ modelId: "qwen", day: [100, 5_000] }]),
    );
    const qwen = row(snapshot, "qwen");
    assert.equal(qwen.requestsPerHealthyMachine, 50);
    assert.equal(qwen.tokensPerHealthyMachine, 2_500);
  });

  test("pressure is null — not zero, not Infinity — when nothing healthy serves the model", () => {
    const snapshot = build(
      [machine("did:plc:a", "m1", ["qwen"], { unhealthy: true })],
      demand([{ modelId: "qwen", day: [40, 400] }]),
    );
    const qwen = row(snapshot, "qwen");
    assert.equal(qwen.requestsPerHealthyMachine, null);
    assert.equal(qwen.tokensPerHealthyMachine, null);
    assert.equal(qwen.unserved, true);
  });

  test("pressure scales with the window length when deciding 'hot'", () => {
    // Exactly at the threshold for the 24h window.
    const atThreshold = HOT_REQUESTS_PER_MACHINE_HOUR * WINDOW_HOURS.day;
    const hot = build(
      [machine("did:plc:a", "m1", ["qwen"])],
      demand([{ modelId: "qwen", day: [atThreshold, 1] }]),
      "day",
    );
    assert.equal(row(hot, "qwen").state, "hot");

    const justUnder = build(
      [machine("did:plc:a", "m1", ["qwen"])],
      demand([{ modelId: "qwen", day: [atThreshold - 1, 1] }]),
      "day",
    );
    assert.equal(row(justUnder, "qwen").state, "steady");

    // The same daily rate read over a week is the same rate — still hot.
    const weekly = build(
      [machine("did:plc:a", "m1", ["qwen"])],
      demand([{ modelId: "qwen", week: [atThreshold * 7, 1] }]),
      "week",
    );
    assert.equal(row(weekly, "qwen").state, "hot");
    // But that week's traffic spread over a week is NOT a hot day.
    const weekOfDayTraffic = build(
      [machine("did:plc:a", "m1", ["qwen"])],
      demand([{ modelId: "qwen", week: [atThreshold, 1] }]),
      "week",
    );
    assert.equal(row(weekOfDayTraffic, "qwen").state, "steady");
  });
});

describe("buildSupplyDemand states", () => {
  test("classifies each supply/demand combination", () => {
    const snapshot = build(
      [
        machine("did:plc:a", "m1", ["busy"]),
        machine("did:plc:b", "m2", ["calm"]),
        machine("did:plc:c", "m3", ["nobody-wants-this"]),
        machine("did:plc:d", "m4", ["all-broken"], { unhealthy: true }),
        machine("did:plc:e", "m5", ["went-away"], { unhealthy: true }),
      ],
      demand([
        { modelId: "busy", day: [10_000, 1] },
        { modelId: "calm", day: [1, 1] },
        { modelId: "went-away", day: [12, 120] },
        // Demand for a model no connected machine advertises at all.
        { modelId: "never-hosted", day: [5, 50] },
      ]),
    );
    const states = Object.fromEntries(snapshot.rows.map((r) => [r.modelId, r.state]));
    assert.deepEqual(states, {
      busy: "hot",
      calm: "steady",
      "nobody-wants-this": "idle",
      "all-broken": "dark",
      "went-away": "unserved",
      "never-hosted": "unserved",
    });
  });

  test("a model with demand but no live supply still gets a row", () => {
    const snapshot = build(
      [machine("did:plc:a", "m1", ["qwen"])],
      demand([{ modelId: "gone", day: [3, 30] }]),
    );
    const gone = row(snapshot, "gone");
    assert.equal(gone.advertising, 0);
    assert.equal(gone.healthy, 0);
    assert.equal(gone.unserved, true);
    assert.deepEqual(gone.blocked, { engineFault: 0, paused: 0, unhealthy: 0, coolingDown: 0 });
  });

  test("an idle model is the 'do not download this' signal", () => {
    const snapshot = build(
      [machine("did:plc:ephk", "m1", ["prism-ml/Ternary-Bonsai-27B-mlx-2bit"])],
      demand([{ modelId: "other", day: [50, 500] }]),
    );
    const idle = row(snapshot, "prism-ml/Ternary-Bonsai-27B-mlx-2bit");
    assert.equal(idle.state, "idle");
    assert.equal(idle.requests, 0);
    assert.equal(idle.requestsPerHealthyMachine, 0);
    assert.equal(snapshot.totals.idleModels, 1);
  });
});

describe("buildSupplyDemand ordering", () => {
  test("stranded demand floats to the top, biggest first", () => {
    const snapshot = build(
      [
        machine("did:plc:a", "m1", ["served"]),
        machine("did:plc:b", "m2", ["stranded-small"], { unhealthy: true }),
        machine("did:plc:c", "m3", ["stranded-big"], { unhealthy: true }),
      ],
      demand([
        { modelId: "served", day: [10, 100] },
        { modelId: "stranded-small", day: [2, 20] },
        { modelId: "stranded-big", day: [40, 400] },
      ]),
    );
    assert.deepEqual(
      snapshot.rows.map((r) => r.modelId),
      ["stranded-big", "stranded-small", "served"],
    );
  });

  test("served models rank by pressure, then raw demand, then id", () => {
    const snapshot = build(
      [
        machine("did:plc:a", "m1", ["thin"]),
        machine("did:plc:b", "m2", ["thick"]),
        machine("did:plc:c", "m3", ["thick"]),
        machine("did:plc:d", "m4", ["zed"]),
        machine("did:plc:e", "m5", ["alpha"]),
      ],
      demand([
        // 20 / 1 machine = 20
        { modelId: "thin", day: [20, 1] },
        // 30 / 2 machines = 15
        { modelId: "thick", day: [30, 1] },
        // tie at 5 each — raw demand equal too, so id breaks it
        { modelId: "zed", day: [5, 1] },
        { modelId: "alpha", day: [5, 1] },
      ]),
    );
    assert.deepEqual(
      snapshot.rows.map((r) => r.modelId),
      ["thin", "thick", "alpha", "zed"],
    );
  });

  test("the smoke-test model is pinned last however much traffic it has", () => {
    const snapshot = build(
      [
        machine("did:plc:a", "m1", [SMOKE_TEST_MODEL_ID, "real"]),
        machine("did:plc:b", "m2", [SMOKE_TEST_MODEL_ID]),
      ],
      demand([
        { modelId: SMOKE_TEST_MODEL_ID, day: [100_000, 1] },
        { modelId: "real", day: [1, 1] },
      ]),
    );
    assert.equal(snapshot.rows.at(-1)?.modelId, SMOKE_TEST_MODEL_ID);
  });

  test("the order is total, so the same input always renders the same table", () => {
    const providers = [
      machine("did:plc:a", "m1", ["x", "y", SMOKE_TEST_MODEL_ID]),
      machine("did:plc:b", "m2", ["y", "z"], { coolingDown: true }),
    ];
    const d = demand([
      { modelId: "x", day: [4, 4] },
      { modelId: "y", day: [4, 4] },
      { modelId: "z", day: [4, 4] },
    ]);
    const forward = build(providers, d).rows.map((r) => r.modelId);
    const reversed = build([...providers].reverse(), {
      models: [...d.models].reverse(),
    }).rows.map((r) => r.modelId);
    assert.deepEqual(forward, reversed);
  });
});

describe("buildSupplyDemand totals", () => {
  test("rolls the fleet and the window up across models", () => {
    const snapshot = build(
      [
        machine("did:plc:a", "m1", ["one", "two", SMOKE_TEST_MODEL_ID]),
        machine("did:plc:b", "m2", ["two", SMOKE_TEST_MODEL_ID]),
        machine("did:plc:c", "m3", ["three", SMOKE_TEST_MODEL_ID], { active: false }),
      ],
      demand([
        { modelId: "one", day: [10, 1_000] },
        { modelId: "two", day: [20, 2_000] },
        { modelId: "four", day: [5, 500] },
      ]),
    );
    assert.deepEqual(snapshot.totals, {
      // one, two, three, four, stub
      models: 5,
      machines: 3,
      healthyMachines: 2,
      // "four" has demand and no supply at all
      unservedModels: 1,
      // "three" (paused machine only) is dark, not idle; stub has no demand
      idleModels: 1,
      requests: 35,
      tokens: 3_500,
    });
  });

  test("an unreachable advisor yields demand-only rows and zero machines", () => {
    // The caller flags `advisorUnreachable` so the UI never reads this as
    // "the network has no capacity" — here we only assert we don't invent any.
    const snapshot = build(null, demand([{ modelId: "qwen", day: [9, 90] }]));
    assert.deepEqual(snapshot.totals.machines, 0);
    assert.equal(row(snapshot, "qwen").advertising, 0);
    assert.equal(row(snapshot, "qwen").unserved, true);
  });

  test("an unreachable AppView yields supply-only rows and zero demand", () => {
    const snapshot = build([machine("did:plc:a", "m1", ["qwen"])], null);
    assert.equal(snapshot.totals.requests, 0);
    assert.equal(row(snapshot, "qwen").healthy, 1);
    assert.equal(row(snapshot, "qwen").state, "idle");
  });

  test("both sources down yields an empty table, not a crash", () => {
    const snapshot = build(null, null);
    assert.deepEqual(snapshot.rows, []);
    assert.equal(snapshot.totals.models, 0);
  });
});

describe("buildSupplyDemand against the live fleet shape", () => {
  // Trimmed from a real https://advisor.cocore.dev/providers response
  // (2026-09-17), including the machine whose triage motivated this view:
  // did:plc:ephkzpinhaqc… advertises only the smoke test behind an engine
  // fault, while two operators double up on Qwen3.5-4B.
  const FLEET: AdvisorSupplyRow[] = [
    machine("did:plc:gotnvwkr56ib", "3mrcczvvxrh2t", [
      "mlx-community/Qwen2.5-7B-Instruct-4bit",
      "prism-ml/Ternary-Bonsai-27B-mlx-2bit",
      "stub",
    ]),
    machine("did:plc:oyare47r4kf6", "3mrv6lzmezu2a", [
      "mlx-community/Qwen2.5-7B-Instruct-4bit",
      "stub",
    ]),
    machine("did:plc:zm5rbjftwyd2", "3monydthybg2u", ["mlx-community/Qwen3.5-4B-MLX-4bit", "stub"]),
    machine("did:plc:62ndsvx3op3z", "3movkkxruem27", [
      "mlx-community/Qwen3.5-0.8B-MLX-4bit",
      "mlx-community/Qwen3.5-4B-MLX-4bit",
      "stub",
    ]),
    machine("did:plc:ephkzpinhaqc", "3moqguy2wqcmi", ["stub"], {
      engineFault: { code: "native-model-missing", message: "model not present", at: "2026-09-16" },
    }),
    machine("did:plc:jijwtzgroy76", "3mtdeliuhwq2e", ["stub"]),
  ];

  test("surfaces the doubled-up model, the orphan model, and the faulted box", () => {
    const snapshot = build(
      FLEET,
      demand([
        { modelId: "mlx-community/Qwen2.5-7B-Instruct-4bit", day: [220, 400_000] },
        { modelId: "mlx-community/Qwen3.5-4B-MLX-4bit", day: [12, 9_000] },
        { modelId: "google/gemma-4-12b", day: [30, 44_000] },
        { modelId: "stub", day: [900, 900] },
      ]),
    );

    // Nobody routes work to the 27B nobody asked for — the operator's signal
    // not to spend a multi-GB download on it.
    const bonsai = row(snapshot, "prism-ml/Ternary-Bonsai-27B-mlx-2bit");
    assert.equal(bonsai.state, "idle");
    assert.equal(bonsai.healthy, 1);
    assert.equal(bonsai.requests, 0);

    // Demand exists for a model nothing on the network serves right now.
    const gemma = row(snapshot, "google/gemma-4-12b");
    assert.equal(gemma.state, "unserved");
    assert.equal(gemma.advertising, 0);

    // The faulted machine adds nothing, even to the model it still lists.
    const stub = row(snapshot, "stub");
    assert.equal(stub.advertising, 6);
    assert.equal(stub.healthy, 5);
    assert.equal(stub.blocked.engineFault, 1);
    assert.equal(stub.smokeTest, true);
    assert.equal(snapshot.rows.at(-1)?.modelId, "stub");

    // Traffic concentrated on two boxes reads hotter than traffic on two
    // boxes with an order of magnitude less of it.
    const qwen25 = row(snapshot, "mlx-community/Qwen2.5-7B-Instruct-4bit");
    const qwen35 = row(snapshot, "mlx-community/Qwen3.5-4B-MLX-4bit");
    assert.equal(qwen25.healthy, 2);
    assert.equal(qwen25.requestsPerHealthyMachine, 110);
    assert.equal(qwen25.operators, 2);
    assert.equal(qwen35.healthy, 2);
    assert.equal(qwen35.requestsPerHealthyMachine, 6);
    assert.equal(qwen25.state, "hot");
    assert.equal(qwen35.state, "steady");

    // "needs help" first: stranded demand, then the hottest served model.
    assert.deepEqual(
      snapshot.rows.slice(0, 2).map((r) => r.modelId),
      ["google/gemma-4-12b", "mlx-community/Qwen2.5-7B-Instruct-4bit"],
    );
    assert.equal(snapshot.totals.machines, 6);
    assert.equal(snapshot.totals.healthyMachines, 5);
  });
});

describe("windowFullyCovered", () => {
  const NOW = Date.parse("2026-09-17T12:00:00.000Z");
  const ago = (days: number) => new Date(NOW - days * 86_400_000).toISOString();

  test("an untruncated scan covers every window", () => {
    for (const window of SUPPLY_DEMAND_WINDOWS) {
      assert.equal(
        windowFullyCovered({ truncated: false, oldestScannedAt: ago(0.5), window, nowMs: NOW }),
        true,
        window,
      );
    }
  });

  test("a truncated scan still covers a window narrower than its floor", () => {
    // Scan reached 3 days back: the 24h total is exact, the 7d one is not.
    assert.equal(
      windowFullyCovered({ truncated: true, oldestScannedAt: ago(3), window: "day", nowMs: NOW }),
      true,
    );
    assert.equal(
      windowFullyCovered({ truncated: true, oldestScannedAt: ago(3), window: "week", nowMs: NOW }),
      false,
    );
  });

  test("a truncated scan that didn't reach back a full day undercounts even 24h", () => {
    assert.equal(
      windowFullyCovered({
        truncated: true,
        oldestScannedAt: ago(0.25),
        window: "day",
        nowMs: NOW,
      }),
      false,
    );
  });

  test("the boundary counts as covered", () => {
    assert.equal(
      windowFullyCovered({ truncated: true, oldestScannedAt: ago(1), window: "day", nowMs: NOW }),
      true,
    );
  });

  test("no usable floor reads as unknown, never as incomplete", () => {
    assert.equal(
      windowFullyCovered({ truncated: true, oldestScannedAt: null, window: "day", nowMs: NOW }),
      null,
    );
    assert.equal(
      windowFullyCovered({ truncated: true, oldestScannedAt: "nope", window: "day", nowMs: NOW }),
      null,
    );
  });
});
