import assert from "node:assert/strict";
import { describe, test } from "vitest";

import {
  aggregateModelActivity,
  MODEL_ACTIVITY_SCAN_LIMIT,
  type ActivityRow,
} from "./model-activity.ts";

const NOW = Date.parse("2026-09-17T12:00:00.000Z");
const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

function receipt(
  opts: {
    did?: string;
    model?: string;
    agoMs?: number;
    tin?: number;
    tout?: number;
    completedAt?: string | undefined;
    indexedAt?: string;
  } = {},
): ActivityRow {
  const ago = opts.agoMs ?? 0;
  const body: Record<string, unknown> = {
    model: opts.model ?? "m/one",
    tokens: { in: opts.tin ?? 10, out: opts.tout ?? 5 },
  };
  if ("completedAt" in opts) {
    if (opts.completedAt !== undefined) body["completedAt"] = opts.completedAt;
  } else {
    body["completedAt"] = new Date(NOW - ago).toISOString();
  }
  return {
    repo: opts.did ?? "did:plc:alice",
    body,
    ...(opts.indexedAt !== undefined ? { indexedAt: opts.indexedAt } : {}),
  };
}

describe("aggregateModelActivity windows", () => {
  test("a receipt counts in every window it falls inside", () => {
    const out = aggregateModelActivity([receipt({ agoMs: 30 * MIN })], NOW);
    const m = out.models[0]!;
    assert.equal(m.modelId, "m/one");
    for (const w of ["hour", "day", "week", "month"] as const) {
      assert.deepEqual(m.totals[w], { requests: 1, tokens: 15 }, w);
    }
  });

  test("a receipt older than a window is excluded from that window only", () => {
    const out = aggregateModelActivity([receipt({ agoMs: 3 * DAY })], NOW);
    const t = out.models[0]!.totals;
    assert.deepEqual(t.hour, { requests: 0, tokens: 0 });
    assert.deepEqual(t.day, { requests: 0, tokens: 0 });
    assert.deepEqual(t.week, { requests: 1, tokens: 15 });
    assert.deepEqual(t.month, { requests: 1, tokens: 15 });
  });

  test("a receipt older than every window contributes nothing at all", () => {
    const out = aggregateModelActivity([receipt({ agoMs: 90 * DAY })], NOW);
    // The model is still keyed (we saw a receipt for it) but every count is 0,
    // and it does not claim coverage back to its own timestamp.
    assert.deepEqual(out.models[0]!.totals.month, { requests: 0, tokens: 0 });
    assert.equal(out.oldestScannedAt, null);
  });

  test("the window boundary is inclusive", () => {
    const out = aggregateModelActivity([receipt({ agoMs: DAY })], NOW);
    assert.equal(out.models[0]!.totals.day.requests, 1);
  });
});

describe("aggregateModelActivity grouping", () => {
  test("sums requests and tokens per model", () => {
    const out = aggregateModelActivity(
      [
        receipt({ model: "m/one", tin: 100, tout: 20 }),
        receipt({ model: "m/one", tin: 1, tout: 2 }),
        receipt({ model: "m/two", tin: 7, tout: 0 }),
      ],
      NOW,
    );
    assert.deepEqual(
      out.models.map((m) => [m.modelId, m.totals.day]),
      [
        ["m/one", { requests: 2, tokens: 123 }],
        ["m/two", { requests: 1, tokens: 7 }],
      ],
    );
  });

  test("breaks each model down by the provider DID that signed the receipt", () => {
    const out = aggregateModelActivity(
      [
        receipt({ did: "did:plc:bob", tin: 5, tout: 5 }),
        receipt({ did: "did:plc:alice", tin: 1, tout: 1 }),
        receipt({ did: "did:plc:bob", tin: 5, tout: 5 }),
      ],
      NOW,
    );
    // Sorted by DID for a stable response.
    assert.deepEqual(
      out.models[0]!.byProvider.map((p) => [p.did, p.stats.day.requests, p.stats.day.tokens]),
      [
        ["did:plc:alice", 1, 2],
        ["did:plc:bob", 2, 20],
      ],
    );
  });

  test("models are sorted by id, so the response is stable across calls", () => {
    const rows = [receipt({ model: "zeta" }), receipt({ model: "alpha" }), receipt({ model: "mu" })];
    assert.deepEqual(
      aggregateModelActivity(rows, NOW).models.map((m) => m.modelId),
      ["alpha", "mu", "zeta"],
    );
  });
});

describe("aggregateModelActivity malformed rows", () => {
  test("skips rows with no usable model id", () => {
    const rows: ActivityRow[] = [
      { repo: "did:plc:alice", body: { tokens: { in: 1, out: 1 } } },
      { repo: "did:plc:alice", body: { model: "", tokens: { in: 1, out: 1 } } },
      { repo: "did:plc:alice", body: { model: 42 } },
      { repo: "did:plc:alice", body: null },
      receipt({ model: "m/real" }),
    ];
    const out = aggregateModelActivity(rows, NOW);
    assert.deepEqual(
      out.models.map((m) => m.modelId),
      ["m/real"],
    );
    // `scanned` reports what we walked, not what we counted.
    assert.equal(out.scanned, 5);
  });

  test("falls back to indexedAt when completedAt is missing or unparseable", () => {
    const at = new Date(NOW - 10 * MIN).toISOString();
    const out = aggregateModelActivity(
      [
        receipt({ completedAt: undefined, indexedAt: at }),
        receipt({ completedAt: "not-a-date", indexedAt: at }),
      ],
      NOW,
    );
    assert.equal(out.models[0]!.totals.hour.requests, 2);
  });

  test("drops a row with neither a usable completedAt nor indexedAt", () => {
    const out = aggregateModelActivity([receipt({ completedAt: undefined })], NOW);
    assert.deepEqual(out.models, []);
  });

  test("treats missing, negative and non-numeric token counts as zero", () => {
    const rows: ActivityRow[] = [
      { repo: "did:plc:alice", body: { model: "m", completedAt: new Date(NOW).toISOString() } },
      {
        repo: "did:plc:alice",
        body: {
          model: "m",
          completedAt: new Date(NOW).toISOString(),
          tokens: { in: -5, out: "9" },
        },
      },
      {
        repo: "did:plc:alice",
        body: { model: "m", completedAt: new Date(NOW).toISOString(), tokens: { in: 3 } },
      },
    ];
    const out = aggregateModelActivity(rows, NOW);
    assert.deepEqual(out.models[0]!.totals.day, { requests: 3, tokens: 3 });
  });
});

describe("aggregateModelActivity coverage reporting", () => {
  test("reports the scan as truncated once it fills the cap", () => {
    const rows = Array.from({ length: 3 }, () => receipt());
    assert.equal(aggregateModelActivity(rows, NOW, 3).truncated, true);
    assert.equal(aggregateModelActivity(rows, NOW, 4).truncated, false);
  });

  test("an empty index is not truncated and has no coverage floor", () => {
    const out = aggregateModelActivity([], NOW);
    assert.deepEqual(out, {
      generatedAt: new Date(NOW).toISOString(),
      models: [],
      scanned: 0,
      scanLimit: MODEL_ACTIVITY_SCAN_LIMIT,
      truncated: false,
      oldestScannedAt: null,
    });
  });

  test("oldestScannedAt is the earliest receipt that landed in a window", () => {
    const out = aggregateModelActivity(
      [
        receipt({ agoMs: 2 * HOUR }),
        receipt({ agoMs: 5 * DAY }),
        // Outside every window — must not drag the coverage floor back.
        receipt({ agoMs: 200 * DAY }),
      ],
      NOW,
    );
    assert.equal(out.oldestScannedAt, new Date(NOW - 5 * DAY).toISOString());
  });

  test("is order-independent apart from the truncation flag", () => {
    const rows = [receipt({ model: "b", agoMs: HOUR }), receipt({ model: "a", agoMs: 2 * DAY })];
    assert.deepEqual(
      aggregateModelActivity(rows, NOW),
      aggregateModelActivity([...rows].reverse(), NOW),
    );
  });
});
