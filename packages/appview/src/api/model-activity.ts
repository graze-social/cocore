// Pure receipt → activity aggregation behind `dev.cocore.compute.modelActivity`.
//
// Split out of read-router.ts so the arithmetic is unit-testable without a
// store, an HTTP server, or an Effect runtime. The router keeps the caching
// and the span; everything below is a fold over indexed receipt rows.
//
// The AppView is a cache/index, never a ledger: every number here is derived
// from provider-signed `dev.cocore.compute.receipt` records and can be
// recomputed from the providers' PDSes at any time.
//
// Coverage is deliberately explicit. The scan walks the most-recent
// `scanLimit` receipts (indexed_at DESC), so the 7d/30d windows can undercount
// on a busy network. Rather than let consumers silently read a truncated
// total as a true one, the response reports `scanned` / `truncated` /
// `oldestScannedAt` and callers surface it.

/** The four windows every `activityWindows` roll-up carries. */
const ACTIVITY_WINDOWS = ["hour", "day", "week", "month"] as const;
type ActivityWindow = (typeof ACTIVITY_WINDOWS)[number];

interface ActivityCounts {
  requests: number;
  tokens: number;
}

type ActivityWindows = Record<ActivityWindow, ActivityCounts>;

interface ModelActivityEntry {
  modelId: string;
  totals: ActivityWindows;
  byProvider: Array<{ did: string; stats: ActivityWindows }>;
}

export interface ModelActivityResponse {
  generatedAt: string;
  models: ModelActivityEntry[];
  /** Receipts the scan actually walked. */
  scanned: number;
  /** The cap the scan applied. */
  scanLimit: number;
  /** True when the scan filled its cap, so older receipts exist that these
   *  totals do NOT include. The wider windows (week/month) are then lower
   *  bounds, not exact counts. */
  truncated: boolean;
  /** Earliest receipt timestamp that contributed to any total, so a consumer
   *  can say "counts cover receipts since …". null when nothing counted. */
  oldestScannedAt: string | null;
}

/** The shape this aggregation needs from an indexed record — structurally a
 *  subset of the store's `IndexedRecord`, so `Store.listByCollection` rows
 *  pass straight in. */
export interface ActivityRow {
  /** Owning DID — for receipts, the provider that signed it. */
  repo: string;
  body: unknown;
  indexedAt?: string;
}

/** Matches the cap read-router applies when listing receipts. Exported so the
 *  router and the truncation report can never drift apart. */
export const MODEL_ACTIVITY_SCAN_LIMIT = 5000;

const MINUTE_MS = 60_000;

function emptyWindows(): ActivityWindows {
  return {
    hour: { requests: 0, tokens: 0 },
    day: { requests: 0, tokens: 0 },
    week: { requests: 0, tokens: 0 },
    month: { requests: 0, tokens: 0 },
  };
}

/** A receipt's effective timestamp: the provider's signed `completedAt` when
 *  it parses, else our own `indexedAt`. NaN when neither is usable — such a
 *  row can't be placed in a window and is skipped. */
function receiptTimeMs(body: { completedAt?: string }, indexedAt: string | undefined): number {
  const completed = body.completedAt ? Date.parse(body.completedAt) : Number.NaN;
  if (Number.isFinite(completed)) return completed;
  return Date.parse(indexedAt ?? "");
}

function safeCount(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) && v > 0 ? v : 0;
}

/** Roll receipt rows up per model + per window, with a per-provider
 *  breakdown. Pure: same rows + same `nowMs` always yield the same response.
 *
 *  Rows are expected newest-first (the store orders by indexed_at DESC) but
 *  the fold is order-independent — only `truncated` depends on how many rows
 *  the caller was willing to hand over. */
export function aggregateModelActivity(
  rows: readonly ActivityRow[],
  nowMs: number,
  scanLimit: number = MODEL_ACTIVITY_SCAN_LIMIT,
): ModelActivityResponse {
  const windows: Record<ActivityWindow, number> = {
    hour: nowMs - 60 * MINUTE_MS,
    day: nowMs - 24 * 60 * MINUTE_MS,
    week: nowMs - 7 * 24 * 60 * MINUTE_MS,
    month: nowMs - 30 * 24 * 60 * MINUTE_MS,
  };

  const byModel = new Map<string, ActivityWindows>();
  const byModelProvider = new Map<string, Map<string, ActivityWindows>>();
  let oldestCountedMs: number | null = null;

  for (const row of rows) {
    const body = row.body as {
      model?: string;
      tokens?: { in?: number; out?: number };
      completedAt?: string;
    } | null;
    const model = body?.model;
    if (typeof model !== "string" || model.length === 0) continue;

    const tsMs = receiptTimeMs(body ?? {}, row.indexedAt);
    if (!Number.isFinite(tsMs)) continue;

    const tokens = safeCount(body?.tokens?.in) + safeCount(body?.tokens?.out);

    let modelStats = byModel.get(model);
    if (!modelStats) {
      modelStats = emptyWindows();
      byModel.set(model, modelStats);
    }
    let providerMap = byModelProvider.get(model);
    if (!providerMap) {
      providerMap = new Map();
      byModelProvider.set(model, providerMap);
    }
    let providerStats = providerMap.get(row.repo);
    if (!providerStats) {
      providerStats = emptyWindows();
      providerMap.set(row.repo, providerStats);
    }

    let counted = false;
    for (const w of ACTIVITY_WINDOWS) {
      if (tsMs < windows[w]) continue;
      modelStats[w].requests += 1;
      modelStats[w].tokens += tokens;
      providerStats[w].requests += 1;
      providerStats[w].tokens += tokens;
      counted = true;
    }
    // Only receipts that landed in at least one window define coverage —
    // a 90-day-old receipt sitting in the scan says nothing about what the
    // reported windows include.
    if (counted && (oldestCountedMs === null || tsMs < oldestCountedMs)) {
      oldestCountedMs = tsMs;
    }
  }

  // Sorted output (model id, then provider DID) so the response is stable
  // across calls and diffable in tests. Consumers look rows up by id.
  const models = [...byModel.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([modelId, totals]) => ({
      modelId,
      totals,
      byProvider: [...(byModelProvider.get(modelId)?.entries() ?? [])]
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([did, stats]) => ({ did, stats })),
    }));

  return {
    generatedAt: new Date(nowMs).toISOString(),
    models,
    scanned: rows.length,
    scanLimit,
    truncated: rows.length >= scanLimit,
    oldestScannedAt: oldestCountedMs === null ? null : new Date(oldestCountedMs).toISOString(),
  };
}
