// Fetch both halves of the model supply/demand view and fold them together.
//
//   supply — the advisor's live `/providers` registry (it holds the sockets,
//            so it is the only thing that knows what is actually connected).
//   demand — the AppView's `dev.cocore.compute.modelActivity` roll-up over
//            indexed `dev.cocore.compute.receipt` records.
//
// The arithmetic is in model-supply-demand.ts (pure, unit-tested); this file
// is the I/O edge. Both fetches are independent and independently tolerant of
// failure: each side reports its own reachability so the UI can say "we don't
// know" rather than render a confident zero. A page that claimed "0 machines"
// because the advisor timed out would tell an operator exactly the wrong
// thing.
//
// Read-only and derived throughout — no state here outlives the request.

import { Effect } from "effect";

import {
  appviewModelActivityEffect,
  type AppviewModelActivityResponse,
} from "@/integrations/appview/appview.server.ts";
import { cocoreConfig } from "@/lib/cocore-config.ts";
import {
  buildSupplyDemand,
  windowFullyCovered,
  type AdvisorSupplyRow,
  type ModelSupplyDemandRow,
  type SupplyDemandTotals,
  type SupplyDemandWindow,
} from "@/lib/model-supply-demand.ts";
import { runTraced } from "@/lib/o11y.server.ts";

/** How long the demand counts a given window reports actually cover. The
 *  AppView scans the most-recent N receipts, so on a busy network a 7d total
 *  can be a lower bound; we pass that through instead of letting the page
 *  present a truncated number as an exact one. */
interface DemandCoverage {
  /** Receipts the AppView's scan walked. null when it didn't report. */
  scanned: number | null;
  /** True when the scan hit its cap — the window totals are lower bounds. */
  truncated: boolean;
  /** Earliest receipt that contributed to any window. */
  oldestScannedAt: string | null;
  /** Whether the scan reached far enough back to make THIS window's totals
   *  exact. A truncated scan only undercounts a window wider than its
   *  coverage floor, so a 24h total can be exact while the 7d one is not.
   *  null when we can't tell — which the UI must not report as incomplete. */
  coversWindow: boolean | null;
}

export interface ModelSupplyDemandPayload {
  window: SupplyDemandWindow;
  /** Wall clock when this snapshot was built. */
  generatedAt: string;
  rows: ModelSupplyDemandRow[];
  totals: SupplyDemandTotals;
  /** True when the advisor didn't answer: supply is UNKNOWN, not zero. */
  advisorUnreachable: boolean;
  /** True when the AppView didn't answer: demand is UNKNOWN, not zero. */
  appviewUnreachable: boolean;
  demandCoverage: DemandCoverage;
}

const ADVISOR_TIMEOUT_MS = 5_000;

/** Read the advisor's live registry. Returns null on any failure, which the
 *  caller turns into `advisorUnreachable` — never an empty fleet.
 *
 *  The advisor's base URL comes from config (`COCORE_ADVISOR_URL`), the same
 *  place every other console→advisor call reads it from; nothing here hardcodes
 *  a host. */
async function fetchAdvisorSupply(): Promise<AdvisorSupplyRow[] | null> {
  const base = cocoreConfig().advisorUrl.replace(/\/$/, "");
  try {
    const resp = await fetch(`${base}/providers`, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(ADVISOR_TIMEOUT_MS),
    });
    if (!resp.ok) {
      console.warn(`[model-supply-demand] advisor /providers returned ${resp.status}`);
      return null;
    }
    const rows = (await resp.json()) as unknown;
    if (!Array.isArray(rows)) {
      console.warn("[model-supply-demand] advisor /providers was not an array");
      return null;
    }
    return rows as AdvisorSupplyRow[];
  } catch (reason) {
    console.warn("[model-supply-demand] advisor /providers failed:", reason);
    return null;
  }
}

function coverageFrom(
  activity: AppviewModelActivityResponse | null,
  window: SupplyDemandWindow,
  nowMs: number,
): DemandCoverage {
  const truncated = activity?.truncated === true;
  const oldestScannedAt =
    typeof activity?.oldestScannedAt === "string" ? activity.oldestScannedAt : null;
  return {
    scanned: typeof activity?.scanned === "number" ? activity.scanned : null,
    truncated,
    oldestScannedAt,
    coversWindow: windowFullyCovered({ truncated, oldestScannedAt, window, nowMs }),
  };
}

/** Build the supply/demand snapshot for one trailing window.
 *
 *  Both sources are fetched concurrently — the page's time-to-first-byte is
 *  whichever is slower, not their sum. The loader AWAITS this in full: an
 *  unawaited query still gates the whole streamed body via dehydration, so
 *  deferring it here would buy nothing and only make the wait harder to
 *  measure. */
export async function buildModelSupplyDemand(
  window: SupplyDemandWindow,
): Promise<ModelSupplyDemandPayload> {
  const [providers, activityResult] = await Promise.all([
    fetchAdvisorSupply(),
    runTraced("models.capacity.appview", Effect.either(appviewModelActivityEffect)),
  ]);

  if (activityResult._tag !== "Right") {
    console.warn("[model-supply-demand] AppView modelActivity failed:", activityResult.left);
  }
  const activity = activityResult._tag === "Right" ? activityResult.right : null;

  const snapshot = buildSupplyDemand({ providers, demand: activity, window });
  const nowMs = Date.now();

  return {
    window,
    generatedAt: new Date(nowMs).toISOString(),
    rows: snapshot.rows,
    totals: snapshot.totals,
    advisorUnreachable: providers === null,
    appviewUnreachable: activity === null,
    demandCoverage: coverageFrom(activity, window, nowMs),
  };
}
