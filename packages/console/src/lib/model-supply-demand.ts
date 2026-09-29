// Model supply/demand — join live capacity against recent demand, per model.
//
// Two questions this answers, from two different sources:
//
//   supply  — the advisor's live `/providers` registry. Every connected
//             machine reports the model ids it can actually serve, plus the
//             flags that decide whether the advisor would route to it.
//   demand  — the AppView's roll-up of indexed `dev.cocore.compute.receipt`
//             records, per model, per trailing window.
//
// Neither side is authoritative state we own: the advisor holds the sockets,
// and receipts live on providers' PDSes. This module is a pure fold over both,
// so the view is derived and recomputable — never a ledger.
//
// The motivating failure: a machine can download a multi-GB model, advertise
// it, and sit at zero demand forever, while another model has real traffic
// spread over one healthy box. Both facts are visible in these two inputs and
// in neither one alone.
//
// Pure and dependency-free so it can be unit-tested without the network; the
// fetching lives in model-supply-demand.server.ts.

export const SUPPLY_DEMAND_WINDOWS = ["day", "week"] as const;
/** Trailing window the table reports over. Names match the AppView's
 *  `activityWindows` keys: `day` = 24h, `week` = 7d. */
export type SupplyDemandWindow = (typeof SUPPLY_DEMAND_WINDOWS)[number];

export const WINDOW_HOURS: Record<SupplyDemandWindow, number> = { day: 24, week: 24 * 7 };

/** Requests per healthy machine per hour at or above which a model reads as
 *  "hot" — i.e. the traffic it already has is concentrated enough that more
 *  capacity would help. A tunable display heuristic, not a routing input:
 *  nothing in the protocol or the advisor consults it. */
export const HOT_REQUESTS_PER_MACHINE_HOUR = 2;

/** The connectivity smoke-test model id. Every agent advertises it whether or
 *  not a real engine came up, so it is supply-inflated by construction and
 *  says nothing about capacity. Kept in the table (its demand is real traffic)
 *  but pinned to the bottom, exactly as /models does. */
export const SMOKE_TEST_MODEL_ID = "stub";

/** The subset of an advisor `/providers` row this view reads. Everything is
 *  `unknown` because the advisor is a separate service on its own release
 *  cadence: a field can be absent on an older deploy, and a missing flag must
 *  never be read as a definite claim. */
export interface AdvisorSupplyRow {
  did?: unknown;
  machineId?: unknown;
  supportedModels?: unknown;
  active?: unknown;
  unhealthy?: unknown;
  coolingDown?: unknown;
  engineFault?: unknown;
  silentFailure?: unknown;
}

/** Why the advisor would not route to a machine right now. Ordered by how
 *  much it tells the operator: an engine that never came up is a different
 *  problem from an owner who simply switched the machine off. */
export type SupplyBlocker = "engineFault" | "paused" | "unhealthy" | "coolingDown";

export const SUPPLY_BLOCKERS: readonly SupplyBlocker[] = [
  "engineFault",
  "paused",
  "unhealthy",
  "coolingDown",
];

type BlockedCounts = Record<SupplyBlocker, number>;

/** What a model's capacity/traffic balance reads as. Drives the UI badge and
 *  the "needs help" sort. */
export type SupplyDemandState =
  /** Demand in the window, nothing healthy serving it. The urgent case. */
  | "unserved"
  /** Healthy supply, but traffic per machine is high — more would help. */
  | "hot"
  /** Healthy supply carrying traffic comfortably. */
  | "steady"
  /** Healthy supply, no traffic at all in the window. The "don't download
   *  this" signal for an operator choosing what to host. */
  | "idle"
  /** Neither healthy supply nor demand — every machine advertising it is
   *  blocked, and nobody is asking for it either. */
  | "dark";

export interface ModelSupplyDemandRow {
  modelId: string;
  /** Machines connected to the advisor that list this model. */
  advertising: number;
  /** Of those, the ones the advisor would actually route work to. */
  healthy: number;
  /** Why the rest are out. Sums to `advertising - healthy`; a machine with
   *  several problems is counted once, under the first blocker in
   *  {@link SUPPLY_BLOCKERS}. */
  blocked: BlockedCounts;
  /** Healthy machines the advisor has flagged as failing silently — they take
   *  work and return nothing. A subset of `healthy`, not a blocker: the
   *  advisor still routes to them, so the capacity is real but suspect. */
  silent: number;
  /** Distinct owner DIDs behind `healthy`. One operator running four boxes is
   *  less resilient than four operators running one each. */
  operators: number;
  /** Completed receipts indexed for this model in the window. */
  requests: number;
  /** Tokens (in + out) across those receipts. */
  tokens: number;
  /** Demand pressure: `requests / healthy`. null when there is no healthy
   *  supply to divide by — read `unserved` to tell "nobody is asking" from
   *  "nobody can serve it". */
  requestsPerHealthyMachine: number | null;
  tokensPerHealthyMachine: number | null;
  /** Window demand with zero healthy supply. */
  unserved: boolean;
  state: SupplyDemandState;
  /** True for {@link SMOKE_TEST_MODEL_ID}. */
  smokeTest: boolean;
}

export interface SupplyDemandTotals {
  models: number;
  /** Distinct machines connected to the advisor (not a per-row sum — one
   *  machine advertising three models counts once). */
  machines: number;
  healthyMachines: number;
  /** Models with demand in the window and no healthy machine serving them. */
  unservedModels: number;
  /** Models with healthy capacity and no demand in the window. */
  idleModels: number;
  requests: number;
  tokens: number;
}

export interface SupplyDemandSnapshot {
  window: SupplyDemandWindow;
  rows: ModelSupplyDemandRow[];
  totals: SupplyDemandTotals;
}

/** Per-model demand as the AppView reports it. Structurally a subset of
 *  `AppviewModelActivityResponse` so that response passes straight in. */
export interface DemandInput {
  models: ReadonlyArray<{
    modelId: string;
    totals: Partial<Record<SupplyDemandWindow, { requests?: number; tokens?: number }>>;
  }>;
}

export interface SupplyDemandInput {
  /** Advisor registry rows. `null` means the advisor was unreachable — supply
   *  is then UNKNOWN, and we must not report zero capacity as if we had
   *  checked (see the caller's `advisorUnreachable`). */
  providers: readonly AdvisorSupplyRow[] | null;
  /** AppView demand roll-up, or `null` when the AppView was unreachable. */
  demand: DemandInput | null;
  window: SupplyDemandWindow;
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

function count(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) && v > 0 ? v : 0;
}

/** Whether the demand counts for `window` are complete, given how far back the
 *  AppView's capped receipt scan actually reached.
 *
 *  A truncated scan only threatens a window WIDER than its coverage floor: if
 *  the scan stopped three days back, the 24h totals are still exact and it
 *  would be wrong to caveat them. Returns null when there is no floor to
 *  compare against (nothing counted, or an unparseable timestamp) — "we can't
 *  tell", which is not the same as "incomplete". */
export function windowFullyCovered(input: {
  truncated: boolean;
  oldestScannedAt: string | null;
  window: SupplyDemandWindow;
  nowMs: number;
}): boolean | null {
  if (!input.truncated) return true;
  if (input.oldestScannedAt === null) return null;
  const oldestMs = Date.parse(input.oldestScannedAt);
  if (!Number.isFinite(oldestMs)) return null;
  return oldestMs <= input.nowMs - WINDOW_HOURS[input.window] * 60 * 60_000;
}

/** A machine normalized out of one advisor row. */
interface SupplyMachine {
  key: string;
  did: string;
  models: string[];
  /** The first blocker that applies, or null when the advisor would route. */
  blocker: SupplyBlocker | null;
  silent: boolean;
}

/** Which blocker (if any) keeps the advisor from routing to this machine.
 *
 *  `active` and `unhealthy`/`coolingDown` are read conservatively in opposite
 *  directions on purpose: only an explicit `active: false` counts as paused
 *  (an older advisor omits the field entirely), while only an explicit `true`
 *  counts as unhealthy or cooling down. An absent flag never invents a
 *  problem, and never hides one we were actually told about. */
export function supplyBlockerFor(row: AdvisorSupplyRow): SupplyBlocker | null {
  // An engine that never came up is first because it is the most actionable,
  // and because such a machine has already dropped the failed models from
  // `supportedModels` — whatever it still advertises (in practice just the
  // smoke test) is not real capacity.
  if (row.engineFault !== null && row.engineFault !== undefined) return "engineFault";
  if (row.active === false) return "paused";
  if (row.unhealthy === true) return "unhealthy";
  if (row.coolingDown === true) return "coolingDown";
  return null;
}

/** Normalize the advisor's rows into one entry per physical machine.
 *
 *  Keyed `did:machineId` (falling back to the DID for a pre-machineId agent),
 *  matching how the rest of the console joins live standing — one DID can run
 *  several machines, and two rows for the same machine must not double-count
 *  as capacity. First row wins on a duplicate key. */
function normalizeSupply(rows: readonly AdvisorSupplyRow[]): SupplyMachine[] {
  const byKey = new Map<string, SupplyMachine>();
  for (const row of rows) {
    const did = str(row.did);
    if (!did) continue;
    const machineId = str(row.machineId);
    const key = machineId ? `${did}:${machineId}` : did;
    if (byKey.has(key)) continue;
    const models = Array.isArray(row.supportedModels)
      ? [...new Set(row.supportedModels.filter((m): m is string => typeof m === "string" && !!m))]
      : [];
    byKey.set(key, {
      key,
      did,
      models,
      blocker: supplyBlockerFor(row),
      silent: row.silentFailure === true,
    });
  }
  return [...byKey.values()];
}

function emptyBlocked(): BlockedCounts {
  return { engineFault: 0, paused: 0, unhealthy: 0, coolingDown: 0 };
}

function stateFor(
  healthy: number,
  requests: number,
  perMachinePerHour: number | null,
): SupplyDemandState {
  if (healthy === 0) return requests > 0 ? "unserved" : "dark";
  if (requests === 0) return "idle";
  if (perMachinePerHour !== null && perMachinePerHour >= HOT_REQUESTS_PER_MACHINE_HOUR) {
    return "hot";
  }
  return "steady";
}

/** Order rows so "needs help" floats to the top.
 *
 *  Smoke test last (it is supply-inflated noise), then unserved models — real
 *  demand with nowhere to go — ranked by how much demand is stranded, then
 *  everything else by pressure. Ties break on raw demand and finally on model
 *  id, so the order is total and the table never reshuffles between renders of
 *  the same data. */
function compareRows(a: ModelSupplyDemandRow, b: ModelSupplyDemandRow): number {
  if (a.smokeTest !== b.smokeTest) return a.smokeTest ? 1 : -1;
  if (a.unserved !== b.unserved) return a.unserved ? -1 : 1;
  if (a.unserved && b.unserved) {
    if (a.requests !== b.requests) return b.requests - a.requests;
  } else {
    const ap = a.requestsPerHealthyMachine ?? 0;
    const bp = b.requestsPerHealthyMachine ?? 0;
    if (ap !== bp) return bp - ap;
  }
  if (a.requests !== b.requests) return b.requests - a.requests;
  return a.modelId < b.modelId ? -1 : a.modelId > b.modelId ? 1 : 0;
}

/** Build the supply/demand table for one trailing window.
 *
 *  Rows cover the UNION of models with live supply and models with demand: a
 *  model everyone stopped serving but requesters still ask for is exactly the
 *  row an operator needs to see, and it exists on the demand side only. */
export function buildSupplyDemand(input: SupplyDemandInput): SupplyDemandSnapshot {
  const { window } = input;
  const machines = normalizeSupply(input.providers ?? []);
  const hours = WINDOW_HOURS[window];

  const demandByModel = new Map<string, { requests: number; tokens: number }>();
  for (const entry of input.demand?.models ?? []) {
    if (typeof entry.modelId !== "string" || entry.modelId.length === 0) continue;
    const stats = entry.totals?.[window];
    const requests = count(stats?.requests);
    const tokens = count(stats?.tokens);
    // Fold rather than overwrite: a malformed input that repeats a model id
    // should add up, not silently drop one of the two.
    const prev = demandByModel.get(entry.modelId);
    demandByModel.set(entry.modelId, {
      requests: (prev?.requests ?? 0) + requests,
      tokens: (prev?.tokens ?? 0) + tokens,
    });
  }

  interface Acc {
    advertising: number;
    healthy: number;
    blocked: BlockedCounts;
    silent: number;
    operators: Set<string>;
  }
  const supplyByModel = new Map<string, Acc>();
  const accFor = (modelId: string): Acc => {
    let acc = supplyByModel.get(modelId);
    if (!acc) {
      acc = {
        advertising: 0,
        healthy: 0,
        blocked: emptyBlocked(),
        silent: 0,
        operators: new Set(),
      };
      supplyByModel.set(modelId, acc);
    }
    return acc;
  };

  for (const machine of machines) {
    for (const modelId of machine.models) {
      const acc = accFor(modelId);
      acc.advertising += 1;
      if (machine.blocker) {
        acc.blocked[machine.blocker] += 1;
        continue;
      }
      acc.healthy += 1;
      acc.operators.add(machine.did);
      if (machine.silent) acc.silent += 1;
    }
  }

  const modelIds = new Set<string>([...supplyByModel.keys(), ...demandByModel.keys()]);
  const rows: ModelSupplyDemandRow[] = [];
  for (const modelId of modelIds) {
    const supply = supplyByModel.get(modelId);
    const demand = demandByModel.get(modelId);
    const advertising = supply?.advertising ?? 0;
    const healthy = supply?.healthy ?? 0;
    const requests = demand?.requests ?? 0;
    const tokens = demand?.tokens ?? 0;
    const requestsPerHealthyMachine = healthy > 0 ? requests / healthy : null;
    const perMachinePerHour =
      requestsPerHealthyMachine === null ? null : requestsPerHealthyMachine / hours;
    rows.push({
      modelId,
      advertising,
      healthy,
      blocked: supply?.blocked ?? emptyBlocked(),
      silent: supply?.silent ?? 0,
      operators: supply?.operators.size ?? 0,
      requests,
      tokens,
      requestsPerHealthyMachine,
      tokensPerHealthyMachine: healthy > 0 ? tokens / healthy : null,
      unserved: healthy === 0 && requests > 0,
      state: stateFor(healthy, requests, perMachinePerHour),
      smokeTest: modelId === SMOKE_TEST_MODEL_ID,
    });
  }
  rows.sort(compareRows);

  return {
    window,
    rows,
    totals: {
      models: rows.length,
      machines: machines.length,
      healthyMachines: machines.filter((m) => m.blocker === null).length,
      unservedModels: rows.filter((r) => r.unserved).length,
      idleModels: rows.filter((r) => r.state === "idle").length,
      requests: rows.reduce((n, r) => n + r.requests, 0),
      tokens: rows.reduce((n, r) => n + r.tokens, 0),
    },
  };
}
