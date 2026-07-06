import type { AppviewIndexedRecord } from "@/integrations/appview/appview.server.ts";
import { cocoreConfig } from "@/lib/cocore-config.ts";
import { resolveVerifiedTier, type VerifiedTier } from "@/lib/verified-standing.server.ts";

import type { Machine, MachineState } from "./machines-data.ts";

export type FleetReceiptStats = {
  /** Sum of receipt prices in tokens (credits). Receipts are priced in
   *  CC, the closed-loop credit currency, at 1 minor unit = 1 token. */
  earn24hTokens: number;
  earn7dTokens: number;
  earn30dTokens: number;
  earnLifetimeTokens: number;
  jobs24h: number;
  jobs7d: number;
  jobs30d: number;
  jobsLifetime: number;
  /** Hourly token totals for the last 24 hours (index 0 = oldest hour in window). */
  hourlyEarnTokens: number[];
  /** Receipt-activity index per hour (0–100); not GPU telemetry. */
  hourlyActivityPct: number[];
  /** Daily token totals for the last 7 days (index 0 = oldest day). */
  dailyEarnTokens7d: number[];
  /** Daily token totals for the last 30 days (index 0 = oldest day). */
  dailyEarnTokens30d: number[];
  dailyActivityPct7d: number[];
  dailyActivityPct30d: number[];
};

type EngineFaultBody = {
  code?: string;
  message?: string;
  models?: string[];
};

type AdvisorFaultBody = {
  code?: string;
  message?: string;
  observedAt?: string;
};

type ProviderRecordBody = {
  machineLabel?: string;
  chip?: string;
  ramGB?: number;
  gpuCores?: number;
  memoryBandwidthGBs?: number;
  createdAt?: string;
  active?: boolean;
  provisioning?: boolean;
  serving?: boolean;
  trustLevel?: string;
  tier?: string;
  desiredTier?: string;
  supportedModels?: string[];
  desiredModels?: string[];
  engineFault?: EngineFaultBody;
  advisorFault?: AdvisorFaultBody;
  shareLocation?: boolean;
  region?: string;
  proBono?: { mode?: string; dids?: string[] };
  toolCalls?: boolean;
  attestationPubKey?: string;
};

type ReceiptRecordBody = {
  price?: { amount: number; currency: string };
  completedAt?: string;
  model?: string;
  tokensIn?: number;
  tokensOut?: number;
  /** Strong-ref to the dev.cocore.compute.attestation this receipt was
   *  signed under. Resolving it to the attestation's `publicKey` is how
   *  we attribute a receipt to the specific machine that served it. */
  attestationUri?: string;
  /** DID of the requester who ran this job, denormalized onto the receipt
   *  by the lexicon. Lets a machine's work timeline show *who* used it. */
  requester?: string;
};

/** A machine reads as "running" when one of the models it advertises had
 *  a receipt complete within this window — i.e. it just served a job. */
const RECENTLY_ACTIVE_MS = 5 * 60 * 1000;

const HOURS = 24;
const DAYS_7 = 7;
const DAYS_30 = 30;
const MS_DAY = 24 * 60 * 60 * 1000;

function parseProviderBody(body: unknown): ProviderRecordBody {
  if (!body || typeof body !== "object") return {};
  const o = body as Record<string, unknown>;
  return {
    machineLabel: typeof o.machineLabel === "string" ? o.machineLabel : undefined,
    chip: typeof o.chip === "string" ? o.chip : undefined,
    ramGB: typeof o.ramGB === "number" ? o.ramGB : undefined,
    gpuCores: typeof o.gpuCores === "number" ? o.gpuCores : undefined,
    memoryBandwidthGBs: typeof o.memoryBandwidthGBs === "number" ? o.memoryBandwidthGBs : undefined,
    createdAt: typeof o.createdAt === "string" ? o.createdAt : undefined,
    active: typeof o.active === "boolean" ? o.active : undefined,
    provisioning: typeof o.provisioning === "boolean" ? o.provisioning : undefined,
    serving: typeof o.serving === "boolean" ? o.serving : undefined,
    trustLevel: typeof o.trustLevel === "string" ? o.trustLevel : undefined,
    tier: typeof o.tier === "string" ? o.tier : undefined,
    desiredTier: typeof o.desiredTier === "string" ? o.desiredTier : undefined,
    supportedModels: Array.isArray(o.supportedModels)
      ? o.supportedModels.filter((m): m is string => typeof m === "string")
      : undefined,
    desiredModels: Array.isArray(o.desiredModels)
      ? o.desiredModels.filter((m): m is string => typeof m === "string")
      : undefined,
    engineFault: parseEngineFault(o.engineFault),
    advisorFault: parseAdvisorFault(o.advisorFault),
    shareLocation: typeof o.shareLocation === "boolean" ? o.shareLocation : undefined,
    region: typeof o.region === "string" ? o.region : undefined,
    proBono: parseProBono(o.proBono),
    toolCalls: typeof o.toolCalls === "boolean" ? o.toolCalls : undefined,
    attestationPubKey:
      typeof o.attestationPubKey === "string" && o.attestationPubKey.length > 0
        ? o.attestationPubKey
        : undefined,
  };
}

/** Parse the provider record's `proBono` policy (mode + optional DID
 *  allowlist), tolerating malformed shapes (treated as off). */
function parseProBono(raw: unknown): { mode?: string; dids?: string[] } | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const o = raw as Record<string, unknown>;
  const mode = typeof o.mode === "string" ? o.mode : undefined;
  if (mode !== "any" && mode !== "direct") return undefined;
  const dids = Array.isArray(o.dids)
    ? o.dids.filter((d): d is string => typeof d === "string")
    : undefined;
  return { mode, ...(dids && dids.length > 0 ? { dids } : {}) };
}

function parseEngineFault(raw: unknown): EngineFaultBody | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const o = raw as Record<string, unknown>;
  const code = typeof o.code === "string" ? o.code : undefined;
  const message = typeof o.message === "string" ? o.message : undefined;
  // A fault is only meaningful with a human-readable message; ignore
  // malformed records rather than rendering an empty alert.
  if (!message) return undefined;
  return {
    code,
    message,
    models: Array.isArray(o.models)
      ? o.models.filter((m): m is string => typeof m === "string")
      : undefined,
  };
}

/** Parse the provider record's `advisorFault` — published by the agent when
 *  its WebSocket to the advisor keeps failing to connect, i.e. the machine
 *  serves locally but is invisible to the network. Same tolerance posture as
 *  {@link parseEngineFault}: a fault is only meaningful with a message. */
function parseAdvisorFault(raw: unknown): AdvisorFaultBody | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const o = raw as Record<string, unknown>;
  const code = typeof o.code === "string" ? o.code : undefined;
  const message = typeof o.message === "string" ? o.message : undefined;
  if (!message) return undefined;
  return {
    code,
    message,
    observedAt: typeof o.observedAt === "string" ? o.observedAt : undefined,
  };
}

function parseReceiptBody(body: unknown): ReceiptRecordBody {
  if (!body || typeof body !== "object") return {};
  const o = body as Record<string, unknown>;
  const priceRaw = o.price;
  let price: ReceiptRecordBody["price"];
  if (priceRaw && typeof priceRaw === "object") {
    const p = priceRaw as Record<string, unknown>;
    if (typeof p.amount === "number" && typeof p.currency === "string") {
      price = { amount: p.amount, currency: p.currency };
    }
  }
  const attestation = o.attestation;
  let attestationUri: string | undefined;
  if (attestation && typeof attestation === "object") {
    const a = attestation as Record<string, unknown>;
    if (typeof a.uri === "string") attestationUri = a.uri;
  }
  let tokensIn: number | undefined;
  let tokensOut: number | undefined;
  if (o.tokens && typeof o.tokens === "object") {
    const t = o.tokens as Record<string, unknown>;
    if (typeof t.in === "number") tokensIn = t.in;
    if (typeof t.out === "number") tokensOut = t.out;
  }
  return {
    price,
    completedAt: typeof o.completedAt === "string" ? o.completedAt : undefined,
    model: typeof o.model === "string" ? o.model : undefined,
    tokensIn,
    tokensOut,
    attestationUri,
    requester: typeof o.requester === "string" ? o.requester : undefined,
  };
}

/** The credit currency receipts are priced in. cocore is a closed-loop
 *  token system — every receipt's `price` is denominated in CC at
 *  1 minor unit = 1 token, so the token total is just the sum of
 *  `price.amount` over CC receipts. (Historically the dashboard assumed
 *  USD receipts converted to tokens via the exchange rate; the provider
 *  has only ever published CC, so that path counted nothing.) */
const TOKEN_CURRENCY = "CC";

/** Tokens earned by a single receipt, or null if it isn't a CC-priced
 *  receipt we can count. */
function receiptTokens(body: ReceiptRecordBody): number | null {
  if (!body.price) return null;
  if (body.price.currency.toUpperCase() !== TOKEN_CURRENCY) return null;
  if (!Number.isFinite(body.price.amount)) return null;
  return body.price.amount;
}

function formatMachinePairedAt(iso: string | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    year: "numeric",
    timeZone: "UTC",
  }).format(d);
}

function receiptCompletedMs(row: AppviewIndexedRecord, body: ReceiptRecordBody): number {
  if (body.completedAt) {
    const t = new Date(body.completedAt).getTime();
    if (!Number.isNaN(t)) return t;
  }
  if (row.indexedAt) {
    const t = new Date(row.indexedAt).getTime();
    if (!Number.isNaN(t)) return t;
  }
  return NaN;
}

/** Model NSIDs that had a receipt complete within the last
 *  {@link RECENTLY_ACTIVE_MS}. A machine advertising any of these models
 *  is treated as "running" (it just served a job). We key on the model
 *  rather than the bare DID so that, when an account owns several
 *  machines serving different models, only the box that actually ran the
 *  job lights up. (Two machines serving the SAME model both light up —
 *  we can't disambiguate without resolving each receipt's attestation,
 *  and "both candidates are warm" is a reasonable read.) */
export function recentlyActiveModels(
  receipts: AppviewIndexedRecord[],
  nowMs: number,
  windowMs: number = RECENTLY_ACTIVE_MS,
): Set<string> {
  const cutoff = nowMs - windowMs;
  const out = new Set<string>();
  for (const row of receipts) {
    const body = parseReceiptBody(row.body);
    if (!body.model) continue;
    const completed = receiptCompletedMs(row, body);
    if (!Number.isNaN(completed) && completed >= cutoff) out.add(body.model);
  }
  return out;
}

export function aggregateReceiptsForDid(
  receipts: AppviewIndexedRecord[],
  nowMs: number,
): FleetReceiptStats {
  const start24h = nowMs - 24 * 60 * 60 * 1000;
  const start7d = nowMs - DAYS_7 * MS_DAY;
  const start30d = nowMs - DAYS_30 * MS_DAY;

  let earn24hTokens = 0;
  let earn7dTokens = 0;
  let earn30dTokens = 0;
  let earnLifetimeTokens = 0;
  let jobs24h = 0;
  let jobs7d = 0;
  let jobs30d = 0;
  let jobsLifetime = 0;

  const hourlyEarnTokens = Array.from({ length: HOURS }, () => 0);
  const hourlyCount = Array.from({ length: HOURS }, () => 0);
  const dailyEarn7d = Array.from({ length: DAYS_7 }, () => 0);
  const dailyCount7d = Array.from({ length: DAYS_7 }, () => 0);
  const dailyEarn30d = Array.from({ length: DAYS_30 }, () => 0);
  const dailyCount30d = Array.from({ length: DAYS_30 }, () => 0);

  for (const row of receipts) {
    const body = parseReceiptBody(row.body);
    const tokens = receiptTokens(body);
    if (tokens === null) continue;
    earnLifetimeTokens += tokens;
    jobsLifetime += 1;

    const completed = receiptCompletedMs(row, body);
    if (!Number.isNaN(completed)) {
      if (completed >= start24h && completed <= nowMs) {
        earn24hTokens += tokens;
        jobs24h += 1;
      }
      if (completed >= start7d && completed <= nowMs) {
        earn7dTokens += tokens;
        jobs7d += 1;
      }
      if (completed >= start30d && completed <= nowMs) {
        earn30dTokens += tokens;
        jobs30d += 1;
      }

      if (completed >= start24h && completed <= nowMs) {
        const hourIndex = Math.floor((completed - start24h) / (60 * 60 * 1000));
        const idx = Math.min(HOURS - 1, Math.max(0, hourIndex));
        hourlyEarnTokens[idx] = (hourlyEarnTokens[idx] ?? 0) + tokens;
        hourlyCount[idx] = (hourlyCount[idx] ?? 0) + 1;
      }

      if (completed >= start7d && completed <= nowMs) {
        const dayIdx = Math.min(
          DAYS_7 - 1,
          Math.max(0, Math.floor((completed - start7d) / MS_DAY)),
        );
        dailyEarn7d[dayIdx] = (dailyEarn7d[dayIdx] ?? 0) + tokens;
        dailyCount7d[dayIdx] = (dailyCount7d[dayIdx] ?? 0) + 1;
      }

      if (completed >= start30d && completed <= nowMs) {
        const dayIdx = Math.min(
          DAYS_30 - 1,
          Math.max(0, Math.floor((completed - start30d) / MS_DAY)),
        );
        dailyEarn30d[dayIdx] = (dailyEarn30d[dayIdx] ?? 0) + tokens;
        dailyCount30d[dayIdx] = (dailyCount30d[dayIdx] ?? 0) + 1;
      }
    }
  }

  const maxHourly = Math.max(1, ...hourlyCount);
  const hourlyActivityPct = hourlyCount.map((c) =>
    Math.min(100, Math.round((c / maxHourly) * 100)),
  );

  const maxDay7 = Math.max(1, ...dailyCount7d);
  const dailyActivityPct7d = dailyCount7d.map((c) =>
    Math.min(100, Math.round((c / maxDay7) * 100)),
  );
  const maxDay30 = Math.max(1, ...dailyCount30d);
  const dailyActivityPct30d = dailyCount30d.map((c) =>
    Math.min(100, Math.round((c / maxDay30) * 100)),
  );

  return {
    earn24hTokens,
    earn7dTokens,
    earn30dTokens,
    earnLifetimeTokens,
    jobs24h,
    jobs7d,
    jobs30d,
    jobsLifetime,
    hourlyEarnTokens,
    hourlyActivityPct,
    dailyEarnTokens7d: dailyEarn7d,
    dailyEarnTokens30d: dailyEarn30d,
    dailyActivityPct7d,
    dailyActivityPct30d,
  };
}

/** Per-machine slice of the fleet receipt totals. Same fields
 *  `providerRowsToMachines` needs for a row, but attributed to the
 *  specific machine that served the receipts rather than split evenly. */
export type MachineReceiptStats = {
  earn24hTokens: number;
  earn7dTokens: number;
  earnLifetimeTokens: number;
  jobsLifetime: number;
};

/** Attribute receipts to the machine (provider rkey) that actually served
 *  them, instead of splitting the fleet total evenly. Each receipt
 *  strong-refs the attestation it was signed under; `attUriToPubkey` maps
 *  that attestation URI to its `publicKey`, and `pubkeyToRkey` maps that
 *  pubkey (a provider record's `attestationPubKey`) to the machine's rkey.
 *
 *  Receipts whose attestation can't be resolved to a CURRENT machine — a
 *  retired or re-keyed box that no longer has a provider record — are left
 *  out of every machine's slice. They still count in the fleet total
 *  (`aggregateReceiptsForDid`), so per-machine rows can sum to slightly
 *  less than the headline; that gap is genuinely unattributable. Machines
 *  with no attributed receipts are simply absent from the returned map. */
export function aggregateReceiptsByMachine(
  receipts: AppviewIndexedRecord[],
  attUriToPubkey: Map<string, string>,
  pubkeyToRkey: Map<string, string>,
  nowMs: number,
): Map<string, MachineReceiptStats> {
  const start24h = nowMs - 24 * 60 * 60 * 1000;
  const start7d = nowMs - DAYS_7 * MS_DAY;
  const out = new Map<string, MachineReceiptStats>();

  for (const row of receipts) {
    const body = parseReceiptBody(row.body);
    const tokens = receiptTokens(body);
    if (tokens === null || !body.attestationUri) continue;
    const pubkey = attUriToPubkey.get(body.attestationUri);
    if (!pubkey) continue;
    const rkey = pubkeyToRkey.get(pubkey);
    if (!rkey) continue;

    let s = out.get(rkey);
    if (!s) {
      s = { earn24hTokens: 0, earn7dTokens: 0, earnLifetimeTokens: 0, jobsLifetime: 0 };
      out.set(rkey, s);
    }
    s.earnLifetimeTokens += tokens;
    s.jobsLifetime += 1;

    const completed = receiptCompletedMs(row, body);
    if (!Number.isNaN(completed)) {
      if (completed >= start24h && completed <= nowMs) s.earn24hTokens += tokens;
      if (completed >= start7d && completed <= nowMs) s.earn7dTokens += tokens;
    }
  }
  return out;
}

/** One served job on a machine's work timeline. Token-native: the
 *  `priceTokens` is the receipt price in CC (1 minor unit = 1 token),
 *  matching how the dashboards count earnings; `tokensIn`/`tokensOut`
 *  are the model's own token counts from the receipt. */
export type MachineWorkItem = {
  /** Receipt record key — stable id for list rendering. */
  rkey: string;
  /** RFC3339 completion time (falls back to the AppView index time). */
  completedAt: string;
  /** Epoch ms of {@link completedAt}, for client-side bucketing/sort. */
  completedMs: number;
  model: string;
  tokensIn: number;
  tokensOut: number;
  priceTokens: number;
  /** DID of the requester who ran this job, or null when the receipt
   *  omits it. The detail server fn resolves this to a handle below. */
  requester: string | null;
  /** Resolved handle for {@link requester} (e.g. `alice.bsky.social`),
   *  or null when unresolved — filled by the server fn, not this pure
   *  transform. The UI links to the requester's profile either way. */
  requesterHandle: string | null;
  /** Resolved display name for {@link requester}, when known. */
  requesterDisplayName: string | null;
};

/** The receipts a single machine served, newest first. Attributes each
 *  receipt to the machine via its attestation pubkey (same join the fleet
 *  dashboard uses): `attUriToPubkey` maps a receipt's attestation URI →
 *  the attestation's publicKey, and `machinePubkeys` is the set of pubkeys
 *  this machine's provider record(s) published. A machine that has only
 *  ever published one attestation key matches one key; a re-keyed box can
 *  match several. Receipts whose attestation can't be resolved to this
 *  machine's key are dropped. Caps the result to {@link limit} items. */
export function machineWorkTimeline(
  receipts: AppviewIndexedRecord[],
  attUriToPubkey: Map<string, string>,
  machinePubkeys: Set<string>,
  limit = 100,
): MachineWorkItem[] {
  const out: MachineWorkItem[] = [];
  for (const row of receipts) {
    const body = parseReceiptBody(row.body);
    if (!body.attestationUri) continue;
    const pubkey = attUriToPubkey.get(body.attestationUri);
    if (!pubkey || !machinePubkeys.has(pubkey)) continue;
    const completedMs = receiptCompletedMs(row, body);
    if (Number.isNaN(completedMs)) continue;
    out.push({
      rkey: row.rkey,
      completedAt: body.completedAt ?? row.indexedAt ?? new Date(completedMs).toISOString(),
      completedMs,
      model: body.model ?? "unknown",
      tokensIn: body.tokensIn ?? 0,
      tokensOut: body.tokensOut ?? 0,
      priceTokens: receiptTokens(body) ?? 0,
      requester: body.requester ?? null,
      // Resolved by the detail server fn after this pure transform runs.
      requesterHandle: null,
      requesterDisplayName: null,
    });
  }
  out.sort((a, b) => b.completedMs - a.completedMs);
  return out.slice(0, limit);
}

/** Map each provider record's `attestationPubKey` → its rkey, so a
 *  receipt (resolved to an attestation pubkey) can be attributed to the
 *  machine. Reads the field straight off the raw record body — it isn't
 *  part of the trimmed `ProviderRecordBody` the dashboard otherwise uses. */
export function pubkeyToRkeyMap(rows: AppviewIndexedRecord[]): Map<string, string> {
  const m = new Map<string, string>();
  for (const row of rows) {
    const body = row.body as { attestationPubKey?: unknown };
    if (typeof body?.attestationPubKey === "string" && body.attestationPubKey.length > 0) {
      m.set(body.attestationPubKey, row.rkey);
    }
  }
  return m;
}

/** Live per-machine standing as the advisor sees it, keyed by machineId
 *  (which equals the provider-record rkey == {@link Machine.id}). */
interface AdvisorStanding {
  unhealthy: boolean;
  unhealthyReason: string | null;
  silentFailure: boolean;
  /** Tier recomputed from the machine's actual signed attestation (proof-
   *  backed; see verified-standing.server.ts), not its self-asserted value. */
  verifiedTier: VerifiedTier;
  /** Set when the machine was capped below the tier it opted into — the
   *  operator-facing "why + how to regain it" nudge. */
  verifiedTierReason?: string;
}

export interface AdvisorStandingResult {
  /** Standing for each of the caller's machines currently CONNECTED to the
   *  advisor, keyed by machineId. A machine absent from the map is not
   *  connected to the grid right now. */
  byMachineId: Map<string, AdvisorStanding>;
  /** False when the advisor was unreachable — callers must then treat
   *  standing as UNKNOWN (never fabricate "healthy"). */
  reachable: boolean;
}

interface AdvisorProviderRow {
  did?: unknown;
  machineId?: unknown;
  unhealthy?: unknown;
  unhealthyReason?: unknown;
  silentFailure?: unknown;
  attestationUri?: unknown;
  confidentialEligible?: unknown;
  codeAttested?: unknown;
  registrationAuthenticated?: unknown;
}

/** Read live machine standing from the advisor's `/providers` and key it by
 *  machineId, scoped to one owner's DID. The advisor is the ONLY authority
 *  on live standing (it holds the socket and runs the preflight), so we read
 *  it directly rather than waiting on a PDS round-trip — a little latency is
 *  fine, but the answer must be correct. If the advisor is unreachable we
 *  return `reachable: false` so the UI shows "status unavailable" instead of
 *  guessing. */
export async function fetchAdvisorStanding(did: string): Promise<AdvisorStandingResult> {
  const byMachineId = new Map<string, AdvisorStanding>();
  try {
    const resp = await fetch(`${cocoreConfig().advisorUrl}/providers`, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(5_000),
    });
    if (!resp.ok) return { byMachineId, reachable: false };
    const rows = (await resp.json()) as AdvisorProviderRow[];
    if (!Array.isArray(rows)) return { byMachineId, reachable: false };
    const mine = rows.filter(
      (r) => r.did === did && typeof r.machineId === "string" && r.machineId.length > 0,
    );
    // Recompute each machine's tier from its actual signed attestation
    // (proof-backed, cached by attestation CID), in parallel with the rest.
    await Promise.all(
      mine.map(async (r) => {
        const { tier, reason } = await resolveVerifiedTier({
          did,
          attestationUri: typeof r.attestationUri === "string" ? r.attestationUri : null,
          confidentialEligible: r.confidentialEligible === true,
          codeAttested: r.codeAttested === true,
          // Only an explicit `false` downgrades; a pre-signal advisor omits it
          // (undefined) and is treated as authenticated.
          registrationAuthenticated:
            typeof r.registrationAuthenticated === "boolean"
              ? r.registrationAuthenticated
              : undefined,
        });
        byMachineId.set(r.machineId as string, {
          unhealthy: r.unhealthy === true,
          unhealthyReason: typeof r.unhealthyReason === "string" ? r.unhealthyReason : null,
          silentFailure: r.silentFailure === true,
          verifiedTier: tier,
          ...(reason ? { verifiedTierReason: reason } : {}),
        });
      }),
    );
    return { byMachineId, reachable: true };
  } catch {
    return { byMachineId, reachable: false };
  }
}

/** Overlay live advisor standing onto machines built from PDS records. The
 *  join is by machineId == provider-record rkey == {@link Machine.id}, with a
 *  fallback on the record's `attestationPubKey`: an agent that couldn't
 *  publish its provider record at boot (dead PDS session) registers without
 *  a `machine_id`, and the advisor then keys it by its attestation pubkey —
 *  the machine is live on the network, so it must not read "not reachable".
 *  When the advisor was unreachable, `standingKnown` is false on every
 *  machine and no unhealthy/connected claim is made (correctness over a
 *  fabricated green). */
export function applyAdvisorStanding(
  machines: Machine[],
  standing: AdvisorStandingResult,
): Machine[] {
  return machines.map((m) => {
    if (!standing.reachable) {
      return { ...m, standingKnown: false };
    }
    const s =
      standing.byMachineId.get(m.id) ??
      (m.attestationPubKey ? standing.byMachineId.get(m.attestationPubKey) : undefined);
    return {
      ...m,
      standingKnown: true,
      advisorConnected: s !== undefined,
      unhealthy: s?.unhealthy ?? false,
      unhealthyReason: s?.unhealthyReason ?? undefined,
      silentFailure: s?.silentFailure ?? false,
      verifiedTier: s?.verifiedTier ?? "best-effort",
      verifiedTierReason: s?.verifiedTierReason,
    };
  });
}

export function countProvidersByRepo(rows: AppviewIndexedRecord[]): Map<string, number> {
  const m = new Map<string, number>();
  for (const r of rows) {
    m.set(r.repo, (m.get(r.repo) ?? 0) + 1);
  }
  return m;
}

export function myProviderRecords(
  sessionDid: string,
  allProviders: AppviewIndexedRecord[],
): AppviewIndexedRecord[] {
  return allProviders.filter(
    (p) => p.repo === sessionDid && p.collection === "dev.cocore.compute.provider",
  );
}

function machineStateFromProvider(body: ProviderRecordBody, recentlyActive: boolean): MachineState {
  // The agent publishes its record immediately on serve start with
  // `provisioning: true`, before its engine has loaded — show that as a
  // distinct state rather than a false "idle".
  if (body.provisioning === true) return "provisioning";
  if (body.active === false) return "paused";
  // The agent flips `serving` to false on graceful shutdown (SIGTERM on
  // quit / pause / bounce), so a machine that stopped serving reads as
  // "offline" the moment it stops rather than lingering as "idle".
  // `serving` is absent on pre-2026-06 records — treat absence as unknown,
  // not offline. `provisioning`/`paused` win because they're more specific.
  if (body.serving === false) return "offline";
  // A machine that served a job in the last few minutes reads as
  // "running" rather than "idle".
  if (recentlyActive) return "running";
  return "idle";
}

function splitInt(total: number, parts: number, indexInPart: number): number {
  if (parts <= 0) return total;
  const base = Math.floor(total / parts);
  const remainder = total % parts;
  return base + (indexInPart < remainder ? 1 : 0);
}

export function providerRowsToMachines(
  rows: AppviewIndexedRecord[],
  stats: FleetReceiptStats,
  repoCounts: Map<string, number>,
  recentModels: Set<string> = new Set(),
  /** Real per-machine attribution (keyed by provider rkey). When present,
   *  each machine shows what IT actually earned/served. When null (the
   *  attestation lookup was unavailable), we fall back to splitting the
   *  fleet total evenly across the account's machines — the historical
   *  behavior, which made every row show the same number. */
  perMachine: Map<string, MachineReceiptStats> | null = null,
): Machine[] {
  const indexInRepo = new Map<string, number>();

  return rows.map((row) => {
    const body = parseProviderBody(row.body);
    // "running" if any model this machine advertises had a recent receipt.
    const recentlyActive = (body.supportedModels ?? []).some((m) => recentModels.has(m));
    const n = repoCounts.get(row.repo) ?? 1;
    const i = indexInRepo.get(row.repo) ?? 0;
    indexInRepo.set(row.repo, i + 1);

    let earn24: number;
    let earn7: number;
    let earnLife: number;
    let jobs: number;
    if (perMachine) {
      // Attributed: this machine's own receipts (absent = it served none).
      const mine = perMachine.get(row.rkey);
      earn24 = mine?.earn24hTokens ?? 0;
      earn7 = mine?.earn7dTokens ?? 0;
      earnLife = mine?.earnLifetimeTokens ?? 0;
      jobs = mine?.jobsLifetime ?? 0;
    } else {
      // Fallback: even split of the fleet total across the account's boxes.
      const share = n > 1 ? 1 / n : 1;
      earn24 = stats.earn24hTokens * share;
      earn7 = stats.earn7dTokens * share;
      earnLife = stats.earnLifetimeTokens * share;
      jobs = splitInt(stats.jobsLifetime, n, i);
    }

    const chip = body.chip?.trim() || "unknown chip";
    const ram = body.ramGB ?? 0;
    const gpuCores = body.gpuCores ?? 0;
    const chipMeta = gpuCores > 0 ? `${gpuCores} cores` : `${Math.max(0, ram)} gb ram`;

    const base: Machine = {
      id: row.rkey,
      attestationPubKey: body.attestationPubKey,
      alias: body.machineLabel?.trim() || row.rkey,
      state: machineStateFromProvider(body, recentlyActive),
      gpu: chip,
      vram: gpuCores > 0 ? gpuCores : ram,
      chipMeta,
      ram,
      pairedAt: formatMachinePairedAt(body.createdAt),
      earnings24h: earn24,
      earnings7d: earn7,
      earningsLifetime: earnLife,
      jobsCompleted: jobs,
      trustLevel: body.trustLevel,
      tier: typeof body.tier === "string" ? body.tier : undefined,
      desiredTier: typeof body.desiredTier === "string" ? body.desiredTier : undefined,
      supportedModels: Array.isArray(body.supportedModels)
        ? body.supportedModels.filter((m): m is string => typeof m === "string")
        : undefined,
      desiredModels: Array.isArray(body.desiredModels)
        ? body.desiredModels.filter((m): m is string => typeof m === "string")
        : undefined,
      faultCode: body.engineFault?.code,
      faultReason: body.engineFault?.message,
      faultModels: body.engineFault?.models,
      advisorFaultCode: body.advisorFault?.code,
      advisorFaultReason: body.advisorFault?.message,
      advisorFaultAt: body.advisorFault?.observedAt,
      shareLocation: body.shareLocation,
      region: body.region,
      proBonoMode:
        body.proBono?.mode === "any" || body.proBono?.mode === "direct"
          ? body.proBono.mode
          : undefined,
      proBonoDids: body.proBono?.dids,
      toolCalls: body.toolCalls,
    };

    if (body.active === false) {
      return {
        ...base,
        pausedReason: "retired in provider record",
      };
    }

    return base;
  });
}
