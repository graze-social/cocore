import { mutationOptions, queryOptions } from "@tanstack/react-query";
import { createServerFn } from "@tanstack/react-start";
import { Effect } from "effect";
import { z } from "zod";

import { runTraced } from "@/lib/o11y.server.ts";
import type { Machine } from "@/components/machines/machines-data.ts";
import type {
  FleetReceiptStats,
  MachineReceiptStats,
} from "@/components/machines/machines.server.ts";
import type { MachineWorkItem } from "@/components/machines/machines.server.ts";
import {
  aggregateReceiptsByMachine,
  aggregateReceiptsForDid,
  applyAdvisorStanding,
  countProvidersByRepo,
  fetchAdvisorStanding,
  machineWorkTimeline,
  myProviderRecords,
  providerRowsToMachines,
  pubkeyToRkeyMap,
  recentlyActiveModels,
} from "@/components/machines/machines.server.ts";
import {
  appviewGetReceiptsEffect,
  appviewListProvidersEffect,
} from "@/integrations/appview/appview.server.ts";
import { cocoreConfig } from "@/lib/cocore-config.ts";
import { resolveActorsForDids } from "@/lib/friends.server.ts";
import { fetchAttestationPubkeys } from "@/lib/machine-attribution.server.ts";
import {
  type DedupResult,
  dedupMyProviderRecords,
  deleteMyProviderRecord,
  getMyProviderRecord,
  setProviderRecordActive,
  setProviderRecordDesiredModels,
  setProviderRecordDesiredTier,
  setProviderRecordMachineLabel,
  setProviderRecordProBono,
  setProviderRecordShareLocation,
} from "@/lib/provider-record-pds.server.ts";
import { authMiddleware } from "@/middleware/auth.ts";

const providerRkeySchema = z.object({
  rkey: z.string().min(1).max(200),
});

const setProviderActiveSchema = providerRkeySchema.extend({
  active: z.boolean(),
});

const setProviderDesiredModelsSchema = providerRkeySchema.extend({
  models: z.array(z.string()),
});

const setProviderDesiredTierSchema = providerRkeySchema.extend({
  tier: z.enum(["attested-confidential", "best-effort"]),
});

const setProviderMachineLabelSchema = providerRkeySchema.extend({
  label: z.string().min(1).max(200),
});

const setProviderShareLocationSchema = providerRkeySchema.extend({
  share: z.boolean(),
});

const setProviderProBonoSchema = providerRkeySchema.extend({
  // null clears the policy (pro bono off). `direct` carries an optional DID
  // allowlist; `any` ignores it (everyone is already free).
  policy: z
    .object({
      mode: z.enum(["any", "direct"]),
      dids: z.array(z.string()).max(1024).optional(),
    })
    .nullable(),
});

export type MyMachinesPayload = {
  did: string;
  fetchedAt: string;
  machines: Machine[];
  receiptStats: FleetReceiptStats;
  /** Error from listProviders or getReceipts (machines may still be partial). */
  appviewError: string | null;
};

function emptyStats(): FleetReceiptStats {
  const hourlyEarnTokens = Array.from({ length: 24 }, () => 0);
  const hourlyActivityPct = Array.from({ length: 24 }, () => 0);
  const dailyEarnTokens7d = Array.from({ length: 7 }, () => 0);
  const dailyEarnTokens30d = Array.from({ length: 30 }, () => 0);
  const dailyActivityPct7d = Array.from({ length: 7 }, () => 0);
  const dailyActivityPct30d = Array.from({ length: 30 }, () => 0);
  return {
    earn24hTokens: 0,
    earn7dTokens: 0,
    earn30dTokens: 0,
    earnLifetimeTokens: 0,
    jobs24h: 0,
    jobs7d: 0,
    jobs30d: 0,
    jobsLifetime: 0,
    hourlyEarnTokens,
    hourlyActivityPct,
    dailyEarnTokens7d,
    dailyEarnTokens30d,
    dailyActivityPct7d,
    dailyActivityPct30d,
  };
}

const listMyMachinesServerFn = createServerFn({ method: "GET" })
  .middleware([authMiddleware])
  .handler(({ context }) =>
    runTraced(
      "machines.listMine",
      Effect.gen(function* () {
        const fetchedAt = new Date().toISOString();
        const base = () => ({
          fetchedAt,
          receiptStats: emptyStats(),
          appviewError: null as string | null,
        });

        const did = context.did;
        // Providers and receipts are independent AppView reads — fetch them
        // concurrently instead of waterfalling one cross-service round-trip
        // after the other.
        const [providersEither, receiptsEither, standing] = yield* Effect.all(
          [
            Effect.either(appviewListProvidersEffect),
            Effect.either(appviewGetReceiptsEffect({ provider: did })),
            // Live advisor standing — independent of the AppView reads, so
            // fetch it concurrently. Resolves with reachable:false rather than
            // failing, so a down advisor never blocks the fleet list.
            Effect.promise(() => fetchAdvisorStanding(did)),
          ],
          { concurrency: "unbounded" },
        );
        if (providersEither._tag === "Left") {
          return {
            did,
            machines: [] as Machine[],
            ...base(),
            appviewError: providersEither.left.message,
          };
        }

        const mine = myProviderRecords(did, providersEither.right.providers);
        const repoCounts = countProvidersByRepo(mine);

        const receiptRows = receiptsEither._tag === "Right" ? receiptsEither.right.receipts : [];
        const receiptErr = receiptsEither._tag === "Left" ? receiptsEither.left.message : null;

        const now = Date.now();
        const stats = aggregateReceiptsForDid(receiptRows, now);
        // Models with a receipt in the last 5 min → their machines read
        // "running" instead of "idle".
        const recentModels = recentlyActiveModels(receiptRows, now);

        // Attribute receipts to the machine that actually served them (via
        // attestation pubkey). This only matters with 2+ machines — for the
        // common single-machine account the one box gets the whole total via
        // the even-split fallback (n=1), so we SKIP the live PDS attestation
        // lookup entirely and save a round-trip on the hot path. Best-effort:
        // if the lookup yields nothing, `perMachine` stays null and
        // providerRowsToMachines falls back to the even split.
        let perMachine: Map<string, MachineReceiptStats> | null = null;
        if (mine.length > 1) {
          const attEither = yield* Effect.either(
            Effect.promise(() => fetchAttestationPubkeys(context.oauthSession)),
          );
          const attUriToPubkey =
            attEither._tag === "Right" ? attEither.right : new Map<string, string>();
          if (attUriToPubkey.size > 0) {
            const byMachine = aggregateReceiptsByMachine(
              receiptRows,
              attUriToPubkey,
              pubkeyToRkeyMap(mine),
              now,
            );
            if (byMachine.size > 0) perMachine = byMachine;
          }
        }

        const machines = applyAdvisorStanding(
          providerRowsToMachines(mine, stats, repoCounts, recentModels, perMachine),
          standing,
        );

        return {
          did,
          fetchedAt,
          machines,
          receiptStats: stats,
          appviewError: receiptErr,
        };
      }),
    ),
  );

export const listMyMachinesQueryOptions = queryOptions({
  queryKey: ["machines", "fleet"] as const,
  queryFn: listMyMachinesServerFn,
  // Dashboard data tolerates a couple minutes of staleness; keeping it
  // cached makes navigating away and back instant (stale-while-revalidate)
  // instead of re-paying the full server round-trip. gcTime keeps it in
  // memory long enough that tab-switching stays snappy.
  staleTime: 120_000,
  gcTime: 600_000,
});

type MyMachineDetailPayload = {
  did: string;
  fetchedAt: string;
  /** The resolved machine (owner-scoped), or null when the rkey isn't one
   *  of the caller's provider records — the route renders a not-found. */
  machine: Machine | null;
  /** Receipts this machine served, newest first (capped). Empty when the
   *  machine couldn't be attributed any receipts (or has served none). */
  timeline: MachineWorkItem[];
  /** Error from listProviders or getReceipts (detail may be partial). */
  appviewError: string | null;
};

/** Owner-scoped detail for one machine, addressed by its provider-record
 *  rkey. Resolves the machine ONLY from records owned by `context.did`, so
 *  a caller can never read another account's box — an rkey that isn't
 *  theirs returns `machine: null` and the route 404s. Builds the work
 *  timeline by attributing receipts to this machine's attestation
 *  pubkey(s), the same join the fleet dashboard uses for per-row earnings. */
const getMyMachineDetailServerFn = createServerFn({ method: "GET" })
  .middleware([authMiddleware])
  .inputValidator(providerRkeySchema)
  .handler(({ context, data }) =>
    runTraced(
      "machines.getDetail",
      Effect.gen(function* () {
        const fetchedAt = new Date().toISOString();
        const did = context.did;

        const [providersEither, receiptsEither, standing] = yield* Effect.all(
          [
            Effect.either(appviewListProvidersEffect),
            Effect.either(appviewGetReceiptsEffect({ provider: did })),
            Effect.promise(() => fetchAdvisorStanding(did)),
          ],
          { concurrency: "unbounded" },
        );
        if (providersEither._tag === "Left") {
          return {
            did,
            fetchedAt,
            machine: null,
            timeline: [],
            appviewError: providersEither.left.message,
          } satisfies MyMachineDetailPayload;
        }

        const mine = myProviderRecords(did, providersEither.right.providers);
        const target = mine.find((r) => r.rkey === data.rkey);
        if (!target) {
          // Not one of the caller's machines (or no such rkey) — the route
          // turns this into a not-found.
          return {
            did,
            fetchedAt,
            machine: null,
            timeline: [],
            appviewError: receiptsEither._tag === "Left" ? receiptsEither.left.message : null,
          } satisfies MyMachineDetailPayload;
        }

        const receiptRows = receiptsEither._tag === "Right" ? receiptsEither.right.receipts : [];
        const receiptErr = receiptsEither._tag === "Left" ? receiptsEither.left.message : null;
        const now = Date.now();
        const recentModels = recentlyActiveModels(receiptRows, now);
        const stats = aggregateReceiptsForDid(receiptRows, now);
        const repoCounts = countProvidersByRepo([target]);

        // Per-machine attribution so this single row shows its OWN totals,
        // not the fleet split. The attestation lookup also feeds the
        // timeline join below — fetch it once.
        const attEither = yield* Effect.either(
          Effect.promise(() => fetchAttestationPubkeys(context.oauthSession)),
        );
        const attUriToPubkey =
          attEither._tag === "Right" ? attEither.right : new Map<string, string>();

        let perMachine: Map<string, MachineReceiptStats> | null = null;
        if (attUriToPubkey.size > 0) {
          const byMachine = aggregateReceiptsByMachine(
            receiptRows,
            attUriToPubkey,
            pubkeyToRkeyMap(mine),
            now,
          );
          if (byMachine.size > 0) perMachine = byMachine;
        }

        const [machine] = applyAdvisorStanding(
          providerRowsToMachines([target], stats, repoCounts, recentModels, perMachine),
          standing,
        );

        // The pubkeys THIS machine's provider record published — a re-keyed
        // box can carry several across records that share its machineLabel,
        // but the AppView returns one record per rkey, so in practice this
        // is the single key on the target record.
        const machinePubkeys = new Set<string>();
        const targetPub = (target.body as { attestationPubKey?: unknown }).attestationPubKey;
        if (typeof targetPub === "string" && targetPub.length > 0) machinePubkeys.add(targetPub);

        const timeline =
          machinePubkeys.size > 0 && attUriToPubkey.size > 0
            ? machineWorkTimeline(receiptRows, attUriToPubkey, machinePubkeys)
            : [];

        // Resolve the requesters (who ran each job) to handles so the
        // timeline can link to their profiles — the social view of who
        // actually used this machine. Deduped + parallel; a failed lookup
        // degrades to the raw DID in the UI.
        const requesterDids = timeline
          .map((it) => it.requester)
          .filter((d): d is string => d != null);
        const resolved =
          requesterDids.length > 0
            ? yield* Effect.promise(() => resolveActorsForDids(requesterDids))
            : null;
        const enrichedTimeline = resolved
          ? timeline.map((it) => {
              const r = it.requester ? resolved.get(it.requester) : undefined;
              return r
                ? { ...it, requesterHandle: r.handle, requesterDisplayName: r.displayName }
                : it;
            })
          : timeline;

        return {
          did,
          fetchedAt,
          machine: machine ?? null,
          timeline: enrichedTimeline,
          appviewError: receiptErr,
        } satisfies MyMachineDetailPayload;
      }),
    ),
  );

export const myMachineDetailQueryOptions = (rkey: string) =>
  queryOptions({
    queryKey: ["machines", "detail", rkey] as const,
    queryFn: () => getMyMachineDetailServerFn({ data: { rkey } }),
    staleTime: 120_000,
    gcTime: 600_000,
  });

/** Nudge the advisor to tell a connected agent its start/stop switch
 *  changed, so the machine drops out of (or back into) routing within ~a
 *  second instead of at the agent's next 30s poll. Best-effort: the PDS
 *  write is the durable source of truth; the poll is the fallback. */
async function nudgeAdvisorControl(did: string): Promise<void> {
  try {
    await fetch(`${cocoreConfig().advisorUrl}/control`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ did }),
      signal: AbortSignal.timeout(5_000),
    });
  } catch {
    // The agent re-reads its own PDS on a 30s poll regardless.
  }
}

/** Ask the advisor to tell a specific machine to self-right NOW (the owner
 *  clicked "Try to recover" on an unhealthy machine). The advisor relays an
 *  unprivileged `recover_request` to that machine's socket; the agent runs
 *  its engine recovery and reports back, and the advisor restores the machine
 *  to routing on success. Returns whether the signal was delivered to a
 *  connected machine. */
async function requestSelfRight(did: string, machineId: string): Promise<{ delivered: boolean }> {
  try {
    const resp = await fetch(`${cocoreConfig().advisorUrl}/control`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ did, machineId, action: "self-right" }),
      signal: AbortSignal.timeout(5_000),
    });
    if (!resp.ok) return { delivered: false };
    const body = (await resp.json()) as { delivered?: unknown };
    return { delivered: typeof body.delivered === "number" && body.delivered > 0 };
  } catch {
    return { delivered: false };
  }
}

const recoverMachineServerFn = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .inputValidator(providerRkeySchema)
  .handler(async ({ context, data }) => {
    // The machine's advisor machine_id is its provider-record rkey.
    return requestSelfRight(context.did, data.rkey);
  });

export const recoverMachineMutationOptions = mutationOptions({
  mutationFn: (variables: { rkey: string }) => recoverMachineServerFn({ data: variables }),
});

const setMyProviderActiveServerFn = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .inputValidator(setProviderActiveSchema)
  .handler(async ({ context, data }) => {
    await setProviderRecordActive(context.oauthSession, data.rkey, data.active);
    await nudgeAdvisorControl(context.did);
    return { ok: true as const };
  });

const setMyProviderDesiredModelsServerFn = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .inputValidator(setProviderDesiredModelsSchema)
  .handler(async ({ context, data }) => {
    await setProviderRecordDesiredModels(context.oauthSession, data.rkey, data.models);
    await nudgeAdvisorControl(context.did);
    return { ok: true as const };
  });

const setMyProviderDesiredTierServerFn = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .inputValidator(setProviderDesiredTierSchema)
  .handler(async ({ context, data }) => {
    // Opt this machine into (or out of) confidential — owner INTENT only. The
    // agent reconciles toward it and publishes the higher achieved tier only
    // once earned; opting out reverts the machine to exactly its prior behavior.
    await setProviderRecordDesiredTier(context.oauthSession, data.rkey, data.tier);
    await nudgeAdvisorControl(context.did);
    return { ok: true as const };
  });

const setMyProviderMachineLabelServerFn = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .inputValidator(setProviderMachineLabelSchema)
  .handler(async ({ context, data }) => {
    await setProviderRecordMachineLabel(context.oauthSession, data.rkey, data.label);
    await nudgeAdvisorControl(context.did);
    return { ok: true as const };
  });

const setMyProviderShareLocationServerFn = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .inputValidator(setProviderShareLocationSchema)
  .handler(async ({ context, data }) => {
    // Owner INTENT only. The agent reads `shareLocation` off its own record at
    // serve start and re-derives (or clears) the coarse `region` from its IP.
    await setProviderRecordShareLocation(context.oauthSession, data.rkey, data.share);
    await nudgeAdvisorControl(context.did);
    return { ok: true as const };
  });

const setMyProviderProBonoServerFn = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .inputValidator(setProviderProBonoSchema)
  .handler(async ({ context, data }) => {
    // Owner INTENT only. The agent reconciles toward it and serves a matching
    // requester free; clearing it (null) bills every job again.
    await setProviderRecordProBono(context.oauthSession, data.rkey, data.policy);
    await nudgeAdvisorControl(context.did);
    return { ok: true as const };
  });

const deleteMyProviderRecordServerFn = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .inputValidator(providerRkeySchema)
  .handler(async ({ context, data }) => {
    // The record may already be gone from the PDS while a stale row
    // lingers in the AppView — a reinstall that re-keyed this machine, an
    // earlier partial unpair, or an out-of-band wipe. Fetching the swap
    // CID first must NOT turn that into a hard "Could not locate record"
    // error: fall back to a swap-less delete, which deleteMyProviderRecord
    // resolves idempotently (clears the AppView row, reports success).
    let cid: string | undefined;
    try {
      cid = (await getMyProviderRecord(context.oauthSession, data.rkey)).cid;
    } catch {
      cid = undefined;
    }
    await deleteMyProviderRecord(context.oauthSession, data.rkey, cid);
    return { ok: true as const };
  });

const dedupMyProviderRecordsServerFn = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .handler(async ({ context }): Promise<DedupResult> => {
    return dedupMyProviderRecords(context.oauthSession);
  });

export type SetMyProviderActiveInput = z.infer<typeof setProviderActiveSchema>;
export type SetMyProviderDesiredModelsInput = z.infer<typeof setProviderDesiredModelsSchema>;
export type SetMyProviderMachineLabelInput = z.infer<typeof setProviderMachineLabelSchema>;
export type DeleteMyProviderInput = z.infer<typeof providerRkeySchema>;

export const setMyProviderActiveMutationOptions = mutationOptions({
  mutationFn: (variables: SetMyProviderActiveInput) =>
    setMyProviderActiveServerFn({ data: variables }),
});

export const setMyProviderDesiredModelsMutationOptions = mutationOptions({
  mutationFn: (variables: SetMyProviderDesiredModelsInput) =>
    setMyProviderDesiredModelsServerFn({ data: variables }),
});

export type SetMyProviderDesiredTierInput = z.infer<typeof setProviderDesiredTierSchema>;

export const setMyProviderDesiredTierMutationOptions = mutationOptions({
  mutationFn: (variables: SetMyProviderDesiredTierInput) =>
    setMyProviderDesiredTierServerFn({ data: variables }),
});

export const setMyProviderMachineLabelMutationOptions = mutationOptions({
  mutationFn: (variables: SetMyProviderMachineLabelInput) =>
    setMyProviderMachineLabelServerFn({ data: variables }),
});

export type SetMyProviderShareLocationInput = z.infer<typeof setProviderShareLocationSchema>;
export type SetMyProviderProBonoInput = z.infer<typeof setProviderProBonoSchema>;

export const setMyProviderShareLocationMutationOptions = mutationOptions({
  mutationFn: (variables: SetMyProviderShareLocationInput) =>
    setMyProviderShareLocationServerFn({ data: variables }),
});

export const setMyProviderProBonoMutationOptions = mutationOptions({
  mutationFn: (variables: SetMyProviderProBonoInput) =>
    setMyProviderProBonoServerFn({ data: variables }),
});

export const deleteMyProviderRecordMutationOptions = mutationOptions({
  mutationFn: (variables: DeleteMyProviderInput) =>
    deleteMyProviderRecordServerFn({ data: variables }),
});

export const dedupMyProviderRecordsMutationOptions = mutationOptions({
  mutationFn: () => dedupMyProviderRecordsServerFn(),
});
