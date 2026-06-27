import type { OAuthSession } from "@atcute/oauth-node-client";

import { cocoreConfig } from "@/lib/cocore-config.ts";
import {
  type CasRecordStore,
  isRecordNotFound,
  transactRecord,
} from "@/lib/record-transactor.server.ts";

const PROVIDER_COLLECTION = "dev.cocore.compute.provider";

/** Best-effort mirror to the local AppView indexer so a delete on
 *  PDS also clears the row that backs /machines. Same shape as the
 *  proxy createRecord's mirror. */
function mirrorDeleteToBridge(uri: string): void {
  const bridgeUrl = cocoreConfig().bridgeUrl?.replace(/\/$/, "");
  if (!bridgeUrl) return;
  void fetch(`${bridgeUrl}/xrpc/dev.cocore.bridge.unpublish`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ uri }),
  }).catch(() => {
    // swallowed — the AppView will eventually catch up via firehose
  });
}

/** Best-effort mirror of an OAuth-driven putRecord into the AppView's
 *  index. The console writes provider-record edits (active /
 *  payoutsEnabled) directly to the user's PDS via OAuth — the bridge
 *  + AppView don't see those PDS writes on their own (we have no real
 *  firehose subscription in this stack), so the AppView's `/machines`
 *  + `/eligibility` views stay stuck on the previous version. Mirror
 *  the new record body to `dev.cocore.bridge.publish` so the indexer
 *  picks it up immediately. Same swallow-errors-on-failure pattern as
 *  the proxy endpoints. */
function mirrorPutToBridge(args: {
  did: string;
  rkey: string;
  cid: string;
  record: Record<string, unknown>;
}): void {
  const bridgeUrl = cocoreConfig().bridgeUrl?.replace(/\/$/, "");
  if (!bridgeUrl) return;
  const uri = `at://${args.did}/${PROVIDER_COLLECTION}/${args.rkey}`;
  void fetch(`${bridgeUrl}/xrpc/dev.cocore.bridge.publish`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      uri,
      cid: args.cid,
      collection: PROVIDER_COLLECTION,
      repo: args.did,
      rkey: args.rkey,
      body: args.record,
    }),
  }).catch(() => {
    // swallowed — the AppView is a cache, not a checkpoint
  });
}

async function readPdsError(res: Response): Promise<string> {
  const text = await res.text();
  try {
    const j = JSON.parse(text) as { error?: string; message?: string };
    if (j.message) return j.message;
    if (j.error) return j.error;
  } catch {
    /* ignore */
  }
  return text.slice(0, 400) || `HTTP ${res.status}`;
}

export async function getMyProviderRecord(
  session: OAuthSession,
  rkey: string,
): Promise<{ cid: string; value: Record<string, unknown> }> {
  const params = new URLSearchParams({
    repo: session.did,
    collection: PROVIDER_COLLECTION,
    rkey,
  });
  const res = await session.handle(`/xrpc/com.atproto.repo.getRecord?${params}`, { method: "GET" });
  if (!res.ok) {
    const err = await readPdsError(res);
    throw new Error(
      res.status === 401 || res.status === 403 ? `${err} · try signing out and back in` : err,
    );
  }
  const body = (await res.json()) as { cid?: string; value?: unknown };
  if (!body.cid || !body.value || typeof body.value !== "object" || body.value === null) {
    throw new Error("Unexpected getRecord response from PDS");
  }
  return { cid: body.cid, value: body.value as Record<string, unknown> };
}

/** Raw `com.atproto.repo.putRecord` over the OAuth session: write `record` at
 *  `rkey`, optionally guarded by `swapRecord` (the CID it was read at — the
 *  compare-and-swap token). Returns the committed CID. Does NOT stamp
 *  `createdAt` or mirror — those are the transactor's job, so there's exactly
 *  one place that owns the read-modify-write semantics. */
async function rawPutProviderRecord(
  session: OAuthSession,
  rkey: string,
  record: Record<string, unknown>,
  swapRecord: string | null,
): Promise<{ cid: string }> {
  const res = await session.handle(`/xrpc/com.atproto.repo.putRecord`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      repo: session.did,
      collection: PROVIDER_COLLECTION,
      rkey,
      record,
      ...(swapRecord ? { swapRecord } : {}),
    }),
  });
  if (!res.ok) {
    const err = await readPdsError(res);
    throw new Error(
      res.status === 401 || res.status === 403 ? `${err} · try signing out and back in` : err,
    );
  }
  const body = (await res.json().catch(() => ({}))) as { cid?: string };
  return { cid: body?.cid ?? "" };
}

/** The PDS-backed CAS store the transactor drives for provider records. `read`
 *  maps a genuine 404 to `null` (so `createIfMissing` can create) while
 *  rethrowing transport/auth blips (so the transaction aborts rather than
 *  fabricating a record); `write` performs the swap-guarded put and fires the
 *  best-effort bridge mirror so the AppView index reflects the new body
 *  immediately. */
function providerRecordStore(session: OAuthSession): CasRecordStore {
  return {
    async read(rkey) {
      try {
        return await getMyProviderRecord(session, rkey);
      } catch (err) {
        if (isRecordNotFound(err)) return null;
        throw err;
      }
    },
    async write(rkey, value, swapRecord) {
      const { cid } = await rawPutProviderRecord(session, rkey, value, swapRecord);
      if (cid) mirrorPutToBridge({ did: session.did, rkey, cid, record: value });
      return { cid };
    },
  };
}

/** Mutate this machine's provider record through the single CAS transactor:
 *  read the latest record, apply `patch` (which sets only the owner-intent
 *  field(s) it owns and leaves everything else — including agent-authored and
 *  unknown fields — untouched), bump the monotonic `createdAt`, and putRecord
 *  with a swap guard, retrying on `InvalidSwap`. A failed read aborts without
 *  writing. This is what every `setProviderRecord*` runs on. */
async function transactProviderRecord(
  session: OAuthSession,
  rkey: string,
  patch: (current: Record<string, unknown>) => Record<string, unknown>,
): Promise<void> {
  await transactRecord(providerRecordStore(session), rkey, patch, { stampCreatedAt: true });
}

export async function setProviderRecordActive(
  session: OAuthSession,
  rkey: string,
  active: boolean,
): Promise<void> {
  await transactProviderRecord(session, rkey, (value) => ({ ...value, active }));
}

/** Opt a machine into (or out of) the confidential tier by writing
 *  `desiredTier` onto its provider record — the owner's INTENT. The agent reads
 *  it, reconciles toward it (the measured native engine + hardware-attested
 *  posture), and only publishes the higher ACHIEVED `tier`/`trustLevel` once it
 *  actually earns them. Writing `attested-confidential` NEVER fakes the achieved
 *  state. `best-effort` (or any non-confidential value) DELETES the key, opting
 *  the machine back out — it then serves exactly as before. Same
 *  get→put-with-swap→bridge-mirror path as {@link setProviderRecordActive}. */
export async function setProviderRecordDesiredTier(
  session: OAuthSession,
  rkey: string,
  tier: "attested-confidential" | "best-effort",
): Promise<void> {
  await transactProviderRecord(session, rkey, (value) => {
    const next = { ...value };
    if (tier === "attested-confidential") {
      next["desiredTier"] = tier;
    } else {
      delete next["desiredTier"];
    }
    return next;
  });
}

/** Pin the set of models a machine serves by writing `desiredModels` onto
 *  its provider record. The agent reads/reconciles this field and (re)loads
 *  the listed models. An empty selection DELETES the key, reverting the
 *  machine to its own local default model config. Trims, dedupes, and drops
 *  empty entries before writing. Same get→put-with-swap→bridge-mirror path
 *  as {@link setProviderRecordActive}. */
export async function setProviderRecordDesiredModels(
  session: OAuthSession,
  rkey: string,
  models: string[],
): Promise<void> {
  const cleaned: string[] = [];
  const seen = new Set<string>();
  for (const m of models) {
    const trimmed = m.trim();
    if (trimmed.length === 0 || seen.has(trimmed)) continue;
    seen.add(trimmed);
    cleaned.push(trimmed);
  }
  await transactProviderRecord(session, rkey, (value) => {
    const next = { ...value };
    if (cleaned.length > 0) {
      next["desiredModels"] = cleaned;
    } else {
      delete next["desiredModels"];
    }
    return next;
  });
}

/** Opt a machine into (or out of) publishing its coarse country by writing
 *  the owner-INTENT `shareLocation` switch onto its provider record. The agent
 *  reads this off its own record at serve start: when `true` it resolves the
 *  machine's country from its public IP and stamps `region` (refreshed every
 *  serve); when off it omits the region fields, so the next re-publish drops
 *  any previously-shared value. `false` DELETES the key (absent ≡ off), keeping
 *  the record minimal. Same get→put-with-swap→bridge-mirror path as
 *  {@link setProviderRecordActive}. */
export async function setProviderRecordShareLocation(
  session: OAuthSession,
  rkey: string,
  share: boolean,
): Promise<void> {
  await transactProviderRecord(session, rkey, (value) => {
    const next = { ...value };
    if (share) {
      next["shareLocation"] = true;
    } else {
      delete next["shareLocation"];
    }
    return next;
  });
}

/** The owner's pro-bono election for a machine, mirroring the lexicon
 *  `dev.cocore.compute.provider#proBonoPolicy`. `null` clears the policy. */
export type ProBonoPolicyInput = { mode: "any" | "direct"; dids?: string[] } | null;

/** Set (or clear) a machine's pro-bono policy by writing `proBono` onto its
 *  provider record — the owner's INTENT, like `desiredModels`/`desiredTier`.
 *  The agent reconciles toward it: a matching requester is served free
 *  (`proBono: true`, zero price, zero tokens; the exchange takes no cut).
 *  `null` (or `mode` neither `any`/`direct`) DELETES the key, turning pro bono
 *  off so the machine bills every job again. Under `direct`, `dids` is trimmed,
 *  deduped, and emptied of blanks — an empty list means "serve no one pro bono
 *  yet" (the safe default for a half-configured policy). Same
 *  get→put-with-swap→bridge-mirror path as {@link setProviderRecordActive}. */
export async function setProviderRecordProBono(
  session: OAuthSession,
  rkey: string,
  policy: ProBonoPolicyInput,
): Promise<void> {
  await transactProviderRecord(session, rkey, (value) => {
    const next = { ...value };
    if (policy && (policy.mode === "any" || policy.mode === "direct")) {
      if (policy.mode === "direct") {
        const cleaned: string[] = [];
        const seen = new Set<string>();
        for (const d of policy.dids ?? []) {
          const trimmed = d.trim();
          if (trimmed.length === 0 || seen.has(trimmed)) continue;
          seen.add(trimmed);
          cleaned.push(trimmed);
        }
        next["proBono"] = { mode: "direct", ...(cleaned.length > 0 ? { dids: cleaned } : {}) };
      } else {
        next["proBono"] = { mode: "any" };
      }
    } else {
      delete next["proBono"];
    }
    return next;
  });
}

/** Rename a machine by writing `machineLabel` onto its provider record.
 *  The console writes the field directly; the agent normally sets it from
 *  `COCORE_MACHINE_LABEL`, but the record's `machineLabel` is the value the
 *  dashboard reads for a machine's alias. Requires a non-empty label (trims
 *  surrounding whitespace) — we never clear the field, since an empty label
 *  would just fall the row back to the bare rkey. Same
 *  get→spread→put-with-swap→bridge-mirror path as
 *  {@link setProviderRecordActive}. */
export async function setProviderRecordMachineLabel(
  session: OAuthSession,
  rkey: string,
  label: string,
): Promise<void> {
  const trimmed = label.trim();
  if (trimmed.length === 0) {
    throw new Error("Machine name cannot be empty");
  }
  await transactProviderRecord(session, rkey, (value) => ({ ...value, machineLabel: trimmed }));
}

interface ListRecordsResponse {
  records: Array<{ uri: string; cid: string; value: unknown }>;
  cursor?: string;
}

/** Page through every provider record the signed-in DID owns. Used
 *  internally by {@link dedupMyProviderRecords}; no external callers
 *  under closed-loop (the per-machine payouts-flip path is gone). */
async function listMyProviderRecords(
  session: OAuthSession,
): Promise<Array<{ rkey: string; cid: string; value: Record<string, unknown> }>> {
  const out: Array<{ rkey: string; cid: string; value: Record<string, unknown> }> = [];
  let cursor: string | undefined;
  for (let i = 0; i < 100; i += 1) {
    // Hard cap: 100 pages * default page size (typically 50) = 5000
    // records. If a single user has more than that we have a
    // bigger problem than this loop.
    const params = new URLSearchParams({
      repo: session.did,
      collection: PROVIDER_COLLECTION,
      limit: "100",
    });
    if (cursor) params.set("cursor", cursor);
    const res = await session.handle(`/xrpc/com.atproto.repo.listRecords?${params}`, {
      method: "GET",
    });
    if (!res.ok) {
      const err = await readPdsError(res);
      throw new Error(
        res.status === 401 || res.status === 403 ? `${err} · try signing out and back in` : err,
      );
    }
    const body = (await res.json()) as ListRecordsResponse;
    for (const r of body.records) {
      if (!r.value || typeof r.value !== "object") continue;
      const rkey = r.uri.slice(r.uri.lastIndexOf("/") + 1);
      out.push({ rkey, cid: r.cid, value: r.value as Record<string, unknown> });
    }
    if (!body.cursor || body.records.length === 0) break;
    cursor = body.cursor;
  }
  return out;
}

export interface DedupResult {
  /** Total provider records the DID owned at start. */
  totalBefore: number;
  /** rkeys we kept (one per unique attestationPubKey, plus any
   *  records that didn't carry an attestationPubKey at all). */
  kept: string[];
  /** rkeys we deleted as duplicates. */
  deleted: string[];
  /** Errors from the deleteRecord PDS calls, surfaced for operator
   *  review. The function continues past individual failures —
   *  partial cleanup is better than none. */
  errors: Array<{ rkey: string; message: string }>;
}

/** Group key for "the same machine". We key on `machineLabel` (the
 *  host's name) FIRST, not `attestationPubKey`: a Mac that's been
 *  uninstalled-and-reinstalled regenerates its software signing key, so
 *  every reinstall publishes a record with a NEW attestationPubKey.
 *  Grouping on the key alone therefore never collapses reinstall
 *  duplicates — which is the exact pile this cleanup exists to remove.
 *  Falls back to the key when there's no label, and returns null (keep
 *  as-is) when a record carries neither.
 *
 *  Note this is intentionally only in the USER-INVOKED console cleanup —
 *  the agent's own automatic dedup stays conservative (key-only) so a
 *  background serve never deletes a record it can't prove is its own. */
function sameMachineGroupKey(value: Record<string, unknown>): string | null {
  const label = value["machineLabel"];
  if (typeof label === "string" && label.length > 0) return `label:${label}`;
  const key = value["attestationPubKey"];
  if (typeof key === "string" && key.length > 0) return `key:${key}`;
  return null;
}

/** De-duplicate provider records owned by `session.did`. Records that
 *  describe the same machine (see {@link sameMachineGroupKey}) collapse
 *  to the one with the most recent `createdAt` (string compare on RFC3339
 *  is monotonic — the newest is the current install); the rest are
 *  deleted. Records with no machineLabel and no attestationPubKey are
 *  kept as-is.
 *
 *  This is a one-shot, user-invoked cleanup from the /machines dashboard.
 *  The prevention story (a stable per-machine id so reinstalls upsert
 *  instead of duplicating) is a separate, provider-side change. */
export async function dedupMyProviderRecords(session: OAuthSession): Promise<DedupResult> {
  const all = await listMyProviderRecords(session);
  const totalBefore = all.length;
  const groups = new Map<string, Array<{ rkey: string; cid: string; createdAt: string }>>();
  const kept: string[] = [];

  for (const r of all) {
    const gk = sameMachineGroupKey(r.value);
    if (gk === null) {
      // No identity hint at all; keep as-is.
      kept.push(r.rkey);
      continue;
    }
    const createdAt =
      typeof r.value["createdAt"] === "string" ? (r.value["createdAt"] as string) : "";
    const list = groups.get(gk) ?? [];
    list.push({ rkey: r.rkey, cid: r.cid, createdAt });
    groups.set(gk, list);
  }

  const deleted: string[] = [];
  const errors: Array<{ rkey: string; message: string }> = [];

  for (const list of groups.values()) {
    // Sort newest-first by createdAt; first wins. Empty createdAt
    // sorts last (lexicographic) so any timestamped record beats a
    // legacy unstamped one.
    list.sort((a, b) => (b.createdAt > a.createdAt ? 1 : b.createdAt < a.createdAt ? -1 : 0));
    const [winner, ...losers] = list;
    if (!winner) continue;
    kept.push(winner.rkey);
    for (const l of losers) {
      try {
        await deleteMyProviderRecord(session, l.rkey, l.cid);
        deleted.push(l.rkey);
      } catch (e) {
        errors.push({ rkey: l.rkey, message: e instanceof Error ? e.message : String(e) });
      }
    }
  }

  return { totalBefore, kept, deleted, errors };
}

export async function deleteMyProviderRecord(
  session: OAuthSession,
  rkey: string,
  // Optional concurrency guard. Omitted when the caller couldn't read the
  // record's CID (e.g. it's already gone from PDS but a stale AppView row
  // remains) — a swap-less delete still removes it, and a "not found" is
  // handled idempotently below.
  swapRecord?: string,
): Promise<void> {
  const uri = `at://${session.did}/${PROVIDER_COLLECTION}/${rkey}`;
  const res = await session.handle(`/xrpc/com.atproto.repo.deleteRecord`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      repo: session.did,
      collection: PROVIDER_COLLECTION,
      rkey,
      ...(swapRecord ? { swapRecord } : {}),
    }),
  });
  // Always clear the AppView mirror — the goal is "this row vanishes
  // from the dashboard". If PDS already doesn't have the record (a
  // previous Unpair partly succeeded, or the user wiped their PDS
  // out-of-band) the AppView still has a stale row that the user
  // actively wants gone.
  if (!res.ok) {
    const err = await readPdsError(res);
    if (res.status === 404 || /not.*locate|InvalidSwap|not.*found/i.test(err)) {
      // Record is already gone from PDS — clear the AppView and
      // surface success rather than a confusing error.
      mirrorDeleteToBridge(uri);
      return;
    }
    throw new Error(
      res.status === 401 || res.status === 403 ? `${err} · try signing out and back in` : err,
    );
  }
  mirrorDeleteToBridge(uri);
}
