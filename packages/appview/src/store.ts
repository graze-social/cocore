// SQLite store for indexed cocore records.
//
// We index a flattened view of provider/attestation/receipt/settlement
// records keyed by their AT URI + CID. Original record bodies are kept
// as a JSON column so verifyReceipt can re-canonicalize them on demand.
//
// Postgres parity is not done here — the `Store` interface is the seam
// for swapping. M3 ships a Postgres adapter for production deployments.

import Database from "better-sqlite3";
import type { Database as DB } from "better-sqlite3";

/** Pull a record body's `createdAt` (RFC3339 string) if present. Provider
 *  and job records carry one; the provider agent stamps a fresh value on
 *  every (re-)publish, and the console stamps one on every owner edit, so
 *  for those collections `createdAt` is a monotonic "last-published-at"
 *  version we can order conflicting writes by. Records without it (e.g.
 *  receipts, attestations) return null and fall back to last-writer-wins. */
function bodyCreatedAt(body: unknown): string | null {
  if (!body || typeof body !== "object") return null;
  const v = (body as Record<string, unknown>)["createdAt"];
  return typeof v === "string" && v.length > 0 ? v : null;
}

/** Whether an incoming record version is STRICTLY older than the one we
 *  already hold. Compared as parsed instants (not lexicographically) so
 *  producers that serialize `createdAt` at different sub-second precisions
 *  still order correctly. Unparseable timestamps compare as "not older" so
 *  we never silently drop a write we can't reason about. Equal instants are
 *  NOT older — the later arrival still wins, preserving idempotent replay. */
function isStaleVersion(incoming: string, existing: string): boolean {
  const a = Date.parse(incoming);
  const b = Date.parse(existing);
  if (Number.isNaN(a) || Number.isNaN(b)) return false;
  return a < b;
}

export interface IndexedRecord {
  uri: string;
  cid: string;
  collection: string;
  repo: string; // owning DID
  rkey: string;
  body: unknown; // record body (for re-canonicalization)
  indexedAt: string;
}

/** Joined-record shape returned by `Store.listAccounts`. One row per
 *  signed-up DID, with profile fields denormalized so the UI can
 *  render a card without a per-row profile lookup. */
export interface AccountSummary {
  did: string;
  /** Profile-record handle, if the user has published a profile. May
   *  be stale relative to PLC; consumers should treat it as a display
   *  hint, not authoritative. */
  handle: string | null;
  displayName: string | null;
  /** Display URL — either the legacy `avatarUrl` string or null. Blob
   *  refs are NOT resolved here because they need the owning PDS's
   *  base URL; the console resolves them. */
  avatarUrl: string | null;
  /** When the DID's first `dev.cocore.account.tokenGrant` was indexed
   *  — effectively, signup time. */
  joinedAt: string;
  /** Most recent indexed activity of any kind by this DID — profile
   *  edit, job submission, receipt, provider record. Used as the
   *  default sort. */
  lastActivityAt: string;
  /** Number of `dev.cocore.compute.provider` records this DID owns.
   *  Non-zero means they're running an agent; the UI tags those with
   *  a "provider" badge. */
  providerCount: number;
  isProvider: boolean;
}

/** Per-machine row included in `ProfilePagePayload.machines`. Lifts
 *  the fields a profile-page UI cares about out of the provider
 *  record body so the page can render without a per-row decode. */
interface ProfileMachineSummary {
  rkey: string;
  machineLabel: string | null;
  chip: string | null;
  ramGB: number | null;
  supportedModels: string[];
  active: boolean | null;
  createdAt: string | null;
  trustLevel: string | null;
}

/** Last 52 ISO weeks (UTC Monday → Sunday), oldest bucket first.
 *  All counts are derived from AppView `indexed_at` (ingestion time),
 *  not on-chain claim timestamps, unless otherwise noted. */
export interface ProfileWeekSeries {
  /** UTC calendar date (YYYY-MM-DD) of the Monday starting bucket 0. */
  oldestWeekStart: string;
  /** Jobs in this DID's repo (`dev.cocore.compute.job`). */
  jobsDispatched: number[];
  /** Receipts in this DID's repo (provider-published receipts). */
  receiptsServed: number[];
  /** Cumulative count of provider rows indexed through each week end. */
  machinesIndexedCumulative: number[];
  /** Sum of receipt token in+out for receipts indexed that week. */
  tokensIndexed: number[];
  /** New inbound friend records (subject = this DID) indexed that week. */
  trustedByNew: number[];
}

/** Latency summary computed from the most-recent receipts in a group
 *  (a provider's repo, a single model, or the whole network). The
 *  per-receipt latency is `completedAt − startedAt` in milliseconds —
 *  the provider's own signed claim of how long the work took, so the
 *  figure is derived from the source-of-truth records, not a side
 *  metrics store that could drift from them. `null` fields mean "no
 *  usable samples yet". */
export interface LatencyStats {
  /** Number of receipts that contributed a usable latency sample
   *  (capped at the group's sample window, e.g. the last 100). */
  sampleCount: number;
  /** Median (p50) latency in ms over the sampled receipts. */
  p50Ms: number | null;
  /** 95th-percentile latency in ms. */
  p95Ms: number | null;
  /** Mean latency in ms. */
  avgMs: number | null;
  /** The freshest sample's latency in ms (most-recently indexed receipt). */
  lastMs: number | null;
}

/** Network-wide latency rollup returned by `Store.latencyOverview`.
 *  `overall` is computed over the last N receipts across every
 *  provider; `byProvider` / `byModel` keep an independent last-N
 *  window per group so a high-volume machine doesn't crowd out a
 *  low-volume one's samples. */
export interface LatencyOverview {
  generatedAt: string;
  overall: LatencyStats;
  byProvider: Array<{ did: string; stats: LatencyStats }>;
  byModel: Array<{ modelId: string; stats: LatencyStats }>;
}

/** Empty latency stats (no samples). */
function emptyLatencyStats(): LatencyStats {
  return { sampleCount: 0, p50Ms: null, p95Ms: null, avgMs: null, lastMs: null };
}

/** Summarize a list of latency samples ordered newest-first (so
 *  `samples[0]` is the freshest). Percentiles use the
 *  nearest-rank method on a sorted copy; `lastMs` is the freshest. */
function summarizeLatencies(samplesNewestFirst: number[]): LatencyStats {
  const n = samplesNewestFirst.length;
  if (n === 0) return emptyLatencyStats();
  const sorted = [...samplesNewestFirst].sort((a, b) => a - b);
  const pct = (p: number): number => {
    const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
    return sorted[idx]!;
  };
  const sum = samplesNewestFirst.reduce((a, b) => a + b, 0);
  return {
    sampleCount: n,
    p50Ms: pct(50),
    p95Ms: pct(95),
    avgMs: Math.round(sum / n),
    lastMs: samplesNewestFirst[0]!,
  };
}

/** Parse a receipt body (JSON text) into its latency in ms plus its
 *  model id. Returns null when the receipt lacks a usable
 *  startedAt/completedAt pair (malformed, missing, or negative). */
function parseReceiptLatency(body: string): { ms: number; model: string | null } | null {
  let parsed: { startedAt?: unknown; completedAt?: unknown; model?: unknown };
  try {
    parsed = JSON.parse(body) as typeof parsed;
  } catch {
    return null;
  }
  if (typeof parsed.startedAt !== "string" || typeof parsed.completedAt !== "string") return null;
  const start = Date.parse(parsed.startedAt);
  const end = Date.parse(parsed.completedAt);
  if (!Number.isFinite(start) || !Number.isFinite(end)) return null;
  const ms = end - start;
  if (!Number.isFinite(ms) || ms < 0) return null;
  const model = typeof parsed.model === "string" && parsed.model.length > 0 ? parsed.model : null;
  return { ms, model };
}

/** Full payload for the profile page at `/u/$identifier`. One round-
 *  trip carries everything the page needs: account fields, machines,
 *  activity counts, and the inbound-friends count + sample. */
export interface ProfilePagePayload {
  did: string;
  handle: string | null;
  displayName: string | null;
  bio: string | null;
  avatarUrl: string | null;
  joinedAt: string | null;
  lastActivityAt: string | null;
  /** Machines this DID owns (their `dev.cocore.compute.provider`
   *  records). Empty when the DID isn't running any agents. */
  machines: ProfileMachineSummary[];
  /** Number of `dev.cocore.compute.job` + `dev.cocore.compute.receipt`
   *  records on this DID's repo (requester's jobs; provider's receipts). */
  jobCount: number;
  receiptCount: number;
  /** Number of OTHER DIDs that have published a friend record with
   *  this DID as the `subject`. The "X people have trusted you with
   *  work" surface. */
  incomingFriendsCount: number;
  /** Weekly buckets for profile sparklines / heatmap (52 entries). */
  weekSeries: ProfileWeekSeries;
  /** Inference latency over this DID's last (≤100) receipts, derived
   *  from each receipt's `completedAt − startedAt`. */
  latency: LatencyStats;
}

/** Returned by `Store.listIncomingFriends(did)`. One row per friend
 *  record whose `subject` is the queried DID — i.e. people who have
 *  trusted this DID with their work. */
export interface IncomingFriend {
  /** DID of the person who friended me. */
  friender: string;
  /** Denormalized handle from the friend record (display hint). */
  frienderHandle: string | null;
  createdAt: string;
}

/** A single directed trust edge in the friend graph: `friender`
 *  (the repo that holds the `dev.cocore.account.friend` record)
 *  trusts `subject` to run its private jobs. Returned by
 *  `Store.listFriendEdges()` for the network explorer. */
export interface FriendEdge {
  friender: string;
  subject: string;
  createdAt: string;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS records (
  uri TEXT PRIMARY KEY,
  cid TEXT NOT NULL,
  collection TEXT NOT NULL,
  repo TEXT NOT NULL,
  rkey TEXT NOT NULL,
  body TEXT NOT NULL,
  indexed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS records_collection_idx ON records(collection);
CREATE INDEX IF NOT EXISTS records_repo_idx ON records(repo);
-- The hot read is "newest N of a collection": WHERE collection = ?
-- ORDER BY indexed_at DESC LIMIT ? (listByCollection, getReceipts, etc.).
-- With only the collection index SQLite filters then filesorts the whole
-- matching set every request; this composite lets it walk the index in
-- order and stop at LIMIT. Superset of records_collection_idx, but that one
-- is left in place to avoid churn on existing deployments.
CREATE INDEX IF NOT EXISTS records_collection_indexed_idx ON records(collection, indexed_at);

CREATE TABLE IF NOT EXISTS cursor (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
`;

export class Store {
  readonly db: DB;
  private upsertStmt;
  private deleteStmt;
  private getStmt;
  private getByCollectionStmt;
  private existingVersionStmt;
  private guardedUpsertTxn;

  constructor(path: string) {
    this.db = new Database(path);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA);
    this.upsertStmt = this.db.prepare(
      `INSERT INTO records (uri, cid, collection, repo, rkey, body)
       VALUES (@uri, @cid, @collection, @repo, @rkey, @body)
       ON CONFLICT(uri) DO UPDATE SET
         cid = excluded.cid,
         body = excluded.body,
         indexed_at = CURRENT_TIMESTAMP`,
    );
    this.deleteStmt = this.db.prepare(`DELETE FROM records WHERE uri = ?`);
    this.getStmt = this.db.prepare(
      `SELECT uri, cid, collection, repo, rkey, body, indexed_at as indexedAt
       FROM records WHERE uri = ?`,
    );
    this.getByCollectionStmt = this.db.prepare(
      `SELECT uri, cid, collection, repo, rkey, body, indexed_at as indexedAt
       FROM records WHERE collection = ?
       ORDER BY indexed_at DESC LIMIT ?`,
    );
    this.existingVersionStmt = this.db.prepare(
      `SELECT json_extract(body, '$.createdAt') AS createdAt FROM records WHERE uri = ?`,
    );
    // Version-guarded write as ONE atomic step. We compare timestamps in JS
    // (see isStaleVersion) rather than in the SQL `ON CONFLICT … WHERE` clause
    // because the provider agent serializes `createdAt` at sub-millisecond
    // (µs/ns) RFC3339 precision, which SQLite's date functions can't compare
    // reliably (julianday/strftime cap at ms and return NULL on extra digits).
    // Keeping the compare in JS means the read + conditional write straddle two
    // statements, so wrap them in an IMMEDIATE transaction: it takes the write
    // lock up front, so a second writer (a future multi-process AppView sharing
    // this WAL database) can't land between the check and the write and defeat
    // the guard.
    this.guardedUpsertTxn = this.db.transaction(
      (incoming: string, params: Record<string, unknown>) => {
        const row = this.existingVersionStmt.get(params["uri"]) as
          | { createdAt: string | null }
          | undefined;
        const existing = row?.createdAt ?? null;
        if (existing !== null && isStaleVersion(incoming, existing)) return;
        this.upsertStmt.run(params);
      },
    );
  }

  /** Drop the indexed copy of a record. Mirrors a PDS deleteRecord
   *  call so the AppView's dashboards stop showing a record the
   *  user just removed from their repo. Returns true if a row was
   *  deleted. */
  delete(uri: string): boolean {
    const r = this.deleteStmt.run(uri);
    return r.changes > 0;
  }

  /** Hard-delete every row tied to a single DID. "Tied" means:
   *  - the DID owns the record (repo = did), OR
   *  - the record's body references the DID as requester or provider
   *    (e.g. autoresponder receipts referencing the user's job).
   *
   *  Used by the "Wipe my data" affordance on /api-keys. Returns
   *  the number of rows removed. */
  purgeForDid(did: string): number {
    const r = this.db
      .prepare(
        `DELETE FROM records
           WHERE repo = ?
              OR json_extract(body, '$.requester') = ?
              OR json_extract(body, '$.provider') = ?`,
      )
      .run(did, did, did);
    return r.changes;
  }

  /** DIDs the viewer has friended — the `subject` of every
   *  `dev.cocore.account.friend` record in their own repo.
   *
   *  Pulled out so {@link listAccounts} can exclude them with a literal set
   *  instead of a correlated subquery that JSON-parses the viewer's friend
   *  records once per candidate row. Scoped by `repo` + `collection`, both of
   *  which the records table indexes, so this is a small indexed read no
   *  matter how large the directory grows. Rows with a malformed or missing
   *  `subject` are skipped rather than yielding nulls into the filter. */
  listViewerFriendSubjects(viewerDid: string): string[] {
    if (!viewerDid) return [];
    const rows = this.db
      .prepare(
        `SELECT json_extract(body, '$.subject') AS subject
           FROM records
          WHERE repo = ?
            AND collection = 'dev.cocore.account.friend'`,
      )
      .all(viewerDid) as Array<{ subject: unknown }>;
    const out: string[] = [];
    for (const r of rows) {
      if (typeof r.subject === "string" && r.subject.length > 0) out.push(r.subject);
    }
    return out;
  }

  upsert(rec: Omit<IndexedRecord, "indexedAt">): void {
    // Version guard: never let a stale, out-of-order, or replayed ingest
    // clobber a newer record body. The AppView is a cache the dashboard
    // reads, fed by two independent, unordered writers — the console's
    // best-effort bridge mirror (fired the instant an owner edits a setting)
    // and the firehose (which lags and can re-deliver older commits on
    // reconnect/backfill). A blind `INSERT OR REPLACE` here makes the LAST
    // ARRIVAL win regardless of which write is actually newer, so a lagging
    // firehose replay of a pre-edit provider commit silently reverts an
    // owner's just-saved `shareLocation` / `proBono` (and every other
    // owner-set field) in the dashboard even though their PDS — the real
    // source of truth — is correct. Drop the write when the incoming body
    // is strictly older than what we hold; equal/newer still applies, so
    // idempotent replay and legitimate updates are unaffected. Records with
    // no comparable `createdAt` keep the prior last-writer-wins behavior.
    const params = {
      uri: rec.uri,
      cid: rec.cid,
      collection: rec.collection,
      repo: rec.repo,
      rkey: rec.rkey,
      body: JSON.stringify(rec.body),
    };
    const incoming = bodyCreatedAt(rec.body);
    if (incoming === null) {
      // No version to compare — plain last-writer-wins, no read needed.
      this.upsertStmt.run(params);
      return;
    }
    // Versioned record — guard the write atomically (see guardedUpsertTxn).
    this.guardedUpsertTxn.immediate(incoming, params);
  }

  get(uri: string): IndexedRecord | null {
    const row = this.getStmt.get(uri) as
      | (Omit<IndexedRecord, "body"> & { body: string })
      | undefined;
    if (!row) return null;
    return { ...row, body: JSON.parse(row.body) };
  }

  listByCollection(collection: string, limit = 50): IndexedRecord[] {
    const rows = this.getByCollectionStmt.all(collection, limit) as Array<
      Omit<IndexedRecord, "body"> & { body: string }
    >;
    return rows.map((r) => ({ ...r, body: JSON.parse(r.body) }));
  }

  /** Discovery directory used by /friends.
   *
   *  Returns every DID that's left ANY footprint under
   *  `dev.cocore.*` on the AppView — i.e. anyone who has OAuth'd
   *  into the console (the first sign-in callback publishes a
   *  profile record), dispatched a job, run a provider, or
   *  friended someone. Joined with their profile + provider
   *  counts so the UI can render a card without further fan-out.
   *
   *  Why not just tokenGrant: token-grant records are published to
   *  the EXCHANGE's repo (with the recipient DID in body.recipient),
   *  not the recipient's own repo — so grouping by `repo` over
   *  tokenGrants surfaces only the exchange. The right primary
   *  signal is profile records (auto-provisioned on every OAuth
   *  callback via `ensureMyProfile`), unioned with any other
   *  cocore namespace activity to catch power users who use the
   *  API directly without ever loading the console.
   *
   *  Sortable by `recent` (most recent indexed activity of any
   *  kind) or `newest` (first time we saw any cocore record from
   *  this DID — effectively signup time when the profile path
   *  fires).
   *
   *  Pagination: OFFSET-based. The directory turns over slowly and
   *  the page size is small (≤100); a sliding cursor would add
   *  complexity without changing the access pattern. Limit caps at
   *  100 to keep a hot page-load bounded.
   *
   *  Excludes the signed-in viewer's own DID when `viewerDid` is
   *  supplied — there's no value in offering "friend yourself" in
   *  the directory.
   *
   *  `excludeViewerFriends` (with `viewerDid`) omits DIDs the viewer
   *  has already friended (`dev.cocore.account.friend` subject).
   *
   *  `providersOnly` filters down to DIDs that own at least one
   *  `dev.cocore.compute.provider` record — useful for users
   *  who want to friend hardware operators rather than fellow
   *  requesters. */
  listAccounts(
    opts: {
      limit?: number;
      offset?: number;
      sortBy?: "recent" | "newest";
      providersOnly?: boolean;
      viewerDid?: string;
      /** When true with `viewerDid`, omit directory rows whose DID appears as
       *  `subject` on any `dev.cocore.account.friend` record in the viewer's repo
       *  (people you've already friended). */
      excludeViewerFriends?: boolean;
      /** Case-insensitive substring match on profile handle and/or DID (for
       *  directory search / typeahead). Leading `@` is ignored. */
      query?: string;
    } = {},
  ): { accounts: AccountSummary[]; total: number } {
    const limit = Math.min(Math.max(opts.limit ?? 24, 1), 100);
    const offset = Math.max(opts.offset ?? 0, 0);
    const sortBy = opts.sortBy ?? "recent";
    const providersOnly = opts.providersOnly === true;
    const viewerDid = opts.viewerDid ?? "";
    const excludeViewerFriends = opts.excludeViewerFriends === true && viewerDid.length > 0;
    const queryNeedle = opts.query?.trim().replace(/^@/, "").toLowerCase() ?? "";
    const useQueryFilter = queryNeedle.length > 0;

    // We compute the candidate set + ordering in SQL with a CTE so
    // the database does the sort + slice. Profile fields are joined
    // in but `body` is left as a JSON text column — we parse only
    // the fields we need (displayName, avatarUrl, handle) per row,
    // not the whole record.
    //
    // The "recent activity" timestamp considers ALL collections,
    // not just tokenGrant — so a member who hasn't published a
    // profile but has been dispatching jobs is surfaced near the
    // top, while a member who signed up months ago and has been
    // dormant sinks. (We could narrow this to compute records if
    // pure-touch activity proves noisy; flatlining the dormant set
    // by ANY indexed record is the right v1 signal.)
    const orderColumn = sortBy === "newest" ? "m.joinedAt" : "a.lastActivityAt";

    const filterClauses: string[] = [];
    const params: Array<string | number> = [];
    if (viewerDid) {
      filterClauses.push("m.repo != ?");
      params.push(viewerDid);
    }
    if (excludeViewerFriends) {
      // Read the viewer's friend DIDs ONCE, then filter with a literal set.
      //
      // This used to be a correlated `NOT EXISTS` subquery running
      // `json_extract(fr.body, '$.subject')` per candidate row. There is no
      // index on the extracted field, so SQLite re-scanned the viewer's friend
      // records and JSON-parsed each one for every member in the directory —
      // O(members x friends) with a parse per pair. `better-sqlite3` is
      // synchronous, so that pinned the AppView's single event loop for the
      // whole query, and every other request (down to the trivial
      // `session-info` read) queued behind it. Measured on production:
      // listAccounts went from 0.64s to 19.5s purely by adding
      // `excludeViewerFriends=true&viewerDid=...`, and /friends issues four of
      // these concurrently.
      //
      // A viewer's friend list is small and bounded, so one query up front is
      // strictly cheaper than a per-row subquery, and the JSON parsing happens
      // once per friend instead of once per (member, friend) pair.
      const friendDids = this.listViewerFriendSubjects(viewerDid);
      if (friendDids.length > 0) {
        filterClauses.push(`m.repo NOT IN (${friendDids.map(() => "?").join(",")})`);
        params.push(...friendDids);
      }
      // No friends → nothing to exclude, so no clause at all.
    }
    if (providersOnly) {
      filterClauses.push("pc.providerCount > 0");
    }
    if (useQueryFilter) {
      filterClauses.push(
        "(instr(lower(coalesce(json_extract(p.profileBody, '$.handle'), '')), ?) > 0 OR instr(lower(m.repo), ?) > 0)",
      );
      params.push(queryNeedle, queryNeedle);
    }
    const where = filterClauses.length === 0 ? "" : `WHERE ${filterClauses.join(" AND ")}`;

    // Count first — we need the total for "page N of M" UI.
    //
    // The base `members` CTE is the candidate set: every distinct
    // repo that's published ANY dev.cocore.* record. `joinedAt` is
    // their earliest-indexed record, which is signup-time when
    // their first record is a profile (the common case for users
    // who hit the console) or first-activity-time for power users
    // who came in via the API.
    const countSql = `
      WITH members AS (
        SELECT repo, MIN(indexed_at) AS joinedAt
        FROM records WHERE collection LIKE 'dev.cocore.%'
        GROUP BY repo
      ),
      provider_counts AS (
        SELECT repo, COUNT(*) AS providerCount
        FROM records WHERE collection = 'dev.cocore.compute.provider'
        GROUP BY repo
      ),
      profiles AS (
        SELECT repo, body AS profileBody
        FROM records WHERE collection = 'dev.cocore.account.profile'
      )
      SELECT COUNT(*) AS n FROM members m
      LEFT JOIN provider_counts pc USING (repo)
      LEFT JOIN profiles p USING (repo)
      ${where}
    `;
    const total = (this.db.prepare(countSql).get(...params) as { n: number }).n;

    const sql = `
      WITH members AS (
        SELECT repo, MIN(indexed_at) AS joinedAt
        FROM records WHERE collection LIKE 'dev.cocore.%'
        GROUP BY repo
      ),
      activity AS (
        SELECT repo, MAX(indexed_at) AS lastActivityAt
        FROM records
        GROUP BY repo
      ),
      profiles AS (
        SELECT repo, body AS profileBody
        FROM records WHERE collection = 'dev.cocore.account.profile'
      ),
      provider_counts AS (
        SELECT repo, COUNT(*) AS providerCount
        FROM records WHERE collection = 'dev.cocore.compute.provider'
        GROUP BY repo
      )
      SELECT
        m.repo AS did,
        m.joinedAt,
        a.lastActivityAt,
        p.profileBody,
        COALESCE(pc.providerCount, 0) AS providerCount
      FROM members m
      LEFT JOIN activity a USING (repo)
      LEFT JOIN profiles p USING (repo)
      LEFT JOIN provider_counts pc USING (repo)
      ${where}
      ORDER BY ${orderColumn} DESC
      LIMIT ? OFFSET ?
    `;
    const rows = this.db.prepare(sql).all(...params, limit, offset) as Array<{
      did: string;
      joinedAt: string;
      lastActivityAt: string | null;
      profileBody: string | null;
      providerCount: number;
    }>;

    const accounts: AccountSummary[] = rows.map((r) => {
      let handle: string | null = null;
      let displayName: string | null = null;
      let avatarUrl: string | null = null;
      if (r.profileBody) {
        try {
          const profile = JSON.parse(r.profileBody) as {
            handle?: unknown;
            displayName?: unknown;
            avatarUrl?: unknown;
          };
          if (typeof profile.handle === "string" && profile.handle.length > 0) {
            handle = profile.handle;
          }
          if (typeof profile.displayName === "string" && profile.displayName.length > 0) {
            displayName = profile.displayName;
          }
          if (typeof profile.avatarUrl === "string" && profile.avatarUrl.length > 0) {
            avatarUrl = profile.avatarUrl;
          }
        } catch {
          // malformed profile body — fall through with null fields
        }
      }
      return {
        did: r.did,
        handle,
        displayName,
        avatarUrl,
        joinedAt: r.joinedAt,
        lastActivityAt: r.lastActivityAt ?? r.joinedAt,
        providerCount: r.providerCount,
        isProvider: r.providerCount > 0,
      };
    });

    return { accounts, total };
  }

  /** Build the full profile-page payload for a DID. Returns null when
   *  the DID has no cocore footprint at all (no record under their
   *  repo in any `dev.cocore.*` collection). The page route treats
   *  null as a 404. "Joined at" is the earliest indexed record on
   *  the DID's repo — when a user OAuth's into the console for the
   *  first time, `ensureMyProfile` publishes a profile record, and
   *  that record's indexedAt becomes their effective signup time. */
  getProfile(did: string): ProfilePagePayload | null {
    const headRows = this.db
      .prepare(
        `WITH
           membership AS (
             SELECT repo, MIN(indexed_at) AS joinedAt
             FROM records WHERE collection LIKE 'dev.cocore.%' AND repo = ?
             GROUP BY repo
           ),
           activity AS (
             SELECT repo, MAX(indexed_at) AS lastActivityAt
             FROM records WHERE repo = ?
             GROUP BY repo
           ),
           profile AS (
             SELECT repo, body AS profileBody
             FROM records WHERE collection = 'dev.cocore.account.profile' AND repo = ?
             LIMIT 1
           )
         SELECT
           ? AS did,
           g.joinedAt AS joinedAt,
           a.lastActivityAt AS lastActivityAt,
           p.profileBody AS profileBody
         FROM (SELECT 1) one
         LEFT JOIN membership g ON 1=1
         LEFT JOIN activity a ON 1=1
         LEFT JOIN profile p ON 1=1`,
      )
      .all(did, did, did, did) as Array<{
      did: string;
      joinedAt: string | null;
      lastActivityAt: string | null;
      profileBody: string | null;
    }>;

    const head = headRows[0];
    if (!head || (!head.joinedAt && !head.lastActivityAt && !head.profileBody)) {
      return null;
    }

    let handle: string | null = null;
    let displayName: string | null = null;
    let avatarUrl: string | null = null;
    let bio: string | null = null;
    if (head.profileBody) {
      try {
        const profile = JSON.parse(head.profileBody) as {
          handle?: unknown;
          displayName?: unknown;
          avatarUrl?: unknown;
          bio?: unknown;
        };
        if (typeof profile.handle === "string" && profile.handle.length > 0) {
          handle = profile.handle;
        }
        if (typeof profile.displayName === "string" && profile.displayName.length > 0) {
          displayName = profile.displayName;
        }
        if (typeof profile.avatarUrl === "string" && profile.avatarUrl.length > 0) {
          avatarUrl = profile.avatarUrl;
        }
        if (typeof profile.bio === "string" && profile.bio.length > 0) {
          bio = profile.bio;
        }
      } catch {
        // malformed body — fall through with null fields
      }
    }

    const machineRows = this.db
      .prepare(
        `SELECT rkey, body FROM records
         WHERE collection = 'dev.cocore.compute.provider' AND repo = ?
         ORDER BY indexed_at DESC`,
      )
      .all(did) as Array<{ rkey: string; body: string }>;
    const machines: ProfileMachineSummary[] = machineRows.map((row) => {
      let parsed: {
        machineLabel?: unknown;
        chip?: unknown;
        ramGB?: unknown;
        supportedModels?: unknown;
        active?: unknown;
        createdAt?: unknown;
        trustLevel?: unknown;
      } = {};
      try {
        parsed = JSON.parse(row.body) as typeof parsed;
      } catch {
        /* leave defaults */
      }
      return {
        rkey: row.rkey,
        machineLabel:
          typeof parsed.machineLabel === "string" && parsed.machineLabel.length > 0
            ? parsed.machineLabel
            : null,
        chip: typeof parsed.chip === "string" && parsed.chip.length > 0 ? parsed.chip : null,
        ramGB: typeof parsed.ramGB === "number" ? parsed.ramGB : null,
        supportedModels: Array.isArray(parsed.supportedModels)
          ? parsed.supportedModels.filter((m): m is string => typeof m === "string")
          : [],
        active: typeof parsed.active === "boolean" ? parsed.active : null,
        createdAt:
          typeof parsed.createdAt === "string" && parsed.createdAt.length > 0
            ? parsed.createdAt
            : null,
        trustLevel:
          typeof parsed.trustLevel === "string" && parsed.trustLevel.length > 0
            ? parsed.trustLevel
            : null,
      };
    });

    const counts = this.db
      .prepare(
        `SELECT
           SUM(CASE WHEN collection = 'dev.cocore.compute.job' THEN 1 ELSE 0 END) AS jobCount,
           SUM(CASE WHEN collection = 'dev.cocore.compute.receipt' THEN 1 ELSE 0 END) AS receiptCount
         FROM records WHERE repo = ?`,
      )
      .get(did) as { jobCount: number | null; receiptCount: number | null };

    // Count DISTINCT frienders, not raw friend records. Without this,
    // a friender who accidentally published the same friend record N
    // times (race between concurrent "Friend" clicks before the
    // post-write dedup in addFriend landed) would inflate the
    // "Trusted by N" headline. We treat one friender = one trust
    // declaration regardless of how many records they emitted.
    const inbound = this.db
      .prepare(
        `SELECT COUNT(DISTINCT repo) AS n FROM records
         WHERE collection = 'dev.cocore.account.friend'
           AND json_extract(body, '$.subject') = ?`,
      )
      .get(did) as { n: number };

    return {
      did,
      handle,
      displayName,
      bio,
      avatarUrl,
      joinedAt: head.joinedAt,
      lastActivityAt: head.lastActivityAt,
      machines,
      jobCount: counts.jobCount ?? 0,
      receiptCount: counts.receiptCount ?? 0,
      incomingFriendsCount: inbound.n,
      weekSeries: this.buildProfileWeekSeries(did),
      latency: this.getProviderLatency(did),
    };
  }

  /** Latency summary over a single provider's most-recent receipts.
   *  Walks at most `limit` (default 100) of the DID's receipts,
   *  newest-first, and folds each one's `completedAt − startedAt`
   *  into the summary. */
  getProviderLatency(did: string, limit = 100): LatencyStats {
    const cap = Math.max(1, Math.min(limit, 1000));
    const rows = this.db
      .prepare(
        `SELECT body FROM records
         WHERE repo = ? AND collection = 'dev.cocore.compute.receipt'
         ORDER BY indexed_at DESC LIMIT ?`,
      )
      .all(did, cap) as Array<{ body: string }>;
    const samples: number[] = [];
    for (const row of rows) {
      const l = parseReceiptLatency(row.body);
      if (l) samples.push(l.ms);
    }
    return summarizeLatencies(samples);
  }

  /** Network latency rollup for the `latency` AppView endpoint and the
   *  marketing snapshot. `overall` is the last `perGroupLimit` receipts
   *  across the whole network; `byProvider` / `byModel` each keep an
   *  independent last-`perGroupLimit` window so the figures answer
   *  "what's the typical recent latency for this machine / model?"
   *  without one heavy hitter swamping the sample. We scan a bounded
   *  slice of recent receipts (same 5000 cap as `modelActivity`) so a
   *  large index doesn't turn this into a full-table walk. */
  latencyOverview(perGroupLimit = 100): LatencyOverview {
    const rows = this.db
      .prepare(
        `SELECT repo, body FROM records
         WHERE collection = 'dev.cocore.compute.receipt'
         ORDER BY indexed_at DESC LIMIT 5000`,
      )
      .all() as Array<{ repo: string; body: string }>;
    const overall: number[] = [];
    const byProvider = new Map<string, number[]>();
    const byModel = new Map<string, number[]>();
    for (const row of rows) {
      const l = parseReceiptLatency(row.body);
      if (!l) continue;
      if (overall.length < perGroupLimit) overall.push(l.ms);
      let ps = byProvider.get(row.repo);
      if (!ps) {
        ps = [];
        byProvider.set(row.repo, ps);
      }
      if (ps.length < perGroupLimit) ps.push(l.ms);
      if (l.model) {
        let ms = byModel.get(l.model);
        if (!ms) {
          ms = [];
          byModel.set(l.model, ms);
        }
        if (ms.length < perGroupLimit) ms.push(l.ms);
      }
    }
    return {
      generatedAt: new Date().toISOString(),
      overall: summarizeLatencies(overall),
      byProvider: Array.from(byProvider.entries()).map(([did, s]) => ({
        did,
        stats: summarizeLatencies(s),
      })),
      byModel: Array.from(byModel.entries()).map(([modelId, s]) => ({
        modelId,
        stats: summarizeLatencies(s),
      })),
    };
  }

  /** 52 weekly buckets (UTC Monday boundaries) for profile sparklines. */
  private buildProfileWeekSeries(did: string): ProfileWeekSeries {
    const MS_DAY = 86_400_000;
    const MS_WEEK = 7 * MS_DAY;
    const now = Date.now();
    const clock = new Date(now);
    const utcMidnight = Date.UTC(clock.getUTCFullYear(), clock.getUTCMonth(), clock.getUTCDate());
    const dow = clock.getUTCDay();
    const daysFromMonday = (dow + 6) % 7;
    const newestMonday = utcMidnight - daysFromMonday * MS_DAY;
    const oldestMonday = newestMonday - 51 * MS_WEEK;
    const starts = Array.from({ length: 53 }, (_, i) => oldestMonday + i * MS_WEEK);
    const oldestDate = new Date(oldestMonday);
    const pad2 = (n: number) => String(n).padStart(2, "0");
    const oldestWeekStart = `${oldestDate.getUTCFullYear()}-${pad2(oldestDate.getUTCMonth() + 1)}-${pad2(oldestDate.getUTCDate())}`;

    const weekIndex = (iso: string | null | undefined): number => {
      if (!iso) return 0;
      const ts = Date.parse(iso);
      if (!Number.isFinite(ts)) return 0;
      const start0 = starts[0];
      const start52 = starts[52];
      if (start0 === undefined || start52 === undefined) return 0;
      if (ts < start0) return 0;
      if (ts >= start52) return 51;
      for (let i = 0; i < 52; i++) {
        const a = starts[i];
        const b = starts[i + 1];
        if (a === undefined || b === undefined) continue;
        if (ts >= a && ts < b) return i;
      }
      return 51;
    };

    const jobsDispatched = Array.from({ length: 52 }, () => 0);
    const jobRows = this.db
      .prepare(
        `SELECT indexed_at FROM records
         WHERE repo = ? AND collection = 'dev.cocore.compute.job'`,
      )
      .all(did) as Array<{ indexed_at: string }>;
    for (const row of jobRows) {
      const wi = weekIndex(row.indexed_at);
      jobsDispatched[wi] = (jobsDispatched[wi] ?? 0) + 1;
    }

    const receiptsServed = Array.from({ length: 52 }, () => 0);
    const tokensIndexed = Array.from({ length: 52 }, () => 0);
    const receiptRows = this.db
      .prepare(
        `SELECT indexed_at, body FROM records
         WHERE repo = ? AND collection = 'dev.cocore.compute.receipt'`,
      )
      .all(did) as Array<{ indexed_at: string; body: string }>;
    for (const row of receiptRows) {
      const w = weekIndex(row.indexed_at);
      receiptsServed[w] = (receiptsServed[w] ?? 0) + 1;
      let tok = 0;
      try {
        const body = JSON.parse(row.body) as {
          tokens?: { in?: unknown; out?: unknown };
        };
        const tin = body.tokens?.in;
        const tout = body.tokens?.out;
        const a = typeof tin === "number" && Number.isFinite(tin) ? tin : 0;
        const b = typeof tout === "number" && Number.isFinite(tout) ? tout : 0;
        tok = a + b;
      } catch {
        /* ignore */
      }
      tokensIndexed[w] = (tokensIndexed[w] ?? 0) + tok;
    }

    const trustedByNew = Array.from({ length: 52 }, () => 0);
    const friendRows = this.db
      .prepare(
        `SELECT indexed_at FROM records
         WHERE collection = 'dev.cocore.account.friend'
           AND json_extract(body, '$.subject') = ?`,
      )
      .all(did) as Array<{ indexed_at: string }>;
    for (const row of friendRows) {
      const wi = weekIndex(row.indexed_at);
      trustedByNew[wi] = (trustedByNew[wi] ?? 0) + 1;
    }

    const provRows = this.db
      .prepare(
        `SELECT indexed_at FROM records
         WHERE repo = ? AND collection = 'dev.cocore.compute.provider'
         ORDER BY indexed_at ASC`,
      )
      .all(did) as Array<{ indexed_at: string }>;
    const machinesIndexedCumulative = Array.from({ length: 52 }, () => 0);
    let p = 0;
    for (let w = 0; w < 52; w++) {
      const end = starts[w + 1];
      if (end === undefined) break;
      while (p < provRows.length) {
        const ts = Date.parse(provRows[p]!.indexed_at);
        if (!Number.isFinite(ts) || ts >= end) break;
        p += 1;
      }
      machinesIndexedCumulative[w] = p;
    }

    return {
      oldestWeekStart,
      jobsDispatched,
      receiptsServed,
      machinesIndexedCumulative,
      tokensIndexed,
      trustedByNew,
    };
  }

  /** "Who has trusted me with work?" — every distinct friender whose
   *  PDS has a `dev.cocore.account.friend` record naming `did` as
   *  `body.subject`. Capped at `limit` (defaults to 50 — the UI
   *  surface is a sidebar, not a full directory).
   *
   *  Returns one row per friender, even when a friender's PDS
   *  carries multiple records for the same subject (which happens
   *  if their console rapid-fire-double-published before the
   *  post-write dedup in `addFriend` landed). For each friender we
   *  keep the record with the OLDEST `body.createdAt` — that's the
   *  stable "when did this trust start" timestamp regardless of
   *  later re-publishes.
   *
   *  Implementation: fetch all candidate rows, dedup in JS. We
   *  can't dedup purely in SQL because SQLite's CURRENT_TIMESTAMP
   *  has only second-level precision; three records inserted in
   *  the same second share an `indexed_at`, and the only reliable
   *  ordering signal is the `body.createdAt` we extract per row.
   *  The candidate set is bounded — `limit * 3` covers any
   *  pathologically duplicated friender — so the JS pass is cheap. */
  listIncomingFriends(did: string, limit = 50): IncomingFriend[] {
    const cap = Math.max(1, Math.min(limit, 200));
    // Pull more candidates than we need so the JS dedup has room.
    // Even if every friender has 10 dupes, 3x is enough to deliver
    // `cap` distinct frienders post-dedup. The query plan walks the
    // collection index + a hash on body.subject so this is O(matched
    // rows), not O(table).
    const rows = this.db
      .prepare(
        `SELECT repo, body, indexed_at AS indexedAt FROM records
         WHERE collection = 'dev.cocore.account.friend'
           AND json_extract(body, '$.subject') = ?
         ORDER BY indexed_at DESC
         LIMIT ?`,
      )
      .all(did, cap * 3) as Array<{ repo: string; body: string; indexedAt: string }>;
    if (rows.length === 0) return [];

    // Group by friender and keep the OLDEST record per group (by
    // body.createdAt, falling back to indexed_at if the body's
    // createdAt is missing/malformed). The kept row's createdAt is
    // what the UI shows as "friended you on …".
    interface Candidate {
      repo: string;
      body: string;
      createdAt: string;
      indexedAt: string;
    }
    const oldestPerRepo = new Map<string, Candidate>();
    for (const row of rows) {
      let createdAt = row.indexedAt;
      try {
        const parsed = JSON.parse(row.body) as { createdAt?: unknown };
        if (typeof parsed.createdAt === "string" && parsed.createdAt.length > 0) {
          createdAt = parsed.createdAt;
        }
      } catch {
        /* fall through to indexedAt */
      }
      const candidate: Candidate = {
        repo: row.repo,
        body: row.body,
        createdAt,
        indexedAt: row.indexedAt,
      };
      const existing = oldestPerRepo.get(row.repo);
      if (!existing || candidate.createdAt < existing.createdAt) {
        oldestPerRepo.set(row.repo, candidate);
      }
    }

    // Newest-friender-first ordering for the UI: sort by the
    // surviving createdAt descending, then trim to the requested
    // limit.
    const deduped = [...oldestPerRepo.values()].sort((a, b) =>
      a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : 0,
    );
    const ordered = deduped.slice(0, cap);

    const out: IncomingFriend[] = [];
    for (const row of ordered) {
      const createdAt = row.createdAt;
      let frienderHandle: string | null = null;
      try {
        const body = JSON.parse(row.body) as {
          subjectHandle?: unknown;
        };
        // subjectHandle is the friender's denormalization of the
        // SUBJECT's handle (= my handle on their record), not the
        // friender's own handle. We can't recover the friender's
        // handle from their record body — the console resolves it
        // via the AppView profile lookup if needed.
        if (typeof body.subjectHandle === "string" && body.subjectHandle.length > 0) {
          // Intentionally unused here; left in the type for forward
          // compat if we add per-record handle context.
          void body.subjectHandle;
        }
      } catch {
        /* leave defaults */
      }
      out.push({
        friender: row.repo,
        frienderHandle,
        createdAt,
      });
    }
    return out;
  }

  /** Every directed trust edge in the network, for the explorer's
   *  friend graph. One row per `dev.cocore.account.friend` record:
   *  `repo` is the friender, `body.subject` the trusted DID. Deduped
   *  on (friender, subject) keeping the oldest createdAt, mirroring
   *  the console's per-(friender,subject) upsert so a double-click
   *  doesn't draw a doubled edge. `limit` caps raw rows scanned. */
  listFriendEdges(limit = 5000): FriendEdge[] {
    const cap = Math.max(1, Math.min(limit, 20000));
    const rows = this.db
      .prepare(
        `SELECT repo, body, indexed_at AS indexedAt FROM records
         WHERE collection = 'dev.cocore.account.friend'
           AND json_extract(body, '$.subject') IS NOT NULL
         ORDER BY indexed_at DESC
         LIMIT ?`,
      )
      .all(cap) as Array<{ repo: string; body: string; indexedAt: string }>;
    const byPair = new Map<string, FriendEdge>();
    for (const row of rows) {
      let subject: string | null = null;
      let createdAt = row.indexedAt;
      try {
        const body = JSON.parse(row.body) as { subject?: unknown; createdAt?: unknown };
        if (typeof body.subject === "string" && body.subject.startsWith("did:")) {
          subject = body.subject;
        }
        if (typeof body.createdAt === "string" && body.createdAt.length > 0) {
          createdAt = body.createdAt;
        }
      } catch {
        /* skip malformed bodies */
      }
      if (!subject || subject === row.repo) continue; // no self-edges
      const key = `${row.repo} ${subject}`;
      const existing = byPair.get(key);
      if (!existing || createdAt < existing.createdAt) {
        byPair.set(key, { friender: row.repo, subject, createdAt });
      }
    }
    return [...byPair.values()];
  }

  setCursor(k: string, v: string): void {
    this.db
      .prepare(`INSERT INTO cursor (k, v) VALUES (?, ?)
                ON CONFLICT(k) DO UPDATE SET v = excluded.v`)
      .run(k, v);
  }
  getCursor(k: string): string | null {
    const row = this.db.prepare(`SELECT v FROM cursor WHERE k = ?`).get(k) as
      | { v: string }
      | undefined;
    return row?.v ?? null;
  }
}
