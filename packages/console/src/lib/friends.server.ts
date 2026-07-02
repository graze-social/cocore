// `dev.cocore.account.friend` CRUD via the user's PDS.
//
// A "friend" is a one-way trust declaration: the signed-in DID
// vouches that the subject DID is allowed to handle their private
// (friends-only) compute jobs. The subject does not need to
// consent or even know — this is the friender's own routing
// preference, not a permission grant. See the lexicon at
// `lexicons/dev/cocore/account/friend.json` for the wire shape.
//
// Operations exposed here:
//   * listMyFriends — listRecords against my own repo, returns
//     friends in createdAt order (newest first).
//   * addFriend — createRecord with a fresh tid. Pre-checks the
//     existing friend set so re-friending the same DID is a no-op
//     instead of producing a duplicate record.
//   * removeFriend — deleteRecord by rkey.
//   * lookupActor — `app.bsky.actor.getProfile` shim that resolves
//     either a handle or a DID into both (and a display name +
//     avatar URL for UI rendering). Used by the /friends search
//     box; lives here because friending is the only consumer
//     today and inlining keeps the surface small.
//
// Server-only — this module touches the user's OAuth session.

import type { OAuthSession } from "@atcute/oauth-node-client";

import { bridgeHeaders, cocoreConfig } from "@/lib/cocore-config.ts";

const FRIEND_COLLECTION = "dev.cocore.account.friend";

/** Best-effort mirror to the local AppView indexer so the friend
 *  record shows up immediately in the discovery directory + the
 *  subject's profile-page incoming-friends count, without waiting
 *  for the firehose subscription's catch-up cycle. Failure is
 *  silently swallowed — the PDS write has already succeeded and
 *  the relay subscription is the durable path. */
function mirrorFriendToBridge(args: {
  uri: string;
  cid: string;
  repo: string;
  record: Record<string, unknown>;
}): void {
  const bridgeUrl = cocoreConfig().bridgeUrl?.replace(/\/$/, "");
  if (!bridgeUrl) return;
  void fetch(`${bridgeUrl}/xrpc/dev.cocore.bridge.publish`, {
    method: "POST",
    headers: bridgeHeaders(),
    body: JSON.stringify({
      uri: args.uri,
      cid: args.cid,
      collection: FRIEND_COLLECTION,
      repo: args.repo,
      rkey: rkeyFromBridgeUri(args.uri),
      body: args.record,
    }),
  }).catch(() => {
    /* swallowed — AppView catches up via firehose */
  });
}

function mirrorFriendDeleteToBridge(uri: string): void {
  const bridgeUrl = cocoreConfig().bridgeUrl?.replace(/\/$/, "");
  if (!bridgeUrl) return;
  void fetch(`${bridgeUrl}/xrpc/dev.cocore.bridge.unpublish`, {
    method: "POST",
    headers: bridgeHeaders(),
    body: JSON.stringify({ uri }),
  }).catch(() => {});
}

function rkeyFromBridgeUri(uri: string): string {
  const parts = uri.split("/");
  return parts[parts.length - 1] ?? "";
}

export interface CocoreFriend {
  /** The friender's repo holds this record; the friended DID lives
   *  on `subject`. */
  rkey: string;
  subject: string;
  subjectHandle: string | null;
  note: string | null;
  createdAt: string;
}

interface RawFriendRecord {
  subject?: unknown;
  subjectHandle?: unknown;
  note?: unknown;
  createdAt?: unknown;
}

interface ListRecordsResponse {
  records?: Array<{
    uri?: string;
    cid?: string;
    value?: RawFriendRecord;
  }>;
  cursor?: string;
}

// Exported for unit testing — see friends.test.ts. The regex
// trails the at:// URI and picks up the rkey segment after the
// last slash, which matches both record URIs
// (`at://did/coll/rkey`) and is no-op on bare strings.
export function parseRkeyFromUri(uri: string): string | null {
  const m = /\/([^/]+)$/.exec(uri);
  return m ? m[1]! : null;
}

export function rowToFriend(uri: string, value: RawFriendRecord): CocoreFriend | null {
  const rkey = parseRkeyFromUri(uri);
  if (!rkey) return null;
  if (typeof value.subject !== "string" || value.subject.length === 0) return null;
  return {
    rkey,
    subject: value.subject,
    subjectHandle:
      typeof value.subjectHandle === "string" && value.subjectHandle.length > 0
        ? value.subjectHandle
        : null,
    note: typeof value.note === "string" && value.note.length > 0 ? value.note : null,
    createdAt: typeof value.createdAt === "string" ? value.createdAt : "",
  };
}

/** List the current user's friend records. Paginates internally;
 *  callers get the full set in one call. Returns newest-first by
 *  createdAt (with ties broken by rkey, which is a tid so it sorts
 *  monotonically with time anyway). */
export async function listMyFriends(session: OAuthSession): Promise<CocoreFriend[]> {
  const out: CocoreFriend[] = [];
  let cursor: string | undefined;
  // Hard cap on iterations so a buggy PDS can't loop us forever.
  // 50 friends * 10 pages = 500 friends, comfortably above the
  // realistic ceiling for a personal trust list.
  for (let i = 0; i < 10; i += 1) {
    const params = new URLSearchParams({
      repo: session.did,
      collection: FRIEND_COLLECTION,
      limit: "50",
    });
    if (cursor) params.set("cursor", cursor);
    const r = await session.handle(`/xrpc/com.atproto.repo.listRecords?${params}`, {
      method: "GET",
    });
    if (r.status === 404) return [];
    if (!r.ok) {
      const body = await r.text().catch(() => "");
      throw new Error(`listRecords friend returned ${r.status}: ${body.slice(0, 200)}`);
    }
    const body = (await r.json()) as ListRecordsResponse;
    const records = body.records ?? [];
    for (const row of records) {
      if (!row.uri || !row.value) continue;
      const friend = rowToFriend(row.uri, row.value);
      if (friend) out.push(friend);
    }
    cursor = body.cursor;
    if (!cursor || records.length === 0) break;
  }
  // Newest first. createdAt is RFC3339; lexicographic sort works
  // for that format. Fall back to rkey (tid) on ties — tids are
  // also monotonically increasing.
  out.sort((a, b) => {
    if (a.createdAt !== b.createdAt) return a.createdAt < b.createdAt ? 1 : -1;
    return a.rkey < b.rkey ? 1 : -1;
  });
  return out;
}

/** Convenience: just the DIDs, deduped, in arbitrary order. This is
 *  what the private chat-completions endpoint actually needs — the
 *  full friend records are only useful for UI rendering. */
export async function listMyFriendDids(session: OAuthSession): Promise<Set<string>> {
  const friends = await listMyFriends(session);
  return new Set(friends.map((f) => f.subject));
}

export interface AddFriendInputs {
  subject: string;
  subjectHandle?: string | null;
  note?: string | null;
}

export interface AddFriendResult {
  /** Always a friend record at the end of this call. `created`
   *  signals whether we did a write — useful for telling the user
   *  "you've already friended this DID" vs "added." */
  friend: CocoreFriend;
  created: boolean;
}

/** Idempotent. If a record already exists for `subject`, returns it
 *  (no PDS write). Otherwise publishes a fresh record at a tid
 *  rkey, runs a post-write dedup sweep, and returns the surviving
 *  entry.
 *
 *  Two-phase dedup:
 *
 *  1. **Pre-flight check** (cheap, optimistic). One list call;
 *     return the existing record if any. This handles the
 *     common case (user clicks Friend, already friended → no
 *     write).
 *
 *  2. **Post-write reconciliation** (race-safe). After the
 *     `createRecord` succeeds, list AGAIN. If there are multiple
 *     records for the same subject — which happens when two
 *     concurrent Friend clicks both pass step 1 before either has
 *     written — keep the OLDEST and delete the rest. The oldest's
 *     `createdAt` is the stable "trust started here" timestamp;
 *     deleting the newer records keeps the friend-set semantics
 *     clean without losing the original friendship date.
 *
 *  This is the load-bearing dedup. ATProto doesn't give us
 *  `INSERT ... ON CONFLICT` semantics across PDS commits, so we
 *  fix up after the fact instead. The cleanup costs at most one
 *  list + N deletes per call, where N is "how many duplicates
 *  slipped through" — almost always zero. */
export async function addFriend(
  session: OAuthSession,
  inputs: AddFriendInputs,
): Promise<AddFriendResult> {
  if (typeof inputs.subject !== "string" || !inputs.subject.startsWith("did:")) {
    throw new Error("subject must be a DID");
  }
  if (inputs.subject === session.did) {
    throw new Error("you can't friend yourself");
  }
  // Pre-flight: cheap optimistic check. Covers the common case
  // (single click, already a friend).
  const existing = await listMyFriends(session);
  const hit = existing.find((f) => f.subject === inputs.subject);
  if (hit) {
    // Even on the fast path, the user may have ACCUMULATED
    // duplicates from an earlier race — sweep them up so the next
    // page render is clean.
    await dedupeFriendsForSubject(session, inputs.subject, existing);
    return { friend: hit, created: false };
  }

  const now = new Date().toISOString();
  const record: Record<string, unknown> = {
    subject: inputs.subject,
    createdAt: now,
  };
  if (inputs.subjectHandle && inputs.subjectHandle.trim().length > 0) {
    record.subjectHandle = inputs.subjectHandle.trim().slice(0, 256);
  }
  if (inputs.note && inputs.note.trim().length > 0) {
    record.note = inputs.note.trim().slice(0, 1024);
  }

  const r = await session.handle("/xrpc/com.atproto.repo.createRecord", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      repo: session.did,
      collection: FRIEND_COLLECTION,
      record,
    }),
  });
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    if (r.status === 403 && body.includes("ScopeMissingError")) {
      throw new Error(
        "Your sign-in is missing the friend scope. Sign out and back in to re-authorize.",
      );
    }
    throw new Error(`createRecord friend returned ${r.status}: ${body.slice(0, 200)}`);
  }
  const body = (await r.json()) as { uri?: string; cid?: string };
  if (!body.uri) throw new Error("createRecord returned no uri");
  const rkey = parseRkeyFromUri(body.uri);
  if (!rkey) throw new Error("createRecord returned malformed uri");

  // Mirror to the AppView so the discovery directory + subject's
  // profile-page incoming-friends counter reflect this write
  // immediately. Relay-firehose path remains the durable backstop.
  mirrorFriendToBridge({
    uri: body.uri,
    cid: body.cid ?? "",
    repo: session.did,
    record,
  });

  // Post-write reconciliation. If a concurrent call slipped past
  // the pre-flight check, both clients wrote a record. Cleanup
  // collapses them: keep oldest (stable trust-started-at date),
  // delete the rest, return the survivor.
  const survivor = await dedupeFriendsForSubject(session, inputs.subject);
  if (survivor && survivor.rkey !== rkey) {
    // Our just-written record was older than another concurrent
    // one and got nuked → return the survivor. Otherwise our
    // write is the survivor and we return it below.
    return { friend: survivor, created: false };
  }

  return {
    created: true,
    friend: {
      rkey,
      subject: inputs.subject,
      subjectHandle: typeof record.subjectHandle === "string" ? record.subjectHandle : null,
      note: typeof record.note === "string" ? record.note : null,
      createdAt: now,
    },
  };
}

/** Delete every friend record this user has for `subject` except
 *  the oldest one (by createdAt, then rkey as tiebreak). Returns
 *  the surviving record, or null if no records exist for the
 *  subject. Safe to call even when there are no duplicates — the
 *  no-op cost is one list call already paid by the caller, since
 *  we accept a pre-fetched friend set via `prefetched` when
 *  available.
 *
 *  Best-effort: if a delete fails (transient PDS error), we log
 *  via tracing-equivalent and keep going. The caller's user-
 *  visible behavior is unchanged — the AppView's read-time dedup
 *  in listIncomingFriends already collapses duplicates for the
 *  viewer; this just keeps the PDS itself tidy. */
async function dedupeFriendsForSubject(
  session: OAuthSession,
  subject: string,
  prefetched?: CocoreFriend[],
): Promise<CocoreFriend | null> {
  const all = prefetched ?? (await listMyFriends(session));
  const matches = all.filter((f) => f.subject === subject);
  if (matches.length <= 1) return matches[0] ?? null;

  // Sort by createdAt ascending (oldest first), with rkey as a
  // deterministic tiebreak (tids are monotonic so this matches
  // chronological order even when createdAt strings are equal).
  matches.sort((a, b) => {
    if (a.createdAt !== b.createdAt) return a.createdAt < b.createdAt ? -1 : 1;
    return a.rkey < b.rkey ? -1 : 1;
  });
  const [keep, ...trash] = matches;
  for (const dup of trash) {
    try {
      await removeFriend(session, dup.rkey);
    } catch {
      // Swallow per-record cleanup failures. The AppView's read
      // path dedups by friender too, so a stuck-on-PDS duplicate
      // doesn't surface to viewers.
    }
  }
  return keep ?? null;
}

/** Delete a friend record by rkey. Idempotent — a missing record is
 *  treated as success. Returns the rkey that was removed (or would
 *  have been, on a no-op) so callers can pattern-match against UI
 *  state without an extra read. */
export async function removeFriend(session: OAuthSession, rkey: string): Promise<string> {
  if (!rkey || rkey.includes("/")) throw new Error("invalid rkey");
  const r = await session.handle("/xrpc/com.atproto.repo.deleteRecord", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      repo: session.did,
      collection: FRIEND_COLLECTION,
      rkey,
    }),
  });
  if (r.status === 404) return rkey;
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    throw new Error(`deleteRecord friend returned ${r.status}: ${body.slice(0, 200)}`);
  }
  // Mirror the delete so the AppView's directory + incoming-friends
  // counts update immediately. Constructing the URI here from
  // (did, collection, rkey) is fine because the PDS uses the same
  // canonical shape.
  mirrorFriendDeleteToBridge(`at://${session.did}/${FRIEND_COLLECTION}/${rkey}`);
  return rkey;
}

export interface ActorLookup {
  did: string;
  handle: string;
  displayName: string | null;
  avatarUrl: string | null;
}

/** Use bsky profile fields only when `lookup.did` matches `expectedDid`.
 *  Otherwise return null portrait/name and fall back to `fallbackHandle`
 *  for display (typically the handle stored on the friend record). */
export function appviewProfileFieldsForDid(
  lookup: ActorLookup | null,
  expectedDid: string,
  fallbackHandle: string | null,
): { avatarUrl: string | null; displayName: string | null; displayHandle: string | null } {
  if (lookup == null || lookup.did !== expectedDid) {
    return {
      avatarUrl: null,
      displayName: null,
      displayHandle: fallbackHandle,
    };
  }
  return {
    avatarUrl: lookup.avatarUrl,
    displayName: lookup.displayName,
    displayHandle: lookup.handle,
  };
}

/** Resolve a handle (e.g. `alice.bsky.social`) or a DID into the full
 *  identity tuple. Backed by `app.bsky.actor.getProfile`'s public
 *  appview — works without authentication and returns DID + handle
 *  for any indexed account. Returns null on any failure (no such
 *  user, transient network, malformed input) so callers can show a
 *  friendly "not found" message without diagnosing the underlying
 *  cause.
 *
 *  Used by the /friends search box. Trims whitespace and a leading
 *  `@` so the user can paste either `@alice.bsky.social` or just
 *  `alice.bsky.social`. */
export async function lookupActor(input: string): Promise<ActorLookup | null> {
  const cleaned = input.trim().replace(/^@/, "");
  if (cleaned.length === 0) return null;
  // The bsky public appview's getProfile accepts either a handle or
  // a DID via the `actor` query param. We pass through verbatim;
  // any normalization on our side risks breaking did:web identifiers.
  const url = new URL("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile");
  url.searchParams.set("actor", cleaned);
  let res: Response;
  try {
    res = await fetch(url, { headers: { accept: "application/json" } });
  } catch {
    return null;
  }
  if (!res.ok) return null;
  let body: {
    did?: unknown;
    handle?: unknown;
    displayName?: unknown;
    avatar?: unknown;
  };
  try {
    body = (await res.json()) as typeof body;
  } catch {
    return null;
  }
  if (typeof body.did !== "string" || !body.did.startsWith("did:")) return null;
  if (typeof body.handle !== "string" || body.handle.length === 0) return null;
  return {
    did: body.did,
    handle: body.handle,
    displayName:
      typeof body.displayName === "string" && body.displayName.length > 0 ? body.displayName : null,
    avatarUrl: typeof body.avatar === "string" && body.avatar.length > 0 ? body.avatar : null,
  };
}

/** Display identity for one DID, all fields null when unresolved. */
export interface ResolvedActor {
  handle: string | null;
  displayName: string | null;
  avatarUrl: string | null;
}

/** Resolve a set of DIDs to display identity (handle / display name /
 *  avatar) in one deduped, parallel pass via the public bsky appview.
 *  A DID that fails to resolve maps to all-null fields, so callers can
 *  degrade gracefully to showing the raw (or abbreviated) DID. Backed by
 *  {@link lookupActor}; the underlying getProfile is cached upstream, so
 *  repeated dashboard loads don't re-fan-out. */
export async function resolveActorsForDids(
  dids: Iterable<string>,
): Promise<Map<string, ResolvedActor>> {
  const unique = [
    ...new Set([...dids].filter((d): d is string => typeof d === "string" && d.length > 0)),
  ];
  const out = new Map<string, ResolvedActor>();
  await Promise.all(
    unique.map(async (did) => {
      const lookup = await lookupActor(did).catch(() => null);
      const { avatarUrl, displayName, displayHandle } = appviewProfileFieldsForDid(
        lookup,
        did,
        null,
      );
      out.set(did, { handle: displayHandle, displayName, avatarUrl });
    }),
  );
  return out;
}
