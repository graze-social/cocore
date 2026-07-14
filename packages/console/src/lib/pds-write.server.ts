// Shared implementation for the console's PDS-write endpoints.
//
// These are internal HTTP RPCs (NOT XRPC/lexicon methods) that write
// ATProto records to the caller's PDS via the console's OAuth session.
// The callers are *other processes* — the Rust provider agent and the
// exchange — that can't talk to bsky directly: real bsky PDSes require
// DPoP-bound tokens, and the JS OAuth client running in the console is
// the only thing that has DPoP wired up.
//
// The canonical routes are `/api/pds/{create,put,delete}Record`. The
// legacy `/xrpc/dev.cocore.proxy.*` routes are thin deprecated aliases
// that call straight into these functions so already-deployed agents
// keep working. Keep the logic here, not in the route files, so the two
// entry points can never drift.

import type { Did } from "@atcute/lexicons";
import { isDid } from "@atcute/lexicons/syntax";
import { Duration, Effect, Schedule } from "effect";

import { runTraced } from "@/lib/o11y.server.ts";

import {
  lastRestoreError,
  restoreAtprotoSessionEffect,
} from "@/integrations/auth/atproto.server.ts";
import { resolveBearerKey } from "@/lib/api-keys.server.ts";
import { appviewBackedSession } from "@/lib/appview-backed-session.server.ts";
import { forwardPdsWrite, isAppviewForwardConfigured } from "@/lib/appview-pds-forward.server.ts";
import { bridgeHeaders, cocoreConfig } from "@/lib/cocore-config.ts";

/** Collection NSIDs these endpoints will write to a user's PDS. We allow
 *  the full `dev.cocore.*` namespace (compute.* receipts/jobs/etc. AND
 *  account.* profile/grant/friend/patronage records) because the services
 *  container needs to publish account records too — see
 *  infra/services/src/main.ts's `emitTokenGrantRecord` and
 *  `emitPatronageRecords`. A bearer API key still gates the call, so the
 *  worst this can do is scribble cocore-shaped records onto the user's
 *  repo; never anything outside the namespace. */
const COLLECTION_PREFIX = "dev.cocore.";

function rkeyFromUri(uri: string): string {
  const parts = uri.split("/");
  return parts[parts.length - 1] ?? "";
}

/** Best-effort mirror to the local AppView indexer. We don't await the
 *  response — if the bridge is down the PDS record still wins, and the
 *  AppView will eventually catch up via the firehose. */
function mirrorToBridge(args: {
  uri: string;
  cid: string;
  collection: string;
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
      collection: args.collection,
      repo: args.repo,
      rkey: rkeyFromUri(args.uri),
      body: args.record,
    }),
  }).catch(() => {
    // swallowed — this is a cache hint, not a checkpoint
  });
}

function mirrorDeleteToBridge(uri: string): void {
  const bridgeUrl = cocoreConfig().bridgeUrl?.replace(/\/$/, "");
  if (!bridgeUrl) return;
  void fetch(`${bridgeUrl}/xrpc/dev.cocore.bridge.unpublish`, {
    method: "POST",
    headers: bridgeHeaders(),
    body: JSON.stringify({ uri }),
  }).catch(() => {
    // swallowed — AppView eventually catches up via firehose
  });
}

function readBearer(request: Request): string | null {
  const h = request.headers.get("authorization");
  if (!h) return null;
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1]!.trim() : null;
}

function jsonError(status: number, message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function jsonOk(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

/** Resolve the bearer key → the owning DID, or a `Response` describing the
 *  auth failure. This stays on the console (the key store) regardless of
 *  where the write executes. */
function resolveCallerDid(request: Request): { did: Did } | Response {
  const bearer = readBearer(request);
  if (!bearer) return jsonError(401, "missing Authorization: Bearer header");
  const resolved = resolveBearerKey(bearer);
  if (!resolved) return jsonError(401, "invalid API key");
  if (!isDid(resolved.did)) return jsonError(500, "stored DID is malformed");
  return { did: resolved.did as Did };
}

/** Legacy path: restore the console-owned DPoP session for `did`, or a 401.
 *  Used only when AppView forwarding is not configured. */
async function restoreSessionOr401(did: Did) {
  const session = await runTraced("auth.restoreSession", restoreAtprotoSessionEffect(did));
  if (!session) {
    // Keep the restore-failure reason (refresh invalid_grant vs no stored
    // session vs DPoP/keyset mismatch — see atproto.server.ts
    // lastRestoreError) server-side only; leaking DPoP/session-store
    // diagnostics into the 401 body hands an attacker internal detail.
    const reason = lastRestoreError(did) ?? "unknown";
    console.error(`[pds-write] session restore failed for ${did}: ${reason}`);
    return jsonError(401, "underlying ATProto session no longer valid; re-authenticate");
  }
  return session;
}

/** A *thrown* fetch means the AppView was unreachable (connection-level
 *  blip — undici surfaces this as "fetch failed"); most recover within a
 *  second, so a couple of quick retries absorb the blip. An HTTP error
 *  *response* is returned by `forwardPdsWrite`, not thrown, so it never
 *  reaches this path — those are the AppView's structured errors and we
 *  relay them verbatim rather than retrying. Mirrors the read-side schedule
 *  in appview.server.ts. */
const forwardRetrySchedule = Schedule.intersect(
  Schedule.exponential(Duration.millis(250), 2),
  Schedule.recurs(2),
);

/** Undici hides the useful part of a network failure ("fetch failed") behind
 *  `cause`; surface the syscall code (ECONNREFUSED, ETIMEDOUT, ENOTFOUND, …)
 *  so a Railway private-networking outage is diagnosable from the 502 alone. */
function describeFetchError(e: unknown): string {
  const message = e instanceof Error ? e.message : String(e);
  const cause = (e as { cause?: { code?: string; message?: string } }).cause;
  const detail = cause?.code ?? cause?.message;
  return `${message}${detail ? ` (${detail})` : ""}`;
}

/** When AppView forwarding is configured, forward the write and return the
 *  AppView's response verbatim; otherwise null so the caller runs the
 *  legacy console-session path. */
async function forwardOrNull(
  op: "createRecord" | "putRecord" | "deleteRecord",
  body: Record<string, unknown>,
): Promise<Response | null> {
  if (!isAppviewForwardConfigured()) return null;
  // Retry only the connection-level failures (see forwardRetrySchedule); a
  // thrown fetch would otherwise escape the route handler as an opaque 500,
  // so collapse the exhausted case to a legible 502.
  const forwarded = await runTraced(
    `pds.forward.${op}`,
    Effect.tryPromise({
      try: () => forwardPdsWrite(op, body),
      catch: (e) => e,
    }).pipe(Effect.retry(forwardRetrySchedule), Effect.either),
  );
  if (forwarded._tag === "Right") {
    const r = forwarded.right;
    return new Response(await r.text(), {
      status: r.status,
      headers: { "content-type": "application/json" },
    });
  }
  return jsonError(502, `appview ${op} forward failed: ${describeFetchError(forwarded.left)}`);
}

// ---- createRecord ---------------------------------------------------

interface CreateRaw {
  collection?: unknown;
  record?: unknown;
  rkey?: unknown;
}
interface CreateParsed {
  collection: string;
  record: Record<string, unknown>;
  rkey?: string;
}

function parseCreate(raw: CreateRaw): CreateParsed | string {
  if (typeof raw.collection !== "string" || raw.collection.length === 0)
    return "collection required";
  if (!raw.collection.startsWith(COLLECTION_PREFIX)) {
    return `collection must start with ${COLLECTION_PREFIX}`;
  }
  if (typeof raw.record !== "object" || raw.record === null || Array.isArray(raw.record)) {
    return "record must be a non-null object";
  }
  if (raw.rkey !== undefined && typeof raw.rkey !== "string") {
    return "rkey must be a string when provided";
  }
  return {
    collection: raw.collection,
    record: raw.record as Record<string, unknown>,
    ...(typeof raw.rkey === "string" ? { rkey: raw.rkey } : {}),
  };
}

export async function pdsCreateRecord(request: Request): Promise<Response> {
  const caller = resolveCallerDid(request);
  if (caller instanceof Response) return caller;
  const { did } = caller;

  let raw: CreateRaw;
  try {
    raw = (await request.json()) as CreateRaw;
  } catch {
    return jsonError(400, "body must be JSON");
  }
  const parsed = parseCreate(raw);
  if (typeof parsed === "string") return jsonError(400, parsed);

  const fwd = await forwardOrNull("createRecord", {
    did,
    collection: parsed.collection,
    record: parsed.record,
    ...(parsed.rkey ? { rkey: parsed.rkey } : {}),
  });
  if (fwd) return fwd;

  const session = await restoreSessionOr401(did);
  if (session instanceof Response) return session;
  const r = await session.handle(`/xrpc/com.atproto.repo.createRecord`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      repo: did,
      collection: parsed.collection,
      record: parsed.record,
      ...(parsed.rkey ? { rkey: parsed.rkey } : {}),
    }),
  });
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    return jsonError(
      r.status >= 500 ? 502 : r.status,
      `pds createRecord ${parsed.collection}: ${body.slice(0, 300)}`,
    );
  }
  // com.atproto.repo.createRecord returns `commit: { cid, rev }` — the
  // signed repo commit the record landed in. Forward it so the caller
  // (e.g. the provider, writing a receipt) can surface an inclusion
  // pointer into the provider's signed MST without the verifier having
  // to re-fetch the repo.
  const out = (await r.json()) as {
    uri: string;
    cid: string;
    commit?: { cid: string; rev: string };
  };
  // Mirror to the local AppView indexer so /machines, /jobs, and /models
  // see the record with low latency. The relay subscription is the
  // durable path; the bridge dispatch shortens the round-trip.
  mirrorToBridge({
    uri: out.uri,
    cid: out.cid,
    collection: parsed.collection,
    repo: did,
    record: parsed.record,
  });
  return jsonOk({ uri: out.uri, cid: out.cid, commit: out.commit });
}

// ---- putRecord ------------------------------------------------------

interface PutRaw {
  collection?: unknown;
  rkey?: unknown;
  record?: unknown;
  swapRecord?: unknown;
}
interface PutParsed {
  collection: string;
  rkey: string;
  record: Record<string, unknown>;
  swapRecord?: string;
}

function parsePut(raw: PutRaw): PutParsed | string {
  if (typeof raw.collection !== "string" || raw.collection.length === 0)
    return "collection required";
  if (!raw.collection.startsWith(COLLECTION_PREFIX)) {
    return `collection must start with ${COLLECTION_PREFIX}`;
  }
  if (typeof raw.rkey !== "string" || raw.rkey.length === 0) {
    return "rkey required for putRecord (use createRecord for fresh rkeys)";
  }
  if (typeof raw.record !== "object" || raw.record === null || Array.isArray(raw.record)) {
    return "record must be a non-null object";
  }
  if (raw.swapRecord !== undefined && typeof raw.swapRecord !== "string") {
    return "swapRecord must be a string when provided";
  }
  return {
    collection: raw.collection,
    rkey: raw.rkey,
    record: raw.record as Record<string, unknown>,
    ...(typeof raw.swapRecord === "string" ? { swapRecord: raw.swapRecord } : {}),
  };
}

export async function pdsPutRecord(request: Request): Promise<Response> {
  const caller = resolveCallerDid(request);
  if (caller instanceof Response) return caller;
  const { did } = caller;

  let raw: PutRaw;
  try {
    raw = (await request.json()) as PutRaw;
  } catch {
    return jsonError(400, "body must be JSON");
  }
  const parsed = parsePut(raw);
  if (typeof parsed === "string") return jsonError(400, parsed);

  const fwd = await forwardOrNull("putRecord", {
    did,
    collection: parsed.collection,
    rkey: parsed.rkey,
    record: parsed.record,
    ...(parsed.swapRecord ? { swapRecord: parsed.swapRecord } : {}),
  });
  if (fwd) return fwd;

  const session = await restoreSessionOr401(did);
  if (session instanceof Response) return session;
  const r = await session.handle(`/xrpc/com.atproto.repo.putRecord`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      repo: did,
      collection: parsed.collection,
      rkey: parsed.rkey,
      record: parsed.record,
      ...(parsed.swapRecord ? { swapRecord: parsed.swapRecord } : {}),
    }),
  });
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    return jsonError(
      r.status >= 500 ? 502 : r.status,
      `pds putRecord ${parsed.collection}: ${body.slice(0, 300)}`,
    );
  }
  const out = (await r.json()) as { uri: string; cid: string };
  mirrorToBridge({
    uri: out.uri,
    cid: out.cid,
    collection: parsed.collection,
    repo: did,
    record: parsed.record,
  });
  return jsonOk({ uri: out.uri, cid: out.cid });
}

// ---- deleteRecord ---------------------------------------------------

interface DeleteRaw {
  collection?: unknown;
  rkey?: unknown;
  swapRecord?: unknown;
}
interface DeleteParsed {
  collection: string;
  rkey: string;
  swapRecord?: string;
}

function parseDelete(raw: DeleteRaw): DeleteParsed | string {
  if (typeof raw.collection !== "string" || raw.collection.length === 0)
    return "collection required";
  if (!raw.collection.startsWith(COLLECTION_PREFIX)) {
    return `collection must start with ${COLLECTION_PREFIX}`;
  }
  if (typeof raw.rkey !== "string" || raw.rkey.length === 0) return "rkey required";
  if (raw.swapRecord !== undefined && typeof raw.swapRecord !== "string") {
    return "swapRecord must be a string when provided";
  }
  return {
    collection: raw.collection,
    rkey: raw.rkey,
    ...(typeof raw.swapRecord === "string" ? { swapRecord: raw.swapRecord } : {}),
  };
}

export async function pdsDeleteRecord(request: Request): Promise<Response> {
  const caller = resolveCallerDid(request);
  if (caller instanceof Response) return caller;
  const { did } = caller;

  let raw: DeleteRaw;
  try {
    raw = (await request.json()) as DeleteRaw;
  } catch {
    return jsonError(400, "body must be JSON");
  }
  const parsed = parseDelete(raw);
  if (typeof parsed === "string") return jsonError(400, parsed);

  const fwd = await forwardOrNull("deleteRecord", {
    did,
    collection: parsed.collection,
    rkey: parsed.rkey,
    ...(parsed.swapRecord ? { swapRecord: parsed.swapRecord } : {}),
  });
  if (fwd) return fwd;

  const session = await restoreSessionOr401(did);
  if (session instanceof Response) return session;
  const r = await session.handle(`/xrpc/com.atproto.repo.deleteRecord`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      repo: did,
      collection: parsed.collection,
      rkey: parsed.rkey,
      ...(parsed.swapRecord ? { swapRecord: parsed.swapRecord } : {}),
    }),
  });
  // Mirror deletion regardless of PDS outcome: a record that's already
  // gone from PDS is still expected to disappear from the AppView (the
  // goal is "this row vanishes from /machines").
  const uri = `at://${did}/${parsed.collection}/${parsed.rkey}`;
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    // 404 / "InvalidSwap" / "could not locate" all collapse to "the
    // record is already gone" — clear the AppView and return success so
    // the agent's dedup loop can move on.
    if (r.status === 404 || /not.*locate|InvalidSwap|not.*found/i.test(body)) {
      mirrorDeleteToBridge(uri);
      return jsonOk({ uri, alreadyGone: true });
    }
    return jsonError(
      r.status >= 500 ? 502 : r.status,
      `pds deleteRecord ${parsed.collection}: ${body.slice(0, 300)}`,
    );
  }
  mirrorDeleteToBridge(uri);
  return jsonOk({ uri });
}

// ---- getServiceAuth -------------------------------------------------
//
// Mint a short-lived atproto service-auth JWT on the caller's PDS via the
// console's DPoP-bound OAuth session. Bearer-key auth resolves the key → DID,
// and the token is signed by THAT DID's repo key — so a caller can only mint a
// token asserting its own identity (no impersonation surface). The Rust agent
// can't call `com.atproto.server.getServiceAuth` directly (no DPoP), so it
// posts here; the returned `{ token }` is what it puts in its advisor Register
// frame (C1: DID-bound registration) and what the console uses for the advisor
// `/control` call. `aud` is the intended service's DID (the advisor's), `lxm`
// the method NSID the token authorizes.

interface ServiceAuthRaw {
  aud?: unknown;
  lxm?: unknown;
}

export async function pdsGetServiceAuth(request: Request): Promise<Response> {
  const caller = resolveCallerDid(request);
  if (caller instanceof Response) return caller;
  const { did } = caller;

  let raw: ServiceAuthRaw;
  try {
    raw = (await request.json()) as ServiceAuthRaw;
  } catch {
    return jsonError(400, "body must be JSON");
  }
  if (typeof raw.aud !== "string" || raw.aud.length === 0) return jsonError(400, "aud required");
  // `lxm` is optional in the lexicon, but we require it: an unscoped token is
  // usable against any method, and every cocore use mints a method-scoped one.
  if (typeof raw.lxm !== "string" || raw.lxm.length === 0) return jsonError(400, "lxm required");
  const aud = raw.aud;
  const lxm = raw.lxm;

  // SECURITY (H1): this endpoint mints a service-auth JWT signed by the caller's
  // repo key. Without a scope restriction, any holder of a (namespace-scoped)
  // cocore API key could mint a token for an ARBITRARY `aud`/`lxm` — turning the
  // key into a general "act as this DID against any AT-Proto service" oracle
  // (confused deputy). Restrict `lxm` to the cocore namespace: an external
  // service won't honor a `dev.cocore.*` lxm, so a minted token is useless
  // outside cocore, and within cocore it only asserts the caller's own DID for
  // methods it is already entitled to use. Optionally pin `aud` to the
  // configured advisor DID (the only `aud` the provider legitimately needs)
  // as defense-in-depth when it is set.
  if (!lxm.startsWith("dev.cocore.")) {
    return jsonError(403, "lxm must be a dev.cocore.* method");
  }
  const advisorDid = process.env["COCORE_ADVISOR_DID"];
  if (advisorDid && aud !== advisorDid) {
    return jsonError(403, "aud not permitted");
  }

  // Single-owner cutover: when forwarding is configured the AppView OWNS and
  // solely refreshes this DID's session. Minting a service-auth token requires
  // a live PDS call (com.atproto.server.getServiceAuth) — and restoring the
  // session locally here refreshes it, rotating the single-use DPoP refresh
  // token out from under the AppView. The agent re-mints on EVERY advisor
  // registration (~every 14 min), so this un-migrated path was the second
  // refresher that cannibalized the session every few hours (browser logouts +
  // agent 401s + registrationAuthenticated dropping → confidential/Secure off).
  // Replay through the AppView-backed session instead; the AppView's internal
  // proxy allowlists exactly this method (see packages/appview/src/pds/write.ts).
  const session = isAppviewForwardConfigured()
    ? appviewBackedSession(did)
    : await restoreSessionOr401(did);
  if (session instanceof Response) return session;
  const qs = new URLSearchParams({ aud, lxm }).toString();
  let r: Response;
  try {
    r = await session.handle(`/xrpc/com.atproto.server.getServiceAuth?${qs}`, {
      method: "GET",
    });
  } catch (e) {
    // An AppView-backed `.handle()` throws only on an internal-layer failure
    // (AppView unreachable / bad secret) — a transient transport problem, not
    // an upstream PDS status. Surface a 502 so the agent registers without the
    // token this cycle and retries on the next, rather than a 500 stack.
    return jsonError(502, `pds getServiceAuth via appview: ${(e as Error).message.slice(0, 200)}`);
  }
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    return jsonError(r.status >= 500 ? 502 : r.status, `pds getServiceAuth: ${body.slice(0, 300)}`);
  }
  const out = (await r.json()) as { token?: unknown };
  if (typeof out.token !== "string" || out.token.length === 0) {
    return jsonError(502, "pds getServiceAuth returned no token");
  }
  return jsonOk({ token: out.token });
}
