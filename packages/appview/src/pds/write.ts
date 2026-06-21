// AppView PDS-write endpoints.
//
// Internal HTTP RPCs (NOT XRPC/lexicon methods) that write ATProto
// records to a user's PDS via a DPoP-bound OAuth session the AppView
// owns. Two auth modes share the exact same write core:
//
//   * /pds/{create,put,delete}Record — bearer API key (cocore-...). The
//     key resolves to a DID against the AppView's AccountStore. Used by
//     callers that hold an AppView-minted key directly.
//
//   * /internal/pds/{create,put,delete}Record — internal shared secret +
//     an asserted `did` in the body. Used by the console, which resolves
//     its own bearer key -> DID and forwards the write here so the
//     OAuth/DPoP session work (and its single-writer refresh) lives only
//     in the AppView. This is how existing console-minted keys keep
//     working with zero customer churn: the console stays the key store,
//     the AppView owns the write. /internal/* is private-network only.
//
// Only `dev.cocore.*` collections are writable.
//
// These are an @effect/platform HttpRouter: each route is an Effect that
// returns an HttpServerResponse. `buildPdsRouter` exposes the CANONICAL
// `/pds/*` paths and the parent re-adds the `/api/*` alias via
// `HttpRouter.prefixAll`. `buildProxyAliasRouter` exposes the DEPRECATED
// legacy `dev.cocore.proxy.*` XRPC paths (same bearer auth, same write
// cores) so agents built before the `/api/pds/*` cutover keep writing
// while they upgrade — see its doc comment. Because this is a write
// proxy, every distinct error path is preserved exactly: 401 (bad bearer
// / dead session), 400 (bad body / args / missing did), 403 (bad internal
// secret), and the upstream PDS status passed through (5xx collapsed to 502).

import type { Did } from "@atcute/lexicons";
import { timingSafeEqual } from "node:crypto";
import { HttpRouter, HttpServerRequest, type HttpServerResponse } from "@effect/platform";
import { Effect } from "effect";

import type { AccountStore } from "../operational/account-store.ts";
import {
  type AppviewOAuthClient,
  type RestoredSession,
  restoreSession,
} from "../auth/oauth-client.ts";
import { bearer, err, header, jsonBody, ok } from "../api/http-app.ts";

const COLLECTION_PREFIX = "dev.cocore.";

export interface PdsWriteContext {
  accounts: AccountStore;
  oauth: AppviewOAuthClient;
  /** Bridge base URL for the best-effort AppView-cache mirror. When unset,
   *  writes still land on the PDS and the firehose catches up. */
  bridgeUrl?: string;
}

// ---- small helpers --------------------------------------------------

/** True when the request method is anything other than POST. All write
 *  routes are POST-only; the old hand-rolled `post()` wrapper returned 405
 *  for everything else and a test still asserts that, so the routes mount
 *  via `HttpRouter.all` and guard on this. */
const methodNotPost = Effect.map(
  HttpServerRequest.HttpServerRequest,
  (req) => req.method !== "POST",
);

function secretEquals(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

function rkeyFromUri(uri: string): string {
  const parts = uri.split("/");
  return parts[parts.length - 1] ?? "";
}

function mirrorPublish(
  bridgeUrl: string | undefined,
  args: {
    uri: string;
    cid: string;
    collection: string;
    repo: string;
    record: Record<string, unknown>;
  },
): void {
  if (!bridgeUrl) return;
  void fetch(`${bridgeUrl.replace(/\/$/, "")}/xrpc/dev.cocore.bridge.publish`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      uri: args.uri,
      cid: args.cid,
      collection: args.collection,
      repo: args.repo,
      rkey: rkeyFromUri(args.uri),
      body: args.record,
    }),
  }).catch(() => {
    /* swallowed — cache hint, not a checkpoint */
  });
}

function mirrorUnpublish(bridgeUrl: string | undefined, uri: string): void {
  if (!bridgeUrl) return;
  void fetch(`${bridgeUrl.replace(/\/$/, "")}/xrpc/dev.cocore.bridge.unpublish`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ uri }),
  }).catch(() => {
    /* swallowed — firehose catches up */
  });
}

function isAllowedCollection(c: unknown): c is string {
  return typeof c === "string" && c.startsWith(COLLECTION_PREFIX);
}

// ---- body validation (shared by both auth modes) --------------------

interface CreateArgs {
  collection: string;
  record: Record<string, unknown>;
  rkey?: string;
}
interface PutArgs {
  collection: string;
  rkey: string;
  record: Record<string, unknown>;
  swapRecord?: string;
}
interface DeleteArgs {
  collection: string;
  rkey: string;
  swapRecord?: string;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function parseCreate(b: Record<string, unknown>): CreateArgs | string {
  if (!isAllowedCollection(b.collection)) return `collection must start with ${COLLECTION_PREFIX}`;
  if (!isRecord(b.record)) return "record must be a non-null object";
  if (b.rkey !== undefined && typeof b.rkey !== "string")
    return "rkey must be a string when provided";
  return {
    collection: b.collection,
    record: b.record,
    ...(typeof b.rkey === "string" ? { rkey: b.rkey } : {}),
  };
}

function parsePut(b: Record<string, unknown>): PutArgs | string {
  if (!isAllowedCollection(b.collection)) return `collection must start with ${COLLECTION_PREFIX}`;
  if (typeof b.rkey !== "string" || b.rkey.length === 0)
    return "rkey required (use createRecord for fresh rkeys)";
  if (!isRecord(b.record)) return "record must be a non-null object";
  if (b.swapRecord !== undefined && typeof b.swapRecord !== "string")
    return "swapRecord must be a string when provided";
  return {
    collection: b.collection,
    rkey: b.rkey,
    record: b.record,
    ...(typeof b.swapRecord === "string" ? { swapRecord: b.swapRecord } : {}),
  };
}

function parseDelete(b: Record<string, unknown>): DeleteArgs | string {
  if (!isAllowedCollection(b.collection)) return `collection must start with ${COLLECTION_PREFIX}`;
  if (typeof b.rkey !== "string" || b.rkey.length === 0) return "rkey required";
  if (b.swapRecord !== undefined && typeof b.swapRecord !== "string")
    return "swapRecord must be a string when provided";
  return {
    collection: b.collection,
    rkey: b.rkey,
    ...(typeof b.swapRecord === "string" ? { swapRecord: b.swapRecord } : {}),
  };
}

// ---- write cores (given an authenticated DID + session) -------------
//
// Each returns the HttpServerResponse to send. The upstream PDS status is
// passed through verbatim (5xx collapsed to 502) via `err`, matching the
// previous `json(res, ...)` passthrough byte-for-byte.

async function doCreate(
  ctx: PdsWriteContext,
  did: string,
  session: RestoredSession,
  a: CreateArgs,
): Promise<HttpServerResponse.HttpServerResponse> {
  const r = await session.handle(`/xrpc/com.atproto.repo.createRecord`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      repo: did,
      collection: a.collection,
      record: a.record,
      ...(a.rkey ? { rkey: a.rkey } : {}),
    }),
  });
  if (!r.ok) {
    const text = await r.text().catch(() => "");
    return err(r.status >= 500 ? 502 : r.status, {
      error: "PdsError",
      message: `createRecord ${a.collection}: ${text.slice(0, 300)}`,
    });
  }
  const out = (await r.json()) as {
    uri: string;
    cid: string;
    commit?: { cid: string; rev: string };
  };
  mirrorPublish(ctx.bridgeUrl, {
    uri: out.uri,
    cid: out.cid,
    collection: a.collection,
    repo: did,
    record: a.record,
  });
  return ok({ uri: out.uri, cid: out.cid, commit: out.commit });
}

async function doPut(
  ctx: PdsWriteContext,
  did: string,
  session: RestoredSession,
  a: PutArgs,
): Promise<HttpServerResponse.HttpServerResponse> {
  const r = await session.handle(`/xrpc/com.atproto.repo.putRecord`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      repo: did,
      collection: a.collection,
      rkey: a.rkey,
      record: a.record,
      ...(a.swapRecord ? { swapRecord: a.swapRecord } : {}),
    }),
  });
  if (!r.ok) {
    const text = await r.text().catch(() => "");
    return err(r.status >= 500 ? 502 : r.status, {
      error: "PdsError",
      message: `putRecord ${a.collection}: ${text.slice(0, 300)}`,
    });
  }
  const out = (await r.json()) as { uri: string; cid: string };
  mirrorPublish(ctx.bridgeUrl, {
    uri: out.uri,
    cid: out.cid,
    collection: a.collection,
    repo: did,
    record: a.record,
  });
  return ok({ uri: out.uri, cid: out.cid });
}

async function doDelete(
  ctx: PdsWriteContext,
  did: string,
  session: RestoredSession,
  a: DeleteArgs,
): Promise<HttpServerResponse.HttpServerResponse> {
  const uri = `at://${did}/${a.collection}/${a.rkey}`;
  const r = await session.handle(`/xrpc/com.atproto.repo.deleteRecord`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      repo: did,
      collection: a.collection,
      rkey: a.rkey,
      ...(a.swapRecord ? { swapRecord: a.swapRecord } : {}),
    }),
  });
  if (!r.ok) {
    const text = await r.text().catch(() => "");
    // Already-gone collapses to success so the agent's dedup loop moves on.
    if (r.status === 404 || /not.*locate|InvalidSwap|not.*found/i.test(text)) {
      mirrorUnpublish(ctx.bridgeUrl, uri);
      return ok({ uri, alreadyGone: true });
    }
    return err(r.status >= 500 ? 502 : r.status, {
      error: "PdsError",
      message: `deleteRecord ${a.collection}: ${text.slice(0, 300)}`,
    });
  }
  mirrorUnpublish(ctx.bridgeUrl, uri);
  return ok({ uri });
}

// ---- shared route bodies --------------------------------------------

type WriteCore<A> = (
  ctx: PdsWriteContext,
  did: string,
  session: RestoredSession,
  a: A,
) => Promise<HttpServerResponse.HttpServerResponse>;

/** Invoke a write-core, converting an unexpected promise rejection into a
 *  structured 502 rather than an Effect defect. `Effect.promise` treats a
 *  rejection as an unrecoverable defect, which the HTTP server renders as an
 *  opaque `{unhandled:true,message:"HTTPError"}` 500 — exactly what the
 *  exchange-bootstrap proxyCreate failure surfaced as. A throw from
 *  `session.handle`, `r.json()`, or the OAuth layer should be a legible
 *  upstream error, not a mystery 500. */
function runCore(
  op: string,
  run: () => Promise<HttpServerResponse.HttpServerResponse>,
): Effect.Effect<HttpServerResponse.HttpServerResponse> {
  return Effect.tryPromise({
    try: run,
    catch: (e) =>
      err(502, {
        error: "PdsWriteFailed",
        message: `${op}: ${e instanceof Error ? e.message : String(e)}`,
      }),
  }).pipe(Effect.merge);
}

/** Restore the session for `did`, or a non-2xx response: 401 when the
 *  session is simply gone, 502 when the restore itself throws (so a broken
 *  OAuth layer is a legible error, not an unhandled defect). */
function sessionOr401(ctx: PdsWriteContext, did: string) {
  return Effect.gen(function* () {
    const restored = yield* Effect.tryPromise({
      try: () => restoreSession(ctx.oauth, did as Did),
      catch: (e) => e,
    }).pipe(Effect.either);
    if (restored._tag === "Left") {
      const e = restored.left;
      return {
        ok: false as const,
        res: err(502, {
          error: "SessionRestoreFailed",
          message: `restore session for ${did}: ${e instanceof Error ? e.message : String(e)}`,
        }),
      };
    }
    if (!restored.right)
      return {
        ok: false as const,
        res: err(401, {
          error: "AuthRequired",
          message: "underlying ATProto session no longer valid; re-authenticate",
        }),
      };
    return { ok: true as const, session: restored.right };
  });
}

/** Bearer-key route: token -> DID -> session, then body -> args -> core.
 *  Order matches the previous hand-rolled handler exactly. */
function bearerRoute<A>(
  ctx: PdsWriteContext,
  op: string,
  parse: (b: Record<string, unknown>) => A | string,
  core: WriteCore<A>,
) {
  return Effect.gen(function* () {
    if (yield* methodNotPost) return err(405, { error: "MethodNotAllowed" });

    const token = yield* bearer;
    if (!token)
      return err(401, { error: "AuthRequired", message: "missing Authorization: Bearer header" });
    const resolved = ctx.accounts.resolveBearerKey(token);
    if (!resolved) return err(401, { error: "AuthRequired", message: "invalid API key" });

    const session = yield* sessionOr401(ctx, resolved.did);
    if (!session.ok) return session.res;

    const parsed = yield* Effect.either(jsonBody);
    if (parsed._tag === "Left")
      return err(400, { error: "InvalidRequest", message: parsed.left.message });

    const a = parse(parsed.right as Record<string, unknown>);
    if (typeof a === "string") return err(400, { error: "InvalidRequest", message: a });

    return yield* runCore(op, () => core(ctx, resolved.did, session.session, a));
  }).pipe(Effect.withSpan(`appview.pds.${op}`));
}

/** Internal-secret route: shared-secret header + asserted `did` in body,
 *  then args -> session -> core. Order matches the previous handler. */
function internalRoute<A>(
  ctx: PdsWriteContext,
  secret: string,
  op: string,
  parse: (b: Record<string, unknown>) => A | string,
  core: WriteCore<A>,
) {
  return Effect.gen(function* () {
    if (yield* methodNotPost) return err(405, { error: "MethodNotAllowed" });

    const presented = yield* header("x-cocore-internal-secret");
    if (typeof presented !== "string" || !secretEquals(presented, secret))
      return err(403, { error: "Forbidden" });

    const parsed = yield* Effect.either(jsonBody);
    if (parsed._tag === "Left")
      return err(400, { error: "InvalidRequest", message: parsed.left.message });
    const b = parsed.right as Record<string, unknown>;

    if (typeof b.did !== "string" || !b.did.startsWith("did:"))
      return err(400, { error: "InvalidRequest", message: "did required" });
    const did = b.did;

    const a = parse(b);
    if (typeof a === "string") return err(400, { error: "InvalidRequest", message: a });

    const session = yield* sessionOr401(ctx, did);
    if (!session.ok) return session.res;

    return yield* runCore(op, () => core(ctx, did, session.session, a));
  }).pipe(Effect.withSpan(`appview.internal.pds.${op}`));
}

// ---- router builders ------------------------------------------------

/** Public, bearer-key-authed `/pds/*` write endpoints. Canonical paths
 *  only; the parent re-adds `/api/*` aliases via `HttpRouter.prefixAll`. */
export function buildPdsRouter(ctx: PdsWriteContext): HttpRouter.HttpRouter<never, never> {
  return HttpRouter.empty.pipe(
    HttpRouter.all("/pds/createRecord", bearerRoute(ctx, "createRecord", parseCreate, doCreate)),
    HttpRouter.all("/pds/putRecord", bearerRoute(ctx, "putRecord", parsePut, doPut)),
    HttpRouter.all("/pds/deleteRecord", bearerRoute(ctx, "deleteRecord", parseDelete, doDelete)),
  );
}

/** DEPRECATED legacy aliases: `dev.cocore.proxy.{create,put,delete}Record`.
 *  Mounted (with the parent's `/api` prefix) at
 *  `/api/xrpc/dev.cocore.proxy.*` to match the path the console served
 *  before the `/api/pds/*` cutover. They reuse the same bearer-authed
 *  write cores as {@link buildPdsRouter}, so behavior is identical — only
 *  the URL differs. They exist solely so agents still on the old path keep
 *  writing while they upgrade; the canonical surface is `/api/pds/*`.
 *
 *  Removal plan: these stay until usage drains. Watch
 *  `url.path = /api/xrpc/dev.cocore.proxy.*` (or the `deprecated.proxyAlias`
 *  span attribute) in Honeycomb; once it hits zero across a release cycle,
 *  delete this builder and its mount in server.ts. Do NOT add new callers. */
export function buildProxyAliasRouter(ctx: PdsWriteContext): HttpRouter.HttpRouter<never, never> {
  const tag = Effect.annotateCurrentSpan("deprecated.proxyAlias", true);
  return HttpRouter.empty.pipe(
    HttpRouter.all(
      "/xrpc/dev.cocore.proxy.createRecord",
      Effect.zipRight(tag, bearerRoute(ctx, "createRecord", parseCreate, doCreate)),
    ),
    HttpRouter.all(
      "/xrpc/dev.cocore.proxy.putRecord",
      Effect.zipRight(tag, bearerRoute(ctx, "putRecord", parsePut, doPut)),
    ),
    HttpRouter.all(
      "/xrpc/dev.cocore.proxy.deleteRecord",
      Effect.zipRight(tag, bearerRoute(ctx, "deleteRecord", parseDelete, doDelete)),
    ),
  );
}

/** Private, internal-secret-authed `/internal/pds/*` write endpoints. The
 *  caller (the console) asserts the record's owning `did` in the body
 *  after resolving its own bearer key. Only served on the private :8081
 *  listener. */
export function buildInternalPdsRouter(
  ctx: PdsWriteContext,
  secret: string,
): HttpRouter.HttpRouter<never, never> {
  return HttpRouter.empty.pipe(
    HttpRouter.all(
      "/internal/pds/createRecord",
      internalRoute(ctx, secret, "createRecord", parseCreate, doCreate),
    ),
    HttpRouter.all(
      "/internal/pds/putRecord",
      internalRoute(ctx, secret, "putRecord", parsePut, doPut),
    ),
    HttpRouter.all(
      "/internal/pds/deleteRecord",
      internalRoute(ctx, secret, "deleteRecord", parseDelete, doDelete),
    ),
  );
}
