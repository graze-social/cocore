// HTTP API over indexed cocore records, as an @effect/platform HttpRouter.
//
// `buildAppviewApp` concatenates the route-group routers (read API +
// account + pds + inference + device-pair) plus a few server-level routes
// (healthz, did:web doc, the internal console↔AppView handoff endpoints)
// into one app. It's served via the platform serve-model (`serveAppview`
// in http-app.ts) inside a long-lived scope so the OTel tracing layer
// exports a span per request to Honeycomb when OTLP is configured.
//
// Route groups are conditionally mounted on `opts` exactly as before:
// without an account store + service DID a deploy serves only the read API.

import { createServer } from "node:http";
import { timingSafeEqual } from "node:crypto";

import { HttpRouter } from "@effect/platform";
import { Effect } from "effect";

import {
  type AppviewOAuthClient,
  isOAuthConfigured,
  makeAppviewOAuth,
  startServiceSessionKeepAlive,
} from "../auth/oauth-client.ts";
import { buildDevicePairRouter } from "../devicepair/routes.ts";
import { PairStore } from "../devicepair/pair-store.ts";
import { buildInferenceRouter } from "../inference/routes.ts";
import { AccountStore } from "../operational/account-store.ts";
import { buildInternalPdsRouter, buildPdsRouter, buildProxyAliasRouter } from "../pds/write.ts";
import { Store } from "../store.ts";
import { buildAccountRouter } from "./account-routes.ts";
import { buildAgentBugReportRouter } from "./agent-bug-report.ts";
import { buildAgentStatusRouter } from "./agent-status.ts";
import { appviewNodeHandler, err, header, jsonBody, ok } from "./http-app.ts";
import { buildReadRouter } from "./read-router.ts";

export interface BuildServerOptions {
  /** Operational store for API keys + OAuth sessions. When provided
   *  together with `appviewDid`, the dev.cocore.account.* methods are
   *  registered. */
  accountStore?: AccountStore;
  /** This AppView's service DID — the `aud` that account.* service-auth
   *  JWTs must target. Required to enable the account methods. */
  appviewDid?: string;
  /** Bridge base URL for the best-effort cache mirror on PDS writes. */
  bridgeUrl?: string;
  /** Shared secret the console presents to hand off a freshly minted
   *  OAuth session (`POST /internal/oauth-session`). When unset, the
   *  handoff endpoints are not registered. */
  internalSecret?: string;
  /** HTTP base for the matchmaking advisor. Required to enable
   *  `dev.cocore.inference.dispatch`. */
  advisorUrl?: string;
  /** Exchange DID stamped onto dispatch's paymentAuthorization + job. */
  exchangeDid?: string;
  /** Long-lived SERVICE DIDs (e.g. the exchange DID) whose OAuth sessions
   *  this AppView should keep warm so they never lapse from disuse and brick
   *  every write under them — the way the exchange session died in 2026-06.
   *  The AppView is the sole session owner, so the keep-alive runs here and
   *  nowhere else. Empty/absent → disabled. */
  keepAliveDids?: string[];
  /** Interval between keep-alive refreshes. Default 6h — comfortably inside a
   *  typical refresh-token lifetime. */
  keepAliveIntervalMs?: number;
}

/** Minimum length for the shared internal secret. The `/internal/*` endpoints
 *  mint API keys, overwrite OAuth sessions, and proxy repo writes for any DID,
 *  so a weak secret is a full account-takeover primitive. Refuse to start with
 *  a set-but-too-short secret rather than run with brute-forceable internal
 *  auth. 32 chars is comfortably beyond online-guessing range for the
 *  constant-time compare these routes use. */
const MIN_INTERNAL_SECRET_LEN = 32;

/** Normalize + validate `opts.internalSecret`. Returns the secret when it's
 *  present AND long enough (so callers can gate `/internal/*` on a truthy
 *  result), or undefined when unset (internal routes stay unmounted — fail
 *  closed). Throws at startup when the secret is set but shorter than
 *  {@link MIN_INTERNAL_SECRET_LEN}, so a misconfiguration is loud, not a silent
 *  weak-auth deployment. */
function validatedInternalSecret(secret: string | undefined): string | undefined {
  if (!secret) return undefined;
  if (secret.length < MIN_INTERNAL_SECRET_LEN) {
    throw new Error(
      `COCORE_INTERNAL_SECRET too short (${secret.length} chars); ` +
        `require >= ${MIN_INTERNAL_SECRET_LEN} for the /internal/* endpoints`,
    );
  }
  return secret;
}

/** Constant-time string compare that tolerates length differences. */
function secretEquals(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/** Upper bound on a persisted OAuth session blob. A StoredSession (DPoP
 *  keypair + token set + metadata) is a few KB; 256 KiB is generous headroom
 *  while rejecting a caller trying to stash an oversized payload under a DID. */
const MAX_OAUTH_SESSION_BYTES = 256 * 1024;

/** Validate the `data` field of an `/internal/oauth-session` write. Accepts a
 *  JSON object (or a JSON string that parses to one), rejects scalars/arrays/
 *  unparseable strings and anything over {@link MAX_OAUTH_SESSION_BYTES}.
 *  Returns the canonical string form to persist on success. */
function validateOAuthSessionData(
  data: unknown,
): { ok: true; data: string } | { ok: false; reason: string } {
  let obj: unknown;
  let serialized: string;
  if (typeof data === "string") {
    serialized = data;
    try {
      obj = JSON.parse(data);
    } catch {
      return { ok: false, reason: "data must be a JSON object (string was not valid JSON)" };
    }
  } else {
    obj = data;
    try {
      serialized = JSON.stringify(data);
    } catch {
      return { ok: false, reason: "data is not serializable" };
    }
  }
  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) {
    return { ok: false, reason: "data must be a StoredSession object" };
  }
  if (Object.keys(obj as Record<string, unknown>).length === 0) {
    return { ok: false, reason: "data must be a non-empty StoredSession object" };
  }
  if (Buffer.byteLength(serialized, "utf8") > MAX_OAUTH_SESSION_BYTES) {
    return { ok: false, reason: "data exceeds the maximum session size" };
  }
  return { ok: true, data: serialized };
}

/** Console↔AppView internal endpoints (shared-secret gated): OAuth session
 *  handoff (the console pushes a freshly minted session so the AppView
 *  becomes its sole owner) + API-key provisioning. */
function buildInternalAccountRouter(
  accountStore: AccountStore,
  secret: string,
): HttpRouter.HttpRouter<never, never> {
  const authorized = Effect.map(
    header("x-cocore-internal-secret"),
    (presented) => typeof presented === "string" && secretEquals(presented, secret),
  );
  return HttpRouter.empty.pipe(
    HttpRouter.post(
      "/internal/oauth-session",
      Effect.gen(function* () {
        if (!(yield* authorized)) return err(403, { error: "Forbidden" });
        const parsed = yield* Effect.either(jsonBody);
        if (parsed._tag === "Left") {
          return err(400, { error: "InvalidRequest", message: "body must be JSON" });
        }
        const body = parsed.right as { did?: unknown; data?: unknown };
        if (typeof body.did !== "string" || !body.did.startsWith("did:")) {
          return err(400, { error: "InvalidRequest", message: "did required" });
        }
        if (body.data === undefined || body.data === null) {
          return err(400, { error: "InvalidRequest", message: "data (StoredSession) required" });
        }
        // H5: validate the session blob's shape before we persist it as the
        // AppView's sole restorable session for this DID. It's an opaque atcute
        // StoredSession (the console owns the exact serialization), but it MUST
        // parse to a non-empty JSON OBJECT (not a scalar/array/garbage string)
        // and stay within a sane size — so a caller can't stash arbitrary junk
        // (or a giant blob) under a DID and brick every subsequent restore.
        const shape = validateOAuthSessionData(body.data);
        if (!shape.ok) {
          return err(400, { error: "InvalidRequest", message: shape.reason });
        }
        accountStore.putOAuthSession(body.did, shape.data);
        return ok({ ok: true });
      }).pipe(Effect.withSpan("appview.internal.oauthSession")),
    ),
    HttpRouter.post(
      "/internal/account/mint-key",
      Effect.gen(function* () {
        if (!(yield* authorized)) return err(403, { error: "Forbidden" });
        const parsed = yield* Effect.either(jsonBody);
        if (parsed._tag === "Left") {
          return err(400, { error: "InvalidRequest", message: "body must be JSON" });
        }
        const body = parsed.right as { did?: unknown; name?: unknown };
        if (typeof body.did !== "string" || !body.did.startsWith("did:")) {
          return err(400, { error: "InvalidRequest", message: "did required" });
        }
        const name = typeof body.name === "string" && body.name.length > 0 ? body.name : "console";
        const out = accountStore.createKey({ did: body.did, name });
        return ok({ key: out.key, secret: out.secret });
      }).pipe(Effect.withSpan("appview.internal.mintKey")),
    ),
    // Resolve a presented bearer key to its owning DID against THIS store.
    // The console's inference path calls this so a key minted via the
    // (documented) AppView `createApiKey` — which lands in account.db, a
    // different store than the console's console.db — still authenticates at
    // `cocore.dev/v1/chat/completions`. Returns 404 when the key is unknown,
    // revoked, or expired (resolveBearerKey collapses all three to null), so
    // the caller never distinguishes those cases.
    HttpRouter.post(
      "/internal/account/resolve-key",
      Effect.gen(function* () {
        if (!(yield* authorized)) return err(403, { error: "Forbidden" });
        const parsed = yield* Effect.either(jsonBody);
        if (parsed._tag === "Left") {
          return err(400, { error: "InvalidRequest", message: "body must be JSON" });
        }
        const body = parsed.right as { key?: unknown };
        if (typeof body.key !== "string" || body.key.length === 0) {
          return err(400, { error: "InvalidRequest", message: "key required" });
        }
        const resolved = accountStore.resolveBearerKey(body.key);
        if (!resolved) return err(404, { error: "NotFound", message: "key not resolvable" });
        return ok({ id: resolved.id, did: resolved.did, name: resolved.name });
      }).pipe(Effect.withSpan("appview.internal.resolveKey")),
    ),
    // AppView half of the console's "reset connection" repair flow:
    // revoke all of a DID's API keys + drop its OAuth session so the user
    // can re-pair from a clean slate. (merged from main #33)
    HttpRouter.post(
      "/internal/account/reset-did",
      Effect.gen(function* () {
        if (!(yield* authorized)) return err(403, { error: "Forbidden" });
        const parsed = yield* Effect.either(jsonBody);
        if (parsed._tag === "Left") {
          return err(400, { error: "InvalidRequest", message: "body must be JSON" });
        }
        const body = parsed.right as { did?: unknown };
        if (typeof body.did !== "string" || !body.did.startsWith("did:")) {
          return err(400, { error: "InvalidRequest", message: "did required" });
        }
        const keysRevoked = accountStore.revokeAllKeysForDid(body.did);
        accountStore.deleteOAuthSession(body.did);
        console.error(`appview: reset auth state for ${body.did} (${keysRevoked} keys revoked)`);
        return ok({ ok: true, keysRevoked });
      }).pipe(Effect.withSpan("appview.internal.resetDid")),
    ),
  );
}

/** Build the AppView's route groups, split into public routes and the
 *  shared-secret `/internal/*` routes. Creates the single OAuth client +
 *  PairStore once, so both views returned by {@link buildAppviewSplit}
 *  share them (no dual-refresh / split device-pair state). */
function buildAppviewRouters(
  store: Store,
  opts: BuildServerOptions,
): {
  publicRouters: Array<HttpRouter.HttpRouter<never, never>>;
  internalRouters: Array<HttpRouter.HttpRouter<never, never>>;
} {
  const routers: Array<HttpRouter.HttpRouter<never, never>> = [buildReadRouter(store)];
  const internalRouters: Array<HttpRouter.HttpRouter<never, never>> = [];

  // Fail-closed on a weak internal secret: throw at startup rather than mount
  // the /internal/* takeover surface behind brute-forceable auth. Unset →
  // undefined → the /internal/* routers below stay unmounted entirely.
  const internalSecret = validatedInternalSecret(opts.internalSecret);

  // Liveness probe.
  routers.push(
    HttpRouter.empty.pipe(
      HttpRouter.get(
        "/healthz",
        Effect.sync(() => ok({ ok: true })).pipe(Effect.withSpan("appview.healthz")),
      ),
    ),
  );

  // did:web DID document so a requester's PDS can resolve this AppView's
  // `#cocore_appview` service endpoint and proxy service-auth calls here.
  const didDoc = opts.appviewDid?.startsWith("did:web:")
    ? {
        "@context": ["https://www.w3.org/ns/did/v1"],
        id: opts.appviewDid,
        service: [
          {
            id: "#cocore_appview",
            type: "CocoreAppView",
            serviceEndpoint: `https://${opts.appviewDid.slice("did:web:".length)}`,
          },
        ],
      }
    : null;
  if (didDoc) {
    routers.push(
      HttpRouter.empty.pipe(
        HttpRouter.get(
          "/.well-known/did.json",
          Effect.sync(() => ok(didDoc)).pipe(Effect.withSpan("appview.didDoc")),
        ),
      ),
    );
  }

  // Operational account methods (API-key management).
  if (opts.accountStore && opts.appviewDid) {
    routers.push(buildAccountRouter(opts.accountStore, opts.appviewDid));
  }

  // Single shared OAuth client (when configured). One client over one
  // session store is required — two would dual-refresh the same session.
  let oauth: AppviewOAuthClient | null = null;
  if (opts.accountStore && isOAuthConfigured()) {
    try {
      oauth = makeAppviewOAuth(opts.accountStore);
    } catch (e) {
      console.error(`appview: OAuth client init failed: ${(e as Error).message}`);
    }
  }

  // Keep configured service-DID sessions warm. The AppView is the single
  // session owner (single-use refresh tokens), so this is the one correct
  // place to do it — a periodic refresh stops a long-idle service session
  // (the exchange DID) from lapsing and 401ing every settlement write.
  if (oauth && opts.keepAliveDids && opts.keepAliveDids.length > 0) {
    startServiceSessionKeepAlive({
      client: oauth,
      dids: opts.keepAliveDids,
      intervalMs: opts.keepAliveIntervalMs ?? 6 * 60 * 60_000,
    });
    console.error(
      `appview: oauth keep-alive enabled for ${opts.keepAliveDids.length} service DID(s)`,
    );
  }

  // PDS-write executor + its `/api/pds/*` alias (a paired agent's apiBase
  // points at this AppView and appends `/api/pds/...`).
  if (opts.accountStore && oauth) {
    const pctx = { accounts: opts.accountStore, oauth, bridgeUrl: opts.bridgeUrl };
    const pds = buildPdsRouter(pctx);
    routers.push(pds, pds.pipe(HttpRouter.prefixAll("/api")));
    // Deprecated legacy alias: agents still on the pre-cutover
    // `/api/xrpc/dev.cocore.proxy.*` path point apiBase here and were 404ing.
    // Same bearer auth + write cores as `/api/pds/*`; remove once usage drains
    // (watch the `deprecated.proxyAlias` span attribute).
    const proxyAlias = buildProxyAliasRouter(pctx);
    routers.push(proxyAlias, proxyAlias.pipe(HttpRouter.prefixAll("/api")));
    if (internalSecret) internalRouters.push(buildInternalPdsRouter(pctx, internalSecret));
    console.error(
      `appview: /pds write endpoints enabled${internalSecret ? " (+ /internal/pds)" : ""} (+ deprecated dev.cocore.proxy.* aliases)`,
    );
  }

  // Menu-bar agent routes: `/api/agent/status` + `/api/agent/bug-report`. A
  // device-pair'd agent's apiBase points at this AppView and its bearer key
  // lives in this AccountStore, so serve these here (the console serves the
  // same routes for console-paired agents — each resolves the keys it minted).
  if (opts.accountStore) {
    const agentStatus = buildAgentStatusRouter({
      accounts: opts.accountStore,
      store,
      bridgeUrl: opts.bridgeUrl,
      advisorUrl: opts.advisorUrl,
    });
    const agentBugReport = buildAgentBugReportRouter({ accounts: opts.accountStore });
    routers.push(
      agentStatus,
      agentStatus.pipe(HttpRouter.prefixAll("/api")),
      agentBugReport,
      agentBugReport.pipe(HttpRouter.prefixAll("/api")),
    );
  }

  // Inference dispatch (SSE).
  if (opts.accountStore && opts.appviewDid && oauth && opts.advisorUrl) {
    routers.push(
      buildInferenceRouter({
        store,
        oauth,
        appviewDid: opts.appviewDid,
        advisorUrl: opts.advisorUrl,
        exchangeDid: opts.exchangeDid ?? "did:web:exchange.local",
        bridgeUrl: opts.bridgeUrl,
      }),
    );
    console.error("appview: inference.dispatch endpoint enabled");
  }

  // Internal console↔AppView handoff endpoints.
  if (opts.accountStore && internalSecret) {
    internalRouters.push(buildInternalAccountRouter(opts.accountStore, internalSecret));
  }

  // Device pairing (start/poll public, confirm service-auth).
  if (opts.accountStore && opts.appviewDid) {
    const verificationBase = (
      process.env["CONSOLE_PUBLIC_URL"] ||
      process.env["ATPROTO_BASE_URL"] ||
      process.env["BETTER_AUTH_URL"] ||
      "http://localhost:3000"
    ).replace(/\/$/, "");
    // Agents always post to the console's `/api/pds/*` (Bearer key → console
    // resolves → internal forward to this AppView). On Railway the AppView
    // service is not publicly routed, so deriving apiBase from `did:web:` would
    // hand agents a dead hostname even though pairing succeeded.
    const apiBase = process.env["COCORE_AGENT_API_BASE"]?.replace(/\/$/, "") || verificationBase;
    routers.push(
      buildDevicePairRouter(new PairStore(verificationBase), {
        accountStore: opts.accountStore,
        appviewDid: opts.appviewDid,
        apiBase,
        ...(internalSecret ? { internalSecret } : {}),
      }),
    );
    console.error("appview: device-pair endpoints enabled");
  }

  return { publicRouters: routers, internalRouters };
}

/** The full AppView app (public routes + `/internal/*`). */
export function buildAppviewApp(
  store: Store,
  opts: BuildServerOptions = {},
): HttpRouter.HttpRouter<never, never> {
  const { publicRouters, internalRouters } = buildAppviewRouters(store, opts);
  return HttpRouter.concatAll(...publicRouters, ...internalRouters);
}

/** Build BOTH the full app and a public-only app (no `/internal/*`) from a
 *  single set of shared resources. The full app serves the private listener;
 *  the public app is safe to mount on a public port (e.g. the services
 *  bridge), keeping the internal console↔AppView endpoints off the wire. */
export function buildAppviewSplit(
  store: Store,
  opts: BuildServerOptions = {},
): { full: HttpRouter.HttpRouter<never, never>; public: HttpRouter.HttpRouter<never, never> } {
  const { publicRouters, internalRouters } = buildAppviewRouters(store, opts);
  return {
    full: HttpRouter.concatAll(...publicRouters, ...internalRouters),
    public: HttpRouter.concatAll(...publicRouters),
  };
}

/** Build a traced Node request listener for the AppView. ONE app instance
 *  (one OAuth client + session store) is served behind `makeHandler` on a
 *  long-lived o11y runtime, so the same listener can back multiple ports
 *  (e.g. infra/services' internal :8081 listener + the public bridge-port
 *  fallback) without two clients dual-refreshing the same session. Spans
 *  export to Honeycomb when OTLP is configured. The listener responds to
 *  every request (404 for unmatched routes). */
export function buildAppviewNodeHandler(store: Store, opts: BuildServerOptions = {}) {
  return appviewNodeHandler(buildAppviewApp(store, opts));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env["COCORE_API_PORT"] ?? 8080);
  const dbPath = process.env["COCORE_DB"] ?? "./appview.db";
  const store = new Store(dbPath);
  const appviewDid = process.env["COCORE_APPVIEW_DID"];
  const accountStore = appviewDid
    ? new AccountStore(process.env["COCORE_ACCOUNT_DB"] ?? "./appview-account.db")
    : undefined;
  const opts: BuildServerOptions = {
    accountStore,
    appviewDid,
    bridgeUrl: process.env["COCORE_BRIDGE_URL"],
    internalSecret: process.env["COCORE_INTERNAL_SECRET"],
  };

  // H5: keep the `/internal/*` takeover surface (mint-key, reset-did,
  // oauth-session handoff, repo-write proxy) OFF the public listener. The
  // public port serves ONLY `.public`; the full app (public + internal) binds
  // to a PRIVATE interface (loopback by default; override the host only for a
  // trusted private network like Railway's). Without a valid internal secret
  // there are no internal routers to serve, so no private listener is started.
  const { full, public: publicApp } = buildAppviewSplit(store, opts);

  const publicHandler = await appviewNodeHandler(publicApp);
  createServer(publicHandler).listen(port, () => {
    console.error(
      `appview api: public listening on :${port} db=${dbPath}` +
        (appviewDid ? ` account=on(aud=${appviewDid})` : ""),
    );
  });

  const internalPortRaw = process.env["COCORE_APPVIEW_INTERNAL_PORT"];
  if (process.env["COCORE_INTERNAL_SECRET"] && internalPortRaw) {
    const internalPort = Number(internalPortRaw);
    // Loopback by default so the internal endpoints are unreachable off-host.
    // Set COCORE_APPVIEW_INTERNAL_HOST to a private-network address (e.g. the
    // Railway service's internal interface) when the console runs elsewhere.
    const internalHost = process.env["COCORE_APPVIEW_INTERNAL_HOST"] ?? "127.0.0.1";
    const internalHandler = await appviewNodeHandler(full);
    createServer(internalHandler).listen(internalPort, internalHost, () => {
      console.error(`appview api: internal listening on ${internalHost}:${internalPort}`);
    });
  }
}
