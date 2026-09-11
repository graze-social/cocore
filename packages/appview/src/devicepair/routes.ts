// Device-pairing XRPC handlers, served by the AppView as an @effect/platform
// HttpRouter over the in-memory PairStore.
//
//   /xrpc/dev.cocore.devicePair.start     (POST, public)        — requester begins a pairing
//   /xrpc/dev.cocore.devicePair.describe  (GET,  public)        — approve screen asks who is asking
//   /xrpc/dev.cocore.devicePair.poll      (GET,  public)        — requester polls for the session
//   /xrpc/dev.cocore.devicePair.confirm   (POST, service-auth)  — user approves/denies
//
// Two kinds of requester share this flow. A provider machine (`cocore agent
// pair`) sends an empty `start` and gets a key named "paired machine". An
// application connecting on a user's behalf (Graze's "Connect co/core") sends
// `{appName, keyName, returnUrl}`: the approve screen then names the app and
// the key, and sends the browser back to the app afterwards. `returnUrl` is
// honoured only for allowlisted hosts (`COCORE_PAIR_RETURN_HOSTS`).
//
// confirm is a real public XRPC method authed via AT Protocol service auth
// (the approving user's PDS proxies the call to `#cocore_appview`). On
// approve the AppView mints a `cocore-...` key scoped to the verified DID,
// builds the ProviderSession, and binds it to the pairing. start/describe/poll
// need no auth, so each carries a per-client rate limit — they are reachable
// from any browser now, not just the user's own terminal.
//
// Handlers close over the PairStore and DevicePairContext (dependency
// injection by closure — no Context tags). Each route is an Effect returning
// an HttpServerResponse and carries an `appview.devicePair.<op>` span.

import { HttpRouter, HttpServerRequest } from "@effect/platform";
import { Effect } from "effect";
import { timingSafeEqual } from "node:crypto";

import { verifyServiceAuthToken } from "../auth/service-auth.ts";
import type { AccountStore } from "../operational/account-store.ts";
import { hydrateDids } from "../bsky-hydrate.ts";
import { bearer, err, header, jsonBody, ok, searchParams } from "../api/http-app.ts";
import { isDid } from "@atcute/lexicons/syntax";

import {
  type AppIdentity,
  type AppResolver,
  createAppResolver,
  matchesRegisteredReturnUrl,
} from "./app-registration.ts";
import { clientKey, createRateLimiter, sanitizePairMeta, type RateLimiter } from "./pair-meta.ts";
import { type PairMeta, PairError, type PairStore, type ProviderSession } from "./pair-store.ts";

/** Constant-time compare that tolerates length differences (never short-
 *  circuits on unequal lengths in a timing-observable way). */
function secretEquals(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

interface DevicePairRateLimits {
  /** Window every limit below is counted in. */
  windowMs: number;
  start: number;
  describe: number;
  confirm: number;
}

/** Generous for a human, tight for a script: nobody pairs 30 machines in
 *  ten minutes, and 30 confirm attempts is far too few to guess an 8-char
 *  code from a 31-symbol alphabet. */
const DEFAULT_RATE_LIMITS: DevicePairRateLimits = {
  windowMs: 10 * 60 * 1000,
  start: 30,
  describe: 120,
  confirm: 30,
};

export interface DevicePairContext {
  /** Mints the scoped API key handed to the paired agent. */
  accountStore: AccountStore;
  /** This AppView's service DID — the `aud` that confirm's service-auth
   *  JWT must target. */
  appviewDid: string;
  /** Console origin agents append `/api/pds/*` to (console resolves the
   *  Bearer key and forwards the write here internally). */
  apiBase: string;
  /** Shared internal secret (M6). A pre-minted `providerSession` in the
   *  confirm body (apiKey/apiBase chosen by the caller) is honored ONLY when
   *  the request carries this secret — i.e. the trusted console forwarding a
   *  key it minted in its own store. Public callers never supply a session:
   *  the AppView always mints it server-side, so a userCode-observer can't
   *  point a victim's agent at an attacker key/endpoint. Undefined → the
   *  pre-minted path is disabled entirely (always mint server-side). */
  internalSecret?: string;
  /** Hosts a requester's `returnUrl` may point at. Empty/undefined → return
   *  URLs are dropped. */
  returnHosts?: readonly string[];
  /** Override the per-client budgets (tests). */
  rateLimits?: DevicePairRateLimits;
  /** Resolves `appDid` → the app's registration record and verifies return
   *  hosts. Defaults to live plc/web + https resolution; tests inject one. */
  appResolver?: AppResolver;
}

function isProviderSession(v: unknown): v is ProviderSession {
  if (typeof v !== "object" || v === null) return false;
  const s = v as Record<string, unknown>;
  return (
    typeof s.did === "string" &&
    s.did.startsWith("did:") &&
    typeof s.handle === "string" &&
    typeof s.apiKey === "string" &&
    s.apiKey.startsWith("cocore-") &&
    typeof s.apiBase === "string" &&
    s.apiBase.startsWith("http")
  );
}

/** The key name for a pairing nobody named: what the CLI has always minted. */
function defaultKeyName(now: Date = new Date()): string {
  return `paired machine (${now.toISOString().slice(0, 10)})`;
}

const rateLimited = err(429, {
  error: "RateLimited",
  message: "too many pairing requests from this client; try again in a few minutes",
});

/** Consume one unit of `limiter` for the calling client; Some(response) when
 *  over budget. */
const consume = (limiter: RateLimiter) =>
  Effect.gen(function* () {
    const fwd = yield* header("x-forwarded-for");
    const real = yield* header("x-real-ip");
    return limiter.allow(clientKey(fwd, real));
  });

export function buildDevicePairRouter(
  store: PairStore,
  ctx: DevicePairContext,
): HttpRouter.HttpRouter<never, never> {
  const limits = ctx.rateLimits ?? DEFAULT_RATE_LIMITS;
  const startLimiter = createRateLimiter(limits.start, limits.windowMs);
  const describeLimiter = createRateLimiter(limits.describe, limits.windowMs);
  const confirmLimiter = createRateLimiter(limits.confirm, limits.windowMs);
  const returnHosts = ctx.returnHosts ?? [];
  const appResolver = ctx.appResolver ?? createAppResolver();

  /** Build the pairing metadata for a `start` body.
   *
   *  Without `appDid` this is the legacy path: a self-declared `appName`, and
   *  a return URL only for operator-allowlisted hosts. With `appDid`, identity
   *  comes from the app's own `dev.cocore.app.registration` record and the
   *  return URL must be one the record lists AND on a host that vouches for the
   *  DID (or that the operator allowlists). An unverified app still pairs — the
   *  approve screen just says so and never sends the browser to it. */
  async function metaForStart(body: unknown): Promise<{ meta: PairMeta } | { error: string }> {
    const meta = sanitizePairMeta(body, returnHosts);
    const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
    if (b.appDid === undefined || b.appDid === null) return { meta };
    if (typeof b.appDid !== "string" || !isDid(b.appDid)) return { error: "appDid must be a DID" };
    const appDid = b.appDid;
    const registration = await appResolver.resolve(appDid);
    if (!registration) {
      return {
        error: `AppNotRegistered: no dev.cocore.app.registration record at ${appDid}; publish one on the app's account first`,
      };
    }
    const handle = (await hydrateDids([appDid]).catch(() => new Map())).get(appDid)?.handle;
    const app: AppIdentity = {
      did: appDid,
      ...(handle ? { handle } : {}),
      name: registration.name,
      ...(registration.website ? { website: registration.website } : {}),
      ...(registration.iconUrl ? { iconUrl: registration.iconUrl } : {}),
      verified: false,
    };
    // The record's name wins over anything the request typed.
    const withApp: PairMeta = { ...meta, appName: registration.name, app };
    delete withApp.returnUrl;
    const requested = typeof b.returnUrl === "string" ? b.returnUrl : undefined;
    if (requested && matchesRegisteredReturnUrl(requested, registration.returnUrls)) {
      const host = new URL(requested).hostname.toLowerCase();
      const verified = returnHosts.includes(host) || (await appResolver.verifyHost(host, appDid));
      if (verified) {
        withApp.returnUrl = requested;
        withApp.app = { ...app, verified: true, verifiedHost: host };
      }
    }
    return { meta: withApp };
  }

  return HttpRouter.empty.pipe(
    // start is mounted with `all` so a wrong method reaches the handler and
    // gets an explicit 405 (the test asserts GET → 405) rather than the
    // router's default 404.
    HttpRouter.all(
      "/xrpc/dev.cocore.devicePair.start",
      Effect.gen(function* () {
        const req = yield* HttpServerRequest.HttpServerRequest;
        if (req.method !== "POST") return err(405, { error: "MethodNotAllowed" });
        if (!(yield* consume(startLimiter))) return rateLimited;
        // The CLI sends no body at all; an app sends JSON. Anything
        // unparseable is treated as "no metadata", never as an error, so a
        // requester that sends a stray content-type still gets paired.
        const parsed = yield* Effect.either(jsonBody);
        const body = parsed._tag === "Right" ? parsed.right : undefined;
        const built = yield* Effect.promise(() => metaForStart(body));
        if ("error" in built) return err(400, { error: "InvalidRequest", message: built.error });
        return ok(store.start(built.meta));
      }).pipe(Effect.withSpan("appview.devicePair.start")),
    ),

    HttpRouter.get(
      "/xrpc/dev.cocore.devicePair.describe",
      Effect.gen(function* () {
        if (!(yield* consume(describeLimiter))) return rateLimited;
        const sp = yield* searchParams;
        const userCode = (sp.get("userCode") ?? "").trim().toUpperCase();
        if (!userCode) return err(400, { error: "InvalidRequest", message: "missing userCode" });
        const described = store.describe(userCode);
        if (!described) return err(404, { error: "NotFound", message: "no such pair code" });
        return ok(described);
      }).pipe(Effect.withSpan("appview.devicePair.describe")),
    ),

    HttpRouter.get(
      "/xrpc/dev.cocore.devicePair.poll",
      Effect.gen(function* () {
        const sp = yield* searchParams;
        const deviceId = sp.get("deviceId");
        if (!deviceId) return err(400, { error: "InvalidRequest", message: "missing deviceId" });
        const r = store.poll(deviceId);
        switch (r.kind) {
          case "unknown":
            return err(404, { status: "unknown" });
          case "pending":
            return ok({ status: "pending" });
          case "denied":
            return err(403, { status: "denied" });
          case "expired":
            return err(410, { status: "expired" });
          case "consumed":
            return err(410, { status: "consumed" });
          case "session":
            return ok({ status: "session", session: r.session });
        }
      }).pipe(Effect.withSpan("appview.devicePair.poll")),
    ),

    HttpRouter.post(
      "/xrpc/dev.cocore.devicePair.confirm",
      Effect.gen(function* () {
        if (!(yield* consume(confirmLimiter))) return rateLimited;
        const token = yield* bearer;
        const auth = yield* Effect.promise(() =>
          verifyServiceAuthToken(token, {
            audience: ctx.appviewDid,
            lxm: "dev.cocore.devicePair.confirm",
          }),
        );
        if (!auth.ok) return err(auth.status, { error: auth.error, message: auth.message });
        const did = auth.did;

        const parsed = yield* Effect.either(jsonBody);
        if (parsed._tag === "Left")
          return err(400, { error: "InvalidRequest", message: parsed.left.message });
        const body = parsed.right as {
          userCode?: unknown;
          decision?: unknown;
          providerSession?: unknown;
        };

        const code = (typeof body.userCode === "string" ? body.userCode : "").trim().toUpperCase();
        if (!code) return err(400, { error: "InvalidRequest", message: "missing userCode" });

        if (body.decision === "deny") {
          try {
            store.deny(code);
          } catch {
            return err(404, { error: "unknown code" });
          }
          return ok({ ok: true, status: "denied" });
        }
        if (body.decision !== "approve") {
          return err(400, {
            error: "InvalidRequest",
            message: "decision must be approve|deny",
          });
        }

        // Look the attempt up BEFORE minting anything: an unknown or already
        // settled code must not cost the user a stray key.
        const pending = store.describe(code);
        if (!pending) return err(404, { error: "NotFound", message: "no such pair code" });
        if (pending.status !== "pending") {
          return err(409, { error: "Conflict", message: `pair already ${pending.status}` });
        }

        // Approve: bind a ProviderSession to the pairing.
        //
        // M6: a caller-supplied `providerSession` (apiKey/apiBase chosen by the
        // request) is TRUSTED only when the request also carries the internal
        // secret — i.e. the console forwarding a key it minted in its own store
        // so Bearer auth on `/api/pds/*` resolves. A PUBLIC caller (anyone who
        // observed a userCode and holds any DID's service-auth) does NOT get to
        // choose apiKey/apiBase: we ignore their body session and mint
        // server-side, so they can't redirect the victim's agent at an attacker
        // endpoint/key. `did` is always the service-auth-verified DID.
        const presentedSecret = yield* header("x-cocore-internal-secret");
        const internalTrusted =
          typeof ctx.internalSecret === "string" &&
          ctx.internalSecret.length > 0 &&
          typeof presentedSecret === "string" &&
          secretEquals(presentedSecret, ctx.internalSecret);
        const bodySession = body.providerSession;
        let session: ProviderSession;
        if (internalTrusted && isProviderSession(bodySession)) {
          session = {
            did,
            handle: bodySession.handle,
            apiKey: bodySession.apiKey,
            apiBase: bodySession.apiBase,
          };
        } else {
          const hydrated = yield* Effect.promise(() => hydrateDids([did]).catch(() => new Map()));
          const handle = hydrated.get(did)?.handle ?? did;
          const { secret } = ctx.accountStore.createKey({
            did,
            name: pending.keyName ?? defaultKeyName(),
          });
          session = { did, handle, apiKey: secret, apiBase: ctx.apiBase };
        }
        try {
          const entry = store.approve(code, session);
          return ok({
            ok: true,
            status: entry.status,
            ...(entry.meta.returnUrl ? { returnUrl: entry.meta.returnUrl } : {}),
          });
        } catch (e) {
          if (e instanceof PairError) return err(409, { error: e.message });
          return err(409, { error: e instanceof Error ? e.message : String(e) });
        }
      }).pipe(Effect.withSpan("appview.devicePair.confirm")),
    ),
  );
}
