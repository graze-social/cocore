// Device-pairing XRPC handlers, served by the AppView as an @effect/platform
// HttpRouter over the in-memory PairStore.
//
//   /xrpc/dev.cocore.devicePair.start    (POST, public)        — agent begins a pairing
//   /xrpc/dev.cocore.devicePair.poll     (GET,  public)        — agent polls for the session
//   /xrpc/dev.cocore.devicePair.confirm  (POST, service-auth)  — user approves/denies
//
// confirm is a real public XRPC method authed via AT Protocol service auth
// (the approving user's PDS proxies the call to `#cocore_appview`). On
// approve the AppView mints a `cocore-...` key scoped to the verified DID,
// builds the ProviderSession, and binds it to the pairing. start/poll are
// agent-facing and need no auth.
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
import { PairError, type PairStore, type ProviderSession } from "./pair-store.ts";

/** Constant-time compare that tolerates length differences (never short-
 *  circuits on unequal lengths in a timing-observable way). */
function secretEquals(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

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

export function buildDevicePairRouter(
  store: PairStore,
  ctx: DevicePairContext,
): HttpRouter.HttpRouter<never, never> {
  return HttpRouter.empty.pipe(
    // start is mounted with `all` so a wrong method reaches the handler and
    // gets an explicit 405 (the test asserts GET → 405) rather than the
    // router's default 404.
    HttpRouter.all(
      "/xrpc/dev.cocore.devicePair.start",
      Effect.gen(function* () {
        const req = yield* HttpServerRequest.HttpServerRequest;
        if (req.method !== "POST") return err(405, { error: "MethodNotAllowed" });
        return ok(store.start());
      }).pipe(Effect.withSpan("appview.devicePair.start")),
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
            name: `paired machine (${new Date().toISOString().slice(0, 10)})`,
          });
          session = { did, handle, apiKey: secret, apiBase: ctx.apiBase };
        }
        try {
          const entry = store.approve(code, session);
          return ok({ ok: true, status: entry.status });
        } catch (e) {
          if (e instanceof PairError) return err(409, { error: e.message });
          return err(409, { error: e instanceof Error ? e.message : String(e) });
        }
      }).pipe(Effect.withSpan("appview.devicePair.confirm")),
    ),
  );
}
