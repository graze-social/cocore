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

import { verifyServiceAuthToken } from "../auth/service-auth.ts";
import type { AccountStore } from "../operational/account-store.ts";
import { hydrateDids } from "../bsky-hydrate.ts";
import { bearer, err, jsonBody, ok, searchParams } from "../api/http-app.ts";
import { type PairStore, type ProviderSession } from "./pair-store.ts";

export interface DevicePairContext {
  /** Mints the scoped API key handed to the paired agent. */
  accountStore: AccountStore;
  /** This AppView's service DID — the `aud` that confirm's service-auth
   *  JWT must target. */
  appviewDid: string;
  /** Console origin agents append `/api/pds/*` to (console resolves the
   *  Bearer key and forwards the write here internally). */
  apiBase: string;
}

/** Whether an `apiBase` is a safe target for a paired agent to POST records
 *  to. The agent trusts whatever apiBase we bind into its ProviderSession
 *  and sends its scoped API key there, so an attacker-supplied apiBase in
 *  the confirm body is a credential-exfiltration vector. Tighten it:
 *   - require https:, EXCEPT localhost/127.0.0.1 over http for dev; and
 *   - when COCORE_DEVICEPAIR_ALLOWED_HOSTS (comma-separated hostnames) is
 *     set, the apiBase host MUST be in that allowlist.
 *  Anything else (plain http to a non-loopback host, an unlisted host, or an
 *  unparseable URL) is rejected. */
function isAllowedApiBase(apiBase: string): boolean {
  let url: URL;
  try {
    url = new URL(apiBase);
  } catch {
    return false;
  }
  const isLoopback = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol === "http:") {
    if (!isLoopback) return false; // http only for local dev
  } else if (url.protocol !== "https:") {
    return false; // no ws:, file:, etc.
  }

  const allowed = process.env["COCORE_DEVICEPAIR_ALLOWED_HOSTS"];
  if (allowed && allowed.trim().length > 0) {
    const hosts = allowed
      .split(",")
      .map((h) => h.trim().toLowerCase())
      .filter((h) => h.length > 0);
    if (!hosts.includes(url.hostname.toLowerCase())) return false;
  }
  return true;
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
    // SECURITY: was `s.apiBase.startsWith("http")`, which accepted any
    // http(s) origin (an apiBase-injection / key-exfil vector). Require a
    // vetted target (https or loopback, plus optional host allowlist).
    isAllowedApiBase(s.apiBase)
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

        if (body.decision !== "approve" && body.decision !== "deny") {
          return err(400, {
            error: "InvalidRequest",
            message: "decision must be approve|deny",
          });
        }

        // SECURITY: any non-approve outcome returns this SAME response
        // (status + body) whether the code was unknown, in the wrong state,
        // or over the confirm-attempt cap — so confirm is not a code-
        // existence oracle and mismatched attempts are throttled in the
        // store. Deny needs no session; build one only for approve.
        const uniformFailure = err(409, { ok: false, status: "denied" });

        if (body.decision === "deny") {
          const r = store.confirm(code, "deny", null);
          return r.ok ? ok({ ok: true, status: r.status }) : uniformFailure;
        }

        // Approve: bind a ProviderSession to the pairing. When the console
        // forwards confirm it mints the key in its own store (so Bearer
        // auth on `/api/pds/*` resolves) and passes the session here.
        // Fall back to minting on the AppView for direct callers / tests.
        // A providerSession with a rejected apiBase (see isAllowedApiBase)
        // fails isProviderSession and is treated as absent — we mint a fresh
        // key against the trusted ctx.apiBase rather than trust the caller's.
        const bodySession = body.providerSession;
        let session: ProviderSession;
        if (isProviderSession(bodySession)) {
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
        const r = store.confirm(code, "approve", session);
        return r.ok ? ok({ ok: true, status: r.status }) : uniformFailure;
      }).pipe(Effect.withSpan("appview.devicePair.confirm")),
    ),
  );
}
