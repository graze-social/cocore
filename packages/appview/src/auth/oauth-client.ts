// AppView-side atproto OAuth client.
//
// The AppView is the *executor* of PDS writes: it `restore()`s a
// DPoP-bound session and calls `session.handle()` for com.atproto.repo.*
// operations. It never runs the authorize/callback handshake — that
// stays browser-facing on the console, which hands the freshly minted
// session off to the AppView (see the session store). Because OAuth
// refresh tokens are single-use, exactly one process may own a session's
// refresh; once handed off, the AppView is that owner.
//
// For token refresh to succeed, this client must present the SAME
// `client_id` + keyset as the console that minted the session — so we
// mirror the console's config (client metadata served at the console
// origin, private key from ATPROTO_PRIVATE_KEY_JWK).

import type { Did } from "@atcute/lexicons";
import type { ClientAssertionPrivateJwk, StoredState } from "@atcute/oauth-node-client";
import {
  CompositeDidDocumentResolver,
  CompositeHandleResolver,
  LocalActorResolver,
  PlcDidDocumentResolver,
  WebDidDocumentResolver,
  WellKnownHandleResolver,
} from "@atcute/identity-resolver";
import { NodeDnsHandleResolver } from "@atcute/identity-resolver-node";
import { MemoryStore, OAuthClient } from "@atcute/oauth-node-client";
import { oauthScopes } from "@cocore/sdk/oauth-scope";
import { logWarn, makeRuntime, metrics, record } from "@cocore/o11y";
import { Metric } from "effect";

import type { AccountStore } from "../operational/account-store.ts";
import { AccountOauthSessionStore } from "./oauth-session-store.ts";

const OAUTH_STATE_TTL_MS = 15 * 60_000;

// One o11y runtime for the module (no-op until OTLP is configured). Used to
// surface session-restore failures, which were previously swallowed silently
// — the 2026-06 incident's dead exchange session showed up only as a
// downstream 401 string with no cause attached.
const runtime = makeRuntime({ serviceName: "cocore-appview" });

/** Classify a `client.restore()` failure into a coarse, low-cardinality
 *  reason so a metric/log can distinguish "a human must re-authenticate"
 *  from "retry later". Single-use refresh tokens mean an `invalid_grant` is
 *  terminal (the session is dead until re-auth); network/5xx errors are
 *  transient. Errs toward "unknown" rather than mislabeling. */
export function classifyRestoreError(e: unknown): "needs_reauth" | "transient" | "unknown" {
  const msg = (e instanceof Error ? e.message : String(e)).toLowerCase();
  if (/invalid_grant|invalid_token|revoked|expired|unauthorized_client|no.*session/.test(msg)) {
    return "needs_reauth";
  }
  if (
    /fetch failed|network|timeout|timed out|socket|econnrefused|econnreset|enotfound|etimedout|503|502|504|429/.test(
      msg,
    )
  ) {
    return "transient";
  }
  return "unknown";
}

/** Base URL of the console origin that owns the OAuth client identity
 *  (serves /api/auth/atproto/metadata.json + jwks.json). Same precedence
 *  as the console's getBaseUrl so both resolve to the same client_id. */
function getClientBaseUrl(): string {
  const url =
    process.env["ATPROTO_BASE_URL"] ||
    process.env["CONSOLE_PUBLIC_URL"] ||
    process.env["BETTER_AUTH_URL"];
  if (url) return url.replace(/\/$/, "");
  return "http://localhost:3000";
}

function isPublicClient(baseUrl: string): boolean {
  return baseUrl.startsWith("http://localhost") || baseUrl.startsWith("http://127.0.0.1");
}

function getRedirectUri(baseUrl: string): string {
  if (isPublicClient(baseUrl)) {
    return `${baseUrl.replace("localhost", "127.0.0.1").replace(/\/$/, "")}/api/auth/atproto/callback`;
  }
  return `${baseUrl}/api/auth/atproto/callback`;
}

function getPrivateKey(): ClientAssertionPrivateJwk {
  const keyJson = process.env["ATPROTO_PRIVATE_KEY_JWK"];
  if (!keyJson) {
    throw new Error("ATPROTO_PRIVATE_KEY_JWK is required for a non-local OAuth client");
  }
  return JSON.parse(keyJson) as ClientAssertionPrivateJwk;
}

// Shared with the console's minting client via `@cocore/sdk/oauth-scope` —
// both the minting client (console) and this restoring client present the
// same grant, so the client-metadata matches at restore/refresh.

function actorResolver(): LocalActorResolver {
  return new LocalActorResolver({
    handleResolver: new CompositeHandleResolver({
      methods: { dns: new NodeDnsHandleResolver(), http: new WellKnownHandleResolver() },
    }),
    didDocumentResolver: new CompositeDidDocumentResolver({
      methods: { plc: new PlcDidDocumentResolver(), web: new WebDidDocumentResolver() },
    }),
  });
}

export type AppviewOAuthClient = InstanceType<typeof OAuthClient>;
export type RestoredSession = Awaited<ReturnType<AppviewOAuthClient["restore"]>>;

/** True when this process can construct a usable OAuth client: always for
 *  a localhost/public client, and for a confidential client only when the
 *  private key is present. Used to decide whether to register the PDS
 *  write routes. */
export function isOAuthConfigured(): boolean {
  const baseUrl = getClientBaseUrl();
  if (isPublicClient(baseUrl)) return true;
  return Boolean(process.env["ATPROTO_PRIVATE_KEY_JWK"]);
}

/** Build the AppView OAuth client, reading/writing sessions through the
 *  AccountStore. States live in memory (only the authorize/callback
 *  handshake uses them, which the AppView does not perform). */
export function makeAppviewOAuth(accounts: AccountStore): AppviewOAuthClient {
  const baseUrl = getClientBaseUrl();
  const redirectUri = getRedirectUri(baseUrl);
  const sessions = new AccountOauthSessionStore(accounts);
  const states = new MemoryStore<string, StoredState>({
    ttl: OAUTH_STATE_TTL_MS,
    ttlAutopurge: true,
  });

  if (isPublicClient(baseUrl)) {
    return new OAuthClient({
      metadata: { redirect_uris: [redirectUri], scope: oauthScopes },
      stores: { sessions, states },
      actorResolver: actorResolver(),
    });
  }
  return new OAuthClient({
    metadata: {
      client_id: `${baseUrl}/api/auth/atproto/metadata.json`,
      redirect_uris: [redirectUri],
      scope: oauthScopes,
      jwks_uri: `${baseUrl}/api/auth/atproto/jwks.json`,
    },
    keyset: [getPrivateKey()],
    stores: { sessions, states },
    actorResolver: actorResolver(),
  });
}

/** Restore the DPoP-bound session for `did`, or null if none is stored /
 *  it can no longer be refreshed. */
export async function restoreSession(
  client: AppviewOAuthClient,
  did: Did,
  opts: {
    /** Called when the failure is definitively `needs_reauth`, so the caller
     *  can drop the dead stored session. Without this the stored blob keeps
     *  its (now useless) refresh token, `/internal/pds/session-info` keeps
     *  answering `present: true`, and the console treats the user as signed
     *  in while every write 401s — instead of logging them out. */
    onNeedsReauth?: (did: Did) => void;
  } = {},
): Promise<RestoredSession | null> {
  try {
    return await client.restore(did);
  } catch (e) {
    // Don't swallow silently. The 2026-06 settlement stall hid here: a dead
    // exchange session surfaced only as a downstream 401 string with no
    // cause, so it took days to spot. Emit a classified metric + structured
    // log so "this service DID needs re-auth" is a first-class, alertable
    // signal. Still return null (the caller's "session gone → 401" contract
    // is unchanged) — we only make the failure observable.
    const reason = classifyRestoreError(e);
    record(runtime, Metric.increment(metrics.oauthRestoreFailed(reason)));
    record(
      runtime,
      logWarn("oauth session restore failed", {
        did,
        reason,
        error: e instanceof Error ? e.message : String(e),
      }),
    );
    // Only a definitive verdict drops the session; a transient/unknown
    // failure must never log a user out.
    if (reason === "needs_reauth") {
      try {
        opts.onNeedsReauth?.(did);
      } catch {
        /* best-effort: the 401 contract below is unchanged */
      }
    }
    return null;
  }
}

/** Keep a set of long-lived SERVICE DID sessions warm so they never lapse
 *  from disuse. The AppView is the single owner/refresher of every session
 *  (refresh tokens are single-use — two refreshers cannibalize one token), so
 *  this MUST run in exactly one place: here, inside the AppView. Each tick
 *  calls `restoreSession`, which rotates + persists the refresh token, so a
 *  session that would otherwise sit idle past its refresh-token lifetime (the
 *  way the exchange DID died in 2026-06, blocking every settlement write)
 *  stays alive — and any failure is surfaced by `restoreSession`'s metric/log
 *  above. Returns a stop function. No-op for an empty DID list. */
export function startServiceSessionKeepAlive(opts: {
  client: AppviewOAuthClient;
  dids: string[];
  intervalMs: number;
  /** Seam for tests; defaults to the real `restoreSession`. */
  restore?: (client: AppviewOAuthClient, did: Did) => Promise<RestoredSession | null>;
  log?: (line: string) => void;
}): () => void {
  const dids = opts.dids.filter((d) => typeof d === "string" && d.startsWith("did:"));
  if (dids.length === 0 || opts.intervalMs <= 0) return () => {};
  const restore = opts.restore ?? restoreSession;
  const log = opts.log ?? ((l: string) => console.error(l));

  const tick = async () => {
    for (const did of dids) {
      try {
        const session = await restore(opts.client, did as Did);
        if (!session) {
          log(`oauth-keepalive: ${did} session could not be restored (needs re-auth?)`);
        }
      } catch (e) {
        // restore() shouldn't throw (it catches internally), but never let a
        // keep-alive tick crash the timer.
        log(`oauth-keepalive: ${did} threw: ${(e as Error).message}`);
      }
    }
  };

  // Fire once on the next tick (not synchronously — let the caller finish
  // wiring) and then on the interval. unref so the timer never holds the
  // process open on its own.
  const timer = setInterval(() => void tick(), opts.intervalMs);
  if (typeof timer.unref === "function") timer.unref();
  // Eager warm-up shortly after boot.
  const warm = setTimeout(() => void tick(), 5_000);
  if (typeof warm.unref === "function") warm.unref();

  return () => {
    clearInterval(timer);
    clearTimeout(warm);
  };
}
