// A stand-in for an @atcute `OAuthSession` whose PDS calls are executed by
// the AppView instead of by a live, locally-refreshed session.
//
// THE point of the cutover: refresh tokens are single-use, so exactly one
// process may refresh a given session. The AppView is that owner (the
// console hands the session off at login). If the console ALSO restored +
// refreshed locally — which `OAuthClient.restore()` does whenever the
// access token is stale — the two would rotate the same token in parallel
// and cannibalize it (`invalid_grant` → dead session → write 401s). So
// when forwarding is configured, the console's auth entry points return
// THIS object instead of a restored session. Every `.handle()` it makes is
// replayed by the AppView's owned session via `/internal/pds/proxy`; the
// console refreshes nothing.
//
// The console's PDS helpers consume a session through exactly three
// members — `.did`, `.handle(path, init)`, and `.getTokenInfo().aud` — so
// this implements those and is handed back through the same `OAuthSession`
// type (a structural cast at the factory). It is gated on the same
// COCORE_APPVIEW_INTERNAL_URL + COCORE_INTERNAL_SECRET as the write
// forward; with them unset the entry points keep using the legacy local
// session and nothing here runs.

import type { Did } from "@atcute/lexicons";
import type { OAuthSession } from "@atcute/oauth-node-client";

import { slowCallThresholdMs, warnFields } from "@/lib/o11y.server.ts";

/** Time one console→AppView call and log it when slow.
 *
 *  The AppView already records its own handler time (`pds.restore_ms`,
 *  `pds.upstream_ms`), and both come back fast while signed-in pages take
 *  seconds. That leaves a gap neither side measures: the round-trip over
 *  Railway internal networking, plus any queueing before the handler runs.
 *  This closes it by timing from the caller — `ms` here minus the AppView's
 *  own handler time IS that gap. */
async function timedInternalCall<T>(op: string, did: string, run: () => Promise<T>): Promise<T> {
  const start = Date.now();
  try {
    return await run();
  } finally {
    const ms = Date.now() - start;
    if (ms >= slowCallThresholdMs()) {
      warnFields("slow console→appview call", { op, did, ms });
    }
  }
}

function base(): string | null {
  return process.env["COCORE_APPVIEW_INTERNAL_URL"]?.replace(/\/$/, "") || null;
}
function secret(): string | null {
  return process.env["COCORE_INTERNAL_SECRET"] || null;
}

/** Read a header value off the loose `HeadersInit` shapes the helpers pass
 *  (`Headers`, array of tuples, or a plain record). Case-insensitive. */
function headerValue(headers: HeadersInit | undefined, name: string): string | undefined {
  if (!headers) return undefined;
  const lower = name.toLowerCase();
  if (headers instanceof Headers) return headers.get(name) ?? undefined;
  if (Array.isArray(headers)) {
    for (const [k, v] of headers) if (k.toLowerCase() === lower) return v;
    return undefined;
  }
  for (const [k, v] of Object.entries(headers)) if (k.toLowerCase() === lower) return v;
  return undefined;
}

interface ProxyResult {
  status: number;
  bodyText: string;
  contentType?: string;
}

type HandleInit = { method?: string; headers?: HeadersInit; body?: BodyInit };

class AppviewBackedSession {
  readonly did: Did;

  constructor(did: Did) {
    this.did = did;
  }

  /** Replay an XRPC call through the AppView's owned session. Returns a real
   *  `Response` rebuilt from the upstream status + body, so the console's
   *  helpers (`r.ok` / `r.status` / `r.json()` / `r.text()`) behave exactly
   *  as they did against a local session — including a 404 for a missing
   *  record or a 401 for a dead session. */
  async handle(path: string, init?: HandleInit): Promise<Response> {
    const b = base();
    const s = secret();
    if (!b || !s) throw new Error("AppView forward not configured");

    const method = (init?.method ?? "GET").toUpperCase();
    const contentType = headerValue(init?.headers, "content-type");
    let bodyText: string | undefined;
    let blobB64: string | undefined;
    const body = init?.body;
    if (body != null && method !== "GET" && method !== "HEAD") {
      if (typeof body === "string") bodyText = body;
      else if (body instanceof Uint8Array) blobB64 = Buffer.from(body).toString("base64");
      else if (body instanceof ArrayBuffer)
        blobB64 = Buffer.from(new Uint8Array(body)).toString("base64");
      else bodyText = String(body);
    }

    const res = await timedInternalCall("proxy", this.did, () =>
      fetch(`${b}/internal/pds/proxy`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-cocore-internal-secret": s },
        body: JSON.stringify({
          did: this.did,
          path,
          method,
          ...(bodyText !== undefined ? { bodyText } : {}),
          ...(blobB64 !== undefined ? { blobB64 } : {}),
          ...(contentType ? { contentType } : {}),
        }),
      }),
    );
    if (!res.ok) {
      // Internal-layer failure (403 secret / 502 restore-threw / network):
      // a real transport problem, not an upstream PDS status. Throw so the
      // helpers' catch / `!r.ok` paths treat it like a local session throw.
      const t = await res.text().catch(() => "");
      throw new Error(`appview proxy ${path} internal ${res.status}: ${t.slice(0, 200)}`);
    }
    const out = (await res.json()) as ProxyResult;
    return new Response(out.bodyText, {
      status: out.status,
      headers: { "content-type": out.contentType ?? "application/json" },
    });
  }

  /** Only `.aud` is consumed by callers (to render the PDS URL). Served by
   *  the AppView's non-refreshing session-info read. */
  async getTokenInfo(): Promise<{ aud: string }> {
    const info = await appviewSessionInfo(this.did);
    if (!info.aud) throw new Error("AppView session-info missing aud");
    return { aud: info.aud };
  }
}

export type AppviewSessionInfo = { checked: boolean; present: boolean; aud: string | null };

/**
 * Rendering one signed-in page asked the AppView for the SAME session-info,
 * with the same DID, twice: once in `atprotoSessionForRequestEffect` to decide
 * whether a live session exists, and again via `getPdsUrl` → `getTokenInfo()`
 * to read `.aud`. Both are serial and on the critical path, so the second one
 * was pure duplicated latency — measured at roughly a third of a signed-in
 * page's server time.
 *
 * A short TTL collapses them. It is deliberately brief: this read gates
 * logging a user out, so it must not serve a stale "present" for long. Only
 * DEFINITIVE answers (`checked: true`) are cached — a transient AppView blip
 * must be retried on the next call, never remembered.
 */
const SESSION_INFO_TTL_MS = 5_000;
/** Bound on distinct DIDs held at once; the cache is a latency trick, not a
 *  store, so it is cheaper to drop it wholesale than to track an LRU. */
const SESSION_INFO_MAX_ENTRIES = 5_000;

const sessionInfoCache = new Map<string, { expiresAt: number; value: AppviewSessionInfo }>();

/** Test seam: drop memoized session-info so cases don't leak into each other. */
export function resetAppviewSessionInfoCache(): void {
  sessionInfoCache.clear();
}

async function fetchAppviewSessionInfo(did: string): Promise<AppviewSessionInfo> {
  const b = base();
  const s = secret();
  if (!b || !s) return { checked: false, present: false, aud: null };
  try {
    const res = await timedInternalCall("session-info", did, () =>
      fetch(`${b}/internal/pds/session-info?did=${encodeURIComponent(did)}`, {
        headers: { "x-cocore-internal-secret": s },
      }),
    );
    if (!res.ok) return { checked: false, present: false, aud: null };
    const body = (await res.json()) as { present?: boolean; aud?: string | null };
    return { checked: true, present: body.present === true, aud: body.aud ?? null };
  } catch {
    return { checked: false, present: false, aud: null };
  }
}

/** Liveness + PDS-URL for a DID, read from the AppView's owned session
 *  WITHOUT refreshing. `checked` distinguishes a definitive answer (the
 *  AppView responded) from "couldn't reach the AppView" — callers must only
 *  log a user out on `checked && !present`, never on a transient blip.
 *  Definitive answers are memoized for SESSION_INFO_TTL_MS. */
export async function appviewSessionInfo(did: string): Promise<AppviewSessionInfo> {
  const now = Date.now();
  const hit = sessionInfoCache.get(did);
  if (hit && hit.expiresAt > now) return hit.value;

  const value = await fetchAppviewSessionInfo(did);
  if (value.checked) {
    if (sessionInfoCache.size >= SESSION_INFO_MAX_ENTRIES) sessionInfoCache.clear();
    sessionInfoCache.set(did, { expiresAt: now + SESSION_INFO_TTL_MS, value });
  } else {
    // Never let a blip mask a later definitive answer.
    sessionInfoCache.delete(did);
  }
  return value;
}

/** Build an AppView-backed session for `did`. Structurally implements the
 *  subset of `OAuthSession` the console's PDS helpers use (`.did`,
 *  `.handle`, `.getTokenInfo`); the cast asserts that contract. */
export function appviewBackedSession(did: Did): OAuthSession {
  return new AppviewBackedSession(did) as unknown as OAuthSession;
}
