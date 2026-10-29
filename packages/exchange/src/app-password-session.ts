// App-password session manager for the exchange's OWN PDS writes.
//
// Why this exists: the exchange writes settlement / policy / attestation
// records to its own repo (cocore.dev). Routing those through the console's
// OAuth/DPoP proxy made settlement depend on a single-use, single-owner OAuth
// refresh token that lapsed from disuse and required a HUMAN to
// re-authenticate — the root cause of the 2026-06 settlement stall (and it
// added a console→appview hop that was independently 502'ing).
//
// A service account is better served by a credential it fully controls: an
// ATProto app password. From it the exchange can mint a fresh session
// (com.atproto.server.createSession) at any time and keep the short-lived
// access token fresh (com.atproto.server.refreshSession), re-minting straight
// from the app password if a refresh ever fails. No browser, no human, no
// expiry cliff. App-password sessions are plain Bearer (not DPoP-bound),
// which is exactly what com.atproto.repo.createRecord accepts — so the
// exchange writes directly to its PDS with no proxy in the path.
//
// This is scoped to the exchange's own service identity. It does NOT replace
// per-user OAuth (the console can't hold one app password for every member).

import { withRecordType } from "@cocore/sdk/record-type";
import { resolvePdsEndpoint } from "@cocore/sdk/resolve";

export type SessionEvent = "created" | "refreshed" | "refresh_failed" | "create_failed";

export interface AppPasswordSessionOptions {
  /** Login identifier — the account handle (e.g. "cocore.dev") or its DID. */
  identifier: string;
  /** ATProto app password (xxxx-xxxx-xxxx-xxxx). A long-lived secret. */
  appPassword: string;
  /** DID of the account; used to resolve the PDS endpoint when one isn't
   *  given explicitly, and as the fallback `repo` for writes. */
  did: string;
  /** Explicit PDS base URL. When absent, resolved from `did` via the DID doc. */
  pdsEndpoint?: string;
  /** Injectable fetch (tests). */
  fetchImpl?: typeof fetch;
  /** Observability hook — fired on each session lifecycle event. */
  onEvent?: (event: SessionEvent) => void;
  /** Logger seam (defaults to console.error). */
  log?: (line: string) => void;
  /** Refresh the access token this many ms before its `exp`. Default 120s. */
  refreshSkewMs?: number;
  /** Clock seam (tests). */
  now?: () => number;
}

interface SessionTokens {
  accessJwt: string;
  refreshJwt: string;
  did: string;
  /** Access-token expiry (epoch ms); 0 if unknown, negative once invalidated. */
  accessExpMs: number;
}

const DEFAULT_REFRESH_SKEW_MS = 120_000;

/** Decode a JWT's `exp` (seconds) → epoch ms, or 0 when unavailable. Used only
 *  to refresh PROACTIVELY; we still refresh REACTIVELY on any 401, so a
 *  missing/garbled exp just degrades to refresh-on-demand. */
function jwtExpMs(jwt: string): number {
  const parts = jwt.split(".");
  if (parts.length < 2) return 0;
  try {
    const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as {
      exp?: number;
    };
    return typeof payload.exp === "number" ? payload.exp * 1000 : 0;
  } catch {
    return 0;
  }
}

export class AppPasswordSession {
  private tokens: SessionTokens | null = null;
  private pds: string | null;
  private inflight: Promise<SessionTokens> | null = null;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private readonly refreshSkewMs: number;
  // Explicit field + assignment (not a constructor parameter property):
  // the services container runs the TS source under Node's strip-only type
  // stripping, which rejects `constructor(private ...)` parameter properties.
  private readonly opts: AppPasswordSessionOptions;

  constructor(opts: AppPasswordSessionOptions) {
    this.opts = opts;
    this.pds = opts.pdsEndpoint?.replace(/\/$/, "") ?? null;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.now = opts.now ?? (() => Date.now());
    this.refreshSkewMs = opts.refreshSkewMs ?? DEFAULT_REFRESH_SKEW_MS;
  }

  private log(line: string): void {
    (this.opts.log ?? ((l: string) => console.error(l)))(line);
  }

  /** Resolve (and cache) the account's PDS endpoint. */
  async pdsEndpoint(): Promise<string> {
    if (this.pds) return this.pds;
    const ep = await resolvePdsEndpoint(this.opts.did);
    if (!ep) throw new Error(`app-password: no PDS endpoint published for ${this.opts.did}`);
    this.pds = ep.replace(/\/$/, "");
    return this.pds;
  }

  /** The account's DID — from the minted session, falling back to config. */
  did(): string {
    return this.tokens?.did ?? this.opts.did;
  }

  /** A valid access token, minting or refreshing as needed. Concurrent callers
   *  share one in-flight mint/refresh. */
  async accessToken(): Promise<string> {
    const t = this.tokens;
    if (
      t &&
      t.accessExpMs >= 0 &&
      (t.accessExpMs === 0 || this.now() < t.accessExpMs - this.refreshSkewMs)
    ) {
      return t.accessJwt;
    }
    return (await this.ensure()).accessJwt;
  }

  /** Force the next accessToken() to refresh — call after a 401. */
  invalidate(): void {
    if (this.tokens) this.tokens.accessExpMs = -1;
  }

  /** Authenticated request against the session's PDS, with one refresh+retry on
   *  a 401 (stale access token). `path` is an xrpc path beginning with "/". */
  async fetchAuthed(
    path: string,
    init: { method: string; body?: string; contentType?: string },
  ): Promise<Response> {
    const pds = await this.pdsEndpoint();
    let last: Response | null = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      const token = await this.accessToken();
      const headers: Record<string, string> = { authorization: `Bearer ${token}` };
      if (init.contentType) headers["content-type"] = init.contentType;
      last = await this.fetchImpl(`${pds}${path}`, {
        method: init.method,
        headers,
        ...(init.body !== undefined ? { body: init.body } : {}),
      });
      if (last.status === 401 && attempt === 0) {
        this.invalidate();
        continue;
      }
      return last;
    }
    return last as Response;
  }

  private ensure(): Promise<SessionTokens> {
    if (this.inflight) return this.inflight;
    const p = (async () => {
      try {
        if (this.tokens?.refreshJwt) {
          try {
            return await this.refresh();
          } catch (e) {
            this.log(`app-password: refresh failed (${(e as Error).message}); re-creating session`);
            this.opts.onEvent?.("refresh_failed");
          }
        }
        return await this.create();
      } finally {
        this.inflight = null;
      }
    })();
    this.inflight = p;
    return p;
  }

  private async create(): Promise<SessionTokens> {
    const pds = await this.pdsEndpoint();
    const r = await this.fetchImpl(`${pds}/xrpc/com.atproto.server.createSession`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier: this.opts.identifier, password: this.opts.appPassword }),
    });
    if (!r.ok) {
      this.opts.onEvent?.("create_failed");
      const text = await r.text().catch(() => "");
      throw new Error(`createSession ${r.status}: ${text.slice(0, 200)}`);
    }
    this.tokens = this.tokensFrom(await r.json());
    this.opts.onEvent?.("created");
    return this.tokens;
  }

  private async refresh(): Promise<SessionTokens> {
    const pds = await this.pdsEndpoint();
    const r = await this.fetchImpl(`${pds}/xrpc/com.atproto.server.refreshSession`, {
      method: "POST",
      headers: { authorization: `Bearer ${this.tokens!.refreshJwt}` },
    });
    if (!r.ok) {
      const text = await r.text().catch(() => "");
      throw new Error(`refreshSession ${r.status}: ${text.slice(0, 200)}`);
    }
    this.tokens = this.tokensFrom(await r.json());
    this.opts.onEvent?.("refreshed");
    return this.tokens;
  }

  private tokensFrom(body: unknown): SessionTokens {
    const b = body as { accessJwt?: unknown; refreshJwt?: unknown; did?: unknown };
    if (typeof b.accessJwt !== "string" || typeof b.refreshJwt !== "string") {
      throw new Error("session response missing accessJwt/refreshJwt");
    }
    return {
      accessJwt: b.accessJwt,
      refreshJwt: b.refreshJwt,
      did: typeof b.did === "string" ? b.did : this.opts.did,
      accessExpMs: jwtExpMs(b.accessJwt),
    };
  }
}

/** Write a record to the session owner's repo, refreshing + retrying once on a
 *  401. Returns the created record's strong-ref. Throws on any other non-2xx. */
export async function createRecordViaSession(
  session: AppPasswordSession,
  args: { collection: string; record: unknown; rkey?: string },
): Promise<{ uri: string; cid: string }> {
  const r = await session.fetchAuthed("/xrpc/com.atproto.repo.createRecord", {
    method: "POST",
    contentType: "application/json",
    body: JSON.stringify({
      repo: session.did(),
      collection: args.collection,
      record: withRecordType(args.collection, args.record as object),
      ...(args.rkey ? { rkey: args.rkey } : {}),
    }),
  });
  if (!r.ok) {
    const text = await r.text().catch(() => "");
    throw new Error(`createRecord ${args.collection} returned ${r.status}: ${text.slice(0, 300)}`);
  }
  return (await r.json()) as { uri: string; cid: string };
}
