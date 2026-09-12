// Who is asking? Resolving an application's identity for device pairing.
//
// An application that connects users' co/core accounts ("Sign in with
// co/core") announces itself with a `dev.cocore.app.registration` record on
// its OWN account — there is no central app registry, consistent with the
// rest of co/core. When `devicePair.start` carries `appDid`, this module:
//
//   1. resolves the DID document → PDS endpoint, and reads the record;
//   2. decides whether a requested return URL is one the record allows; and
//   3. checks the return host proves it belongs to that DID by serving
//      `https://<host>/.well-known/cocore-app.json` with `{"did": "<appDid>"}`.
//
// (3) is what stops a record on a stranger's account from borrowing a real
// app's domain: the record can claim any URL, but the browser is only sent
// somewhere that vouches for the DID. Everything here is cached in memory;
// `fetch` and the DID resolver are injectable so the tests need no network.

import { getPdsEndpoint } from "@atcute/identity";
import {
  CompositeDidDocumentResolver,
  PlcDidDocumentResolver,
  WebDidDocumentResolver,
} from "@atcute/identity-resolver";
import type { Did } from "@atcute/lexicons";
import { isDid } from "@atcute/lexicons/syntax";

const APP_REGISTRATION_COLLECTION = "dev.cocore.app.registration";
const WELL_KNOWN_PATH = "/.well-known/cocore-app.json";

const NAME_MAX = 40;
const DESCRIPTION_MAX = 300;
const RETURN_URLS_MAX = 10;
const REGISTRATION_TTL_MS = 10 * 60 * 1000;
const REGISTRATION_MISS_TTL_MS = 60 * 1000;
const HOST_OK_TTL_MS = 60 * 60 * 1000;
const HOST_FAIL_TTL_MS = 5 * 60 * 1000;
const FETCH_TIMEOUT_MS = 6000;

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/g;

/** The validated content of an app's registration record. */
export interface AppRegistration {
  did: string;
  name: string;
  description?: string;
  website?: string;
  iconUrl?: string;
  returnUrls: string[];
}

/** What the approve screen shows about the app; stored on the pairing. */
export interface AppIdentity {
  did: string;
  handle?: string;
  name: string;
  website?: string;
  iconUrl?: string;
  /** The return host proved it belongs to `did`. */
  verified: boolean;
  verifiedHost?: string;
}

export interface AppResolver {
  resolve(did: string): Promise<AppRegistration | null>;
  /** Does `https://<host>/.well-known/cocore-app.json` name `did`? */
  verifyHost(host: string, did: string): Promise<boolean>;
}

export interface AppResolverDeps {
  fetch?: typeof fetch;
  /** DID → PDS base URL, or null when unresolvable. Defaults to plc/web resolution. */
  resolvePds?: (did: string) => Promise<string | null>;
  now?: () => number;
}

function httpsUrl(value: unknown, max = 2048): string | undefined {
  if (typeof value !== "string" || !value || value.length > max) return undefined;
  try {
    const u = new URL(value);
    return u.protocol === "https:" && !u.username && !u.password ? u.toString() : undefined;
  } catch {
    return undefined;
  }
}

function text(value: unknown, max: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const cleaned = value.replace(CONTROL_CHARS, "").replace(/\s+/g, " ").trim();
  return cleaned ? cleaned.slice(0, max) : undefined;
}

/** Validate a raw record value into an AppRegistration, or null if unusable. */
export function parseRegistration(did: string, value: unknown): AppRegistration | null {
  if (typeof value !== "object" || value === null) return null;
  const v = value as Record<string, unknown>;
  const name = text(v.name, NAME_MAX);
  if (!name) return null;
  const returnUrls = Array.isArray(v.returnUrls)
    ? v.returnUrls
        .map((u) => httpsUrl(u))
        .filter((u): u is string => Boolean(u))
        .slice(0, RETURN_URLS_MAX)
    : [];
  const description = text(v.description, DESCRIPTION_MAX);
  const website = httpsUrl(v.website);
  const iconUrl = httpsUrl(v.iconUrl);
  return {
    did,
    name,
    ...(description ? { description } : {}),
    ...(website ? { website } : {}),
    ...(iconUrl ? { iconUrl } : {}),
    returnUrls,
  };
}

/** A requested return URL matches a registered one when origin and path
 *  agree; the query string may differ (apps pass state in it). https only. */
export function matchesRegisteredReturnUrl(
  candidate: string,
  registered: readonly string[],
): boolean {
  let c: URL;
  try {
    c = new URL(candidate);
  } catch {
    return false;
  }
  if (c.protocol !== "https:" || c.username || c.password) return false;
  const path = c.pathname.replace(/\/+$/, "") || "/";
  return registered.some((r) => {
    try {
      const ru = new URL(r);
      return ru.origin === c.origin && (ru.pathname.replace(/\/+$/, "") || "/") === path;
    } catch {
      return false;
    }
  });
}

const defaultDidResolver = new CompositeDidDocumentResolver({
  methods: { plc: new PlcDidDocumentResolver(), web: new WebDidDocumentResolver() },
});

async function defaultResolvePds(did: string): Promise<string | null> {
  if (!isDid(did)) return null;
  try {
    const doc = await defaultDidResolver.resolve(did as Did<"plc" | "web">);
    return getPdsEndpoint(doc) ?? null;
  } catch {
    return null;
  }
}

async function fetchWithTimeout(f: typeof fetch, url: string, ms: number): Promise<Response> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), ms);
  try {
    return await f(url, {
      signal: ac.signal,
      redirect: "follow",
      headers: { accept: "application/json" },
    });
  } finally {
    clearTimeout(t);
  }
}

export function createAppResolver(deps: AppResolverDeps = {}): AppResolver {
  const f = deps.fetch ?? fetch;
  const resolvePds = deps.resolvePds ?? defaultResolvePds;
  const now = deps.now ?? (() => Date.now());
  const registrations = new Map<string, { at: number; value: AppRegistration | null }>();
  const hosts = new Map<string, { at: number; ok: boolean }>();

  return {
    async resolve(did) {
      if (!isDid(did)) return null;
      const cached = registrations.get(did);
      if (cached) {
        const ttl = cached.value ? REGISTRATION_TTL_MS : REGISTRATION_MISS_TTL_MS;
        if (now() - cached.at < ttl) return cached.value;
      }
      let value: AppRegistration | null = null;
      try {
        const pds = await resolvePds(did);
        if (pds) {
          const url =
            `${pds.replace(/\/$/, "")}/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(did)}` +
            `&collection=${APP_REGISTRATION_COLLECTION}&rkey=self`;
          const res = await fetchWithTimeout(f, url, FETCH_TIMEOUT_MS);
          if (res.ok) {
            const body = (await res.json()) as { value?: unknown };
            value = parseRegistration(did, body.value);
          }
        }
      } catch {
        value = null;
      }
      registrations.set(did, { at: now(), value });
      return value;
    },

    async verifyHost(host, did) {
      const key = `${host.toLowerCase()}|${did}`;
      const cached = hosts.get(key);
      if (cached && now() - cached.at < (cached.ok ? HOST_OK_TTL_MS : HOST_FAIL_TTL_MS)) {
        return cached.ok;
      }
      let ok = false;
      try {
        const res = await fetchWithTimeout(
          f,
          `https://${host}${WELL_KNOWN_PATH}`,
          FETCH_TIMEOUT_MS,
        );
        if (res.ok) {
          const body = (await res.json()) as { did?: unknown; dids?: unknown };
          const listed = Array.isArray(body.dids) ? body.dids : [body.did];
          ok = listed.some((d) => typeof d === "string" && d === did);
        }
      } catch {
        ok = false;
      }
      hosts.set(key, { at: now(), ok });
      return ok;
    },
  };
}
