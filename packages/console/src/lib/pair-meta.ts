// Validation for what a requester may attach to a pairing attempt, and a
// small in-memory rate limiter for the now web-facing pair endpoints.
//
// Why this exists: `start` was designed for a CLI on the user's own machine.
// A web app such as Graze calling it on behalf of its users makes the approve
// screen a consent screen ("Graze wants a key on your account") and makes the
// endpoints reachable from any browser, so the inputs get bounds and the
// endpoints get a budget. Pure functions, no Effect — easy to test.

import type { PairMeta } from "./pair-store.ts";

export const APP_NAME_MAX = 40;
export const KEY_NAME_MAX = 100;
export const RETURN_URL_MAX = 2000;

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/g;

function cleanText(value: unknown, max: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const cleaned = value.replace(CONTROL_CHARS, "").replace(/\s+/g, " ").trim();
  if (!cleaned) return undefined;
  return cleaned.slice(0, max);
}

/** Parse `COCORE_PAIR_RETURN_HOSTS` ("www.graze.social, graze.social") into
 *  a lower-cased host list. Empty means no return URL is ever honoured. */
export function parseReturnHosts(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter((h) => h.length > 0);
}

/** A return URL is honoured only when it is https (http for localhost, so a
 *  developer can test), carries no credentials, and its host is on the
 *  allowlist. Anything else yields undefined — dropped, never an error, so a
 *  misconfigured requester still gets a working pairing. */
export function sanitizeReturnUrl(
  value: unknown,
  allowedHosts: readonly string[],
): string | undefined {
  if (typeof value !== "string" || value.length === 0 || value.length > RETURN_URL_MAX)
    return undefined;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return undefined;
  }
  if (url.username || url.password) return undefined;
  const host = url.hostname.toLowerCase();
  const isLocal = host === "localhost" || host === "127.0.0.1";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLocal)) return undefined;
  if (!allowedHosts.includes(host)) return undefined;
  return url.toString();
}

/** Turn an arbitrary `start` body into a PairMeta, applying every bound. */
export function sanitizePairMeta(body: unknown, allowedHosts: readonly string[]): PairMeta {
  if (typeof body !== "object" || body === null) return {};
  const b = body as Record<string, unknown>;
  const appName = cleanText(b.appName, APP_NAME_MAX);
  const keyName = cleanText(b.keyName, KEY_NAME_MAX);
  const returnUrl = sanitizeReturnUrl(b.returnUrl, allowedHosts);
  return {
    ...(appName ? { appName } : {}),
    ...(keyName ? { keyName } : {}),
    ...(returnUrl ? { returnUrl } : {}),
  };
}

/** The client IP as the edge saw it: first hop of `x-forwarded-for`, else
 *  `x-real-ip`, else "unknown" (which then shares one budget — acceptable for
 *  a fallback that should never happen behind Railway's proxy). */
export function clientKey(forwardedFor: string | undefined, realIp: string | undefined): string {
  const first = (forwardedFor ?? "").split(",")[0]?.trim();
  if (first) return first;
  const real = (realIp ?? "").trim();
  return real || "unknown";
}

export interface RateLimiter {
  /** true = allowed (and counted); false = over budget. */
  allow(key: string, now?: number): boolean;
  /** For tests and diagnostics. */
  size(): number;
}

/** Fixed-window counter per key. `limit` events per `windowMs`; a key's
 *  window starts at its first event. Windows that have elapsed are pruned on
 *  the way past, so the map cannot grow without bound. */
export function createRateLimiter(limit: number, windowMs: number): RateLimiter {
  const windows = new Map<string, { startedAt: number; count: number }>();
  let lastPrune = 0;
  return {
    allow(key, now = Date.now()) {
      if (now - lastPrune > windowMs) {
        for (const [k, w] of windows) if (now - w.startedAt > windowMs) windows.delete(k);
        lastPrune = now;
      }
      const w = windows.get(key);
      if (!w || now - w.startedAt > windowMs) {
        windows.set(key, { startedAt: now, count: 1 });
        return true;
      }
      w.count += 1;
      return w.count <= limit;
    },
    size() {
      return windows.size;
    },
  };
}
