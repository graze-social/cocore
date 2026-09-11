// Validation for what a requester may attach to a pairing attempt.
//
// Twin of the relevant half of packages/appview/src/devicepair/pair-meta.ts
// (the packages do not share code). The console only needs this for its
// legacy in-process pair store; in production it forwards `start` to the
// AppView, which validates and rate-limits.

import type { PairMeta } from "./pair-store.ts";

const APP_NAME_MAX = 40;
const KEY_NAME_MAX = 100;
const RETURN_URL_MAX = 2000;

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

function sanitizeReturnUrl(value: unknown, allowedHosts: readonly string[]): string | undefined {
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
