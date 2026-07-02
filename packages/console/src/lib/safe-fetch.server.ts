// SSRF-hardened fetch for user-supplied URLs (currently: remote `image_url`s in
// the OpenAI-compatible chat-completions proxy).
//
// The chat-completions body lets a caller point an `image_url` at ANY http(s)
// URL, which the console then fetches from its own network position. Without a
// guard that is a server-side request forgery primitive: a caller can reach
// cloud metadata (169.254.169.254), loopback, and internal-only services, and
// use response status / timing as an oracle. This module gates every such fetch:
//
//   * scheme must be http/https; port must be 80/443 (blocks odd internal ports)
//   * the hostname is DNS-resolved and EVERY resolved IP must be public
//     (loopback / private / link-local / ULA / CGNAT / multicast / reserved and
//     IPv4-mapped/embedded forms are rejected)
//   * redirects are followed manually and each hop is re-validated (a public URL
//     can 302 to an internal one)
//   * an AbortController bounds the wall-clock, and callers cap the body size
//   * all failures collapse to a single generic Error — no URL/status/host is
//     reflected back to the caller, so the oracle is closed
//
// Residual risk: DNS rebinding between our lookup and fetch's own connect. Full
// mitigation needs pinning the validated IP for the socket; Node's fetch doesn't
// expose that, so we accept the narrow TOCTOU and re-validate on every redirect.

import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

const DEFAULT_TIMEOUT_MS = Number(process.env["COCORE_IMAGE_FETCH_TIMEOUT_MS"] ?? 10_000);
const MAX_REDIRECTS = 3;

/** Remote (non-data:) image fetching can be disabled entirely — the envelope
 *  already supports inline `data:` URIs, so an operator can require those. */
const REMOTE_DISABLED = process.env["COCORE_IMAGE_FETCH_REMOTE_DISABLED"] === "1";

/** Optional comma-separated hostname allowlist. When set, only these hosts
 *  (exact, case-insensitive) may be fetched, in addition to the IP checks. */
const HOST_ALLOWLIST = (process.env["COCORE_IMAGE_FETCH_ALLOW_HOSTS"] ?? "")
  .split(",")
  .map((h) => h.trim().toLowerCase())
  .filter((h) => h.length > 0);

/** A deliberately opaque error — callers surface it verbatim so no upstream
 *  status, content-type, host, or reachability signal leaks to the requester. */
export class ImageFetchError extends Error {
  constructor() {
    super("image fetch failed");
    this.name = "ImageFetchError";
  }
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const o = Number(p);
    if (!Number.isInteger(o) || o < 0 || o > 255 || !/^\d+$/.test(p)) return null;
    n = n * 256 + o;
  }
  return n >>> 0;
}

function isBlockedIpv4(ip: string): boolean {
  const n = ipv4ToInt(ip);
  if (n === null) return true; // unparseable ⇒ treat as blocked
  const inRange = (base: string, prefix: number): boolean => {
    const b = ipv4ToInt(base)!;
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return (n & mask) === (b & mask);
  };
  return (
    inRange("0.0.0.0", 8) || // "this" network / unspecified
    inRange("10.0.0.0", 8) || // private
    inRange("100.64.0.0", 10) || // CGNAT
    inRange("127.0.0.0", 8) || // loopback
    inRange("169.254.0.0", 16) || // link-local (incl. 169.254.169.254 metadata)
    inRange("172.16.0.0", 12) || // private
    inRange("192.0.0.0", 24) || // IETF protocol assignments
    inRange("192.0.2.0", 24) || // TEST-NET-1
    inRange("192.88.99.0", 24) || // 6to4 relay anycast
    inRange("192.168.0.0", 16) || // private
    inRange("198.18.0.0", 15) || // benchmarking
    inRange("198.51.100.0", 24) || // TEST-NET-2
    inRange("203.0.113.0", 24) || // TEST-NET-3
    inRange("224.0.0.0", 4) || // multicast
    inRange("240.0.0.0", 4) // reserved / broadcast
  );
}

function isBlockedIpv6(ip: string): boolean {
  const lower = ip.toLowerCase().split("%")[0]!; // strip any zone id
  // IPv4-mapped/embedded (::ffff:a.b.c.d, ::a.b.c.d, 64:ff9b::a.b.c.d) — pull
  // out the trailing dotted-quad and apply the v4 rules.
  const embedded = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(lower);
  if (embedded) return isBlockedIpv4(embedded[1]!);
  if (lower === "::" || lower === "::1") return true; // unspecified / loopback
  if (lower.startsWith("fe8") || lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb")) {
    return true; // fe80::/10 link-local
  }
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // fc00::/7 ULA
  if (lower.startsWith("ff")) return true; // ff00::/8 multicast
  return false;
}

function isBlockedIp(ip: string): boolean {
  const kind = isIP(ip);
  if (kind === 4) return isBlockedIpv4(ip);
  if (kind === 6) return isBlockedIpv6(ip);
  return true; // not an IP literal ⇒ blocked
}

/** Validate scheme/port/host and confirm every resolved IP is public. Throws
 *  {@link ImageFetchError} on any violation. */
async function assertSafeUrl(raw: string): Promise<URL> {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new ImageFetchError();
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new ImageFetchError();
  if (u.port !== "" && u.port !== "80" && u.port !== "443") throw new ImageFetchError();

  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (HOST_ALLOWLIST.length > 0 && !HOST_ALLOWLIST.includes(host)) throw new ImageFetchError();

  // If the host is an IP literal, check it directly; otherwise resolve all
  // addresses and require every one to be public.
  if (isIP(host)) {
    if (isBlockedIp(host)) throw new ImageFetchError();
    return u;
  }
  let addrs: { address: string }[];
  try {
    addrs = await lookup(host, { all: true });
  } catch {
    throw new ImageFetchError();
  }
  if (addrs.length === 0) throw new ImageFetchError();
  for (const a of addrs) {
    if (isBlockedIp(a.address)) throw new ImageFetchError();
  }
  return u;
}

/**
 * SSRF-guarded GET for a user-supplied image URL. Validates the URL (and every
 * redirect hop) against the private-range/scheme/port rules, bounds the
 * wall-clock, and returns the final 2xx `Response`. The caller is responsible
 * for content-type and body-size checks. Throws {@link ImageFetchError} — with
 * no detail — on any failure.
 */
export async function safeImageFetch(rawUrl: string): Promise<Response> {
  if (REMOTE_DISABLED) throw new ImageFetchError();

  let current = rawUrl;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
  try {
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const url = await assertSafeUrl(current);
      const res = await fetch(url, {
        redirect: "manual",
        signal: controller.signal,
        headers: { accept: "image/*" },
      });
      // Manual redirect handling: re-validate the target before following.
      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get("location");
        if (!loc) throw new ImageFetchError();
        current = new URL(loc, url).toString();
        continue;
      }
      if (!res.ok) throw new ImageFetchError();
      return res;
    }
    throw new ImageFetchError(); // too many redirects
  } catch (e) {
    if (e instanceof ImageFetchError) throw e;
    throw new ImageFetchError(); // network error / abort / anything ⇒ opaque
  } finally {
    clearTimeout(timer);
  }
}
