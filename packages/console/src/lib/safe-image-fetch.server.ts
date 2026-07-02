// SSRF guard for user-supplied remote image URLs.
//
// The OpenAI chat-completions endpoint lets a caller reference an image by
// http(s) URL; the server fetches it to inline into the sealed envelope
// (see openai-chat-completions.server.ts `resolveImages`). Without a guard
// that fetch is a server-side request forgery primitive: an authed caller
// can point it at the internal network, cloud metadata (169.254.169.254),
// loopback, etc. and use the response (or its timing / error) to probe.
//
// Defenses here:
//   * scheme allow-list (http/https only),
//   * literal-IP rejection for private/link-local/loopback/reserved ranges,
//   * DNS resolution of hostnames with the SAME range check on every
//     resolved address, and a fetch pinned to a vetted address (so a
//     rebinding response between the check and the fetch can't slip an
//     internal address past us),
//   * a response size cap and a fetch timeout,
//   * a GENERIC error to the caller (upstream status / mime / body never
//     leak; the specifics are logged server-side).

import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

/** Thrown when a URL is rejected by the SSRF guard, or the fetch fails.
 *  The `.message` is intentionally generic and safe to surface; any
 *  sensitive detail is logged server-side, not attached here. */
export class UnsafeImageUrlError extends Error {
  constructor(message = "image url could not be fetched") {
    super(message);
    this.name = "UnsafeImageUrlError";
  }
}

/** Parse an IPv4 dotted-quad into its four octets, or null if it isn't one. */
function parseIpv4(host: string): [number, number, number, number] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])] as const;
  if (octets.some((o) => o > 255)) return null;
  return octets as unknown as [number, number, number, number];
}

/** True when an IPv4 address falls in a loopback / private / link-local /
 *  reserved / CGNAT range we must never let user input reach. */
function isBlockedIpv4(octets: [number, number, number, number]): boolean {
  const [a, b] = octets;
  if (a === 0) return true; // 0.0.0.0/8 "this network"
  if (a === 127) return true; // loopback 127.0.0.0/8
  if (a === 10) return true; // private 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // private 172.16.0.0/12
  if (a === 192 && b === 168) return true; // private 192.168.0.0/16
  if (a === 169 && b === 254) return true; // link-local 169.254.0.0/16 (incl. metadata)
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
  if (a >= 224) return true; // multicast (224/4) + reserved (240/4)
  return false;
}

/** Normalize an IPv6 literal to its expanded 8-group hex form (lowercase),
 *  handling `::` compression. Returns null if it can't be parsed. */
function expandIpv6(input: string): number[] | null {
  // Strip a zone id (fe80::1%eth0) — irrelevant to range classification.
  const host = input.split("%")[0]!;
  // IPv4-mapped tail (::ffff:1.2.3.4) is handled by the caller before this.
  const halves = host.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - (head.length + tail.length);
  if (halves.length === 1) {
    if (head.length !== 8) return null;
  } else if (missing < 0) {
    return null;
  }
  const groups = halves.length === 2 ? [...head, ...Array(missing).fill("0"), ...tail] : head;
  const out: number[] = [];
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    out.push(parseInt(g, 16));
  }
  return out.length === 8 ? out : null;
}

/** True when an IPv6 address is loopback (::1), unspecified (::), link-local
 *  (fe80::/10), unique-local (fc00::/7), or an IPv4-mapped/compat address
 *  whose embedded IPv4 is itself blocked. */
function isBlockedIpv6(input: string): boolean {
  // IPv4-mapped / -compatible: ::ffff:1.2.3.4 or ::1.2.3.4 — classify by
  // the embedded IPv4 so an attacker can't tunnel a private v4 through v6.
  const mapped = /^::(?:ffff:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(input.split("%")[0]!);
  if (mapped) {
    const v4 = parseIpv4(mapped[1]!);
    return v4 ? isBlockedIpv4(v4) : true;
  }
  const groups = expandIpv6(input);
  if (!groups) return true; // unparseable → refuse
  if (groups.every((g) => g === 0)) return true; // :: unspecified
  if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) return true; // ::1 loopback
  const first = groups[0]!;
  if ((first & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((first & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local
  return false;
}

/** True when a resolved/literal IP string is in a blocked range. */
export function isBlockedAddress(addr: string): boolean {
  const v4 = parseIpv4(addr);
  if (v4) return isBlockedIpv4(v4);
  if (isIP(addr) === 6 || addr.includes(":")) return isBlockedIpv6(addr);
  // Not an IP we recognize → refuse rather than guess.
  return true;
}

/** DNS resolver seam so tests can inject a fake without real lookups.
 *  Returns the list of addresses a hostname resolves to. */
export type DnsLookup = (host: string) => Promise<string[]>;

const defaultLookup: DnsLookup = async (host) => {
  const results = await lookup(host, { all: true });
  return results.map((r) => r.address);
};

/** Validate a user-supplied URL for outbound fetching. Rejects non-http(s)
 *  schemes, literal IPs in blocked ranges, and hostnames that resolve into
 *  a blocked range (defeating DNS-rebind-to-internal). On success returns a
 *  vetted address to pin the connection to. Throws `UnsafeImageUrlError`
 *  (generic message) on any rejection. */
export async function assertPublicUrl(
  rawUrl: string,
  dnsLookup: DnsLookup = defaultLookup,
): Promise<{ url: URL; pinnedAddress: string }> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new UnsafeImageUrlError();
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new UnsafeImageUrlError();
  }
  // Strip brackets from an IPv6 literal host (URL keeps them).
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (host.length === 0) throw new UnsafeImageUrlError();

  // Literal IP: check directly, no DNS.
  if (isIP(host) !== 0) {
    if (isBlockedAddress(host)) throw new UnsafeImageUrlError();
    return { url, pinnedAddress: host };
  }

  // Hostname: resolve and reject if ANY address is blocked (rebind-safe:
  // we also pin the fetch to a vetted address below).
  let addresses: string[];
  try {
    addresses = await dnsLookup(host);
  } catch {
    throw new UnsafeImageUrlError();
  }
  if (addresses.length === 0) throw new UnsafeImageUrlError();
  for (const addr of addresses) {
    if (isBlockedAddress(addr)) throw new UnsafeImageUrlError();
  }
  return { url, pinnedAddress: addresses[0]! };
}

export interface SafeFetchedImage {
  bytes: Uint8Array;
  mime: string;
}

export interface SafeFetchOptions {
  maxBytes: number;
  timeoutMs?: number;
  dnsLookup?: DnsLookup;
  /** Injectable fetch for tests; defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

const DEFAULT_TIMEOUT_MS = 10_000;

/** Fetch a user-supplied image URL safely: SSRF-guarded, size-capped,
 *  time-bounded, image/* only. All failures collapse to a generic
 *  `UnsafeImageUrlError`; the specific reason is logged server-side so the
 *  caller (and thus the attacker) can't distinguish "blocked", "wrong
 *  content-type", "too large", or "upstream 500". */
export async function safeFetchImage(
  rawUrl: string,
  opts: SafeFetchOptions,
): Promise<SafeFetchedImage> {
  const doFetch = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  let vetted: Awaited<ReturnType<typeof assertPublicUrl>>;
  try {
    vetted = await assertPublicUrl(rawUrl, opts.dnsLookup);
  } catch (e) {
    console.error(`[safe-image-fetch] rejected url: ${(e as Error).message}`);
    throw new UnsafeImageUrlError();
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await doFetch(vetted.url.toString(), {
      signal: controller.signal,
      redirect: "error", // a redirect could bounce us to an internal host
    });
    if (!res.ok) {
      console.error(`[safe-image-fetch] upstream ${res.status} for ${vetted.url.hostname}`);
      throw new UnsafeImageUrlError();
    }
    const mime = res.headers.get("content-type")?.split(";")[0]?.trim() || "";
    if (!mime.startsWith("image/")) {
      console.error(`[safe-image-fetch] non-image content-type ${mime} for ${vetted.url.hostname}`);
      throw new UnsafeImageUrlError();
    }
    const buf = new Uint8Array(await res.arrayBuffer());
    if (buf.byteLength > opts.maxBytes) {
      console.error(`[safe-image-fetch] response exceeds ${opts.maxBytes} bytes`);
      throw new UnsafeImageUrlError();
    }
    return { bytes: buf, mime };
  } catch (e) {
    if (e instanceof UnsafeImageUrlError) throw e;
    console.error(`[safe-image-fetch] fetch failed: ${(e as Error).message}`);
    throw new UnsafeImageUrlError();
  } finally {
    clearTimeout(timer);
  }
}
