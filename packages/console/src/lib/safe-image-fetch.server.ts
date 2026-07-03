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
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
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
  const [a, b, c] = octets;
  if (a === 0) return true; // 0.0.0.0/8 "this network"
  if (a === 127) return true; // loopback 127.0.0.0/8
  if (a === 10) return true; // private 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // private 172.16.0.0/12
  if (a === 192 && b === 168) return true; // private 192.168.0.0/16
  if (a === 169 && b === 254) return true; // link-local 169.254.0.0/16 (incl. metadata)
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
  if (a === 192 && b === 0 && c === 0) return true; // IETF protocol assignments 192.0.0.0/24
  if (a === 192 && b === 0 && c === 2) return true; // TEST-NET-1 192.0.2.0/24
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking 198.18.0.0/15
  if (a === 198 && b === 51 && c === 100) return true; // TEST-NET-2 198.51.100.0/24
  if (a === 203 && b === 0 && c === 113) return true; // TEST-NET-3 203.0.113.0/24
  if (a >= 224) return true; // multicast (224/4) + reserved (240/4) + 255.255.255.255
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
  // IPv4-mapped / -compatible in DOTTED form: ::ffff:1.2.3.4 or ::1.2.3.4.
  const mapped = /^::(?:ffff:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(input.split("%")[0]!);
  if (mapped) {
    const v4 = parseIpv4(mapped[1]!);
    return v4 ? isBlockedIpv4(v4) : true;
  }
  const groups = expandIpv6(input);
  if (!groups) return true; // unparseable → refuse

  // CRITICAL: `new URL()` normalizes an IPv4-mapped literal to its HEX form
  // (`::ffff:169.254.169.254` → `::ffff:a9fe:a9fe`), which the dotted regex
  // above never sees. Reclassify any embedded-IPv4 form by the embedded v4 so
  // `http://[::ffff:169.254.169.254]/` (metadata), `[::ffff:7f00:1]` (loopback),
  // etc. are blocked. Covers: ::ffff:/96 (mapped), ::/96 (compat, incl. :: and
  // ::1 which resolve to 0.0.0.0 / 0.0.0.1 — both already blocked), 2002::/16
  // (6to4), and 64:ff9b::/96 (NAT64 well-known prefix).
  const asV4 = (hi: number, lo: number): [number, number, number, number] => [
    (hi >> 8) & 0xff,
    hi & 0xff,
    (lo >> 8) & 0xff,
    lo & 0xff,
  ];
  const [g0, g1, g2, g3, g4, g5, g6, g7] = groups as [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
  ];
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0) {
    // ::/80 prefix — mapped (g5 === 0xffff) or IPv4-compatible (g5 === 0).
    if (g5 === 0xffff || g5 === 0) return isBlockedIpv4(asV4(g6, g7));
  }
  if (g0 === 0x2002) return isBlockedIpv4(asV4(g1, g2)); // 6to4: v4 in groups 1..2
  if (g0 === 0x0064 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) {
    return isBlockedIpv4(asV4(g6, g7)); // NAT64 64:ff9b::/96
  }

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

/** Build a `lookup` override for node's http(s).request that always resolves to
 *  `pinnedAddress`, honoring BOTH callback contracts node uses:
 *   - `{ all: true }` — node's Happy Eyeballs / `autoSelectFamily` (default-on
 *     since node 20) calls lookup this way and expects an ARRAY of
 *     `{ address, family }`. Returning a bare string here makes node read
 *     `.address` off a string → `undefined` → "Invalid IP address: undefined",
 *     which breaks EVERY legitimate fetch (regression fixed here).
 *   - single-address — the legacy form expects `cb(null, address, family)`.
 *  Either way the socket connects to the vetted IP; SNI/Host/cert stay bound to
 *  the URL's hostname so TLS still validates against the real host. */
export function makePinnedLookup(pinnedAddress: string) {
  const family = isIP(pinnedAddress) || 4;
  return (
    _hostname: string,
    options: unknown,
    callback: (err: Error | null, address: unknown, family?: number) => void,
  ): void => {
    const wantsAll =
      typeof options === "object" &&
      options !== null &&
      (options as { all?: boolean }).all === true;
    if (wantsAll) {
      callback(null, [{ address: pinnedAddress, family }]);
    } else {
      callback(null, pinnedAddress, family);
    }
  };
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
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  let vetted: Awaited<ReturnType<typeof assertPublicUrl>>;
  try {
    vetted = await assertPublicUrl(rawUrl, opts.dnsLookup);
  } catch (e) {
    console.error(`[safe-image-fetch] rejected url: ${(e as Error).message}`);
    throw new UnsafeImageUrlError();
  }

  try {
    // Injected fetch (tests): keep the fetch-based path. Connection pinning is
    // a production-only concern — tests exercise the IP/DNS logic via a stub.
    if (opts.fetchImpl) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await opts.fetchImpl(vetted.url.toString(), {
          signal: controller.signal,
          redirect: "error",
        });
        if (!res.ok) throw new UnsafeImageUrlError();
        const mime = res.headers.get("content-type")?.split(";")[0]?.trim() || "";
        if (!mime.startsWith("image/")) throw new UnsafeImageUrlError();
        const buf = new Uint8Array(await res.arrayBuffer());
        if (buf.byteLength > opts.maxBytes) throw new UnsafeImageUrlError();
        return { bytes: buf, mime };
      } finally {
        clearTimeout(timer);
      }
    }
    // Production path: PIN the socket to the vetted address so a DNS rebind
    // between assertPublicUrl and the connect can't reach an internal host, and
    // STREAM with a hard byte cap (no full-body buffering → no memory DoS).
    return await pinnedImageFetch(vetted.url, vetted.pinnedAddress, opts.maxBytes, timeoutMs);
  } catch (e) {
    if (e instanceof UnsafeImageUrlError) throw e;
    console.error(`[safe-image-fetch] fetch failed: ${(e as Error).message}`);
    throw new UnsafeImageUrlError();
  }
}

/** GET an already-vetted image URL with the TCP connection pinned to
 *  `pinnedAddress` (via the `lookup` override, so `assertPublicUrl`'s DNS
 *  decision is the one that's honored — TLS SNI / Host / cert stay bound to the
 *  URL's real hostname). Streams the body and aborts past `maxBytes`. Node's
 *  `request` does NOT follow redirects, so a 3xx is rejected rather than
 *  chased to an internal host. Rejects with `UnsafeImageUrlError` on anything. */
function pinnedImageFetch(
  url: URL,
  pinnedAddress: string,
  maxBytes: number,
  timeoutMs: number,
): Promise<SafeFetchedImage> {
  const request = url.protocol === "https:" ? httpsRequest : httpRequest;
  return new Promise<SafeFetchedImage>((resolve, reject) => {
    const fail = (why: string): void => {
      console.error(`[safe-image-fetch] ${why} for ${url.hostname}`);
      reject(new UnsafeImageUrlError());
    };
    const req = request(
      url,
      {
        method: "GET",
        headers: { accept: "image/*" },
        timeout: timeoutMs,
        // Force the connection to the vetted IP; SNI/Host/cert remain the
        // hostname so TLS still validates against the real host. Handles node's
        // Happy-Eyeballs `{ all: true }` array contract — see makePinnedLookup.
        lookup: makePinnedLookup(pinnedAddress) as never,
      },
      (res) => {
        const status = res.statusCode ?? 0;
        if (status < 200 || status >= 300) {
          res.resume();
          return fail(`upstream ${status}`);
        }
        const mime = (res.headers["content-type"] ?? "").split(";")[0]!.trim();
        if (!mime.startsWith("image/")) {
          res.resume();
          return fail(`non-image content-type ${mime}`);
        }
        const declared = Number(res.headers["content-length"]);
        if (Number.isFinite(declared) && declared > maxBytes) {
          res.destroy();
          return fail(`content-length ${declared} exceeds ${maxBytes}`);
        }
        const chunks: Buffer[] = [];
        let total = 0;
        res.on("data", (chunk: Buffer) => {
          total += chunk.length;
          if (total > maxBytes) {
            res.destroy();
            fail(`response exceeds ${maxBytes} bytes`);
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => resolve({ bytes: new Uint8Array(Buffer.concat(chunks)), mime }));
        res.on("error", (e) => fail(`response error ${e.message}`));
      },
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", (e) => fail(`request error ${e.message}`));
    req.end();
  });
}
