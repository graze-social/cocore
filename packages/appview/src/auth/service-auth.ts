// AT Protocol service-auth verification for AppView XRPC methods.
//
// Ported from the console's service-auth.server.ts (the canonical
// `dev.cocore.account.*` path), parameterized so it isn't tied to the
// console's config: the caller passes the expected `audience` (this
// service's DID) and `lxm` (the method NSID).
//
// A requester's client asks its own PDS to proxy the call
// (`atproto-proxy: <appviewDid>#cocore_appview`); the PDS mints a
// short-lived JWT signed by the user's repo signing key and forwards it
// as `Authorization: Bearer <jwt>`. The JWT carries:
//
//   iss  the requester's DID            (who we authenticate)
//   aud  this service's DID              (must equal `audience`)
//   lxm  the method NSID being called    (must equal `lxm`)
//   exp  expiry (unix seconds)
//
// We verify the signature against the key published in the issuer's DID
// document — a valid token *is* proof the holder controls that DID, with
// no shared secret and no credential of ours to leak.

import { getPublicKeyFromDidController, verifySig } from "@atcute/crypto";
import { getAtprotoVerificationMaterial } from "@atcute/identity";
import {
  CompositeDidDocumentResolver,
  PlcDidDocumentResolver,
  WebDidDocumentResolver,
} from "@atcute/identity-resolver";
import type { Did } from "@atcute/lexicons";
import { isDid } from "@atcute/lexicons/syntax";
import { fromBase64Url } from "@atcute/multibase";
import { makeRuntime } from "@cocore/o11y";
import { Cache, Duration, Effect, Exit } from "effect";

/** Tolerance for clock skew between the issuing PDS and us. */
const CLOCK_SKEW_SECONDS = 30;

/** Max accepted token lifetime (L9). A captured service-auth JWT replays until
 *  its `exp`; a malicious or buggy issuer can set `exp` far in the future,
 *  widening that window arbitrarily. Reject any token whose `exp` is more than
 *  this far out, so even a leaked token expires quickly. Service-auth tokens
 *  are minted per-call right before use, so a few minutes is ample. */
const MAX_TOKEN_LIFETIME_SECONDS = 5 * 60;

/** In-memory replay guard (L9). When a token carries a `jti`, remember it for
 *  the token's remaining lifetime and reject a second presentation — a captured
 *  token can't be replayed within its (now short) validity window. Best-effort:
 *  per-process only (fine for our single-listener AppView) and additive (tokens
 *  without a `jti` are unaffected). Entries are pruned lazily on insert. */
const seenJti = new Map<string, number>();

function jtiAlreadySeen(jti: string, expMs: number): boolean {
  const now = Date.now();
  // Opportunistic prune so the map can't grow without bound.
  if (seenJti.size > 10_000) {
    for (const [k, v] of seenJti) if (v <= now) seenJti.delete(k);
  }
  const prior = seenJti.get(jti);
  if (prior !== undefined && prior > now) return true;
  seenJti.set(jti, expMs);
  return false;
}

/** Success carries the authenticated DID; failure carries everything a
 *  handler needs to emit an error response. Distinct error codes mirror
 *  the standard atproto auth-failure vocabulary so callers can tell an
 *  expired token from a wrong audience. */
export type ServiceAuthResult =
  | { ok: true; did: string }
  | { ok: false; status: number; error: string; message: string };

function fail(status: number, error: string, message: string): ServiceAuthResult {
  return { ok: false, status, error, message };
}

// did:plc and did:web only — matches the repo-wide DID policy.
const didResolver = new CompositeDidDocumentResolver({
  methods: {
    plc: new PlcDidDocumentResolver(),
    web: new WebDidDocumentResolver(),
  },
});

type ResolvableDid = Did<"plc" | "web">;

// Cached, traced DID-document resolution. The verify path resolves the
// issuer's DID document on every request to fetch its signing key; the
// same handful of requesters call repeatedly within seconds, so an
// uncached resolve hammers plc.directory / the did:web host. We wrap the
// resolver in an Effect `Cache` with a TTL so repeated lookups for a DID
// hit memory instead of the network, and put a span around each *actual*
// lookup (cache misses only) named "identity.resolve".
//
// Failures are NOT cached: `makeWith` gives a zero TTL to a failed Exit,
// so a transient resolution error doesn't pin a DID into a broken state
// — the next request re-resolves, matching the pre-cache behavior.
const DID_DOC_CACHE_CAPACITY = 1024;
const DID_DOC_CACHE_TTL = Duration.minutes(5);

// One telemetry runtime for this module. A no-op (Layer.empty tracing)
// until OTEL_EXPORTER_OTLP_* is set — see @cocore/o11y.
const runtime = makeRuntime({
  serviceName: process.env["OTEL_SERVICE_NAME"] ?? "cocore-appview",
  serviceVersion: process.env["COCORE_SOFTWARE_VERSION"],
});

const didDocCache = runtime.runSync(
  Cache.makeWith({
    capacity: DID_DOC_CACHE_CAPACITY,
    lookup: (did: ResolvableDid) =>
      Effect.tryPromise(() => didResolver.resolve(did)).pipe(
        Effect.withSpan("identity.resolve", { attributes: { did } }),
      ),
    timeToLive: (exit) => (Exit.isSuccess(exit) ? DID_DOC_CACHE_TTL : Duration.zero),
  }),
);

/** Resolve a DID document through the TTL cache. Mirrors
 *  `didResolver.resolve` — rejects on resolution failure (which is not
 *  cached). Kept private; the verify path is the only caller. */
function resolveDidDocument(
  did: ResolvableDid,
): Promise<Awaited<ReturnType<typeof didResolver.resolve>>> {
  return runtime.runPromise(didDocCache.get(did));
}

function readBearer(request: Request): string | null {
  const h = request.headers.get("authorization");
  if (!h) return null;
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1]!.trim() : null;
}

interface JwtPayload {
  iss?: unknown;
  aud?: unknown;
  lxm?: unknown;
  exp?: unknown;
  nbf?: unknown;
  jti?: unknown;
}

function decodeJson(segment: string): unknown {
  return JSON.parse(new TextDecoder().decode(fromBase64Url(segment)));
}

export interface VerifyServiceAuthOptions {
  /** This service's DID. The JWT's `aud` must equal it. */
  audience: string;
  /** The method NSID. The JWT's `lxm` must equal it. */
  lxm: string;
}

/** Verify the service-auth JWT on `request` for `opts.audience` +
 *  `opts.lxm`. Convenience wrapper over {@link verifyServiceAuthToken}
 *  for Web `Request` callers; node:http handlers should extract the
 *  bearer token themselves and call `verifyServiceAuthToken`. */
export function verifyServiceAuth(
  request: Request,
  opts: VerifyServiceAuthOptions,
): Promise<ServiceAuthResult> {
  return verifyServiceAuthToken(readBearer(request), opts);
}

/** Verify a raw service-auth JWT string for `opts.audience` + `opts.lxm`.
 *  Returns the authenticated DID on success. Every failure collapses to
 *  a 401-shaped result (success vs. each failure isn't meaningfully
 *  distinguishable to an attacker; the error code aids legitimate
 *  debugging). Pass `null` when no token was presented. */
export async function verifyServiceAuthToken(
  jwt: string | null,
  opts: VerifyServiceAuthOptions,
): Promise<ServiceAuthResult> {
  if (!jwt) {
    return fail(401, "AuthRequired", "Authorization: Bearer <service-auth jwt> required");
  }

  const parts = jwt.split(".");
  if (parts.length !== 3) return fail(401, "BadJwt", "malformed JWT");
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

  let header: { alg?: unknown };
  let payload: JwtPayload;
  try {
    header = decodeJson(headerB64) as { alg?: unknown };
    payload = decodeJson(payloadB64) as JwtPayload;
  } catch {
    return fail(401, "BadJwt", "JWT header/payload not valid base64url JSON");
  }

  if (header.alg !== "ES256" && header.alg !== "ES256K") {
    return fail(401, "BadJwt", "unsupported JWT alg (expected ES256 or ES256K)");
  }

  const { iss, aud, lxm, exp, nbf, jti } = payload;

  if (typeof iss !== "string" || !isDid(iss)) {
    return fail(401, "BadJwtIssuer", "iss must be a DID");
  }
  if (!iss.startsWith("did:plc:") && !iss.startsWith("did:web:")) {
    return fail(401, "BadJwtIssuer", "iss must be a did:plc or did:web");
  }
  if (aud !== opts.audience) {
    return fail(401, "BadJwtAudience", "aud does not match this service");
  }
  if (lxm !== opts.lxm) {
    return fail(401, "BadJwtLexicon", `lxm does not match ${opts.lxm}`);
  }
  if (typeof exp !== "number") {
    return fail(401, "BadJwt", "exp missing");
  }
  const now = Date.now() / 1000;
  if (exp <= now - CLOCK_SKEW_SECONDS) {
    return fail(401, "JwtExpired", "token expired");
  }
  if (typeof nbf === "number" && nbf > now + CLOCK_SKEW_SECONDS) {
    return fail(401, "BadJwt", "token not yet valid");
  }
  // L9: cap the accepted lifetime so a captured (or maliciously long-lived)
  // token can't replay for hours. `nbf` when present anchors the lower bound;
  // otherwise measure from now.
  const issuedFloor = typeof nbf === "number" ? nbf : now;
  if (exp - issuedFloor > MAX_TOKEN_LIFETIME_SECONDS + CLOCK_SKEW_SECONDS) {
    return fail(401, "BadJwt", "token lifetime exceeds the maximum allowed");
  }

  // Resolve the issuer's DID document and pull the atproto signing key.
  let material: { type: string; publicKeyMultibase: string } | undefined;
  try {
    const doc = await resolveDidDocument(iss as ResolvableDid);
    material = getAtprotoVerificationMaterial(doc);
  } catch {
    return fail(401, "BadJwtIssuer", "could not resolve issuer DID document");
  }
  if (!material) {
    return fail(401, "BadJwtIssuer", "issuer DID document has no atproto signing key");
  }

  let verified: boolean;
  try {
    const key = getPublicKeyFromDidController(material);
    if (key.jwtAlg !== header.alg) {
      return fail(401, "BadJwtSignature", "JWT alg does not match issuer key");
    }
    const data = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    verified = await verifySig(key, fromBase64Url(sigB64), data);
  } catch {
    return fail(401, "BadJwtSignature", "signature verification failed");
  }
  if (!verified) return fail(401, "BadJwtSignature", "signature verification failed");

  // L9: single-use replay guard for tokens carrying a `jti`. Recorded only
  // AFTER the signature verifies, so an attacker can't pre-poison the cache
  // with a victim's jti on an unsigned token to deny the legitimate call.
  // Additive — tokens without a `jti` are accepted exactly as before.
  if (typeof jti === "string" && jti.length > 0) {
    if (jtiAlreadySeen(jti, exp * 1000)) {
      return fail(401, "JwtReplayed", "token already used");
    }
  }

  return { ok: true, did: iss };
}
