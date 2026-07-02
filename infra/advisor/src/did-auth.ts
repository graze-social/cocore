// AT Protocol service-auth verification for the advisor.
//
// Ported from packages/appview/src/auth/service-auth.ts, trimmed to what
// the advisor needs and made resolver-injectable so the verify path can be
// unit-tested without hitting plc.directory / a did:web host (tests pass a
// stub resolver; production uses the real did:plc + did:web resolver).
//
// The provider mints the JWT via `com.atproto.server.getServiceAuth` with
//   aud = COCORE_ADVISOR_DID   (this advisor's DID, e.g. did:web:advisor.cocore.dev)
//   lxm = the method NSID being authorized (register / control)
// Its PDS signs the JWT with the provider's repo signing key. A valid token
// IS proof the holder controls the `iss` DID — no shared secret, nothing of
// ours to leak. We verify the signature against the key published in the
// issuer's DID document.
//
// The JWT carries:
//   iss  the provider's DID          (who we authenticate — must be did:plc/did:web)
//   aud  this advisor's DID          (must equal `audience`)
//   lxm  the method NSID             (must equal `lxm`)
//   exp  expiry (unix seconds)       (checked with clock skew)
//   nbf  not-before (optional)       (checked with clock skew)

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

/** Tolerance for clock skew between the issuing PDS and us. */
const CLOCK_SKEW_SECONDS = 30;

/** Max accepted token lifetime (L9 parity / defense-in-depth). A
 *  `getServiceAuth` token is short-lived (~60s by default), so a token whose
 *  `exp` is far in the future is anomalous — a captured one would otherwise
 *  replay until that distant expiry. Reject anything valid for materially
 *  longer than a mint-and-use round-trip needs. */
const MAX_TOKEN_LIFETIME_SECONDS = 300;

/** TTL for the DID-document resolution cache below. */
const DID_DOC_CACHE_TTL_MS = 5 * 60_000;
const DID_DOC_CACHE_MAX = 4096;
/** Hard ceiling on a single DID-document resolution. The verify path awaits
 *  this on the register hot path; without a bound a slow/hostile plc.directory
 *  (or a did:web host that never responds) would stall the registration. On
 *  timeout we reject → the token fails to verify (fail-closed). */
const DID_RESOLVE_TIMEOUT_MS = 8_000;

/** Success carries the authenticated DID; failure carries a status + error
 *  code (mirroring the atproto auth-failure vocabulary) so legitimate
 *  debugging can tell an expired token from a wrong audience. */
export type ServiceAuthResult =
  | { ok: true; did: string }
  | { ok: false; status: number; error: string; message: string };

function fail(status: number, error: string, message: string): ServiceAuthResult {
  return { ok: false, status, error, message };
}

type ResolvableDid = Did<"plc" | "web">;

/** The one thing the verify path needs from a DID resolver: fetch the
 *  document so we can pull the atproto signing key. Injectable so tests can
 *  stub resolution instead of hitting the network. */
export interface DidDocumentResolver {
  resolve(did: ResolvableDid): Promise<unknown>;
}

// did:plc and did:web only — matches the repo-wide DID policy.
const defaultResolver: DidDocumentResolver = new CompositeDidDocumentResolver({
  methods: {
    plc: new PlcDidDocumentResolver(),
    web: new WebDidDocumentResolver(),
  },
});

// TTL cache for DID-document resolution against the DEFAULT resolver only.
// The verify path resolves the issuer's DID doc on every register/control, and
// the advisor sees frequent reconnect churn (Railway edge recycles sockets
// every ~30–90s), so the same handful of providers re-register repeatedly
// within seconds — an uncached resolve would hammer plc.directory / the
// did:web host. Failures are NOT cached (a transient error mustn't pin a DID
// into a broken state — the next call re-resolves). Injected resolvers (tests)
// bypass this cache so a test that expects re-resolution isn't defeated.
const didDocCache = new Map<string, { doc: unknown; at: number }>();

/** Reject `p` if it hasn't settled within `ms`. Used to bound DID resolution. */
function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    timer.unref?.();
    p.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

async function resolveCached(did: ResolvableDid, now = Date.now()): Promise<unknown> {
  const hit = didDocCache.get(did);
  if (hit && now - hit.at < DID_DOC_CACHE_TTL_MS) return hit.doc;
  const doc = await withTimeout(
    Promise.resolve(defaultResolver.resolve(did)),
    DID_RESOLVE_TIMEOUT_MS,
    "did resolve",
  );
  // Bound the cache: on overflow, drop the oldest inserted entry (Map preserves
  // insertion order) so a churn of distinct DIDs can't grow it unbounded.
  if (didDocCache.size >= DID_DOC_CACHE_MAX) {
    const oldest = didDocCache.keys().next().value;
    if (oldest !== undefined) didDocCache.delete(oldest);
  }
  didDocCache.set(did, { doc, at: now });
  return doc;
}

interface JwtPayload {
  iss?: unknown;
  aud?: unknown;
  lxm?: unknown;
  exp?: unknown;
  nbf?: unknown;
}

function decodeJson(segment: string): unknown {
  return JSON.parse(new TextDecoder().decode(fromBase64Url(segment)));
}

export interface VerifyServiceAuthOptions {
  /** This advisor's DID. The JWT's `aud` must equal it. */
  audience: string;
  /** The method NSID. The JWT's `lxm` must equal it. */
  lxm: string;
  /** DID-document resolver; defaults to the real did:plc + did:web one.
   *  Tests inject a stub to avoid the network. */
  resolver?: DidDocumentResolver;
}

/** Verify a raw service-auth JWT string for `opts.audience` + `opts.lxm`.
 *  Returns the authenticated DID on success. Every failure collapses to a
 *  401-shaped result (success vs. each failure isn't meaningfully
 *  distinguishable to an attacker; the error code aids legitimate
 *  debugging). Pass `null`/`undefined` when no token was presented. */
export async function verifyServiceAuthToken(
  jwt: string | null | undefined,
  opts: VerifyServiceAuthOptions,
): Promise<ServiceAuthResult> {
  if (!jwt) {
    return fail(401, "AuthRequired", "service-auth JWT required");
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

  const { iss, aud, lxm, exp, nbf } = payload;

  if (typeof iss !== "string" || !isDid(iss)) {
    return fail(401, "BadJwtIssuer", "iss must be a DID");
  }
  if (!iss.startsWith("did:plc:") && !iss.startsWith("did:web:")) {
    return fail(401, "BadJwtIssuer", "iss must be a did:plc or did:web");
  }
  if (aud !== opts.audience) {
    return fail(401, "BadJwtAudience", "aud does not match this advisor");
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
  // Reject a token whose lifetime is implausibly long (L9 / replay window).
  if (exp - now > MAX_TOKEN_LIFETIME_SECONDS + CLOCK_SKEW_SECONDS) {
    return fail(401, "BadJwt", "token lifetime exceeds the accepted maximum");
  }
  if (typeof nbf === "number" && nbf > now + CLOCK_SKEW_SECONDS) {
    return fail(401, "BadJwt", "token not yet valid");
  }

  // Resolve the issuer's DID document and pull the atproto signing key. An
  // injected resolver (tests) is used directly; the default resolver goes
  // through the TTL cache to avoid hammering plc.directory under reconnect
  // churn.
  let material: { type: string; publicKeyMultibase: string } | undefined;
  try {
    const doc = opts.resolver
      ? await opts.resolver.resolve(iss as ResolvableDid)
      : await resolveCached(iss as ResolvableDid);
    material = getAtprotoVerificationMaterial(
      doc as Parameters<typeof getAtprotoVerificationMaterial>[0],
    );
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

  return { ok: true, did: iss };
}

/** NSIDs the advisor authorizes service-auth JWTs against. The provider mints
 *  its Register JWT with `lxm = LXM_REGISTER`; the console mints its /control
 *  JWT with `lxm = LXM_CONTROL`. Binding each token to a single method stops a
 *  JWT minted for one advisor action being replayed against another. */
export const LXM_REGISTER = "dev.cocore.compute.register";
export const LXM_CONTROL = "dev.cocore.compute.control";
