// Configuration the console needs to talk to the local cocore stack.
//
// In docker-compose the bridge + AppView live alongside the console
// at fixed ports. In bare-node dev (cd infra/services && aube run start)
// they default to the same ports on localhost. Operators can override
// each via env: COCORE_BRIDGE_URL / COCORE_APPVIEW_URL / COCORE_ADVISOR_URL.
//
// `advisorUrl` is the HTTP base for the matchmaking service —
// `/jobs` for dispatch, `/providers` for discovery. The provider's
// WebSocket lives at `wss://…/v1/agent` but the console only
// makes HTTP calls.

export interface CocoreConfig {
  bridgeUrl: string;
  appviewUrl: string;
  advisorUrl: string;
  exchangeDid: string;
  /** The console's own service DID. Inbound AT Protocol service-auth
   *  JWTs (e.g. for the dev.cocore.account.* management endpoints
   *  reached via PDS service proxying) must carry this as their `aud`.
   *  Its DID document is served at /.well-known/did.json. */
  consoleDid: string;
  /** Shared secret for internal-only services endpoints (must match the
   *  services container's COCORE_INTERNAL_API_KEY). Used to countersign
   *  terms acceptances via the exchange. Empty when unset — callers that
   *  need it fail loud rather than silently skipping the signature. */
  internalApiKey: string;
}

/** Headers for an internal bridge call (`dev.cocore.bridge.*`). These routes
 *  are operator-gated on the services container (constant-time `authOk` over
 *  the shared `COCORE_INTERNAL_API_KEY`), so the console — the sole legitimate
 *  caller — must present the Bearer key. When the key is unset the header is
 *  omitted and the bridge fails the call closed; the PDS write still wins
 *  (these calls are best-effort cache hints), so a missing key degrades to
 *  "cache not mirrored," never a broken write. */
export function bridgeHeaders(extra?: Record<string, string>): Record<string, string> {
  const key = cocoreConfig().internalApiKey;
  return {
    "content-type": "application/json",
    ...(key ? { authorization: `Bearer ${key}` } : {}),
    ...extra,
  };
}

/** The console's service DID, derived from CONSOLE_PUBLIC_URL exactly as
 *  routes/[.]well-known.did[.]json.ts derives the `id` it publishes.
 *
 *  🔴 Why this is derived and not a literal. Until 2026-09-15 the default here
 *  was the literal `did:web:console.cocore.dev` while the published document
 *  said `did:web:cocore.dev` (CONSOLE_PUBLIC_URL is https://cocore.dev since
 *  the cocore.dev cutover). That combination is a deadlock, and it silently
 *  broke every third-party service-auth call:
 *
 *    aud did:web:cocore.dev          -> 401 BadJwtAudience here
 *    aud did:web:console.cocore.dev  -> accepted here, but a PDS cannot
 *                                       resolve that DID, because
 *                                       console.cocore.dev/.well-known/did.json
 *                                       declares id did:web:cocore.dev and a
 *                                       did:web document whose id does not
 *                                       match the DID being resolved is invalid
 *
 *  Both verified against production on 2026-09-15. Deriving both ends from one
 *  URL makes the pair impossible to get wrong again. docs/api-keys.md already
 *  documents did:web:cocore.dev#cocore_console, which is now what we accept. */
function consoleDidFromPublicUrl(): string {
  const url = process.env["CONSOLE_PUBLIC_URL"] ?? "https://console.cocore.dev";
  try {
    // host with `:port` becomes `%3Aport` per the did:web spec.
    return `did:web:${new URL(url).host.replace(":", "%3A")}`;
  } catch {
    return "did:web:console.cocore.dev";
  }
}

export function cocoreConfig(): CocoreConfig {
  return {
    bridgeUrl: process.env["COCORE_BRIDGE_URL"] ?? "http://localhost:8080",
    appviewUrl: process.env["COCORE_APPVIEW_URL"] ?? "http://localhost:8081",
    advisorUrl: process.env["COCORE_ADVISOR_URL"] ?? "https://advisor.cocore.dev",
    internalApiKey: process.env["COCORE_INTERNAL_API_KEY"] ?? "",
    // Defaults to the production exchange DID. In local dev,
    // override with COCORE_EXCHANGE_DID=did:web:exchange.local
    // (or whatever resolves locally).
    exchangeDid: process.env["COCORE_EXCHANGE_DID"] ?? "did:web:console.cocore.dev:exchange",
    // DERIVED from CONSOLE_PUBLIC_URL, the same source /.well-known/did.json
    // uses for the `id` it publishes. These two MUST agree: the verifier
    // compares an inbound JWT's `aud` against this, while a requester's PDS
    // resolves the DID by fetching our document and checking its `id`. When
    // they disagree, nothing can call us at all — see the note below.
    // Override with COCORE_CONSOLE_DID only when the two cannot be derived
    // from one URL (local dev: did:web:127.0.0.1%3A3000).
    consoleDid: process.env["COCORE_CONSOLE_DID"] ?? consoleDidFromPublicUrl(),
  };
}
