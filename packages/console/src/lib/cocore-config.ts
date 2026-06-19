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
    // Defaults to the production console DID. In local dev, override
    // with COCORE_CONSOLE_DID=did:web:127.0.0.1%3A3000 (or whatever
    // matches the host a requester's PDS will proxy to).
    consoleDid: process.env["COCORE_CONSOLE_DID"] ?? "did:web:console.cocore.dev",
  };
}
