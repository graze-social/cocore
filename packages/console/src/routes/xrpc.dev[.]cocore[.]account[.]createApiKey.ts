// POST /xrpc/dev.cocore.account.createApiKey
//
// Mint a new cocore API key for the authenticated account and return the
// full secret exactly once. Authenticated via AT Protocol service auth:
// the caller proxies the request through its own PDS
// (`atproto-proxy: <consoleDid>#cocore_console`), which signs a JWT with
// the account's repo key. See service-auth.server.ts.
//
// The /api/xrpc/dev.cocore.account.createApiKey route is the legacy
// alias (session cookie / bearer key); this is the proper atproto path.
//
// Body:    { name: string, expiresAt?: string | null }
// Returns: 200 { key: apiKeyView, secret } | 400 | 401
//
// Lexicon: dev.cocore.account.createApiKey

import { createFileRoute } from "@tanstack/react-router";

import { parseCreateApiKeyBody } from "@/lib/account-xrpc.server.ts";
import { createKey } from "@/lib/api-keys.server.ts";
import { verifyServiceAuth } from "@/lib/service-auth.server.ts";
import { apiKeyView, xrpcError, xrpcJson } from "@/lib/xrpc-key-auth.server.ts";

const LXM = "dev.cocore.account.createApiKey";

export const Route = createFileRoute("/xrpc/dev.cocore.account.createApiKey")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const auth = await verifyServiceAuth(request, LXM);
        if (!auth.ok) return xrpcError(auth.status, auth.error, auth.message);

        let raw: unknown;
        try {
          raw = await request.json();
        } catch {
          return xrpcError(400, "InvalidRequest", "body must be JSON");
        }
        const parsed = parseCreateApiKeyBody(raw as Record<string, unknown>);
        if (typeof parsed === "string") return xrpcError(400, "InvalidRequest", parsed);

        const created = createKey({
          did: auth.did,
          name: parsed.name,
          expiresAt: parsed.expiresAt,
        });
        return xrpcJson({ key: apiKeyView(created.key), secret: created.secret }, 200);
      },
    },
  },
});
