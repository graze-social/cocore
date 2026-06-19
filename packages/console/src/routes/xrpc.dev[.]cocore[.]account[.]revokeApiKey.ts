// POST /xrpc/dev.cocore.account.revokeApiKey
//
// Revoke one of the authenticated account's API keys. The key stops
// authenticating immediately; the row survives with `revokedAt` set so
// it stays visible in listApiKeys for audit. Scoped to the caller's DID,
// which comes from a verified AT Protocol service-auth JWT (see
// service-auth.server.ts).
//
// The /api/xrpc/dev.cocore.account.revokeApiKey route is the legacy alias.
//
// Body:    { id: string }
// Returns: 200 { revoked: boolean } | 400 | 401
//
// Lexicon: dev.cocore.account.revokeApiKey

import { createFileRoute } from "@tanstack/react-router";

import { parseApiKeyId } from "@/lib/account-xrpc.server.ts";
import { revokeKey } from "@/lib/api-keys.server.ts";
import { verifyServiceAuth } from "@/lib/service-auth.server.ts";
import { xrpcError, xrpcJson } from "@/lib/xrpc-key-auth.server.ts";

const LXM = "dev.cocore.account.revokeApiKey";

export const Route = createFileRoute("/xrpc/dev.cocore.account.revokeApiKey")({
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
        const id = parseApiKeyId(raw as Record<string, unknown>);
        if (id === null) return xrpcError(400, "InvalidRequest", "id must be a 1–200 char string");

        const revoked = revokeKey({ id, did: auth.did });
        return xrpcJson({ revoked }, 200);
      },
    },
  },
});
