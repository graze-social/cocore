// POST /xrpc/dev.cocore.account.deleteApiKey
//
// Hard-delete one of the authenticated account's API keys, removing the
// row entirely (no audit-trail recovery). Prefer revokeApiKey for most
// flows; use this to clean up revoked or expired keys. Scoped to the
// caller's DID, which comes from a verified AT Protocol service-auth JWT
// (see service-auth.server.ts).
//
// The /api/xrpc/dev.cocore.account.deleteApiKey route is the legacy alias.
//
// Body:    { id: string }
// Returns: 200 { deleted: boolean } | 400 | 401
//
// Lexicon: dev.cocore.account.deleteApiKey

import { createFileRoute } from "@tanstack/react-router";

import { parseApiKeyId } from "@/lib/account-xrpc.server.ts";
import { deleteKey } from "@/lib/api-keys.server.ts";
import { verifyServiceAuth } from "@/lib/service-auth.server.ts";
import { xrpcError, xrpcJson } from "@/lib/xrpc-key-auth.server.ts";

const LXM = "dev.cocore.account.deleteApiKey";

export const Route = createFileRoute("/xrpc/dev.cocore.account.deleteApiKey")({
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

        const deleted = deleteKey({ id, did: auth.did });
        return xrpcJson({ deleted }, 200);
      },
    },
  },
});
