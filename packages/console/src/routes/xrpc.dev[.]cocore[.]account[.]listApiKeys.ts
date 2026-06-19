// GET /xrpc/dev.cocore.account.listApiKeys
//
// List every API key owned by the authenticated account, newest first.
// The owning DID comes from a verified AT Protocol service-auth JWT (see
// service-auth.server.ts); there is no parameter to list another
// account's keys. Secrets are never returned.
//
// The /api/xrpc/dev.cocore.account.listApiKeys route is the legacy alias.
//
// Returns: 200 { keys: apiKeyView[] } | 401
//
// Lexicon: dev.cocore.account.listApiKeys

import { createFileRoute } from "@tanstack/react-router";

import { listKeysForDid } from "@/lib/api-keys.server.ts";
import { verifyServiceAuth } from "@/lib/service-auth.server.ts";
import { apiKeyView, xrpcError, xrpcJson } from "@/lib/xrpc-key-auth.server.ts";

const LXM = "dev.cocore.account.listApiKeys";

export const Route = createFileRoute("/xrpc/dev.cocore.account.listApiKeys")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const auth = await verifyServiceAuth(request, LXM);
        if (!auth.ok) return xrpcError(auth.status, auth.error, auth.message);

        const keys = listKeysForDid(auth.did).map(apiKeyView);
        return xrpcJson({ keys }, 200);
      },
    },
  },
});
