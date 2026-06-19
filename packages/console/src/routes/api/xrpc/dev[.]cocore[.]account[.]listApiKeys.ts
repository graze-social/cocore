// GET /api/xrpc/dev.cocore.account.listApiKeys
//
// List every API key owned by the authenticated account, newest first.
// The owning DID comes from the presented credential (session cookie or
// `Authorization: Bearer cocore-...`); there is no parameter to list
// another account's keys. Secrets are never returned.
//
// Returns: 200 { keys: apiKeyView[] } | 401
//
// Lexicon: dev.cocore.account.listApiKeys

import { createFileRoute } from "@tanstack/react-router";

import { listKeysForDid } from "@/lib/api-keys.server.ts";
import { apiKeyView, resolveXrpcCaller, xrpcError, xrpcJson } from "@/lib/xrpc-key-auth.server.ts";

export const Route = createFileRoute("/api/xrpc/dev.cocore.account.listApiKeys")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const caller = await resolveXrpcCaller(request);
        if (!caller) return xrpcError(401, "AuthRequired", "session cookie or bearer key required");

        const keys = listKeysForDid(caller.did).map(apiKeyView);
        return xrpcJson({ keys }, 200);
      },
    },
  },
});
