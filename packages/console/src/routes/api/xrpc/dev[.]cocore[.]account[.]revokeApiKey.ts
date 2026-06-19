// POST /api/xrpc/dev.cocore.account.revokeApiKey
//
// Revoke one of the authenticated account's API keys. The key stops
// authenticating immediately; the row survives with `revokedAt` set so
// it stays visible in listApiKeys for audit. Scoped to the caller's DID.
//
// Body:    { id: string }
// Returns: 200 { revoked: boolean } | 400 | 401
//
// Lexicon: dev.cocore.account.revokeApiKey

import { createFileRoute } from "@tanstack/react-router";

import { revokeKey } from "@/lib/api-keys.server.ts";
import { resolveXrpcCaller, xrpcError, xrpcJson } from "@/lib/xrpc-key-auth.server.ts";

interface RawBody {
  id?: unknown;
}

function parseId(raw: RawBody): string | null {
  if (typeof raw.id !== "string" || raw.id.length < 1 || raw.id.length > 200) return null;
  return raw.id;
}

export const Route = createFileRoute("/api/xrpc/dev.cocore.account.revokeApiKey")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const caller = await resolveXrpcCaller(request);
        if (!caller) return xrpcError(401, "AuthRequired", "session cookie or bearer key required");

        let raw: RawBody;
        try {
          raw = (await request.json()) as RawBody;
        } catch {
          return xrpcError(400, "InvalidRequest", "body must be JSON");
        }
        const id = parseId(raw);
        if (id === null) return xrpcError(400, "InvalidRequest", "id must be a 1–200 char string");

        const revoked = revokeKey({ id, did: caller.did });
        return xrpcJson({ revoked }, 200);
      },
    },
  },
});
