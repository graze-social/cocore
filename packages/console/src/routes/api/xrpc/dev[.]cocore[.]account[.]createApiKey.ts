// POST /api/xrpc/dev.cocore.account.createApiKey
//
// Mint a new cocore API key for the authenticated account and return
// the full secret exactly once. Authenticate with a console session
// cookie or an existing `Authorization: Bearer cocore-...` key — the
// latter is the automation path (mint one key from the console UI,
// then manage the rest headlessly).
//
// Body:    { name: string, expiresAt?: string | null }
// Returns: 200 { key: apiKeyView, secret } | 400 | 401
//
// Lexicon: dev.cocore.account.createApiKey

import { createFileRoute } from "@tanstack/react-router";

import { createKey } from "@/lib/api-keys.server.ts";
import { apiKeyView, resolveXrpcCaller, xrpcError, xrpcJson } from "@/lib/xrpc-key-auth.server.ts";

interface RawBody {
  name?: unknown;
  expiresAt?: unknown;
}

function parseBody(raw: RawBody): { name: string; expiresAt: string | null } | string {
  if (typeof raw.name !== "string" || raw.name.length < 1 || raw.name.length > 100) {
    return "name must be a string of 1–100 characters";
  }
  if (raw.expiresAt !== undefined && raw.expiresAt !== null && typeof raw.expiresAt !== "string") {
    return "expiresAt must be an RFC3339 string, null, or omitted";
  }
  if (typeof raw.expiresAt === "string" && Number.isNaN(Date.parse(raw.expiresAt))) {
    return "expiresAt must be a valid RFC3339 datetime";
  }
  return {
    name: raw.name,
    expiresAt: typeof raw.expiresAt === "string" ? raw.expiresAt : null,
  };
}

export const Route = createFileRoute("/api/xrpc/dev.cocore.account.createApiKey")({
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
        const parsed = parseBody(raw);
        if (typeof parsed === "string") return xrpcError(400, "InvalidRequest", parsed);

        const created = createKey({
          did: caller.did,
          name: parsed.name,
          expiresAt: parsed.expiresAt,
        });
        return xrpcJson({ key: apiKeyView(created.key), secret: created.secret }, 200);
      },
    },
  },
});
