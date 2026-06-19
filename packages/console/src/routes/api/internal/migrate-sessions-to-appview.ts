// POST /api/internal/migrate-sessions-to-appview
//
// One-time cutover migration: bulk-push every console-held OAuth session
// to the AppView so existing users (who haven't re-logged-in since the
// write-path cutover) have their session available for the forwarded
// write path. The per-login handoff covers everyone who signs in after
// the flip; this covers the back catalogue.
//
// Operator-only and deliberate — it is NOT wired to run automatically.
// Run it once, at cutover, AFTER the forward env is configured (so the
// console has stopped refreshing the sessions it pushes). Idempotent (the
// AppView upserts by DID), so re-running is safe.
//
// Gating: `Authorization: Bearer <COCORE_INTERNAL_API_KEY>` (same operator
// key as /api/internal/wipe). The push itself additionally requires
// COCORE_APPVIEW_INTERNAL_URL + COCORE_INTERNAL_SECRET to be set; without
// them the migration is a no-op.

import { createFileRoute } from "@tanstack/react-router";
import { timingSafeEqual } from "node:crypto";

import { migrateAllSessionsToAppview } from "@/lib/appview-session-handoff.server.ts";

function jsonResponse(body: object, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function authOk(header: string | null): boolean {
  const expected = process.env["COCORE_INTERNAL_API_KEY"];
  if (!expected || !header) return false;
  const m = /^Bearer\s+(.+)$/.exec(header);
  if (!m) return false;
  const presented = m[1] ?? "";
  if (presented.length !== expected.length) return false;
  return timingSafeEqual(Buffer.from(presented), Buffer.from(expected));
}

export const Route = createFileRoute("/api/internal/migrate-sessions-to-appview")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        if (!authOk(request.headers.get("authorization"))) {
          return jsonResponse({ error: "unauthorized" }, 401);
        }
        const result = await migrateAllSessionsToAppview();
        console.error(`migrate-sessions-to-appview: ${JSON.stringify(result)}`);
        return jsonResponse({ ok: true, ...result });
      },
    },
  },
});
