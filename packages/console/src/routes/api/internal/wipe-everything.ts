// POST /api/internal/wipe-everything
//
// Operator-only **total** sledgehammer. Drops every piece of cocore
// state we can reach:
//
//   1. **Every PDS we have credentials for.** For every row in
//      `oauth_sessions`, restore the OAuthSession and run
//      `wipeMyData(session)` — that walks every `dev.cocore.*`
//      collection and `deleteRecord`s each row off the user's PDS.
//   2. **The console DB.** TRUNCATE `api_keys`, `oauth_sessions`,
//      `app_sessions`, `console_user_prefs`, `pending_disputes`.
//   3. **The services container.** POST to
//      `/xrpc/dev.cocore.admin.wipe` on the bridge to clear the
//      AppView record mirror + every TokenLedger table.
//
// Gating (same as `/api/internal/wipe`):
//   * `Authorization: Bearer <COCORE_INTERNAL_API_KEY>`
//   * AND `COCORE_ALLOW_WIPE=1` on the console process
// Plus the services bridge must independently have
// `COCORE_ALLOW_WIPE=1` set; if it doesn't, the AppView + ledger
// half won't clear and the report flags it.
//
// This endpoint exists because the one-DID `wipeMyData` server fn
// can only reach the user's own PDS (it uses *their* OAuth session).
// To clean every signed-in user we need to iterate the persisted
// sessions on the server side, which we can only do here.

import { createFileRoute } from "@tanstack/react-router";
import { timingSafeEqual } from "node:crypto";
import { isDid } from "@atcute/lexicons/syntax";

import { runTraced } from "@/lib/o11y.server.ts";

import { restoreAtprotoSessionEffect } from "@/integrations/auth/atproto.server.ts";
import { cocoreConfig } from "@/lib/cocore-config.ts";
import { consoleDb } from "@/lib/console-db.server.ts";
import { wipeMyData, type WipeReport } from "@/lib/wipe-my-data.server.ts";

function jsonResponse(body: object, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function authOk(header: string | null): boolean {
  const expected = process.env["COCORE_INTERNAL_API_KEY"];
  if (!expected) return false;
  if (!header) return false;
  const m = /^Bearer\s+(.+)$/.exec(header);
  if (!m) return false;
  const presented = m[1] ?? "";
  if (presented.length !== expected.length) return false;
  return timingSafeEqual(Buffer.from(presented), Buffer.from(expected));
}

const CONSOLE_TABLES = [
  "app_sessions",
  "oauth_sessions",
  "api_keys",
  "pending_disputes",
  "console_user_prefs",
] as const;

interface PerDidReport {
  did: string;
  ok: boolean;
  /** Populated when `wipeMyData` returned without throwing. */
  report?: WipeReport;
  /** Populated when restore or wipe threw. */
  error?: string;
}

async function wipeAllPdses(): Promise<PerDidReport[]> {
  // Snapshot the DIDs BEFORE we start so a session that gets
  // refreshed mid-wipe (which would re-insert a row into
  // oauth_sessions) doesn't escape the wipe.
  const rows = consoleDb().prepare(`SELECT did FROM oauth_sessions`).all() as Array<{
    did: string;
  }>;
  const results: PerDidReport[] = [];

  // Walk one at a time — concurrent OAuth restore on the same client
  // is fine, but each `wipeMyData` already issues bounded-parallel
  // deleteRecord calls. Stacking those would hammer rate limits.
  for (const { did } of rows) {
    if (!isDid(did)) {
      results.push({ did, ok: false, error: "invalid DID format" });
      continue;
    }
    try {
      const session = await runTraced("auth.restoreSession", restoreAtprotoSessionEffect(did));
      if (!session) {
        results.push({ did, ok: false, error: "session restore returned null" });
        continue;
      }
      const report = await wipeMyData(session);
      results.push({ did, ok: true, report });
    } catch (e) {
      results.push({ did, ok: false, error: e instanceof Error ? e.message : String(e) });
    }
  }
  return results;
}

function truncateConsoleTables(): Record<string, number> {
  const db = consoleDb();
  const counts: Record<string, number> = {};
  for (const table of CONSOLE_TABLES) {
    const exists = db.prepare("SELECT 1 FROM sqlite_master WHERE name = ?").get(table) as
      | { 1: number }
      | undefined;
    if (!exists) continue;
    counts[table] = db.prepare(`DELETE FROM ${table}`).run().changes;
  }
  return counts;
}

async function wipeServicesBridge(): Promise<{ ok: boolean; body: unknown }> {
  const bridge = cocoreConfig().bridgeUrl.replace(/\/$/, "");
  const apiKey = process.env["COCORE_INTERNAL_API_KEY"];
  if (!apiKey) {
    return {
      ok: false,
      body: { error: "COCORE_INTERNAL_API_KEY missing; cannot reach services wipe" },
    };
  }
  try {
    const r = await fetch(`${bridge}/xrpc/dev.cocore.admin.wipe`, {
      method: "POST",
      headers: { authorization: `Bearer ${apiKey}` },
    });
    const text = await r.text();
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      body = { raw: text.slice(0, 500) };
    }
    return { ok: r.ok, body };
  } catch (e) {
    return { ok: false, body: { error: e instanceof Error ? e.message : String(e) } };
  }
}

export const Route = createFileRoute("/api/internal/wipe-everything")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        if (!authOk(request.headers.get("authorization"))) {
          return jsonResponse({ error: "unauthorized" }, 401);
        }
        if (process.env["COCORE_ALLOW_WIPE"] !== "1") {
          return jsonResponse(
            { error: "wipe disabled; set COCORE_ALLOW_WIPE=1 on the console container" },
            403,
          );
        }
        // Railway forks preview environments from production and copies its
        // variables (including COCORE_INTERNAL_API_KEY). This endpoint deletes
        // every signed-in user's dev.cocore.* records off their real PDS, so
        // refuse to run in any non-production Railway env unless explicitly
        // overridden — an inherited key must not be able to wipe from a preview
        // origin. Environments without RAILWAY_ENVIRONMENT_NAME (local dev) are
        // unaffected.
        {
          const railwayEnv = process.env["RAILWAY_ENVIRONMENT_NAME"];
          if (
            railwayEnv &&
            railwayEnv !== "production" &&
            process.env["COCORE_ALLOW_WIPE_NONPROD"] !== "1"
          ) {
            return jsonResponse(
              {
                error: `wipe blocked in non-production Railway env '${railwayEnv}'; set COCORE_ALLOW_WIPE_NONPROD=1 to override`,
              },
              403,
            );
          }
        }

        // 1. Walk every stored OAuth session and wipe that DID's PDS.
        //    Run BEFORE truncating oauth_sessions so we still have the
        //    DPoP credentials at hand.
        const perDid = await wipeAllPdses();

        // 2. Truncate console-side state.
        const consoleCounts = truncateConsoleTables();

        // 3. Drop the AppView record mirror + ledger via the bridge.
        const services = await wipeServicesBridge();

        const summary = {
          pdsWipedCount: perDid.filter((r) => r.ok).length,
          pdsFailedCount: perDid.filter((r) => !r.ok).length,
          consoleTruncated: consoleCounts,
          servicesOk: services.ok,
        };
        console.error(`admin.wipeEverything: ${JSON.stringify(summary)}`);

        return jsonResponse({
          ok: services.ok && perDid.every((r) => r.ok),
          summary,
          perDid,
          consoleCounts,
          services: services.body,
        });
      },
    },
  },
});
