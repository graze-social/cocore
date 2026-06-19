// Hand a freshly minted OAuth session off to the AppView.
//
// The end-state has the AppView own PDS writes (and thus a user's
// DPoP-bound OAuth session). Because refresh tokens are single-use, only
// one process may refresh a given session — so at login the console
// pushes the just-minted session to the AppView, which becomes its owner.
//
// This is best-effort and gated on configuration: when
// COCORE_APPVIEW_INTERNAL_URL + COCORE_INTERNAL_SECRET are set, we POST
// the session blob to the AppView's /internal/oauth-session. A failure
// (or missing config) never blocks login — the console still holds the
// session, so nothing regresses until the write path is cut over.

import { consoleDb } from "@/lib/console-db.server.ts";

/** Push the stored session blob for `did` to the AppView. Resolves to
 *  true on a 2xx handoff, false otherwise (including "not configured").
 *  Never throws. */
export async function handOffSessionToAppview(did: string): Promise<boolean> {
  const base = process.env["COCORE_APPVIEW_INTERNAL_URL"]?.replace(/\/$/, "");
  const secret = process.env["COCORE_INTERNAL_SECRET"];
  if (!base || !secret) return false;

  let data: string | undefined;
  try {
    const row = consoleDb().prepare(`SELECT data FROM oauth_sessions WHERE did = ?`).get(did) as
      | { data: string }
      | undefined;
    data = row?.data;
  } catch {
    return false;
  }
  if (!data) return false;

  try {
    const res = await fetch(`${base}/internal/oauth-session`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-cocore-internal-secret": secret },
      // `data` is already the serialized StoredSession; forward verbatim.
      body: JSON.stringify({ did, data }),
    });
    if (!res.ok) {
      console.warn(`[appview-handoff] AppView returned ${res.status} for ${did}`);
      return false;
    }
    console.log(`[appview-handoff] pushed session for ${did} to AppView`);
    return true;
  } catch (e) {
    console.warn(`[appview-handoff] push failed for ${did}:`, (e as Error).message);
    return false;
  }
}

export interface SessionMigrationResult {
  total: number;
  pushed: number;
  failed: number;
}

/** Bulk-push every stored OAuth session to the AppView. This is the
 *  one-time cutover migration: existing users who don't re-log-in still
 *  need their session on the AppView for the forwarded write path. The
 *  per-login handoff covers everyone who signs in after the flip; this
 *  covers the back catalogue.
 *
 *  Idempotent (the AppView upserts by DID), so it's safe to re-run, but it
 *  is NOT wired to run automatically — invoke it deliberately at cutover
 *  (see scripts/migrate-sessions-to-appview.ts), after the forward env is
 *  set so the console has stopped refreshing the sessions it pushes. */
export async function migrateAllSessionsToAppview(): Promise<SessionMigrationResult> {
  const base = process.env["COCORE_APPVIEW_INTERNAL_URL"]?.replace(/\/$/, "");
  const secret = process.env["COCORE_INTERNAL_SECRET"];
  if (!base || !secret) {
    console.warn(
      "[appview-handoff] migrate skipped — COCORE_APPVIEW_INTERNAL_URL / COCORE_INTERNAL_SECRET not set",
    );
    return { total: 0, pushed: 0, failed: 0 };
  }

  let dids: string[];
  try {
    const rows = consoleDb().prepare(`SELECT did FROM oauth_sessions`).all() as { did: string }[];
    dids = rows.map((r) => r.did);
  } catch (e) {
    console.warn("[appview-handoff] migrate: could not read oauth_sessions:", (e as Error).message);
    return { total: 0, pushed: 0, failed: 0 };
  }

  let pushed = 0;
  let failed = 0;
  for (const did of dids) {
    if (await handOffSessionToAppview(did)) pushed++;
    else failed++;
  }
  console.log(
    `[appview-handoff] migrate complete: ${pushed}/${dids.length} sessions pushed (${failed} failed)`,
  );
  return { total: dids.length, pushed, failed };
}
