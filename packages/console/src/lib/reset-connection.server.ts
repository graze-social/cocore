// "Reset connection" — repair a wedged auth/connection state without
// destroying any data.
//
// This is the non-destructive twin of `wipe-my-data.server.ts`. Where a
// wipe deletes the user's PDS records + AppView index + keys ("start over
// from zero"), a reset rebuilds only the auth plumbing that gets wedged
// ("fix my connection"):
//
//   1. Revoke every API key for the DID (console store + AppView store).
//      A wedged agent key — e.g. left over from a wipe, or split-brained
//      across the console/AppView stores after the cutover — is gone, so
//      `cocore agent pair` mints a clean one.
//   2. Drop the stored OAuth session for the DID (console store + AppView
//      store). A poisoned session `restore()`s successfully but 401s on
//      write (its refresh token was rotated out from under it — the
//      two-daemon race), so we must DELETE it: the only cure is a fresh
//      browser OAuth handshake, which the caller is sent through next.
//
// What this deliberately does NOT do (the line that separates it from a
// wipe):
//   * Touch ANY `dev.cocore.*` PDS records — receipts, jobs, provider,
//     attestation, settlement all survive.
//   * Purge the AppView's firehose-indexed receipt cache.
//   * Delete `console_user_prefs`.
//   * Touch any other DID.
//
// The server fn that calls this (api-keys.functions.ts) additionally
// clears the browser session so the user is forced through a fresh login
// — that login is what re-establishes a valid OAuth session.

import type { Did } from "@atcute/lexicons";

import { revokeAllKeysForDid } from "@/lib/api-keys.server.ts";
import { resetConnectionOnAppview } from "@/lib/appview-session-handoff.server.ts";
import { SqliteOauthSessionStore } from "@/lib/oauth-session-store.server.ts";

export interface ResetConnectionReport {
  /** Active keys revoked in the console store. */
  apiKeysRevoked: number;
  /** Whether the console's OAuth session row was dropped. */
  oauthClearedConsole: boolean;
  /** Outcome of the AppView half (no-op when handoff isn't configured). */
  appview: { attempted: boolean; ok: boolean; keysRevoked: number };
}

export async function resetMyConnection(did: string): Promise<ResetConnectionReport> {
  const apiKeysRevoked = revokeAllKeysForDid(did);

  let oauthClearedConsole = false;
  try {
    new SqliteOauthSessionStore().delete(did as Did);
    oauthClearedConsole = true;
  } catch {
    oauthClearedConsole = false;
  }

  const appview = await resetConnectionOnAppview(did);

  return { apiKeysRevoked, oauthClearedConsole, appview };
}
