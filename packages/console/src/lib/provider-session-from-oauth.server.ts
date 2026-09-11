// Mint a ProviderSession for the device-pair flow.
//
// Pre-v0.3.0 this flattened the user's OAuth StoredSession into a
// JSON bundle the agent persisted. With the proxy-via-console
// architecture the agent doesn't see OAuth tokens at all — instead
// we mint a scoped API key on pair-approve. The agent authenticates
// to the console with that key and the console signs every bsky
// call with its own DPoP-aware OAuth session.
//
// The minted key is named after the pair flow so the user can
// recognize + revoke it on /account.

import type { Did } from "@atcute/lexicons";
import { Effect } from "effect";

import { createKey } from "@/lib/api-keys.server.ts";
import { fetchBlueskyPublicProfileFieldsEffect } from "@/lib/bluesky-public-profile.server.ts";

/** JSON-serializable shape used at the server-fn / agent boundary. */
export interface ProviderSessionWire {
  did: string;
  handle: string;
  apiKey: string;
  apiBase: string;
}

function consoleBaseUrl(): string {
  const u =
    process.env["CONSOLE_PUBLIC_URL"] ?? process.env["BETTER_AUTH_URL"] ?? "http://localhost:3000";
  return u.replace(/\/$/, "");
}

/** The key name for a pairing nobody named: what the CLI has always minted. */
export function defaultPairKeyName(now: Date = new Date()): string {
  return `paired machine (${now.toISOString().slice(0, 10)})`;
}

export function providerSessionForDidEffect(
  did: Did,
  keyName?: string,
): Effect.Effect<ProviderSessionWire | null> {
  return Effect.gen(function* () {
    const profile = yield* fetchBlueskyPublicProfileFieldsEffect(did);
    const handle = profile?.handle ?? did;

    const minted = yield* Effect.try({
      try: () => createKey({ did, name: keyName ?? defaultPairKeyName() }),
      catch: (e) => e,
    }).pipe(Effect.either);
    if (minted._tag === "Left") return null;

    return {
      did,
      handle,
      apiKey: minted.right.secret,
      apiBase: consoleBaseUrl(),
    };
  });
}
