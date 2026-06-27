// Resolve a bearer API key against the AppView's account store.
//
// API keys live in two federated stores: console-minted keys in the
// console's console.db (resolveBearerKey in api-keys.server.ts), and
// AppView-minted keys — including every key created via the *documented*
// `dev.cocore.account.createApiKey` endpoint, which the API docs host on
// the AppView (`#cocore_appview`) — in the AppView's account.db. Each
// service natively resolves only the keys it minted.
//
// The console's OpenAI-compatible inference endpoint
// (`cocore.dev/v1/chat/completions`) must accept BOTH, otherwise a key a
// developer mints by following the docs returns a secret but never
// authenticates ("makes a key but it doesn't do anything"). So after a
// local console.db miss, the inference path falls back to this, which asks
// the AppView to resolve the key over the shared-secret internal channel.
//
// Gated on COCORE_APPVIEW_INTERNAL_URL + COCORE_INTERNAL_SECRET (the same
// channel as appview-backed-session.server.ts). With them unset this
// returns null and the caller keeps its local-only behavior.

import type { ResolvedKey } from "@/lib/api-keys.server.ts";

function base(): string | null {
  return process.env["COCORE_APPVIEW_INTERNAL_URL"]?.replace(/\/$/, "") || null;
}
function secret(): string | null {
  return process.env["COCORE_INTERNAL_SECRET"] || null;
}

/** Resolve `presented` against the AppView account store. Returns the
 *  owning DID (+ key id/name) on success, or null when the key is unknown,
 *  revoked, expired, malformed, or the AppView is unreachable / not
 *  configured. Never throws — a transient AppView blip simply declines the
 *  key here (the local console.db path has already been tried). */
export async function resolveBearerKeyViaAppview(presented: string): Promise<ResolvedKey | null> {
  const b = base();
  const s = secret();
  if (!b || !s) return null;
  // Cheap shape gate before a network round-trip: every cocore key is
  // `cocore-…`. A JWT or junk bearer can't be an account key, so skip the call.
  if (!presented.startsWith("cocore-")) return null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3_000);
  try {
    const res = await fetch(`${b}/internal/account/resolve-key`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-cocore-internal-secret": s },
      body: JSON.stringify({ key: presented }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    const body = (await res.json()) as { id?: string; did?: string; name?: string };
    if (typeof body.did !== "string" || body.did.length === 0) return null;
    return { id: body.id ?? "", did: body.did, name: body.name ?? "" };
  } catch {
    return null;
  }
}
