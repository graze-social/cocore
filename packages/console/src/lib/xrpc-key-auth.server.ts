// Shared request authentication for the dev.cocore.account.* API-key
// management XRPC endpoints.
//
// These endpoints are reachable two ways, so that they work both from
// the signed-in console UI and from automation:
//
//   1. Console session cookie — what the browser sends. Lets the
//      account page drive the same surface a script would.
//   2. `Authorization: Bearer cocore-...` — an existing API key. This
//      is the automation path: mint one key from the console once,
//      then create/list/revoke/delete the rest headlessly.
//
// Both resolve to the owning DID; everything downstream is scoped to
// that DID so a caller can only ever touch their own keys.

import { type ApiKeyRow, resolveBearerKey } from "@/lib/api-keys.server.ts";
import { getAtprotoSessionForRequest } from "@/middleware/auth.server.ts";

export interface XrpcCaller {
  did: string;
  /** How the caller authenticated — useful for diagnostics. */
  via: "bearer" | "session";
}

function readBearer(request: Request): string | null {
  const h = request.headers.get("authorization");
  if (!h) return null;
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1]!.trim() : null;
}

/** Resolve the calling account's DID from a bearer API key (preferred,
 *  cheap) or, failing that, a console session cookie. Returns null when
 *  neither credential is present or valid; the caller should respond 401. */
export async function resolveXrpcCaller(request: Request): Promise<XrpcCaller | null> {
  const bearer = readBearer(request);
  if (bearer) {
    const resolved = resolveBearerKey(bearer);
    if (resolved) return { did: resolved.did, via: "bearer" };
    // A presented-but-invalid bearer token is an explicit 401, not a
    // silent fall-through to cookie auth.
    return null;
  }

  const session = await getAtprotoSessionForRequest(request);
  if (session) return { did: session.did, via: "session" };

  return null;
}

/** Shape an internal {@link ApiKeyRow} into the wire form described by
 *  `dev.cocore.account.defs#apiKeyView`: never includes the secret, and
 *  drops null optional fields so the JSON matches the lexicon (absent,
 *  not null). */
export function apiKeyView(row: ApiKeyRow): Record<string, unknown> {
  const view: Record<string, unknown> = {
    id: row.id,
    did: row.did,
    name: row.name,
    prefix: row.prefix,
    createdAt: row.createdAt,
  };
  if (row.expiresAt) view.expiresAt = row.expiresAt;
  if (row.revokedAt) view.revokedAt = row.revokedAt;
  if (row.lastUsedAt) view.lastUsedAt = row.lastUsedAt;
  return view;
}

export function xrpcJson(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export function xrpcError(status: number, error: string, message?: string): Response {
  return xrpcJson(message ? { error, message } : { error }, status);
}
