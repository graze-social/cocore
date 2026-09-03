// Resolve which machine served which receipt, so the machines dashboard
// can show real per-box earnings instead of splitting the fleet total
// evenly. A receipt strong-refs the dev.cocore.compute.attestation it was
// signed under; that attestation carries the machine's `publicKey`, which
// equals the provider record's `attestationPubKey`. This module fetches the
// signed-in user's attestation records and maps each attestation URI → its
// publicKey; the dashboard joins receipt → attestation pubkey → provider.

import type { OAuthSession } from "@atcute/oauth-node-client";

interface ListRecordsResponse {
  records?: Array<{ uri: string; value: Record<string, unknown> }>;
  cursor?: string;
}

/** Up to this many pages (×100 records) of attestation history. One
 *  attestation is published per serve session, so a long-lived account
 *  accumulates several; this bound keeps the request cheap while covering
 *  the recent windows the dashboard shows. */
const MAX_PAGES = 10;

/**
 * Cached pubkey maps, keyed by DID.
 *
 * Paging this is expensive in a way that is easy to miss: each page is a
 * `listRecords` call proxied through the AppView to the user's PDS, and they
 * are strictly SEQUENTIAL because each needs the previous page's cursor. An
 * account with 100+ attestations therefore pays up to MAX_PAGES round-trips —
 * measured at 200-500ms each on /machines, so seconds of the page's TTFB, on
 * every single load.
 *
 * Caching is safe here because this is a best-effort REFINEMENT: it upgrades
 * per-machine earnings from an even split to real attribution. A slightly
 * stale map attributes a few recent receipts to the even-split fallback,
 * which is exactly what happens today when the fetch fails. It is not
 * authoritative for anything — the receipts themselves are.
 *
 * Attestations are append-mostly (one per serve session), so a short TTL
 * keeps a busy dashboard responsive while still picking up new machines
 * within a few minutes.
 */
const PUBKEY_CACHE_TTL_MS = 5 * 60_000;
const pubkeyCache = new Map<string, { at: number; value: Map<string, string> }>();

/** Test seam: drop cached maps so cases don't leak into each other. */
export function resetAttestationPubkeyCache(): void {
  pubkeyCache.clear();
}

/** Map each of the signed-in user's `dev.cocore.compute.attestation`
 *  records to its `publicKey`. Best-effort: returns whatever it gathered
 *  (possibly empty) on any error, and the caller falls back to the even
 *  split when the map can't attribute the receipts. Cached per DID for
 *  {@link PUBKEY_CACHE_TTL_MS}. */
export async function fetchAttestationPubkeys(session: OAuthSession): Promise<Map<string, string>> {
  const cached = pubkeyCache.get(session.did);
  if (cached && Date.now() - cached.at <= PUBKEY_CACHE_TTL_MS) return cached.value;
  const fetched = await fetchAttestationPubkeysUncached(session);
  // Don't cache an empty map: that's the shape returned on error, and
  // remembering it would suppress attribution for the whole TTL after one
  // transient blip.
  if (fetched.size > 0) pubkeyCache.set(session.did, { at: Date.now(), value: fetched });
  return fetched;
}

async function fetchAttestationPubkeysUncached(
  session: OAuthSession,
): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  let cursor: string | undefined;
  try {
    for (let page = 0; page < MAX_PAGES; page++) {
      const params = new URLSearchParams({
        repo: session.did,
        collection: "dev.cocore.compute.attestation",
        limit: "100",
      });
      if (cursor) params.set("cursor", cursor);
      const r = await session.handle(`/xrpc/com.atproto.repo.listRecords?${params}`, {
        method: "GET",
      });
      if (!r.ok) break;
      const body = (await r.json()) as ListRecordsResponse;
      const records = body.records ?? [];
      for (const rec of records) {
        const pk = rec.value["publicKey"];
        if (typeof pk === "string" && pk.length > 0) out.set(rec.uri, pk);
      }
      if (!body.cursor || records.length === 0) break;
      cursor = body.cursor;
    }
  } catch {
    return out;
  }
  return out;
}
