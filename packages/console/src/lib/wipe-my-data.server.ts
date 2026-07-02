// "Wipe my data" — factory-reset the user's cocore footprint.
//
// What this does:
//   1. For each `dev.cocore.compute.*` collection, list every record
//      on the user's PDS and `deleteRecord` it.
//   2. Tell the bridge to drop every AppView row tied to the user's
//      DID (covers cross-DID rows like autoresponder receipts that
//      reference the user's jobs).
//   3. Hard-delete every API key the user has minted and any
//      `console_user_prefs` row for this DID.
//
// cocore is a closed-loop credit system — there are no external
// payment accounts to disconnect, so a wipe is purely PDS + AppView +
// API keys.
//
// What this does NOT do:
//   * Touch the user's OAuth session (so they stay signed in to
//     cocore.dev).
//   * Touch any provider's (other-DID) PDS records — only the user's
//     own.
//   * Talk to advisor — provider records on advisor are live wire
//     state and rebuild on the next agent restart.
//
// Auth: the caller's OAuth session has to match the DID being wiped.
// This file is server-only — `.server.ts` keeps it out of the client
// bundle so the OAuth handle never leaks browser-side.

import type { OAuthSession } from "@atcute/oauth-node-client";

import { deleteConsoleUserPrefsForDid } from "@/lib/console-user-prefs.server.ts";
import { consoleDb } from "@/lib/console-db.server.ts";
import { bridgeHeaders, cocoreConfig } from "@/lib/cocore-config.ts";

// Every `dev.cocore.compute.*` collection the user might have written
// to. Keep this in lockstep with `lexicons/dev/cocore/compute/*` — a
// missing entry here means a wipe leaves stale records in place (the
// reason a Mar/2026 wipe left `termsAcceptance` records on the user's
// PDS even though the modal reported success).
const COCORE_COLLECTIONS = [
  "dev.cocore.compute.provider",
  "dev.cocore.compute.attestation",
  "dev.cocore.compute.job",
  "dev.cocore.compute.paymentAuthorization",
  "dev.cocore.compute.receipt",
  "dev.cocore.compute.settlement",
  "dev.cocore.compute.dispute",
  "dev.cocore.compute.exchangeAttestation",
  "dev.cocore.compute.exchangePolicy",
  "dev.cocore.compute.termsAcceptance",
  "dev.cocore.account.profile",
] as const;

// PDSes are happy to accept many concurrent deleteRecord calls from
// the same DPoP-bound session. Eight is empirical: large enough that
// wiping ~200 records drops from ~60s to ~5s; small enough that we
// don't trip rate limits on bsky.social-class PDSes.
const DELETE_CONCURRENCY = 8;

export interface WipeReport {
  pdsDeletedByCollection: Record<string, number>;
  pdsErrorsByCollection: Record<string, number>;
  appviewRemoved: number;
  apiKeysRemoved: number;
}

interface ListRecordsResponse {
  records?: Array<{ uri: string }>;
  cursor?: string;
}

async function listAll(session: OAuthSession, collection: string): Promise<string[]> {
  const uris: string[] = [];
  let cursor: string | undefined;
  // PDSes cap listRecords at ~100; loop until exhausted.
  for (let page = 0; page < 100; page++) {
    const params = new URLSearchParams({
      repo: session.did,
      collection,
      limit: "100",
    });
    if (cursor) params.set("cursor", cursor);
    const r = await session.handle(`/xrpc/com.atproto.repo.listRecords?${params}`, {
      method: "GET",
    });
    if (!r.ok) {
      // Non-fatal — caller treats as 0 records for this collection.
      return uris;
    }
    const body = (await r.json()) as ListRecordsResponse;
    for (const rec of body.records ?? []) uris.push(rec.uri);
    if (!body.cursor || (body.records?.length ?? 0) === 0) break;
    cursor = body.cursor;
  }
  return uris;
}

async function deleteOne(session: OAuthSession, collection: string, uri: string): Promise<boolean> {
  const rkey = uri.split("/").pop() ?? "";
  if (!rkey) return false;
  const r = await session.handle(`/xrpc/com.atproto.repo.deleteRecord`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repo: session.did, collection, rkey }),
  });
  return r.ok;
}

async function purgeAppview(did: string): Promise<number> {
  const bridgeUrl = cocoreConfig().bridgeUrl?.replace(/\/$/, "");
  if (!bridgeUrl) return 0;
  try {
    const r = await fetch(`${bridgeUrl}/xrpc/dev.cocore.bridge.purge`, {
      method: "POST",
      headers: bridgeHeaders(),
      body: JSON.stringify({ did }),
    });
    if (!r.ok) return 0;
    const body = (await r.json()) as { removed?: number };
    return body.removed ?? 0;
  } catch {
    return 0;
  }
}

function deleteApiKeysForDid(did: string): number {
  const r = consoleDb().prepare(`DELETE FROM api_keys WHERE did = ?`).run(did);
  return r.changes;
}

// Bounded-parallelism worker pool. We can't lean on `Promise.all` over
// the full URI list because a DID with hundreds of records would open
// hundreds of concurrent fetches and the PDS will start dropping them
// (or rate-limit). The pool keeps DELETE_CONCURRENCY in flight at a
// time and drains.
async function deleteAllConcurrent(
  session: OAuthSession,
  collection: string,
  uris: string[],
): Promise<{ deleted: number; errors: number }> {
  let deleted = 0;
  let errors = 0;
  let cursor = 0;

  async function worker(): Promise<void> {
    while (cursor < uris.length) {
      const i = cursor++;
      const uri = uris[i];
      if (uri === undefined) return;
      const ok = await deleteOne(session, collection, uri).catch(() => false);
      if (ok) deleted++;
      else errors++;
    }
  }

  const workers = Array.from({ length: Math.min(DELETE_CONCURRENCY, uris.length) }, () => worker());
  await Promise.all(workers);
  return { deleted, errors };
}

export async function wipeMyData(session: OAuthSession): Promise<WipeReport> {
  const pdsDeletedByCollection: Record<string, number> = {};
  const pdsErrorsByCollection: Record<string, number> = {};

  for (const collection of COCORE_COLLECTIONS) {
    const uris = await listAll(session, collection);
    const { deleted, errors } = await deleteAllConcurrent(session, collection, uris);
    pdsDeletedByCollection[collection] = deleted;
    pdsErrorsByCollection[collection] = errors;
  }

  const appviewRemoved = await purgeAppview(session.did);
  const apiKeysRemoved = deleteApiKeysForDid(session.did);
  deleteConsoleUserPrefsForDid(session.did);

  return {
    pdsDeletedByCollection,
    pdsErrorsByCollection,
    appviewRemoved,
    apiKeysRemoved,
  };
}
