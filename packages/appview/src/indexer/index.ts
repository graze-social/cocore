// AppView indexer.
//
// Subscribes to a Firehose (in-process today; com.atproto.sync via
// @atproto/sync in M5.5) and upserts every dev.cocore.compute.*
// record into the local SQLite store. The Firehose itself is the
// seam for the wire transport — see @cocore/sdk/firehose.
//
// Federation invariant (proved by indexer.federation.test.ts): any
// two AppView operators subscribed to the same Firehose end up with
// the same set of (uri, cid, body) rows. They may differ in
// retention windows, indexing latency, or the convenience APIs
// they layer on top — but never on whether a given canonical record
// was indexed.

import type { Firehose, IndexedRecord } from "@cocore/sdk";
import { ids, lexicons } from "@cocore/sdk/lex";
import { Store } from "../store.ts";

// Re-export the relay wire transport so consumers (e.g. the
// infra/services container) can wire it up via the same package
// subpath as the in-process Indexer — no separate import path,
// no separate package.json `exports` entry.
export { RelayFirehose, type RelayFirehoseOpts } from "./relay-firehose.ts";

/** Accept any cocore-namespaced record, not just compute.*. Account
 *  collections (profile, tokenGrant, friend, tokenPatronage) are
 *  what powers the discovery directory + profile pages + incoming-
 *  friends UI; without indexing them the AppView can't answer
 *  "who has signed up" or "who has friended me." Using a prefix
 *  check rather than enumerating each NSID means new lexicons in
 *  `dev.cocore.*` automatically flow through without touching this
 *  file — but anything outside `dev.cocore.*` is still filtered. */
const COCORE_NAMESPACE_PREFIX = "dev.cocore.";

function isCocoreCollection(collection: string): boolean {
  return collection.startsWith(COCORE_NAMESPACE_PREFIX);
}

// Firehose records are provider-signed, so the commit signature proves `repo`
// is authentic — but it says NOTHING about the record body's shape or size. A
// single validly-signed-but-hostile record (a 50 MB `model` string, a deeply
// nested blob) would otherwise be stored verbatim and then walked by the
// unauthenticated aggregation endpoints, DoS-ing every federated AppView at
// once. Cap the serialized body and, for the collections we have a record
// lexicon for, schema-validate before indexing.
const MAX_RECORD_BYTES = Number(process.env["COCORE_MAX_RECORD_BYTES"] ?? 256 * 1024);

// The size cap + object-shape check are ALWAYS enforced (they stop the concrete
// memory-amplification DoS). Schema validation is warn-by-default: the indexer
// has always stored loose records and the security-critical read path
// (verifyReceipt) re-validates at serve time, so dropping lexicon-invalid
// records is a behavior change gated behind an explicit flag. Set
// COCORE_INDEX_STRICT_VALIDATION=1 to drop invalid records at ingest.
const STRICT_INDEX_VALIDATION = process.env["COCORE_INDEX_STRICT_VALIDATION"] === "1";

// Collections with a registered `record` lexicon in @cocore/sdk/lex, so we can
// assertValidRecord them. Other dev.cocore.* collections (account.*, which are
// not registered here, plus non-record query NSIDs) are size-capped + shape-
// checked but not schema-validated. Keep in lockstep with the record lexicons.
const VALIDATED_RECORD_COLLECTIONS = new Set<string>([
  ids.DevCocoreComputeAttestation,
  ids.DevCocoreComputeDispute,
  ids.DevCocoreComputeExchangeAttestation,
  ids.DevCocoreComputeExchangePolicy,
  ids.DevCocoreComputeJob,
  ids.DevCocoreComputePaymentAuthorization,
  ids.DevCocoreComputeProvider,
  ids.DevCocoreComputeReceipt,
  ids.DevCocoreComputeSettlement,
  ids.DevCocoreComputeTermsAcceptance,
]);

export interface FirehoseEvent {
  uri: string;
  cid: string;
  collection: string;
  repo: string;
  rkey: string;
  record: unknown;
}

export class Indexer {
  readonly store: Store;
  private unsubscribe: (() => void) | null = null;

  constructor(store: Store) {
    this.store = store;
  }

  /** Process a single firehose event. Used by tests and by the wire layer.
   *  Returns false (drops the record) for non-cocore collections, non-object
   *  bodies, oversized bodies, and lexicon-invalid records. */
  ingest(ev: FirehoseEvent): boolean {
    if (!isCocoreCollection(ev.collection)) return false;

    // Every cocore record is a JSON object; anything else is malformed.
    if (typeof ev.record !== "object" || ev.record === null || Array.isArray(ev.record)) {
      console.error(`indexer: dropping non-object ${ev.collection} record ${ev.uri}`);
      return false;
    }

    // Size cap (all cocore collections) — bounds memory here and in the
    // downstream aggregation scans that JSON-walk stored bodies.
    const bytes = Buffer.byteLength(JSON.stringify(ev.record), "utf8");
    if (bytes > MAX_RECORD_BYTES) {
      console.error(
        `indexer: dropping oversized ${ev.collection} record ${ev.uri} (${bytes}B > ${MAX_RECORD_BYTES}B)`,
      );
      return false;
    }

    // Schema-validate the collections we have a record lexicon for. Drop only
    // under the strict flag; otherwise log and still index (see above).
    if (VALIDATED_RECORD_COLLECTIONS.has(ev.collection)) {
      try {
        lexicons.assertValidRecord(ev.collection, {
          $type: ev.collection,
          ...(ev.record as Record<string, unknown>),
        });
      } catch (e) {
        const msg = (e as Error).message;
        if (STRICT_INDEX_VALIDATION) {
          console.error(`indexer: dropping invalid ${ev.collection} record ${ev.uri}: ${msg}`);
          return false;
        }
        console.warn(
          `indexer: indexing lexicon-invalid ${ev.collection} record ${ev.uri} (strict mode off): ${msg}`,
        );
      }
    }

    this.store.upsert({
      uri: ev.uri,
      cid: ev.cid,
      collection: ev.collection,
      repo: ev.repo,
      rkey: ev.rkey,
      body: ev.record,
    });
    return true;
  }

  /** Subscribe to a Firehose. The handler is registered for every
   *  cocore collection; non-cocore events on the same firehose are
   *  ignored. Returns the unsubscribe fn. */
  subscribe(firehose: Firehose): () => void {
    const unsub = firehose.on(null, async (rec: IndexedRecord) => {
      this.ingest({
        uri: rec.uri,
        cid: rec.cid,
        collection: rec.collection,
        repo: rec.repo,
        rkey: rec.rkey,
        record: rec.body,
      });
    });
    this.unsubscribe = unsub;
    return unsub;
  }

  /** Wire-layer entry point. The real implementation (M5.5) opens a
   *  WebSocket to the relay, decodes CAR blocks, and dispatches via
   *  the Firehose. Today the test harness drives ingest() directly. */
  async runFirehose(_relayUrl: string, _cursor: string | null): Promise<void> {
    throw new Error("runFirehose: not yet wired; use subscribe(firehose) or ingest() directly");
  }
}

// Minimal CLI entry point so `aube run indexer` does something useful.
if (import.meta.url === `file://${process.argv[1]}`) {
  const dbPath = process.env["COCORE_DB"] ?? "./appview.db";
  const relay = process.env["COCORE_RELAY"] ?? "wss://bsky.network";
  const store = new Store(dbPath);
  const indexer = new Indexer(store);
  console.error(`indexer: db=${dbPath} relay=${relay}`);
  await indexer.runFirehose(relay, store.getCursor("relay"));
}
