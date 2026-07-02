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
import { Store } from "../store.ts";
import { validateIngest } from "./validate-ingest.ts";

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
   *  Returns true only when the record was actually indexed. Records that fail
   *  ingest validation (H4: lexicon-invalid, signer-mismatch, or oversized)
   *  are dropped and logged — the AppView is a cache and must never surface a
   *  forged or malformed record as canonical. */
  ingest(ev: FirehoseEvent): boolean {
    if (!isCocoreCollection(ev.collection)) return false;
    const check = validateIngest(ev.collection, ev.repo, ev.record);
    if (!check.ok) {
      console.error(`indexer: dropped ${ev.collection} ${ev.uri} from ${ev.repo}: ${check.reason}`);
      return false;
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
