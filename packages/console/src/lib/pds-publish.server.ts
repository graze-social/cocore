// Publish ATProto records to the user's PDS via the OAuth session.
//
// This replaces `BridgeRecordTransport` (which never wrote to PDS) on
// the dispatch path. The transport here:
//   1. Calls `com.atproto.repo.createRecord` on the user's PDS via
//      `OAuthSession.handle()`. The session takes care of DPoP proof
//      construction, Bearer headers, and transparent token refresh.
//   2. Mirrors the (real) URI/CID into the local AppView indexer so
//      the in-app dashboards see the new job/auth/receipt without
//      waiting for our firehose to subscribe to the user's PDS.
//
// The mirror call is best-effort: a 5xx from the bridge does NOT fail
// the publish, since the PDS already has the authoritative record.

import type { OAuthSession } from "@atcute/oauth-node-client";

import type { PublishedRecord, RecordTransport } from "@cocore/sdk/publish";

import { bridgeHeaders } from "@/lib/cocore-config.ts";

interface CreateRecordResponse {
  uri: string;
  cid: string;
}

function rkeyFromUri(uri: string): string {
  // at://did:plc:.../collection/rkey → rkey
  const parts = uri.split("/");
  return parts[parts.length - 1] ?? "";
}

export class PdsPublishTransport implements RecordTransport {
  readonly session: OAuthSession;
  readonly bridgeUrl: string | null;

  constructor(opts: { session: OAuthSession; bridgeUrl?: string | null }) {
    this.session = opts.session;
    this.bridgeUrl = opts.bridgeUrl?.replace(/\/$/, "") ?? null;
  }

  async publish<T extends Record<string, unknown>>(args: {
    repo: string;
    collection: string;
    record: T;
  }): Promise<PublishedRecord> {
    // 1. Authoritative write to the user's PDS.
    const r = await this.session.handle(`/xrpc/com.atproto.repo.createRecord`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        repo: args.repo,
        collection: args.collection,
        record: args.record,
      }),
    });
    if (!r.ok) {
      const body = await r.text().catch(() => "");
      throw new Error(
        `pds createRecord ${args.collection} returned ${r.status}: ${body.slice(0, 200)}`,
      );
    }
    const out = (await r.json()) as CreateRecordResponse;

    // 2. Best-effort: notify the local AppView indexer. We don't await
    //    successfully — if the bridge is down or returns 5xx, the PDS
    //    record still wins.
    if (this.bridgeUrl) {
      void fetch(`${this.bridgeUrl}/xrpc/dev.cocore.bridge.publish`, {
        method: "POST",
        headers: bridgeHeaders(),
        body: JSON.stringify({
          uri: out.uri,
          cid: out.cid,
          collection: args.collection,
          repo: args.repo,
          rkey: rkeyFromUri(out.uri),
          body: args.record,
        }),
      }).catch(() => {
        // swallowed on purpose — this is a cache hint, not a checkpoint
      });
    }

    return { uri: out.uri, cid: out.cid };
  }
}
