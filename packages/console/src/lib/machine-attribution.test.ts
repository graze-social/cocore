import type { OAuthSession } from "@atcute/oauth-node-client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  fetchAttestationPubkeys,
  resetAttestationPubkeyCache,
} from "@/lib/machine-attribution.server.ts";

/** Minimal stand-in for the session: the module only uses `.did` and
 *  `.handle`. Counts calls so we can assert on round-trips, which is the
 *  whole point — each one is a listRecords page proxied to the user's PDS. */
function fakeSession(did: string, pages: Array<{ records: unknown[]; cursor?: string }>) {
  let calls = 0;
  const session = {
    did,
    handle: (_path: string) => {
      const page = pages[Math.min(calls, pages.length - 1)];
      calls += 1;
      return Promise.resolve(
        new Response(JSON.stringify(page), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      );
    },
  };
  return { session: session as unknown as OAuthSession, calls: () => calls };
}

const rec = (uri: string, publicKey: string) => ({ uri, value: { publicKey } });

describe("fetchAttestationPubkeys", () => {
  beforeEach(() => resetAttestationPubkeyCache());
  afterEach(() => resetAttestationPubkeyCache());

  it("maps attestation URIs to their publicKey", async () => {
    const { session } = fakeSession("did:plc:a", [{ records: [rec("at://a/1", "pk-1")] }]);
    const out = await fetchAttestationPubkeys(session);
    expect(out.get("at://a/1")).toBe("pk-1");
  });

  it("does not re-page the PDS on a second call for the same DID", async () => {
    // Pages are strictly sequential (each needs the previous cursor), so an
    // account with 100+ attestations paid up to 10 proxied round-trips on
    // EVERY /machines load. That was seconds of the page's TTFB.
    const { session, calls } = fakeSession("did:plc:a", [{ records: [rec("at://a/1", "pk-1")] }]);
    await fetchAttestationPubkeys(session);
    const before = calls();
    const second = await fetchAttestationPubkeys(session);
    expect(calls()).toBe(before);
    expect(second.get("at://a/1")).toBe("pk-1");
  });

  it("caches per DID, so one user's map never serves another", async () => {
    const a = fakeSession("did:plc:a", [{ records: [rec("at://a/1", "pk-a")] }]);
    const b = fakeSession("did:plc:b", [{ records: [rec("at://b/1", "pk-b")] }]);
    await fetchAttestationPubkeys(a.session);
    const outB = await fetchAttestationPubkeys(b.session);
    expect(outB.get("at://b/1")).toBe("pk-b");
    expect(outB.has("at://a/1")).toBe(false);
    expect(b.calls()).toBe(1);
  });

  it("never caches an empty map, so one blip can't suppress attribution", async () => {
    // An empty map is also the error shape. Remembering it would fall the
    // dashboard back to the even split for the whole TTL after a single
    // transient failure.
    const { session, calls } = fakeSession("did:plc:a", [{ records: [] }]);
    await fetchAttestationPubkeys(session);
    const after = calls();
    await fetchAttestationPubkeys(session);
    expect(calls()).toBeGreaterThan(after);
  });

  it("follows the cursor across pages", async () => {
    const { session } = fakeSession("did:plc:a", [
      { records: [rec("at://a/1", "pk-1")], cursor: "c1" },
      { records: [rec("at://a/2", "pk-2")] },
    ]);
    const out = await fetchAttestationPubkeys(session);
    expect(out.get("at://a/1")).toBe("pk-1");
    expect(out.get("at://a/2")).toBe("pk-2");
  });
});
