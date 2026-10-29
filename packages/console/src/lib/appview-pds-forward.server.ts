// Forward a PDS write to the AppView's internal write endpoint.
//
// The cutover keeps the console as the key store + customer-facing
// endpoint, but moves the actual OAuth/DPoP write (and its single-writer
// session refresh) to the AppView. The console resolves its bearer key →
// DID (unchanged), then forwards here. So existing console-minted keys
// keep working with zero customer change, while the AppView owns the
// session.
//
// Gated on configuration: when COCORE_APPVIEW_INTERNAL_URL +
// COCORE_INTERNAL_SECRET are set, callers forward; otherwise they fall
// back to the console's own OAuth session (legacy behavior). This makes
// the rollout safe — a deploy without the env behaves exactly as before.

import type { RecordTransport, PublishedRecord } from "@cocore/sdk/publish";
import { withRecordType } from "@cocore/sdk/record-type";

function base(): string | null {
  return process.env["COCORE_APPVIEW_INTERNAL_URL"]?.replace(/\/$/, "") || null;
}
function secret(): string | null {
  return process.env["COCORE_INTERNAL_SECRET"] || null;
}

/** True when PDS writes should be forwarded to the AppView. */
export function isAppviewForwardConfigured(): boolean {
  return Boolean(base() && secret());
}

type PdsOp = "createRecord" | "putRecord" | "deleteRecord";

/** Forward a write to the AppView's `/internal/pds/<op>`. The AppView
 *  restores the DID's session and performs the DPoP write. Returns the
 *  AppView's raw Response so callers can pass it through or parse it. */
export async function forwardPdsWrite(op: PdsOp, body: Record<string, unknown>): Promise<Response> {
  const b = base();
  const s = secret();
  if (!b || !s) throw new Error("AppView PDS forward not configured");
  return fetch(`${b}/internal/pds/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-cocore-internal-secret": s },
    body: JSON.stringify(body),
  });
}

/** RecordTransport that forwards publishes to the AppView (for the
 *  inference-dispatch submitJob path). `repo` carries the owning DID. */
export class AppviewForwardTransport implements RecordTransport {
  async publish<T extends Record<string, unknown>>(args: {
    repo: string;
    collection: string;
    record: T;
  }): Promise<PublishedRecord> {
    const r = await forwardPdsWrite("createRecord", {
      did: args.repo,
      collection: args.collection,
      record: withRecordType(args.collection, args.record),
    });
    if (!r.ok) {
      const text = await r.text().catch(() => "");
      throw new Error(
        `appview createRecord ${args.collection} returned ${r.status}: ${text.slice(0, 300)}`,
      );
    }
    const out = (await r.json()) as PublishedRecord;
    return { uri: out.uri, cid: out.cid };
  }
}
