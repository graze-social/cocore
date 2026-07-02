// Ingest-time validation + signer binding for firehose records (H4).
//
// The indexer historically stored any `dev.cocore.*` record verbatim after
// only a namespace-prefix check, and read APIs then trusted the body fields.
// This module closes the ingest side with three fail-closed gates:
//
//   1. Structural validation — for collections we ship a lexicon for, the
//      record must have every required field present and of the right JSON
//      TYPE (object/array/string/number/boolean). This rejects the
//      type-confused / missing-field garbage a read API would otherwise
//      surface as a canonical receipt. We intentionally do NOT enforce the
//      lexicon's string FORMATS (cid / at-uri / datetime): a forger produces
//      well-formatted values trivially, so format checks add no security, and
//      enforcing them at ingest would drop any record whose producer emits a
//      slightly-off (but semantically fine) value — an availability
//      regression for a component whose invariant is "cache, never ledger."
//      Collections with no registered lexicon (the account.* directory records
//      that power profile/friends pages, and any future NSID) pass untouched,
//      so the change is additive.
//
//   2. Signer binding — a record whose authority is the provider is
//      authoritative ONLY in the provider's own repo. For the current
//      lexicons the provider IS the firehose `repo` (neither the provider nor
//      receipt record carries a body `provider` DID), so this is inherent; the
//      explicit check below is defense-in-depth for any future NSID that adds
//      a `provider` field. `requester` is deliberately NOT bound — the lexicon
//      documents it as denormalized convenience, not an authenticated claim
//      (see read-router's listReceipts comment).
//
//   3. Size cap (also M8) — reject an absurdly large body before it hits
//      SQLite.

import { ids, lexicons } from "@cocore/sdk/lex";

// Minimal shapes of the lexicon def nodes we read. We only touch `type`,
// `required`, and `properties` here; the full @atproto/lexicon types aren't a
// direct dependency of this package, so a structural alias keeps the import
// graph clean without hand-editing generated types.
type LexPropDef = { type?: string; items?: { type?: string } };
type LexRecordMain = {
  type?: string;
  record?: { required?: string[]; properties?: Record<string, LexPropDef> };
};

/** Hard ceiling on a single indexed record's serialized body. cocore records
 *  are small (a receipt with an inline attestation strong-ref is a few KB);
 *  1 MiB is generous headroom while bounding what a single firehose/bridge
 *  event can push into the store. */
const MAX_RECORD_BYTES = 1024 * 1024;

/** Collections whose authoritative signer is the record's `provider` field, if
 *  present. For today's lexicons the provider is the repo (no body field), so
 *  this only bites a future NSID that denormalizes a `provider` DID. */
const PROVIDER_BOUND_COLLECTIONS = new Set<string>([
  ids.DevCocoreComputeProvider,
  ids.DevCocoreComputeReceipt,
]);

export interface IngestValidationResult {
  ok: boolean;
  /** Machine-readable rejection reason (for logs/metrics); undefined on ok. */
  reason?: string;
}

/** Map a lexicon property definition to the JS `typeof`/shape we require, or
 *  null when we don't type-check that kind (unions, refs, unknown, bytes,
 *  blobs, cid-link — validating those structurally is out of scope; presence
 *  of the required key is still enforced). */
function jsonTypeOk(def: LexPropDef | undefined, value: unknown): boolean {
  if (!def) return true;
  switch (def.type) {
    case "string":
      return typeof value === "string";
    case "integer":
      return typeof value === "number" && Number.isFinite(value);
    case "boolean":
      return typeof value === "boolean";
    case "array":
      return Array.isArray(value);
    case "object":
    case "params":
      return typeof value === "object" && value !== null && !Array.isArray(value);
    default:
      // ref / union / unknown / bytes / blob / cid-link / token — presence is
      // enforced by the required-key check; we don't second-guess the shape.
      return true;
  }
}

/** Structural check against the record's main def: required keys present and of
 *  the right JSON type. Returns a reason string on failure, or null when ok. */
function structuralReason(collection: string, record: Record<string, unknown>): string | null {
  const doc = lexicons.get(collection);
  if (!doc) return null; // no schema → nothing to check (see module header)
  const main = doc.defs["main"] as LexRecordMain | undefined;
  if (!main || main.type !== "record" || !main.record) return null;
  const required = main.record.required ?? [];
  const props = main.record.properties ?? {};
  for (const key of required) {
    if (!(key in record) || record[key] === undefined || record[key] === null) {
      return `missing required field: ${key}`;
    }
  }
  for (const [key, value] of Object.entries(record)) {
    if (key === "$type") continue;
    const def = props[key];
    if (def && !jsonTypeOk(def, value)) {
      return `field ${key} has the wrong type`;
    }
  }
  return null;
}

/** Validate a firehose record for ingest. `repo` is the signing DID from the
 *  firehose event. Returns `{ ok: false, reason }` when the record must be
 *  dropped. */
export function validateIngest(
  collection: string,
  repo: string,
  body: unknown,
): IngestValidationResult {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return { ok: false, reason: "body-not-object" };
  }
  const record = body as Record<string, unknown>;

  // Size cap (also M8). JSON.stringify approximates the stored footprint.
  let serialized: string;
  try {
    serialized = JSON.stringify(record);
  } catch {
    return { ok: false, reason: "body-not-serializable" };
  }
  if (Buffer.byteLength(serialized, "utf8") > MAX_RECORD_BYTES) {
    return { ok: false, reason: "record-too-large" };
  }

  // Signer binding: reject a body that names a different provider than its repo.
  if (PROVIDER_BOUND_COLLECTIONS.has(collection)) {
    const bodyProvider = record["provider"];
    if (typeof bodyProvider === "string" && bodyProvider !== repo) {
      return { ok: false, reason: "provider-repo-mismatch" };
    }
  }

  // Structural validation for collections we ship a schema for.
  const reason = structuralReason(collection, record);
  if (reason) return { ok: false, reason: `structural-invalid: ${reason}` };

  return { ok: true };
}
