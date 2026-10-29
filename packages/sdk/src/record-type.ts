// `$type` framing for records written to a PDS.
//
// Every atproto record must carry `$type` naming its lexicon. The reference
// PDS (bsky.network) fills it in from `collection` when it's absent, which is
// why our writers got away without it — but a PDS that validates strictly
// rejects the write with `InvalidRecord: Record missing required $type field`
// (graze-social/cocore#257). Every createRecord / putRecord we issue goes
// through `withRecordType` so the record we send is the record the reference
// PDS would have stored anyway: same bytes, same CID.
//
// Signatures are unaffected: signers canonicalise WITHOUT `$type` and
// verifiers strip it (see p256.ts), or — for records signed with `$type`
// already present (termsAcceptance) — this is a no-op.

/** Return `record` with `$type` set to `collection` when it's missing.
 *  An existing `$type` is left untouched (a mismatch is the PDS's call to
 *  reject, not ours to silently rewrite). `$type` is placed first so the JSON
 *  reads like every other atproto record; key order doesn't affect the CID. */
export function withRecordType<T extends object>(
  collection: string,
  record: T,
): T & { $type: string } {
  const existing = (record as { $type?: unknown }).$type;
  if (typeof existing === "string" && existing.length > 0) {
    return record as T & { $type: string };
  }
  return { $type: collection, ...record };
}
