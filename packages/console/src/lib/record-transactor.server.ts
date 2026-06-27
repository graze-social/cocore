// The single compare-and-swap read-modify-write path for mutating an ATProto
// record. Every settings write in the console (and every agent write that
// proxies through it) should go through `transactRecord` so concurrent writers
// — the console UI, the provider agent, and a manual PDS edit — converge
// deterministically against one set of rules:
//
//   1. PDS is the source of truth. Every attempt reads the LATEST record + CID
//      and patches THAT, so a writer never commits on top of stale state.
//   2. Field-scoped patches. A caller mutates only the keys it owns; all other
//      keys — including fields this code has never heard of — carry through
//      verbatim because the patch starts from the freshly-read body. Two
//      writers touching different fields both land; two touching the same field
//      resolve last-writer-wins. This is what replaces the fragile
//      "rebuild-the-record-and-preserve-an-allowlist-of-other-people's-fields"
//      pattern that silently dropped any field someone forgot to add to the
//      list.
//   3. CAS retry. A putRecord that loses the swap (`InvalidSwap` — the CID
//      moved under us) re-reads the now-current record and retries the patch,
//      bounded. The PDS arbitrates contention; whoever commits last wins.
//   4. Fail-closed. A READ failure ABORTS the transaction (it throws); it never
//      invents a default and writes it. Writing on a failed/blind read is
//      exactly the class of bug that reverted owner settings on a transient
//      blip.
//
// The transactor is intentionally storage-agnostic: it takes a `CasRecordStore`
// so the logic is unit-testable without standing up an OAuth session, and the
// PDS-backed store stays a thin adapter (see provider-record-pds.server.ts).

/** A record store the transactor reads from and writes to under CAS. The
 *  PDS-backed implementation wraps `com.atproto.repo.getRecord` /
 *  `putRecord` over an OAuth session; tests inject an in-memory fake. */
export interface CasRecordStore {
  /** Read the current record body + its CID, or `null` when the record does
   *  not exist. A transport/auth failure MUST throw (so the transaction
   *  aborts) — returning `null` here would let a blip look like a missing
   *  record and, with `createIfMissing`, fabricate one. */
  read(rkey: string): Promise<{ cid: string; value: Record<string, unknown> } | null>;
  /** Write `value` guarded by `swapRecord` (the CID the patch was applied to,
   *  or `null` when creating a brand-new record). MUST throw a swap-conflict
   *  error (recognised by {@link isSwapConflict}) when the CID has moved. */
  write(
    rkey: string,
    value: Record<string, unknown>,
    swapRecord: string | null,
  ): Promise<{ cid: string }>;
}

/** Thrown when a transaction needs an existing record but none is present and
 *  `createIfMissing` was not set. */
export class RecordNotFoundError extends Error {
  constructor(rkey: string) {
    super(`no record at rkey ${rkey}`);
    this.name = "RecordNotFoundError";
  }
}

/** Whether an error is the ATProto optimistic-concurrency conflict — the
 *  `swapRecord` CID no longer matches the record's current CID. The PDS raises
 *  the named XRPC error `InvalidSwap`; the descriptive forms ("Record was at
 *  …") are matched defensively. This is the signal to re-read and retry. */
export function isSwapConflict(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /invalid\s*swap|record\s+was\s+at|swap.*did\s*not\s*match/i.test(msg);
}

/** Whether a READ error means "the record genuinely isn't there" (a 404 /
 *  `RecordNotFound` / "could not locate record"), as opposed to a transport or
 *  auth failure that must abort the transaction. Adapters use this to decide
 *  whether `read` returns `null` (absent) or rethrows (blip). */
export function isRecordNotFound(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /record\s*not\s*found|could\s*not\s*locate|not\s*found/i.test(msg);
}

export interface TransactOptions {
  /** Total read-patch-CAS attempts before giving up. Each lost swap consumes
   *  one. Default 6 — enough to ride out a burst of concurrent republishes. */
  maxAttempts?: number;
  /** Create the record (CAS against a null swap) when it doesn't exist yet,
   *  instead of throwing {@link RecordNotFoundError}. Default false: most
   *  console edits target a machine that has already served at least once. */
  createIfMissing?: boolean;
  /** Stamp `createdAt` to now on every write. The provider record treats
   *  `createdAt` as a monotonic "last-published-at" that the AppView index and
   *  the agent's dedup use to order conflicting writes, so an owner edit must
   *  bump it to strictly win a lagging firehose replay. Default false — the
   *  transactor core imposes no field convention; the provider wrapper opts in. */
  stampCreatedAt?: boolean;
  /** Backoff between attempts, injectable so tests run instantly. Receives the
   *  1-based attempt number that just failed. */
  sleep?: (attempt: number) => Promise<void>;
}

async function defaultBackoff(attempt: number): Promise<void> {
  // Small jittered backoff so a thundering herd of republishes desynchronises.
  const base = 40 * attempt;
  const jitter = Math.floor(Math.random() * 40);
  await new Promise((resolve) => setTimeout(resolve, base + jitter));
}

/**
 * Apply `patch` to the latest version of record `rkey` under compare-and-swap,
 * retrying on swap conflicts. Returns the committed CID + the value written.
 *
 * `patch` receives a shallow copy of the current record body (or `{}` when
 * creating) and must return the next body. It should set ONLY the fields the
 * caller owns and leave everything else as-is — that field-scoping is what
 * makes concurrent writers safe.
 */
export async function transactRecord(
  store: CasRecordStore,
  rkey: string,
  patch: (current: Record<string, unknown>) => Record<string, unknown>,
  opts: TransactOptions = {},
): Promise<{ cid: string; value: Record<string, unknown> }> {
  const maxAttempts = Math.max(1, opts.maxAttempts ?? 6);
  const stampCreatedAt = opts.stampCreatedAt ?? false;
  const sleep = opts.sleep ?? defaultBackoff;
  let lastConflict: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    // Read failures propagate here and abort the whole transaction — we never
    // patch-and-write a guessed default on top of an unreadable record.
    const existing = await store.read(rkey);
    if (!existing && !opts.createIfMissing) {
      throw new RecordNotFoundError(rkey);
    }
    const patched = patch(existing ? { ...existing.value } : {});
    const value = stampCreatedAt ? { ...patched, createdAt: new Date().toISOString() } : patched;
    try {
      const { cid } = await store.write(rkey, value, existing ? existing.cid : null);
      return { cid, value };
    } catch (err) {
      if (isSwapConflict(err) && attempt < maxAttempts) {
        // Someone else committed between our read and write — re-read the now
        // current record and replay the patch onto it.
        lastConflict = err;
        await sleep(attempt);
        continue;
      }
      throw err;
    }
  }
  throw lastConflict ?? new Error(`transactRecord(${rkey}): exhausted ${maxAttempts} attempts`);
}
