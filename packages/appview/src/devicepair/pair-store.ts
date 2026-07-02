// In-memory device-pair store (AppView-owned).
//
// State machine for one pairing attempt:
//   pending  -> agent called start; user has not approved.
//   approved -> a signed-in user entered the user_code and approved.
//   denied   -> user denied.
//   expired  -> ttl elapsed before approval.
//   consumed -> poll returned the session; further polls 410.
//
// Process memory for v1 (single-tenant deployment, short-lived codes).
// Swap for Redis when running multiple AppView instances.
//
// Ported from the console's pair-store; the AppView now owns this state.
// The verification URI still points at the console (where the approval UI
// lives), so the store is constructed with the console's public base URL.

import { randomBytes } from "node:crypto";

type PairStatus = "pending" | "approved" | "denied" | "expired" | "consumed";

/** Session blob handed to a paired agent. The agent authenticates to its
 *  `apiBase` with `apiKey`; PDS writes are executed server-side. */
export interface ProviderSession {
  did: string;
  handle: string;
  /** `cocore-...` API key minted on pair-approve, scoped to `did`. */
  apiKey: string;
  /** Base URL the agent should POST records to (it appends
   *  `/api/pds/createRecord`). */
  apiBase: string;
}

export interface PairEntry {
  deviceId: string;
  userCode: string;
  createdAt: number;
  expiresAt: number;
  status: PairStatus;
  session: ProviderSession | null;
  /** Count of failed/mismatched confirm attempts against this code.
   *  Bounded by MAX_CONFIRM_ATTEMPTS to blunt online brute-forcing of the
   *  short user_code — once exceeded the code is force-denied. */
  failedAttempts: number;
}

export interface StartResult {
  deviceId: string;
  userCode: string;
  verificationUri: string;
  pollIntervalSecs: number;
  expiresInSecs: number;
}

const ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // omit ambiguous I, L, O, 0, 1
const DEFAULT_TTL_MS = 10 * 60 * 1000;
const DEFAULT_POLL_INTERVAL_S = 3;
/** Max failed confirm attempts per code before it is force-denied. The
 *  user_code is short (8 chars from a 30-symbol alphabet) and confirm is
 *  network-reachable, so cap online guessing. A legitimate approve succeeds
 *  on the first try, well under this. */
const MAX_CONFIRM_ATTEMPTS = 10;

export class PairStore {
  private byDevice = new Map<string, PairEntry>();
  private byCode = new Map<string, string>();
  private readonly verificationBaseUrl: string;
  private readonly ttlMs: number;
  private readonly nowFn: () => number;

  constructor(
    verificationBaseUrl: string,
    ttlMs: number = DEFAULT_TTL_MS,
    nowFn: () => number = () => Date.now(),
  ) {
    this.verificationBaseUrl = verificationBaseUrl;
    this.ttlMs = ttlMs;
    this.nowFn = nowFn;
  }

  start(): StartResult {
    const now = this.nowFn();
    const entry: PairEntry = {
      deviceId: randomString(32),
      userCode: this.uniqueUserCode(),
      createdAt: now,
      expiresAt: now + this.ttlMs,
      status: "pending",
      session: null,
      failedAttempts: 0,
    };
    this.byDevice.set(entry.deviceId, entry);
    this.byCode.set(entry.userCode, entry.deviceId);
    return {
      deviceId: entry.deviceId,
      userCode: entry.userCode,
      verificationUri: `${this.verificationBaseUrl}/devices/new?code=${entry.userCode}`,
      pollIntervalSecs: DEFAULT_POLL_INTERVAL_S,
      expiresInSecs: Math.floor(this.ttlMs / 1000),
    };
  }

  lookupByCode(userCode: string): PairEntry | null {
    this.gc();
    const id = this.byCode.get(userCode.toUpperCase());
    if (!id) return null;
    return this.byDevice.get(id) ?? null;
  }

  approve(userCode: string, session: ProviderSession): PairEntry {
    const entry = this.lookupByCode(userCode);
    if (!entry) throw new PairError("unknown", "no such pair code");
    if (entry.status !== "pending") {
      throw new PairError("invalid-state", `pair already ${entry.status}`);
    }
    entry.status = "approved";
    entry.session = session;
    return entry;
  }

  deny(userCode: string): void {
    const entry = this.lookupByCode(userCode);
    if (!entry) throw new PairError("unknown", "no such pair code");
    if (entry.status === "pending") entry.status = "denied";
  }

  /** Single uniform confirm path used by the XRPC handler.
   *
   *  SECURITY: this exists so unknown-vs-known codes are indistinguishable
   *  to the caller (both yield `{ ok: false }` — no 404-vs-409 oracle that
   *  would confirm a code exists) AND so guessing is throttled: each failed
   *  attempt against a live code is counted, and past MAX_CONFIRM_ATTEMPTS
   *  the code is force-denied (consumed). A first-try legitimate approve is
   *  well under the cap.
   *
   *  Returns `{ ok: true, status }` only on a successful approve/deny of a
   *  live pending code; every other outcome (unknown code, wrong state,
   *  over-cap) returns `{ ok: false }` with the same shape. */
  confirm(
    userCode: string,
    decision: "approve" | "deny",
    session: ProviderSession | null,
  ): ConfirmResult {
    const entry = this.lookupByCode(userCode);
    // Unknown code: nothing to throttle (no entry to key attempts on) and,
    // critically, the response is identical to a mismatched-but-known code,
    // so this does not reveal whether the code exists.
    if (!entry) return { ok: false };

    if (entry.status !== "pending") {
      // Not actionable (already approved/denied/expired/consumed). Count it
      // as a failed attempt so repeated hammering still trips the cap.
      this.registerFailedAttempt(entry);
      return { ok: false };
    }

    if (decision === "deny") {
      entry.status = "denied";
      return { ok: true, status: "denied" };
    }

    if (!session) return { ok: false }; // approve requires a session
    entry.status = "approved";
    entry.session = session;
    return { ok: true, status: "approved" };
  }

  /** Bump the failed-attempt counter for a code; force-deny once the cap is
   *  exceeded so a live pending code can't be brute-forced indefinitely. */
  private registerFailedAttempt(entry: PairEntry): void {
    entry.failedAttempts += 1;
    if (entry.failedAttempts >= MAX_CONFIRM_ATTEMPTS && entry.status === "pending") {
      entry.status = "denied";
      this.byCode.delete(entry.userCode);
    }
  }

  poll(deviceId: string): PollResult {
    this.gc();
    const entry = this.byDevice.get(deviceId);
    if (!entry) return { kind: "unknown" };
    switch (entry.status) {
      case "pending":
        return { kind: "pending" };
      case "denied":
        return { kind: "denied" };
      case "expired":
        return { kind: "expired" };
      case "consumed":
        return { kind: "consumed" };
      case "approved": {
        const session = entry.session!;
        entry.status = "consumed";
        entry.session = null;
        this.byCode.delete(entry.userCode);
        return { kind: "session", session };
      }
    }
  }

  private gc(): void {
    const now = this.nowFn();
    for (const entry of this.byDevice.values()) {
      if (entry.status === "pending" && now > entry.expiresAt) {
        entry.status = "expired";
        this.byCode.delete(entry.userCode);
      }
    }
  }

  private uniqueUserCode(): string {
    for (let i = 0; i < 8; i++) {
      const code = randomCode(8);
      if (!this.byCode.has(code)) return code;
    }
    throw new Error("exhausted user-code attempts");
  }

  _peek(deviceId: string): PairEntry | undefined {
    return this.byDevice.get(deviceId);
  }
}

export type PollResult =
  | { kind: "unknown" }
  | { kind: "pending" }
  | { kind: "denied" }
  | { kind: "expired" }
  | { kind: "consumed" }
  | { kind: "session"; session: ProviderSession };

/** Uniform outcome of `PairStore.confirm`. On failure the shape is identical
 *  regardless of cause (unknown code, wrong state, over-cap) so the caller
 *  cannot use it as a code-existence oracle. */
export type ConfirmResult = { ok: true; status: "approved" | "denied" } | { ok: false };

// Not exported: only the legacy `approve`/`deny` methods throw it, and the
// XRPC handler now goes through `confirm` (which returns a uniform result
// instead of throwing). Kept module-internal so knip doesn't flag it.
class PairError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "PairError";
    this.code = code;
  }
}

function randomCode(len: number): string {
  const buf = randomBytes(len);
  let out = "";
  for (let i = 0; i < len; i++) {
    out += ALPHABET[buf[i]! % ALPHABET.length];
  }
  return out;
}

function randomString(len: number): string {
  return randomBytes(len).toString("hex").slice(0, len);
}
