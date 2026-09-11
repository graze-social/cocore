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

/** What the requester told us about itself at `start`. All optional; a bare
 *  `cocore agent pair` sends none of it. Validated by the route layer (length
 *  caps, control characters stripped, `returnUrl` host allowlisted) before it
 *  reaches the store. */
export interface PairMeta {
  /** Human name of the app asking for a key, shown on the approve screen. */
  appName?: string;
  /** Name for the minted API key, so the user can recognise and revoke it. */
  keyName?: string;
  /** Where to send the browser after approval. */
  returnUrl?: string;
}

export interface PairEntry {
  deviceId: string;
  userCode: string;
  createdAt: number;
  expiresAt: number;
  status: PairStatus;
  session: ProviderSession | null;
  meta: PairMeta;
}

/** Public view of one pairing attempt, keyed by the user-visible code. Safe to
 *  return to anyone holding the code: it only echoes what the requester sent. */
export interface DescribeResult {
  status: PairStatus;
  appName?: string;
  keyName?: string;
  returnUrl?: string;
  expiresInSecs: number;
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

  start(meta: PairMeta = {}): StartResult {
    const now = this.nowFn();
    const entry: PairEntry = {
      deviceId: randomString(32),
      userCode: this.uniqueUserCode(),
      createdAt: now,
      expiresAt: now + this.ttlMs,
      status: "pending",
      session: null,
      meta: { ...meta },
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

  describe(userCode: string): DescribeResult | null {
    const entry = this.lookupByCode(userCode);
    if (!entry) return null;
    const remaining = Math.max(0, Math.floor((entry.expiresAt - this.nowFn()) / 1000));
    return {
      status: entry.status,
      ...(entry.meta.appName ? { appName: entry.meta.appName } : {}),
      ...(entry.meta.keyName ? { keyName: entry.meta.keyName } : {}),
      ...(entry.meta.returnUrl ? { returnUrl: entry.meta.returnUrl } : {}),
      expiresInSecs: remaining,
    };
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

export class PairError extends Error {
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
