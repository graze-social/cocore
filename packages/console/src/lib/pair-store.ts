// In-memory device-pair store.
//
// State machine for one pairing attempt:
//
//   pending   -> headless agent has called .start; user has not yet
//                approved.
//   approved  -> a signed-in user entered the user_code in the
//                browser and pressed "approve".
//   denied    -> user clicked deny.
//   expired   -> ttl elapsed before approval.
//   consumed  -> .poll returned the session and the agent is bound;
//                further .poll calls 410.
//
// We keep this in process memory for v1 — the console is single-tenant
// in the typical deployment (the operator runs it for themselves) and
// pair codes are short-lived. M3 swaps this for Redis when we run
// multiple console instances behind a load balancer.

import { randomBytes } from "node:crypto";

type PairStatus = "pending" | "approved" | "denied" | "expired" | "consumed";

/** Session blob handed to a paired agent.
 *
 *  Replaces the OAuth-token bundle we used pre-v0.3.0. The agent no
 *  longer talks to bsky directly: every PDS write is proxied through
 *  the console (which has the DPoP-aware OAuth session). The agent
 *  authenticates to the console with this API key. */
export interface ProviderSession {
  did: string;
  handle: string;
  /** `cocore-...` API key minted on pair-approve, scoped to `did`. */
  apiKey: string;
  /** Console base URL the agent should POST records to. e.g.
   *  `https://cocore.dev`. The agent appends
   *  `/api/pds/createRecord`. */
  apiBase: string;
}

/** What the requester told us about itself at `start`. All optional; a bare
 *  `cocore agent pair` sends none of it. Validated by the route layer before it
 *  reaches the store. */
export interface PairMeta {
  appName?: string;
  keyName?: string;
  returnUrl?: string;
}

export interface PairEntry {
  deviceId: string;
  userCode: string;
  createdAt: number; // epoch ms
  expiresAt: number; // epoch ms
  status: PairStatus;
  session: ProviderSession | null;
  meta: PairMeta;
}

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
  private byCode = new Map<string, string>(); // userCode -> deviceId
  private readonly consoleBaseUrl: string;
  private readonly ttlMs: number;
  private readonly nowFn: () => number;

  constructor(
    consoleBaseUrl: string,
    ttlMs: number = DEFAULT_TTL_MS,
    nowFn: () => number = () => Date.now(),
  ) {
    this.consoleBaseUrl = consoleBaseUrl;
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
      verificationUri: `${this.consoleBaseUrl}/devices/new?code=${entry.userCode}`,
      pollIntervalSecs: DEFAULT_POLL_INTERVAL_S,
      expiresInSecs: Math.floor(this.ttlMs / 1000),
    };
  }

  /** Browser side: look up a pending pair by user code. Returns null
   *  when the code is unknown or already consumed. */
  lookupByCode(userCode: string): PairEntry | null {
    this.gc();
    const id = this.byCode.get(userCode.toUpperCase());
    if (!id) return null;
    return this.byDevice.get(id) ?? null;
  }

  /** Browser side: user pressed "approve" after signing in. */
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

  /** Browser side: user pressed "deny". */
  deny(userCode: string): void {
    const entry = this.lookupByCode(userCode);
    if (!entry) throw new PairError("unknown", "no such pair code");
    if (entry.status === "pending") entry.status = "denied";
  }

  /** Agent side: poll for the session. Returns the session exactly
   *  once on success; subsequent calls 410. */
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

  // Test-only inspection.
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

// One process-wide store per Node process. The Start server reuses the
// module across requests so this is the natural shape.
let _shared: PairStore | null = null;
export function sharedStore(): PairStore {
  if (!_shared) {
    const base = process.env["CONSOLE_PUBLIC_URL"] ?? "http://localhost:3000";
    _shared = new PairStore(base);
  }
  return _shared;
}
