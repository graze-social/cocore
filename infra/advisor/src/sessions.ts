// In-memory dispatch sessions. Each `POST /jobs` opens an SSE
// connection back to the requester and creates a session keyed by
// the `session_id` we forward to the chosen provider. When the
// provider streams `inference_chunk` and `inference_complete` frames
// back, the WS handler looks up the session here and writes
// `data: <json>\n\n` lines to the SSE response. The session ends
// (and the SSE response closes) on the first `inference_complete`,
// or on a configurable idle timeout.
//
// Like the rest of the advisor, this is in-memory only. A Phase 3
// rewrite will move sessions into Redis or similar so dispatch
// survives advisor restarts; for v0 a redeploy just disconnects
// in-flight requesters and they retry.

import { createHash } from "node:crypto";

import type { AttestedSseEvent } from "./events.ts";
import { renderSseEvent } from "./events.ts";

const COMPLETION_TOMBSTONE_MAX = 1_024;
const REPLAY_FINGERPRINT_MAX = 512;

/** Minimal write-side an SSE relay needs. Node's `ServerResponse` satisfies
 *  this structurally (the test + any raw-`createServer` caller pass one
 *  directly), and so does the @effect/platform stream-backed sink the
 *  HttpRouter `/jobs` route uses — letting the SessionManager drive either
 *  transport with identical frame-writing logic. */
export interface SseResponse {
  statusCode: number;
  setHeader(name: string, value: string | number | readonly string[]): void;
  flushHeaders(): void;
  write(chunk: string): boolean;
  end(): void;
  readonly writableEnded: boolean;
}

export interface SessionEntry {
  /** Provider DID this session was dispatched to. */
  providerDid: string;
  /** Machine (within that DID) this session was dispatched to, so an
   *  idle-timeout flags the specific sour machine rather than the whole
   *  identity (a DID can have several machines). */
  providerMachineId: string;
  /** Requester DID — informational; advisor doesn't enforce
   *  anything about it in v0. */
  requesterDid: string;
  /** Epoch ms the session was created. */
  createdAt: number;
  /** Epoch ms the advisor RECEIVED the `/jobs` request (the start of the
   *  user-facing clock). Defaults to `createdAt` when not supplied. Used
   *  to compute time-to-first-token = firstChunk − requestReceivedAt. */
  requestReceivedAt: number;
  /** Last `inference_chunk` arrival (epoch ms), or null if none yet. */
  lastChunkAt: number | null;
  /** Underlying SSE response — we own writing to it. */
  res: SseResponse;
  /** Wall-clock idle timer; reset on every chunk and cleared on complete. */
  idleTimer: NodeJS.Timeout | null;
  /** Unguessable per-dispatch fence. Null keeps legacy fail-fast behavior. */
  resumeToken: string | null;
  /** First chunk sequence not yet relayed to the requester. */
  nextSeq: number;
  /** Reconnect grace timer while the assigned provider transport is absent. */
  resumeTimer: NodeJS.Timeout | null;
  detached: boolean;
  /** Bounded hashes used to reject conflicting duplicate sequence frames. */
  acceptedFingerprints: Map<number, string>;
}

export interface SessionManagerOpts {
  /** How long without any frame from the provider, once it has started
   *  streaming, before we kill the SSE connection and remove the session.
   *  An `inference_chunk` OR an `inference_keepalive` resets this. */
  idleTimeoutMs?: number;
  /** Grace for the FIRST sign of life (chunk or keepalive). Time-to-first-
   *  token can be long on a big model / slow machine — prompt prefill alone
   *  can exceed the steady-state idle budget — so a session that hasn't
   *  produced anything yet gets this (typically larger) window. Defaults to
   *  `idleTimeoutMs` when unset. */
  firstChunkTimeoutMs?: number;
  /** Fired when a session is torn down by the idle timer (the provider
   *  accepted the job but went silent). Lets the advisor flag that specific
   *  machine's standing so it stops getting routed to + the operator is
   *  notified. Not called on a clean complete or a client disconnect.
   *  `streamed` is true when the provider had already sent ≥1 real chunk
   *  before stalling — a slow-then-stalled job, distinct from one that
   *  accepted work and went completely silent; the advisor uses this to
   *  avoid penalizing a merely-slow machine. */
  onIdleTimeout?: (providerDid: string, providerMachineId: string, streamed: boolean) => void;
  /** Fired once per session, when its FIRST `inference_chunk` arrives, with
   *  the time-to-first-token in ms (firstChunk − requestReceivedAt). The
   *  advisor records these into a rolling window for the public "time to
   *  first token" stat. */
  onFirstChunk?: (ttftMs: number) => void;
  /** Grace for a resume-capable provider socket replacement. */
  resumeGraceMs?: number;
  /** Fired once when reconnect grace expires. */
  onResumeExpired?: (providerDid: string, providerMachineId: string) => void;
}

export class SessionManager {
  private bySessionId = new Map<string, SessionEntry>();
  private idleTimeoutMs: number;
  private firstChunkTimeoutMs: number;
  private onIdleTimeout?: (
    providerDid: string,
    providerMachineId: string,
    streamed: boolean,
  ) => void;
  private onFirstChunk?: (ttftMs: number) => void;
  private resumeGraceMs: number;
  private onResumeExpired?: (providerDid: string, providerMachineId: string) => void;
  private completed = new Map<
    string,
    {
      providerDid: string;
      providerMachineId: string;
      resumeToken: string;
      nextSeq: number;
      timer: NodeJS.Timeout;
    }
  >();

  constructor(opts: SessionManagerOpts = {}) {
    this.idleTimeoutMs = opts.idleTimeoutMs ?? 60_000;
    // Prefill grace defaults to the steady-state budget when unset, so
    // existing callers (and tests) keep their single-timeout behavior.
    this.firstChunkTimeoutMs = opts.firstChunkTimeoutMs ?? this.idleTimeoutMs;
    this.onIdleTimeout = opts.onIdleTimeout;
    this.onFirstChunk = opts.onFirstChunk;
    this.resumeGraceMs = opts.resumeGraceMs ?? 30_000;
    this.onResumeExpired = opts.onResumeExpired;
  }

  /** Create a session, write SSE preamble headers, and return the
   *  entry. Caller is responsible for sending the
   *  `inference_request` frame to the provider AFTER this returns
   *  so any racing chunks have a session to land in.
   *
   *  `receivedAt` is when the advisor received the `/jobs` request (the
   *  start of the time-to-first-token clock); defaults to now. */
  open(
    sessionId: string,
    providerDid: string,
    providerMachineId: string,
    requesterDid: string,
    res: SseResponse,
    receivedAt?: number,
    resumeToken?: string,
  ): SessionEntry {
    if (this.known(sessionId)) {
      throw new Error("session_id is already active or recently completed");
    }
    res.statusCode = 200;
    res.setHeader("content-type", "text/event-stream; charset=utf-8");
    res.setHeader("cache-control", "no-cache, no-transform");
    res.setHeader("connection", "keep-alive");
    // Disable proxy buffering (some reverse proxies stall SSE
    // unless told not to buffer the response body).
    res.setHeader("x-accel-buffering", "no");
    res.flushHeaders();

    const now = Date.now();
    const entry: SessionEntry = {
      providerDid,
      providerMachineId,
      requesterDid,
      createdAt: now,
      requestReceivedAt: receivedAt ?? now,
      lastChunkAt: null,
      res,
      idleTimer: null,
      resumeToken: resumeToken ?? null,
      nextSeq: 0,
      resumeTimer: null,
      detached: false,
      acceptedFingerprints: new Map(),
    };
    this.armIdle(sessionId, entry);
    this.bySessionId.set(sessionId, entry);
    this.write(sessionId, { type: "open", sessionId, providerDid });
    return entry;
  }

  has(sessionId: string): boolean {
    return this.bySessionId.has(sessionId);
  }

  /** Would {@link open} refuse this id? True while the session is live OR
   *  within the completed-tombstone grace. `sessionId` is client-supplied on
   *  `/jobs`, so callers must check this and answer with a structured error
   *  instead of letting `open` throw. */
  known(sessionId: string): boolean {
    return this.bySessionId.has(sessionId) || this.completed.has(sessionId);
  }

  /** H6b: is `(providerDid, providerMachineId)` the provider this session was
   *  dispatched to? Session frames (chunk / keepalive / complete) must come
   *  from the ASSIGNED provider — otherwise any socket that learns a
   *  `session_id` could inject chunks, complete with an attacker receipt_uri,
   *  or clear its own bad standing off someone else's job. Returns false for an
   *  unknown session (so a frame for a session we don't track is dropped). */
  ownedBy(sessionId: string, providerDid: string, providerMachineId: string): boolean {
    const entry = this.bySessionId.get(sessionId);
    if (!entry) return false;
    return entry.providerDid === providerDid && entry.providerMachineId === providerMachineId;
  }

  size(): number {
    return this.bySessionId.size;
  }

  /** Number of in-flight sessions currently dispatched to a specific
   *  machine. Used by job dispatch to spread a burst of near-simultaneous
   *  requests across an owner's capable machines (least-loaded first)
   *  instead of piling every one onto the single freshest-heartbeat
   *  machine while an equally-capable sibling sits idle. A session counts
   *  as in-flight from `open` until `complete`/`close`, so a wedged machine
   *  (job accepted, gone silent) keeps an elevated count until its idle
   *  timer fires — which is exactly when we want to route away from it. */
  inflightFor(providerDid: string, providerMachineId: string): number {
    let n = 0;
    for (const e of this.bySessionId.values()) {
      if (e.providerDid === providerDid && e.providerMachineId === providerMachineId) n += 1;
    }
    return n;
  }

  /** Tear down every in-flight session dispatched to a specific machine,
   *  writing a final `error` event with `reason` to each requester's SSE.
   *  Used when the machine's socket drops mid-job so the requester fails fast
   *  (and can fail over) instead of hanging until the idle timer fires. Reuses
   *  {@link close} for each session (which also clears its idle timer).
   *  Returns the number of sessions closed. */
  closeForMachine(providerDid: string, providerMachineId: string, reason: string): number {
    // Collect first, then close: close() mutates bySessionId, so iterating it
    // while deleting would skip entries.
    const ids: string[] = [];
    for (const [id, e] of this.bySessionId) {
      if (e.providerDid === providerDid && e.providerMachineId === providerMachineId) ids.push(id);
    }
    for (const id of ids) this.close(id, reason);
    return ids.length;
  }

  /** Detach resumable sessions for a bounded socket-replacement grace. Legacy
   *  sessions still fail immediately. Returns counts for logging/accounting. */
  detachForMachine(
    providerDid: string,
    providerMachineId: string,
  ): { detached: number; closed: number } {
    const legacy: string[] = [];
    let detached = 0;
    for (const [sessionId, entry] of this.bySessionId) {
      if (entry.providerDid !== providerDid || entry.providerMachineId !== providerMachineId) {
        continue;
      }
      if (!entry.resumeToken) {
        legacy.push(sessionId);
        continue;
      }
      // Idempotent: a session already in grace keeps its ORIGINAL timer. A
      // same-(did,machine) re-register (e.g. a replacement socket that never
      // presents the resume token) must not restart grace and so starve
      // expiry/failure accounting. A genuine second disconnect after a
      // successful resume has detached=false here, so it gets a fresh timer.
      if (entry.detached) continue;
      if (entry.idleTimer) clearTimeout(entry.idleTimer);
      if (entry.resumeTimer) clearTimeout(entry.resumeTimer);
      entry.idleTimer = null;
      entry.detached = true;
      entry.resumeTimer = setTimeout(() => {
        const current = this.bySessionId.get(sessionId);
        if (!current?.detached) return;
        this.close(sessionId, "resume-expired");
        this.onResumeExpired?.(providerDid, providerMachineId);
      }, this.resumeGraceMs);
      entry.resumeTimer.unref?.();
      detached += 1;
    }
    for (const sessionId of legacy) this.close(sessionId, "provider-disconnected");
    return { detached, closed: legacy.length };
  }

  /** Validate a provider's reconnect claim and return the advisor high-water. */
  resume(
    sessionId: string,
    providerDid: string,
    providerMachineId: string,
    resumeToken: string,
    producedSeq: number,
  ):
    | { status: "resume" | "completed"; nextSeq: number }
    | { status: "rejected"; nextSeq: number; reason: string } {
    const entry = this.bySessionId.get(sessionId);
    if (entry) {
      if (
        entry.providerDid !== providerDid ||
        entry.providerMachineId !== providerMachineId ||
        entry.resumeToken !== resumeToken
      ) {
        return { status: "rejected", nextSeq: 0, reason: "resume-owner-mismatch" };
      }
      if (producedSeq < entry.nextSeq) {
        return { status: "rejected", nextSeq: entry.nextSeq, reason: "provider-state-behind" };
      }
      if (entry.resumeTimer) clearTimeout(entry.resumeTimer);
      entry.resumeTimer = null;
      entry.detached = false;
      this.armIdle(sessionId, entry);
      return { status: "resume", nextSeq: entry.nextSeq };
    }

    const done = this.completed.get(sessionId);
    if (
      done &&
      done.providerDid === providerDid &&
      done.providerMachineId === providerMachineId &&
      done.resumeToken === resumeToken
    ) {
      return { status: "completed", nextSeq: done.nextSeq };
    }
    return { status: "rejected", nextSeq: 0, reason: "resume-unknown-or-expired" };
  }

  /** Relay one resumable chunk exactly once. Gaps are not accepted: returning
   *  the current high-water asks the provider to replay the missing frame. */
  acceptChunk(
    sessionId: string,
    seq: number,
    ev: AttestedSseEvent,
  ): { nextSeq: number; resumeToken: string | null } | null {
    const entry = this.bySessionId.get(sessionId);
    if (!entry || ev.type !== "chunk") return null;
    if (!entry.resumeToken) {
      this.write(sessionId, ev);
      return { nextSeq: seq + 1, resumeToken: null };
    }
    const fingerprint = createHash("sha256")
      .update(ev.channel ?? "content")
      .update("\0")
      .update(JSON.stringify(ev.ciphertext))
      .digest("hex");
    if (seq < entry.nextSeq) {
      const accepted = entry.acceptedFingerprints.get(seq);
      if (accepted && accepted !== fingerprint) {
        this.close(sessionId, "resume-sequence-conflict");
        return null;
      }
      return { nextSeq: entry.nextSeq, resumeToken: entry.resumeToken };
    }
    if (entry.detached || seq > entry.nextSeq) {
      return { nextSeq: entry.nextSeq, resumeToken: entry.resumeToken };
    }
    this.write(sessionId, ev);
    if (!this.bySessionId.has(sessionId)) return null;
    if (entry.acceptedFingerprints.size >= REPLAY_FINGERPRINT_MAX) {
      const oldest = entry.acceptedFingerprints.keys().next().value;
      if (oldest !== undefined) entry.acceptedFingerprints.delete(oldest);
    }
    entry.acceptedFingerprints.set(seq, fingerprint);
    entry.nextSeq += 1;
    return { nextSeq: entry.nextSeq, resumeToken: entry.resumeToken };
  }

  /** Write an SSE event to the session's response. No-op if the
   *  session isn't tracked or the response is already closed. */
  write(sessionId: string, ev: AttestedSseEvent): void {
    const entry = this.bySessionId.get(sessionId);
    if (!entry) return;
    if (ev.type === "chunk") {
      const now = Date.now();
      // First chunk for this session → record time-to-first-token
      // (received → first chunk relayed to the requester).
      if (entry.lastChunkAt === null) {
        try {
          this.onFirstChunk?.(now - entry.requestReceivedAt);
        } catch {
          // a metrics hook must never break the relay
        }
      }
      entry.lastChunkAt = now;
      this.armIdle(sessionId, entry);
    }
    try {
      entry.res.write(renderSseEvent(ev));
    } catch {
      // Client disconnected; drop the session.
      this.close(sessionId, "client-disconnected");
    }
  }

  /** Close + remove a session. Sends a final `error` event with
   *  the supplied reason if the response is still writable. */
  close(sessionId: string, reason?: string): void {
    const entry = this.bySessionId.get(sessionId);
    if (!entry) return;
    if (entry.idleTimer) {
      clearTimeout(entry.idleTimer);
      entry.idleTimer = null;
    }
    if (entry.resumeTimer) {
      clearTimeout(entry.resumeTimer);
      entry.resumeTimer = null;
    }
    if (reason && !entry.res.writableEnded) {
      try {
        entry.res.write(renderSseEvent({ type: "error", sessionId, reason }));
      } catch {
        // ignore
      }
    }
    try {
      entry.res.end();
    } catch {
      // ignore
    }
    this.bySessionId.delete(sessionId);
  }

  /** End-of-stream signal from the provider. Writes a `complete`
   *  SSE event and closes the session cleanly. */
  complete(
    sessionId: string,
    summary: { tokensIn: number; tokensOut: number; receiptUri: string },
    finalSeq?: number,
  ): { accepted: boolean; nextSeq: number; resumeToken: string | null } | null {
    const entry = this.bySessionId.get(sessionId);
    if (!entry) return null;
    // Resume-capable completion is valid only after every produced chunk was
    // accepted. Legacy frames omit finalSeq and retain their old behavior.
    if (entry.resumeToken && finalSeq !== entry.nextSeq) {
      return { accepted: false, nextSeq: entry.nextSeq, resumeToken: entry.resumeToken };
    }
    this.write(sessionId, {
      type: "complete",
      sessionId,
      tokensIn: summary.tokensIn,
      tokensOut: summary.tokensOut,
      receiptUri: summary.receiptUri,
    });
    if (!this.bySessionId.has(sessionId)) return null;
    if (entry.idleTimer) clearTimeout(entry.idleTimer);
    if (entry.resumeTimer) clearTimeout(entry.resumeTimer);
    entry.idleTimer = null;
    entry.resumeTimer = null;
    try {
      entry.res.end();
    } catch {
      // ignore
    }
    this.bySessionId.delete(sessionId);
    if (entry.resumeToken) {
      const prior = this.completed.get(sessionId);
      if (!prior && this.completed.size >= COMPLETION_TOMBSTONE_MAX) {
        const oldestId = this.completed.keys().next().value;
        if (oldestId) {
          const oldest = this.completed.get(oldestId);
          if (oldest) clearTimeout(oldest.timer);
          this.completed.delete(oldestId);
        }
      }
      if (prior) clearTimeout(prior.timer);
      const timer = setTimeout(() => this.completed.delete(sessionId), this.resumeGraceMs);
      timer.unref?.();
      this.completed.set(sessionId, {
        providerDid: entry.providerDid,
        providerMachineId: entry.providerMachineId,
        resumeToken: entry.resumeToken,
        nextSeq: entry.nextSeq,
        timer,
      });
    }
    return { accepted: true, nextSeq: entry.nextSeq, resumeToken: entry.resumeToken };
  }

  /** A provider "still working" signal during a long generation (slow
   *  prefill, or a slow patch with no user-visible token yet). Resets the
   *  idle timer so a slow-but-alive job isn't mistaken for a silent one —
   *  WITHOUT counting as a chunk: no TTFT record, nothing relayed to the
   *  requester, and `lastChunkAt` stays put so the streamed-vs-silent
   *  distinction (and the first-chunk budget) is unaffected. No-op for an
   *  unknown/closed session. */
  keepalive(sessionId: string): void {
    const entry = this.bySessionId.get(sessionId);
    if (!entry || entry.detached) return;
    this.armIdle(sessionId, entry);
  }

  private armIdle(sessionId: string, entry: SessionEntry): void {
    if (entry.idleTimer) clearTimeout(entry.idleTimer);
    // Before the first chunk, allow the (typically longer) prefill/TTFT
    // budget; once streaming has started, hold to the tighter steady-state
    // idle budget. A keepalive resets whichever is active.
    const budget = entry.lastChunkAt === null ? this.firstChunkTimeoutMs : this.idleTimeoutMs;
    entry.idleTimer = setTimeout(() => {
      const tracked = this.bySessionId.get(sessionId);
      const providerDid = tracked?.providerDid;
      const providerMachineId = tracked?.providerMachineId;
      const streamed = (tracked?.lastChunkAt ?? null) !== null;
      this.close(sessionId, "idle-timeout");
      // The machine took the job and went silent — flag it so the advisor
      // stops routing here and the operator gets pinged. `streamed` lets the
      // advisor soften that for a machine that was producing tokens and
      // merely slowed (vs one that never sent a thing).
      if (providerDid && providerMachineId) {
        this.onIdleTimeout?.(providerDid, providerMachineId, streamed);
      }
    }, budget);
    entry.idleTimer.unref?.();
  }
}
