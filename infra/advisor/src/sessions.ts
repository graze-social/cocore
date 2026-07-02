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

import type { AttestedSseEvent } from "./events.ts";
import { renderSseEvent } from "./events.ts";

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
  /** Wall-clock idle timer; reset on every chunk and cleared on
   *  complete. */
  idleTimer: NodeJS.Timeout | null;
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

  constructor(opts: SessionManagerOpts = {}) {
    this.idleTimeoutMs = opts.idleTimeoutMs ?? 60_000;
    // Prefill grace defaults to the steady-state budget when unset, so
    // existing callers (and tests) keep their single-timeout behavior.
    this.firstChunkTimeoutMs = opts.firstChunkTimeoutMs ?? this.idleTimeoutMs;
    this.onIdleTimeout = opts.onIdleTimeout;
    this.onFirstChunk = opts.onFirstChunk;
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
  ): SessionEntry {
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
    };
    this.armIdle(sessionId, entry);
    this.bySessionId.set(sessionId, entry);
    this.write(sessionId, { type: "open", sessionId, providerDid });
    return entry;
  }

  has(sessionId: string): boolean {
    return this.bySessionId.has(sessionId);
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
  ): void {
    const entry = this.bySessionId.get(sessionId);
    if (!entry) return;
    this.write(sessionId, {
      type: "complete",
      sessionId,
      tokensIn: summary.tokensIn,
      tokensOut: summary.tokensOut,
      receiptUri: summary.receiptUri,
    });
    if (entry.idleTimer) clearTimeout(entry.idleTimer);
    entry.idleTimer = null;
    try {
      entry.res.end();
    } catch {
      // ignore
    }
    this.bySessionId.delete(sessionId);
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
    if (!entry) return;
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
