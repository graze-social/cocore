// Per-WebSocket connection handler. Lifted out of main.ts so the
// re-attestation timing can be unit-tested with short cadences
// (the real deployment uses 5-min / 60-s; tests use 50-ms / 150-ms).
//
// Lifecycle:
//   * client connects → handleConnection is invoked once
//   * client sends `register` → we issue an immediate challenge and
//     schedule periodic re-challenges
//   * each challenge starts a `responseTimeoutMs` deadline; if the
//     deadline fires before an `attestation_response` arrives, the
//     entry is marked unattested (so any in-flight pickFor stops
//     routing) and the socket is closed with 1008
//   * on socket close we tear down timers and remove the entry

import { randomUUID } from "node:crypto";
import type { IncomingMessage } from "node:http";
import type { WebSocket } from "ws";

import { type ApnsConfig, sendCodeChallenge as pushCodeChallenge } from "./apns.ts";
import {
  isFresh,
  makeChallenge,
  makeCodeNonce,
  verifyAttestation,
  verifyCodeAttestation,
} from "./attest.ts";
import { type DidDocumentResolver, LXM_REGISTER, verifyServiceAuthToken } from "./did-auth.ts";
import type { AdvisorMessage, AttestationChallenge } from "./protocol.ts";
import { validateFrame } from "./protocol.ts";
import { CRASH_LOOP_THRESHOLD, ProviderRegistry } from "./registry.ts";
import type { SessionManager } from "./sessions.ts";

// Code-attestation survives brief reconnects. A machine's binary identity
// doesn't change across a Railway-edge socket recycle (the frequent `1006`
// churn), so re-pushing an APNs code-challenge on EVERY re-register exhausted
// Apple's per-device background-push budget and left machines stuck
// best-effort. Instead we cache the proof by (did, machineId) + the measured
// cdHash and restore standing on re-register without a push; the periodic
// re-challenge refreshes it. A cdHash change (new build) invalidates the cache
// — that machine must re-prove. TTL caps how long a proof is honored unrefreshed.
const CODE_ATTEST_TTL_MS = 11 * 60_000;
const codeAttestCache = new Map<string, { cdHash: string; at: number }>();
const codeAttestKey = (did: string, machineId: string): string => `${did} ${machineId}`;
function cachedCodeAttestFresh(
  did: string,
  machineId: string,
  cdHash: string | null,
  now: number,
): boolean {
  if (!cdHash) return false;
  const e = codeAttestCache.get(codeAttestKey(did, machineId));
  return !!e && e.cdHash === cdHash && now - e.at < CODE_ATTEST_TTL_MS;
}
function rememberCodeAttest(
  did: string,
  machineId: string,
  cdHash: string | null,
  now: number,
): void {
  if (!cdHash) return;
  codeAttestCache.set(codeAttestKey(did, machineId), { cdHash, at: now });
}

export interface ConnectionConfig {
  /** How often to issue a fresh attestation challenge to the
   *  provider after their initial register. */
  rechallengeIntervalMs: number;
  /** How long to wait for a response before treating the provider
   *  as wedged and closing the socket. Must be < rechallengeIntervalMs
   *  in practice; the handler does not enforce that. */
  responseTimeoutMs: number;
  /** Optional hook fired the moment the response deadline expires.
   *  Used by tests to observe the timeout without racing on the
   *  socket-close roundtrip. */
  onUnanswered?: (did: string) => void;
  /** WS protocol-level ping cadence. Two jobs: (1) keeps edge
   *  proxies (Railway's ingress, LBs) from idle-killing sockets
   *  whose app-level heartbeats are too sparse to count as traffic,
   *  and (2) detects half-open sockets — a peer that misses
   *  {@link keepaliveMaxMissed} consecutive pongs is terminated so it
   *  doesn't linger as a routable-but-dead provider until the registry
   *  sweep. 0 / unset disables (tests run without it).
   *
   *  Set well UNDER the proxy's idle cutoff: Railway's edge cuts a
   *  connection that's been idle in EITHER direction for ~45–60s, and the
   *  advisor→provider direction otherwise only carries this ping — so a
   *  60s cadence left that direction idle long enough to be reaped (the
   *  observed ~30–90s `1006` churn). 25s keeps both directions active
   *  (ping out, pong back) under the threshold. */
  keepaliveIntervalMs?: number;
  /** Consecutive missed pongs before a socket is terminated as dead.
   *  >1 so the FREQUENT keepalive ping above doesn't nuke a provider that
   *  briefly can't answer (it now pongs from its read half even
   *  mid-inference, but a momentary stall shouldn't cost it the socket).
   *  Defaults to 2 → ~2–3× the ping interval of tolerance. */
  keepaliveMaxMissed?: number;
  /** Proactively close + recycle a connection after this long, with a
   *  clean close so the provider reconnects on its graceful (backoff-
   *  resetting) path. Railway terminates any connection at a hard ~15-min
   *  ceiling with an abrupt `1006`; recycling a bit under that turns the
   *  inevitable cut into a predictable, graceful cycle we control instead
   *  of an edge-initiated reset. 0 / unset disables. */
  maxConnectionMs?: number;
  /** APNs sender config for the code-identity challenge. Null/absent disables
   *  it: no challenges are sent and confidential eligibility is NOT gated on
   *  code-attestation (the pre-APNs behavior). Set exactly when the advisor has
   *  APNs configured (and the registry is constructed with enforcement on). */
  apns?: ApnsConfig | null;
  /** DID-bound registration (C1). When set, the register handler verifies the
   *  frame's `auth_jwt` (a `com.atproto.server.getServiceAuth` token with
   *  `aud = advisorDid`, `lxm = dev.cocore.compute.register`) and requires the
   *  authenticated DID to EQUAL `provider_did` before calling `registry.upsert`
   *  — so a client can't register as a provider it doesn't control (which would
   *  let it swap in its own attestation key and steal that provider's jobs).
   *  Absent → registration is unauthenticated (legacy behavior). */
  advisorDid?: string;
  /** Enforcement flag for {@link advisorDid}. When true (and `advisorDid` is
   *  set), a register lacking a valid DID-bound JWT is REJECTED (close 1008).
   *  When false, the JWT is still VERIFIED if present (and a valid one binds
   *  keys→DID, closing C1 for upgraded providers), but its ABSENCE is tolerated
   *  — this is the safe staged-rollout mode while the fleet ships the JWT. Ops
   *  flips `COCORE_ADVISOR_REQUIRE_AUTH=true` once the provider fleet has
   *  shipped support for minting the register JWT. */
  requireAuth?: boolean;
  /** DID-document resolver for service-auth verification. Defaults to the real
   *  did:plc + did:web resolver inside did-auth.ts; tests inject a stub so JWT
   *  verification doesn't hit the network. */
  didResolver?: DidDocumentResolver;
}

export function handleConnection(
  socket: WebSocket,
  req: IncomingMessage,
  registry: ProviderRegistry,
  sessions: SessionManager,
  config: ConnectionConfig,
): void {
  const peer = req.socket.remoteAddress ?? "?";
  let registeredDid: string | null = null;
  let registeredMachineId: string | null = null;
  let pendingChallenge: AttestationChallenge | null = null;
  // Nonce of the most recent unanswered APNs code-identity challenge, if any.
  let pendingCodeNonce: string | null = null;
  let challengeTimer: NodeJS.Timeout | null = null;
  let challengeResponseTimer: NodeJS.Timeout | null = null;
  let keepaliveTimer: NodeJS.Timeout | null = null;
  let recycleTimer: NodeJS.Timeout | null = null;

  console.error(`[ws] open peer=${peer}`);

  if (config.keepaliveIntervalMs && config.keepaliveIntervalMs > 0) {
    // Frequent keepalive ping: keeps the advisor→provider direction active
    // under Railway's edge idle cutoff (the cause of the ~30–90s `1006`
    // churn — that direction otherwise carried only the sparse ping), and
    // detects a genuinely dead socket. A pong (auto-sent by conforming
    // clients) resets the miss counter; we terminate only after several
    // CONSECUTIVE misses so the now-frequent ping can't reap a provider
    // that briefly stalls (it answers from its read half even
    // mid-inference, but jitter shouldn't cost it the socket).
    const maxMissed =
      config.keepaliveMaxMissed && config.keepaliveMaxMissed > 0 ? config.keepaliveMaxMissed : 2;
    let missed = 0;
    socket.on("pong", () => {
      missed = 0;
    });
    keepaliveTimer = setInterval(() => {
      if (missed >= maxMissed) {
        console.error(
          `[ws] keepalive missed ${missed}× peer=${peer} did=${registeredDid ?? "?"}; terminating`,
        );
        socket.terminate();
        return;
      }
      missed += 1;
      try {
        socket.ping();
      } catch {
        // socket already closing; the close hook clears this timer
      }
    }, config.keepaliveIntervalMs);
    keepaliveTimer.unref();
  }

  if (config.maxConnectionMs && config.maxConnectionMs > 0) {
    // Beat Railway's hard ~15-min connection ceiling to the punch: close
    // cleanly a bit early so the provider reconnects on its graceful path
    // (clean close → backoff stays at the floor) instead of eating an
    // abrupt edge-initiated `1006` at the cap. Predictable, advisor-driven
    // recycling rather than at-the-mercy-of-the-edge resets.
    recycleTimer = setTimeout(() => {
      console.error(
        `[ws] recycling connection peer=${peer} did=${registeredDid ?? "?"} (pre-empting the edge connection cap)`,
      );
      close(1000, "recycle");
    }, config.maxConnectionMs);
    recycleTimer.unref();
  }

  const close = (code = 1000, reason = "normal"): void => {
    try {
      socket.close(code, reason);
    } catch {
      // ignore
    }
  };

  const send = (msg: AdvisorMessage): void => {
    socket.send(JSON.stringify(msg));
  };

  // App-level liveness probe. Resolvers keyed by nonce; settled by the
  // matching `pong` in onMessage, or by the timeout below. Unlike the
  // WS-level ping (auto-ponged by the read half even when the serve loop
  // is wedged), this round-trips through the provider's serve loop, so a
  // pong proves the loop is actually processing frames.
  const pendingPings = new Map<string, (ok: boolean) => void>();
  const ping = (timeoutMs: number): Promise<boolean> =>
    new Promise<boolean>((resolve) => {
      const nonce = randomUUID();
      const timer = setTimeout(() => {
        if (pendingPings.delete(nonce)) resolve(false);
      }, timeoutMs);
      timer.unref?.();
      pendingPings.set(nonce, (ok) => {
        clearTimeout(timer);
        resolve(ok);
      });
      try {
        send({ type: "ping", nonce });
      } catch {
        if (pendingPings.delete(nonce)) {
          clearTimeout(timer);
          resolve(false);
        }
      }
    });

  const clearResponseTimer = (): void => {
    if (challengeResponseTimer) {
      clearTimeout(challengeResponseTimer);
      challengeResponseTimer = null;
    }
  };

  const closeForUnanswered = (): void => {
    challengeResponseTimer = null;
    if (registeredDid && registeredMachineId) {
      registry.clearAttested(registeredDid, registeredMachineId);
      console.error(
        `[ws] re-challenge unanswered did=${registeredDid} machine=${registeredMachineId} nonce=${
          pendingChallenge?.nonce.slice(0, 8) ?? "?"
        }… — marking unattested and closing`,
      );
      config.onUnanswered?.(registeredDid);
    }
    close(1008, "attestation-response-timeout");
  };

  const sendChallenge = (): void => {
    pendingChallenge = makeChallenge();
    socket.send(
      JSON.stringify({
        type: "attestation_challenge",
        ...pendingChallenge,
      }),
    );
    clearResponseTimer();
    challengeResponseTimer = setTimeout(closeForUnanswered, config.responseTimeoutMs);
    // Don't unref the response timer — it's a short-lived deadline
    // (sub-minute by default) whose firing is load-bearing for
    // re-attestation enforcement. Unrefing it would let the
    // process exit before the timer fired in degenerate cases
    // (e.g. tests that don't hold the loop alive elsewhere); we'd
    // rather pay the small cost of keeping the loop alive than
    // miss the timeout.
    console.error(
      `[ws] -> challenge did=${registeredDid ?? "?"} nonce=${pendingChallenge.nonce.slice(0, 8)}…`,
    );
  };

  // Send an APNs code-identity challenge: a fresh nonce sealed to the machine's
  // X25519 key, pushed to its device token. Only the genuine, AMFI-gated binary
  // can receive + open it, so a valid response proves code identity. No-ops
  // when APNs isn't configured or the machine reported no device token (those
  // machines simply stay best-effort). Unlike the WS attestation challenge,
  // a missed code challenge does NOT close the socket — it only drops the
  // machine's confidential standing (best-effort serving is unaffected).
  const issueCodeChallenge = async (): Promise<void> => {
    if (!config.apns || !registeredDid || !registeredMachineId) return;
    const entry = registry.get(registeredDid, registeredMachineId);
    if (!entry || !entry.apnsDeviceToken) return;
    // A still-pending nonce from the previous cycle means the machine missed a
    // challenge — revoke its code-attested standing until it answers again.
    if (pendingCodeNonce) {
      registry.dropCodeAttested(registeredDid, registeredMachineId);
    }
    const nonce = makeCodeNonce();
    pendingCodeNonce = nonce;
    const res = await pushCodeChallenge(
      config.apns,
      entry.apnsDeviceToken,
      entry.encryptionPubKey,
      nonce,
    );
    if (!res.ok) {
      console.error(
        `[ws] code-challenge push failed did=${registeredDid} status=${res.status} reason=${res.reason ?? "?"}`,
      );
    } else {
      console.error(
        `[ws] -> code-challenge did=${registeredDid ?? "?"} nonce=${nonce.slice(0, 8)}…`,
      );
    }
  };

  socket.on("message", (data) => {
    let raw: unknown;
    try {
      raw = JSON.parse(data.toString("utf8")) as unknown;
    } catch (e) {
      console.error(`[ws] malformed JSON peer=${peer}: ${(e as Error).message}`);
      return;
    }
    // Validate the frame SHAPE before dispatch (C2): a handler dereferences
    // per-type fields directly, so a malformed frame (e.g. `{"type":"register"}`
    // or an `attestation_response` without `signature`) would otherwise throw a
    // TypeError → unhandled rejection → process exit. On a shape mismatch we
    // log and close cleanly instead of throwing.
    const check = validateFrame(raw);
    if (!check.ok) {
      console.error(`[ws] bad-frame peer=${peer}: ${check.reason}; closing`);
      return close(1008, "bad-frame");
    }
    // Wrap dispatch so a rejected promise (e.g. an async verify that throws)
    // can't escape as an unhandled rejection and crash the process. A handler
    // failure closes THIS socket, not the advisor.
    void onMessage(check.msg).catch((e) => {
      console.error(`[ws] onMessage error peer=${peer}: ${(e as Error).message}`);
      close(1011, "internal");
    });
  });

  const onMessage = async (msg: AdvisorMessage): Promise<void> => {
    switch (msg.type) {
      case "register": {
        // C1: DID-bound registration. Verify the frame's service-auth JWT and
        // require the authenticated DID to equal `provider_did` before touching
        // the registry — otherwise a client could register as any provider and
        // swap in its own attestation key, stealing that provider's jobs.
        //
        // `advisorDid` unset → unauthenticated legacy behavior. Set →
        //   * a present `auth_jwt` is ALWAYS verified + must bind to
        //     provider_did (a bad/mismatched token is rejected either way);
        //   * a MISSING token is rejected only when `requireAuth` is true. In
        //     staged-rollout mode (requireAuth false) absence is tolerated so
        //     the fleet can upgrade before enforcement flips on.
        // Default true = "no signal": auth isn't enforced (advisorDid unset), so
        // we don't penalize. Flipped to false only in the soft-cutover branch
        // below, where auth IS expected but the frame carried none.
        let registrationAuthenticated = true;
        if (config.advisorDid) {
          if (msg.auth_jwt) {
            // A PRESENT token is always fully verified. A bad/mismatched token is
            // an active forgery attempt (someone trying to register AS another
            // DID), not an un-upgraded client — hard-reject it either way.
            const auth = await verifyServiceAuthToken(msg.auth_jwt, {
              audience: config.advisorDid,
              lxm: LXM_REGISTER,
              resolver: config.didResolver,
            });
            if (!auth.ok) {
              console.error(
                `[ws] register auth rejected did=${msg.provider_did} peer=${peer}: ${auth.error} — ${auth.message}`,
              );
              return close(1008, "register-auth-failed");
            }
            if (auth.did !== msg.provider_did) {
              console.error(
                `[ws] register DID mismatch peer=${peer}: jwt iss=${auth.did} != provider_did=${msg.provider_did}; closing`,
              );
              return close(1008, "register-did-mismatch");
            }
          } else if (config.requireAuth) {
            // Hard mode (the eventual Phase-3 escalation): a missing token is
            // refused outright. Off by default; ops flips COCORE_ADVISOR_REQUIRE_AUTH.
            console.error(
              `[ws] register missing auth_jwt did=${msg.provider_did} peer=${peer} (requireAuth on); closing`,
            );
            return close(1008, "register-auth-required");
          } else {
            // SOFT CUTOVER: auth is expected (advisorDid set) but this frame
            // carried none, and we're not in hard requireAuth mode. Admit the
            // socket — it still serves best-effort — but mark it unauthenticated
            // so consumers refuse it an attested tier (it hasn't proven it owns
            // `provider_did`, so its attestation record can't be trusted). This
            // downgrades instead of disconnecting: an un-upgraded agent keeps
            // working, it just can't be confidential/hardware-attested.
            registrationAuthenticated = false;
          }
        }
        // M1: refuse the registration if the registry is at capacity (a
        // register flood can't grow the map unbounded). A re-register of an
        // already-present machine always succeeds.
        const upserted = registry.upsert(msg, () => close(1000, "replaced"), send, ping);
        if (upserted === false) {
          console.error(
            `[ws] registry full — refusing register did=${msg.provider_did} peer=${peer}`,
          );
          return close(1013, "registry-full");
        }
        registeredDid = msg.provider_did;
        registeredMachineId = ProviderRegistry.machineIdOf(msg);
        // Record the C1 standing (default entry is authenticated=true, so only
        // the soft-downgrade case needs a write). Drops the machine from
        // confidential routing in the registry AND is surfaced on /providers so
        // the console recompute caps it at best-effort.
        if (!registrationAuthenticated) {
          registry.setRegistrationAuthenticated(registeredDid, registeredMachineId, false);
          console.error(
            `[ws] register UNAUTHENTICATED (soft) did=${msg.provider_did} machine=${registeredMachineId} — admitted best-effort, no attested tier until it mints a register token`,
          );
        }
        console.error(
          `[ws] register did=${msg.provider_did} machine=${registeredMachineId} chip=${msg.chip} models=${msg.supported_models.length}`,
        );
        // Note a degraded provider centrally: it connected but reported
        // it couldn't bring its configured engine(s) online, so it's only
        // serving `stub` and won't be matched for the failed models.
        if (msg.engine_fault) {
          console.error(
            `[ws] provider degraded did=${msg.provider_did} engineFault=${msg.engine_fault.code} models=[${(msg.engine_fault.models ?? []).join(", ")}] — ${msg.engine_fault.message}`,
          );
        }
        sendChallenge();
        // Restore code-attested standing across a reconnect WITHOUT a fresh
        // APNs push when the cached proof is still valid for this exact binary
        // (cdHash). Only push a new challenge when there's no fresh proof — a
        // first connect, an expired cache, or a changed cdHash. This keeps the
        // background-push rate to ~the re-challenge cadence instead of once per
        // (frequent) reconnect, which Apple throttles.
        {
          const e = registry.get(registeredDid, registeredMachineId);
          if (
            config.apns &&
            e &&
            cachedCodeAttestFresh(registeredDid, registeredMachineId, e.cdHash, Date.now())
          ) {
            registry.markCodeAttested(registeredDid, registeredMachineId);
          } else {
            void issueCodeChallenge();
          }
        }
        challengeTimer = setInterval(() => {
          sendChallenge();
          void issueCodeChallenge();
        }, config.rechallengeIntervalMs);
        challengeTimer.unref();
        return;
      }
      case "heartbeat": {
        if (!registeredDid || !registeredMachineId) {
          console.error(`[ws] heartbeat before register peer=${peer}; closing`);
          return close(1002, "heartbeat-before-register");
        }
        registry.touch(registeredDid, registeredMachineId);
        // The heartbeat carries the owner's start/stop switch (read by the
        // agent from its PDS). Absent = serving, for old agents.
        registry.setActive(registeredDid, registeredMachineId, msg.active ?? true);
        // Fold in the content-free crash signature, if the provider sent
        // one. Old agents omit it; a machine that's never crashed omits it.
        // We note a crash-looping machine centrally so an operator watching
        // the logs sees the flapping even before /providers is scraped.
        if (msg.crash) {
          registry.setCrash(registeredDid, registeredMachineId, msg.crash);
          if (msg.crash.count >= CRASH_LOOP_THRESHOLD) {
            console.error(
              `[ws] provider crash-looping did=${registeredDid} machine=${registeredMachineId} count=${msg.crash.count}${
                msg.crash.location ? ` location=${msg.crash.location}` : ""
              }${msg.crash.signature ? ` sig=${msg.crash.signature}` : ""} — excluding from jobs`,
            );
          }
        }
        return;
      }
      case "attestation_response": {
        if (!registeredDid || !registeredMachineId || !pendingChallenge) {
          console.error(`[ws] unsolicited attestation peer=${peer}`);
          return;
        }
        if (!isFresh(pendingChallenge, msg)) {
          console.error(`[ws] stale/mismatched attestation did=${registeredDid}; closing`);
          return close(1008, "attestation-replay");
        }
        // Verify against THIS socket's registered key. Keying the lookup by
        // (did, machine) is what prevents a sibling machine's Register from
        // swapping the expected key out mid-challenge — the old DID-only
        // lookup was the source of spurious "BAD attestation signature".
        const entry = registry.get(registeredDid, registeredMachineId);
        if (!entry) return;
        const ok = await verifyAttestation(msg, entry.attestationPubKey);
        if (!ok) {
          console.error(
            `[ws] BAD attestation signature did=${registeredDid} machine=${registeredMachineId}; closing`,
          );
          return close(1008, "attestation-bad-signature");
        }
        registry.markAttested(registeredDid, registeredMachineId);
        // darkbloom-parity continuous SIP check: a verified challenge that
        // reports SIP off immediately drops the machine from confidential
        // routing. (`sip_enabled` is part of the signed challenge payload, so
        // a provider can't claim SIP-on without holding the attestation key.)
        registry.recordChallengeSip(registeredDid, registeredMachineId, msg.sip_enabled === true);
        console.error(`[ws] attestation OK did=${registeredDid} machine=${registeredMachineId}`);
        pendingChallenge = null;
        clearResponseTimer();
        return;
      }
      case "code_attestation_response": {
        // APNs code-identity proof: the machine recovered the nonce we sealed
        // to its X25519 key (so it received the AMFI-gated push and holds K)
        // and SE-signed it. Grant code-attested standing. A bad/stale response
        // only drops confidential standing — best-effort serving is unaffected,
        // so we don't close the socket.
        if (!registeredDid || !registeredMachineId || !pendingCodeNonce) {
          console.error(`[ws] unsolicited code-attestation peer=${peer}`);
          return;
        }
        const entry = registry.get(registeredDid, registeredMachineId);
        if (!entry) return;
        // Bind the proof to the REGISTERED cdHash (0.9.23): the agent SE-signs
        // {cdHash, nonce} over its measured cdHash, and we reconstruct with the
        // cdHash it registered — so the code-identity proof is tied to a specific
        // measured binary, not just "answered the push". A confidential machine
        // always reports a cdHash; if it's absent we can't bind, so fail closed.
        const ok =
          entry.cdHash != null &&
          (await verifyCodeAttestation(
            msg,
            pendingCodeNonce,
            entry.attestationPubKey,
            entry.cdHash,
          ));
        if (!ok) {
          console.error(
            `[ws] BAD code-attestation did=${registeredDid} machine=${registeredMachineId}`,
          );
          registry.dropCodeAttested(registeredDid, registeredMachineId);
          return;
        }
        registry.markCodeAttested(registeredDid, registeredMachineId);
        // Cache the proof so a reconnect restores standing without re-pushing.
        rememberCodeAttest(registeredDid, registeredMachineId, entry.cdHash, Date.now());
        console.error(
          `[ws] code-attestation OK did=${registeredDid} machine=${registeredMachineId}`,
        );
        pendingCodeNonce = null;
        return;
      }
      case "inference_chunk": {
        // H6b: only the provider this session was dispatched to may stream into
        // it. A socket that merely learned the session_id can't inject chunks.
        if (
          !registeredDid ||
          !registeredMachineId ||
          !sessions.ownedBy(msg.session_id, registeredDid, registeredMachineId)
        ) {
          return;
        }
        sessions.write(msg.session_id, {
          type: "chunk",
          sessionId: msg.session_id,
          seq: msg.seq,
          ...(msg.channel ? { channel: msg.channel } : {}),
          ciphertext: msg.ciphertext,
        });
        return;
      }
      case "inference_keepalive": {
        // "Still generating" — reset the session idle timer so a slow-but-
        // alive job (long prefill / slow decode) isn't killed as silent.
        // Not relayed to the requester; doesn't count as a token.
        // H6b: only the assigned provider may keep its own session alive.
        if (
          registeredDid &&
          registeredMachineId &&
          sessions.ownedBy(msg.session_id, registeredDid, registeredMachineId)
        ) {
          sessions.keepalive(msg.session_id);
        }
        return;
      }
      case "inference_complete": {
        // H6b: only the provider a session was dispatched to may complete it —
        // otherwise a foreign socket could finish someone else's job with an
        // attacker `receipt_uri` AND clear its own bad standing via
        // recordCompletion. Drop the frame from any other socket.
        if (
          !registeredDid ||
          !registeredMachineId ||
          !sessions.ownedBy(msg.session_id, registeredDid, registeredMachineId)
        ) {
          console.error(
            `[ws] drop inference_complete from non-owner did=${registeredDid ?? "?"} machine=${registeredMachineId ?? "?"} session=${msg.session_id}`,
          );
          return;
        }
        // A completion proves this machine isn't silently dropping work —
        // record it so the silent-failure detector clears, bad standing is
        // restored, and the dispatch counter has a denominator.
        registry.recordCompletion(registeredDid, registeredMachineId);
        sessions.complete(msg.session_id, {
          tokensIn: msg.tokens_in,
          tokensOut: msg.tokens_out,
          receiptUri: msg.receipt_uri,
        });
        console.error(
          `[ws] complete did=${registeredDid ?? "?"} session=${msg.session_id} receipt=${msg.receipt_uri || "(none)"}`,
        );
        return;
      }
      case "pong": {
        // Settle the matching preflight ping, if still pending.
        const resolve = pendingPings.get(msg.nonce);
        if (resolve) {
          pendingPings.delete(msg.nonce);
          resolve(true);
        }
        return;
      }
      case "recover_result": {
        // The machine reports the outcome of a self-right attempt. On
        // success, clear bad standing immediately so it's routable again
        // without waiting for the re-probe sweep; on failure leave it
        // excluded (the agent keeps a marker the tray + console surface).
        if (!registeredDid || !registeredMachineId) return;
        if (msg.recovered) {
          registry.markHealthy(registeredDid, registeredMachineId);
          console.error(`[ws] recover OK did=${registeredDid} machine=${registeredMachineId}`);
        } else {
          console.error(
            `[ws] recover FAILED did=${registeredDid} machine=${registeredMachineId}: ${msg.detail ?? "(no detail)"}`,
          );
        }
        return;
      }
      // Advisor→provider frames the advisor never receives.
      case "attestation_challenge":
      case "inference_request":
      case "ping":
      case "health_notice":
      case "control_changed":
      case "recover_request":
        return;
    }
  };

  socket.on("close", (code, reason) => {
    if (challengeTimer) clearInterval(challengeTimer);
    if (keepaliveTimer) clearInterval(keepaliveTimer);
    if (recycleTimer) clearTimeout(recycleTimer);
    clearResponseTimer();
    // H6a: only evict the entry if THIS socket still owns it. When a machine
    // reconnects, its new socket's `upsert` REPLACES the entry (and closes this
    // old socket with 1000/"replaced"). That close fires here — but the entry
    // now belongs to the replacement, so removing it would evict the live
    // socket. Compare the per-connection `send` closure (stable + unique per
    // connection, stored on the entry by upsert) to prove ownership; a
    // late/replaced close then no-ops instead of stranding the machine.
    if (registeredDid && registeredMachineId) {
      const entry = registry.get(registeredDid, registeredMachineId);
      if (entry && entry.send === send) registry.remove(registeredDid, registeredMachineId);
    }
    console.error(
      `[ws] close peer=${peer} did=${registeredDid ?? "?"} machine=${registeredMachineId ?? "?"} code=${code} reason=${reason}`,
    );
  });

  socket.on("error", (err) => {
    console.error(`[ws] error peer=${peer} did=${registeredDid ?? "?"}: ${err.message}`);
  });
}
