// Advisor — WebSocket matchmaker + minimal job dispatch.
//
// Surfaces in this build:
//   * `WS  /v1/agent`  — providers Register, Heartbeat, answer
//                        AttestationChallenges, and forward
//                        InferenceChunk / InferenceComplete back to
//                        whichever requester opened the dispatch.
//   * `GET /healthz`   — Railway healthcheck.
//   * `GET /providers` — debug list of who's online.
//   * `POST /jobs`     — Phase 2.5: requester submits a sealed
//                        prompt, advisor picks an attested provider,
//                        forwards `inference_request`, and streams
//                        chunks back as text/event-stream.
//
// State stays in-memory: ProviderRegistry tracks who's connected
// and live; SessionManager tracks who's awaiting an SSE relay.
// Both are lost on restart — providers reconnect automatically;
// in-flight requesters retry.

import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage } from "node:http";
import { join } from "node:path";

import { HttpRouter } from "@effect/platform";
import { Config, Effect, Metric, Option } from "effect";
import { WebSocketServer } from "ws";

import { makeRuntime, record } from "@cocore/o11y";
import { bearer, err, jsonBody, makeNodeHandler, ok } from "@cocore/o11y/http";

import { loadApnsConfig } from "./apns.ts";
import { handleConnection } from "./connection.ts";
import { type DidDocumentResolver, LXM_CONTROL, verifyServiceAuthToken } from "./did-auth.ts";
import { jobsRoute } from "./jobs.ts";
import { KnownGoodSet } from "./known-good.ts";
import { hydrateLatencyWindow, persistLatencyWindow } from "./latency-store.ts";
import { LatencyWindow } from "./latency-window.ts";
import { ackMs, onlineProviders, ttftMs } from "./metrics.ts";
import { ProviderRegistry } from "./registry.ts";
import { SessionManager } from "./sessions.ts";

const SERVICE = { serviceName: "cocore-advisor" };

// Typed, fail-fast configuration. Read ONCE at startup so a malformed
// numeric knob crashes the process immediately (with a clear Config
// error) rather than silently coercing to NaN deep in a timer. All
// values are integer milliseconds / counts; defaults preserved exactly
// from the previous `Number(process.env[...] ?? n)` reads.
const CONFIG = Effect.runSync(
  Effect.all({
    // PORT wins, then COCORE_ADVISOR_PORT, then 8082 — same precedence
    // as the old `?? ?? 8082` chain.
    port: Config.integer("PORT").pipe(
      Config.orElse(() => Config.integer("COCORE_ADVISOR_PORT")),
      Config.withDefault(8082),
    ),
    heartbeatTimeoutMs: Config.integer("COCORE_ADVISOR_HEARTBEAT_TIMEOUT_MS").pipe(
      Config.withDefault(90_000),
    ),
    sweepIntervalMs: Config.integer("COCORE_ADVISOR_SWEEP_INTERVAL_MS").pipe(
      Config.withDefault(30_000),
    ),
    rechallengeIntervalMs: Config.integer("COCORE_ADVISOR_RECHALLENGE_INTERVAL_MS").pipe(
      Config.withDefault(5 * 60_000),
    ),
    challengeResponseTimeoutMs: Config.integer("COCORE_ADVISOR_CHALLENGE_RESPONSE_TIMEOUT_MS").pipe(
      Config.withDefault(60_000),
    ),
    sessionIdleTimeoutMs: Config.integer("COCORE_ADVISOR_SESSION_IDLE_TIMEOUT_MS").pipe(
      Config.withDefault(90_000),
    ),
    sessionFirstChunkTimeoutMs: Config.integer(
      "COCORE_ADVISOR_SESSION_FIRST_CHUNK_TIMEOUT_MS",
    ).pipe(Config.withDefault(120_000)),
    preflightTimeoutMs: Config.integer("COCORE_ADVISOR_PREFLIGHT_TIMEOUT_MS").pipe(
      Config.withDefault(1500),
    ),
    wsKeepaliveIntervalMs: Config.integer("COCORE_ADVISOR_WS_KEEPALIVE_MS").pipe(
      Config.withDefault(25_000),
    ),
    wsKeepaliveMaxMissed: Config.integer("COCORE_ADVISOR_WS_KEEPALIVE_MAX_MISSED").pipe(
      Config.withDefault(2),
    ),
    wsMaxConnectionMs: Config.integer("COCORE_ADVISOR_WS_MAX_CONNECTION_MS").pipe(
      Config.withDefault(840_000),
    ),
    reprobeIntervalMs: Config.integer("COCORE_ADVISOR_REPROBE_INTERVAL_MS").pipe(
      Config.withDefault(5_000),
    ),
    reprobeTimeoutMs: Config.integer("COCORE_ADVISOR_REPROBE_TIMEOUT_MS").pipe(
      Config.withDefault(1500),
    ),
    ttftWindowSamples: Config.integer("COCORE_ADVISOR_TTFT_SAMPLES").pipe(Config.withDefault(100)),
    // Disk-backed latency cache. `COCORE_ADVISOR_DATA_DIR` wins; otherwise we
    // derive a subdir under the mounted Railway volume so prod persists by
    // default. Neither set (dev/CI) → no persistence, windows stay in-memory.
    dataDir: Config.string("COCORE_ADVISOR_DATA_DIR").pipe(Config.option),
    railwayVolumeMountPath: Config.string("RAILWAY_VOLUME_MOUNT_PATH").pipe(Config.option),
    latencyPersistIntervalMs: Config.integer("COCORE_ADVISOR_LATENCY_PERSIST_INTERVAL_MS").pipe(
      Config.withDefault(30_000),
    ),
    // --- DID-bound auth (C1 / M3) ---
    // This advisor's DID (e.g. did:web:advisor.cocore.dev). It's the `aud` the
    // provider mints its register/control service-auth JWTs for. Unset → auth
    // is off entirely (legacy unauthenticated behavior). Optional so dev/CI can
    // run without it.
    advisorDid: Config.string("COCORE_ADVISOR_DID").pipe(Config.option),
    // Enforcement flag for DID-bound registration + /control. Default false so
    // the live fleet isn't broken before providers ship the JWT: absence of a
    // token is tolerated (but a present token is still verified + bound). Ops
    // flips this to true once the fleet has upgraded.
    requireAuth: Config.boolean("COCORE_ADVISOR_REQUIRE_AUTH").pipe(Config.withDefault(false)),
    // --- Resource caps (M1) ---
    // Max inbound WS frame. Default 256 KiB — our frames are heartbeats +
    // sealed ciphertext, all well under this; the `ws` default of 100 MiB let a
    // single frame exhaust memory. `/jobs` (which carries large multimodal
    // payloads) is a separate HTTP path with its own 32 MiB body cap.
    wsMaxPayloadBytes: Config.integer("COCORE_ADVISOR_WS_MAX_PAYLOAD").pipe(
      Config.withDefault(262_144),
    ),
    // Total concurrent WS connections; over this, new upgrades are refused so a
    // connection flood can't exhaust file descriptors / memory.
    wsMaxConnections: Config.integer("COCORE_ADVISOR_WS_MAX_CONNECTIONS").pipe(
      Config.withDefault(5_000),
    ),
    // Per-remote-IP concurrent WS connections; bounds a single client from
    // eating the whole connection budget. DISABLED by default (0): the advisor
    // runs behind Railway's edge, where every provider connection arrives from
    // one of a few shared proxy IPs — a per-remote-IP cap would then reject the
    // legitimate fleet the moment it exceeded the cap. Enable it (and set
    // COCORE_ADVISOR_TRUST_PROXY=1 so it keys on the forwarded client IP, not
    // the proxy) only in a deployment where remote IPs are per-client. The
    // total cap + maxPayload are the always-on DoS guards.
    wsMaxConnectionsPerIp: Config.integer("COCORE_ADVISOR_WS_MAX_CONNECTIONS_PER_IP").pipe(
      Config.withDefault(0),
    ),
    // Trust `X-Forwarded-For` for the client IP behind a proxy (Railway). Only
    // meaningful when the per-IP cap is enabled; when off, the per-IP key is the
    // direct socket peer. Default false — trusting XFF from a directly-exposed
    // listener would let a client spoof its IP to dodge the per-IP cap.
    wsTrustProxy: Config.boolean("COCORE_ADVISOR_TRUST_PROXY").pipe(Config.withDefault(false)),
    // Max entries the provider registry will hold; a registration over this is
    // refused so a register flood can't grow the map unbounded.
    registryMaxSize: Config.integer("COCORE_ADVISOR_REGISTRY_MAX_SIZE").pipe(
      Config.withDefault(10_000),
    ),
  }),
);

const PORT = CONFIG.port;
const HEARTBEAT_TIMEOUT_MS = CONFIG.heartbeatTimeoutMs;
const SWEEP_INTERVAL_MS = CONFIG.sweepIntervalMs;
const RECHALLENGE_INTERVAL_MS = CONFIG.rechallengeIntervalMs;
/** How long the advisor waits for the provider to answer a
 *  re-challenge before assuming the provider is wedged / offline /
 *  rooted-and-pretending-to-be-alive. On expiry the socket is
 *  closed with 1008 ("policy-violation") and the registry entry is
 *  marked unattested so any in-flight `pickFor` stops routing to
 *  them. The agent's `cocore agent serve` auto-reconnect will
 *  re-register and re-attest within seconds when this happens. */
const CHALLENGE_RESPONSE_TIMEOUT_MS = CONFIG.challengeResponseTimeoutMs;
/** Staleness floor passed to `pickFor` so a one-time-attested
 *  provider whose subsequent challenge responses get lost can't
 *  stay routable indefinitely if the socket-close hook somehow
 *  fails (e.g. the WS library swallowed an error). One full
 *  rechallenge round plus a generous buffer. */
const ATTESTATION_MAX_AGE_MS = RECHALLENGE_INTERVAL_MS + CHALLENGE_RESPONSE_TIMEOUT_MS + 30_000;
/** How long a dispatched job may go without ANY frame (chunk OR keepalive)
 *  from the provider, once it has started streaming, before the advisor
 *  gives up and flags it. Updated providers send an `inference_keepalive`
 *  every ~10s while generating, so this only fires on a genuinely wedged
 *  machine. Raised from 30s so a slow decode patch (a big model on a
 *  laptop, growing KV cache) on an OLD provider that only emits real tokens
 *  isn't mistaken for silence. */
const SESSION_IDLE_TIMEOUT_MS = CONFIG.sessionIdleTimeoutMs;
/** Grace for the FIRST sign of life (chunk or keepalive). Prompt prefill /
 *  time-to-first-token on a large model on modest hardware can take well
 *  over the steady-state idle budget before a single token appears, so the
 *  pre-first-chunk window is larger. Keepalives from updated providers
 *  cover this too; the larger window is the safety net for old providers. */
const SESSION_FIRST_CHUNK_TIMEOUT_MS = CONFIG.sessionFirstChunkTimeoutMs;
/** Per-job preflight budget: how long to wait for the chosen provider to
 *  answer an app-level `ping` before failing over to the next candidate.
 *  A healthy serve loop answers in a few ms; this only needs to clear
 *  network RTT to the provider. */
const PREFLIGHT_TIMEOUT_MS = CONFIG.preflightTimeoutMs;
/** WS protocol-level ping cadence (see ConnectionConfig in
 *  connection.ts). Set UNDER Railway's edge idle cutoff (~45–60s of
 *  one-directional silence → the proxy reaps the socket with a `1006`,
 *  the dominant connection churn we measured: a 30–90s median lifetime).
 *  The advisor→provider direction otherwise carries only this ping, so a
 *  60s cadence left it idle long enough to be cut; 25s keeps both
 *  directions active (ping out + pong back) comfortably under the
 *  threshold. The old 60s value was chosen when a provider mid-inference
 *  couldn't pong — no longer true (it answers from its read half while
 *  inference runs on a blocking thread), and `WS_KEEPALIVE_MAX_MISSED`
 *  tolerance covers any brief stall. Set to 0 to disable. */
const WS_KEEPALIVE_INTERVAL_MS = CONFIG.wsKeepaliveIntervalMs;
/** Consecutive missed pongs before a socket is reaped as dead. >1 so the
 *  frequent keepalive ping can't terminate a provider over a momentary
 *  stall — ~2–3× the ping interval of slack (~50–75s at 25s). */
const WS_KEEPALIVE_MAX_MISSED = CONFIG.wsKeepaliveMaxMissed;
/** Proactively recycle a connection this long after it opens, with a
 *  clean close. Railway hard-caps connection duration at ~15 min and cuts
 *  with an abrupt `1006`; closing cleanly a bit under that lets the
 *  provider reconnect on its graceful, backoff-resetting path instead.
 *  Set to 0 to disable (rely on the edge cap). */
const WS_MAX_CONNECTION_MS = CONFIG.wsMaxConnectionMs;
/** How often to re-probe machines currently in bad standing, to detect that
 *  one has self-righted and restore it to routing. Short so a recovered
 *  machine — especially the only one serving a model — rejoins within
 *  seconds, but not so tight that we hammer a wedged box. */
const REPROBE_INTERVAL_MS = CONFIG.reprobeIntervalMs;
/** Per-machine budget for a recovery re-probe ping. Same shape as the job
 *  preflight: a healthy serve loop answers in a few ms; this only needs to
 *  clear network RTT. */
const REPROBE_TIMEOUT_MS = CONFIG.reprobeTimeoutMs;
/** How many recent jobs the time-to-first-token window keeps. Matches the
 *  "last 100 jobs" the console headline advertises. */
const TTFT_WINDOW_SAMPLES = CONFIG.ttftWindowSamples;
/** Directory the rolling latency windows are persisted to so the public
 *  latency headline survives a restart. Explicit `COCORE_ADVISOR_DATA_DIR`
 *  wins; otherwise an `advisor/` subdir of the mounted Railway volume; else
 *  undefined → persistence off (dev/CI keep the windows purely in-memory). */
const RAILWAY_VOLUME_MOUNT_PATH = Option.getOrUndefined(CONFIG.railwayVolumeMountPath);
const DATA_DIR =
  Option.getOrUndefined(CONFIG.dataDir) ??
  (RAILWAY_VOLUME_MOUNT_PATH
    ? join(RAILWAY_VOLUME_MOUNT_PATH.replace(/\/$/, ""), "advisor")
    : undefined);
/** How often to flush the latency windows to disk. A hard crash loses at most
 *  this much tail — acceptable for a "typical recent latency" headline. */
const LATENCY_PERSIST_INTERVAL_MS = CONFIG.latencyPersistIntervalMs;
/** This advisor's DID — the `aud` of the register/control service-auth JWTs.
 *  Undefined disables DID-bound auth entirely (legacy unauthenticated mode). */
const ADVISOR_DID = Option.getOrUndefined(CONFIG.advisorDid);
/** DID-bound auth enforcement (C1 / M3). When true, a register / control call
 *  lacking a valid DID-bound JWT is rejected; when false (default), a present
 *  token is still verified + bound but absence is tolerated for staged rollout.
 *  Only meaningful when {@link ADVISOR_DID} is set. */
const REQUIRE_AUTH = CONFIG.requireAuth;
/** M1 resource caps. */
const WS_MAX_PAYLOAD_BYTES = CONFIG.wsMaxPayloadBytes;
const WS_MAX_CONNECTIONS = CONFIG.wsMaxConnections;
/** Per-IP concurrent WS cap; 0 disables it (the safe default behind a shared
 *  proxy). See the config comment. */
const WS_MAX_CONNECTIONS_PER_IP = CONFIG.wsMaxConnectionsPerIp;
const WS_TRUST_PROXY = CONFIG.wsTrustProxy;
const REGISTRY_MAX_SIZE = CONFIG.registryMaxSize;

async function main(): Promise<void> {
  // One o11y runtime drives the WebSocket side + the periodic gauge/TTFT
  // metric records. The HTTP face runs on its own runtime inside
  // `makeNodeHandler`; both export under serviceName "cocore-advisor".
  const runtime = makeRuntime(SERVICE);

  // APNs code-identity sender config (APNS_AUTH_KEY/KEY_ID/TEAM_ID/TOPIC). This
  // is the *capability* that lets a machine prove its code identity — not a
  // fleet on/off. Confidential is ALWAYS earned per-machine (a machine must
  // answer the challenge); without APNs configured, no machine can earn the
  // code-identity leg, so confidential is simply unavailable (fail-closed).
  const apnsConfig = loadApnsConfig();
  if (apnsConfig) {
    console.error(`[advisor] APNs code-identity capability ON topic=${apnsConfig.topic}`);
  } else {
    console.error(
      "[advisor] APNs code-identity capability OFF (APNS_* unset) — confidential tier unavailable",
    );
  }
  // DID-bound auth mode (C1 / M3). Three states:
  //   * no COCORE_ADVISOR_DID → auth OFF (legacy: any client can register).
  //   * ADVISOR_DID set, REQUIRE_AUTH false → staged rollout: a present JWT is
  //     verified + bound to provider_did, but absence is tolerated so the fleet
  //     can upgrade before enforcement.
  //   * ADVISOR_DID set, REQUIRE_AUTH true → enforced: a register / control
  //     lacking a valid DID-bound JWT is rejected.
  // Ops flips COCORE_ADVISOR_REQUIRE_AUTH=true once the provider fleet ships
  // support for minting the register JWT.
  if (!ADVISOR_DID) {
    console.error(
      "[advisor] DID-bound auth OFF (COCORE_ADVISOR_DID unset) — registration is unauthenticated",
    );
  } else if (REQUIRE_AUTH) {
    console.error(
      `[advisor] DID-bound auth ENFORCED did=${ADVISOR_DID} — register/control require a valid service-auth JWT`,
    );
  } else {
    console.error(
      `[advisor] DID-bound auth STAGED did=${ADVISOR_DID} — JWT verified+bound when present, absence tolerated (flip COCORE_ADVISOR_REQUIRE_AUTH=true after the fleet ships the JWT)`,
    );
  }

  // Known-good cdHash set (WS-COORDINATOR). Empty unless COCORE_KNOWN_GOOD_CDHASHES
  // is set → fail-closed (no machine is confidential-eligible until a blessed-
  // build set is configured). Confidential eligibility is computed per-machine.
  const registry = new ProviderRegistry(KnownGoodSet.fromEnv(), REGISTRY_MAX_SIZE);
  // Rolling time-to-first-token window (received → first chunk relayed),
  // surfaced at GET /ttft. Folds in the worker's model-load/prefill/gen.
  const ttft = new LatencyWindow(TTFT_WINDOW_SAMPLES);
  // Rolling time-to-ack window (received → inference_request frame handed to
  // the chosen worker's socket), surfaced at GET /ack for the console's public
  // latency headline — the brokerage number, excluding worker-side time.
  const ack = new LatencyWindow(TTFT_WINDOW_SAMPLES);

  // Disk-backed latency cache. When a data dir is configured (prod mounts a
  // volume), seed both windows from the last persisted snapshot so /ack and
  // /ttft serve the last known figures right after a restart instead of the
  // blank "—" headline they'd otherwise show until jobs flow again. Hydrated
  // samples report `cached: true` until live traffic refills the window.
  // The file names identify which window, and hydrateLatencyWindow logs the
  // resident count + snapshot age itself, so no extra logging is needed here.
  const ackLatencyPath = DATA_DIR ? join(DATA_DIR, "ack-latency.json") : null;
  const ttftLatencyPath = DATA_DIR ? join(DATA_DIR, "ttft-latency.json") : null;
  if (ackLatencyPath) await hydrateLatencyWindow(ack, ackLatencyPath);
  if (ttftLatencyPath) await hydrateLatencyWindow(ttft, ttftLatencyPath);
  const sessions = new SessionManager({
    idleTimeoutMs: SESSION_IDLE_TIMEOUT_MS,
    firstChunkTimeoutMs: SESSION_FIRST_CHUNK_TIMEOUT_MS,
    onFirstChunk: (ms) => {
      ttft.record(ms);
      // Mirror the TTFT sample into a histogram for OTLP export (the
      // /ttft route keeps serving the rolling in-memory window).
      record(runtime, Metric.update(ttftMs, ms));
    },
    onIdleTimeout: (providerDid, providerMachineId, streamed) => {
      // The requester's SSE already got a clean `idle-timeout` error. How we
      // treat the MACHINE depends on what it did:
      if (streamed) {
        // It produced real tokens and then stalled (a slow machine on a long
        // job, not a silent one). Don't mark it unhealthy or bounce its
        // engine — that punishes a merely-slow provider and yanks it from
        // routing. Just note it; the failed job is penalty enough.
        console.error(
          `[sessions] idle-timeout did=${providerDid} machine=${providerMachineId}; had streamed — slow job, NOT flagging`,
        );
        return;
      }
      // It accepted the job and never sent a thing: genuinely wedged. Stop
      // routing to it, tell it so (red tray ping), and ask it to self-right.
      registry.markUnhealthy(providerDid, providerMachineId, "job-idle-timeout");
      try {
        const entry = registry.get(providerDid, providerMachineId);
        entry?.send({ type: "health_notice", standing: "bad", reason: "job-idle-timeout" });
        entry?.send({ type: "recover_request", reason: "job-idle-timeout" });
      } catch {
        // socket gone; the sweeper will evict it
      }
      console.error(
        `[sessions] idle-timeout did=${providerDid} machine=${providerMachineId}; silent — marked unhealthy, requested self-right`,
      );
    },
  });

  // --- HTTP face (HttpRouter) ------------------------------------
  // Each route is an Effect returning an HttpServerResponse; `makeNodeHandler`
  // serves the app on its own o11y runtime and returns a plain Node
  // `(req,res) => void` we hand to `createServer` so the port/listen stays.
  const app = HttpRouter.empty.pipe(
    HttpRouter.get(
      "/healthz",
      Effect.sync(() =>
        ok({ ok: true, providers: registry.size(), sessions: sessions.size() }),
      ).pipe(Effect.withSpan("advisor.healthz")),
    ),
    HttpRouter.get(
      "/ttft",
      // Time-to-first-token over the last ~100 jobs (received → first chunk
      // relayed). Distinct from a receipt's completedAt − startedAt (total
      // generation time); folds in the worker's model-load/prefill/gen.
      Effect.sync(() => ok(ttft.stats())).pipe(Effect.withSpan("advisor.ttft")),
    ),
    HttpRouter.get(
      "/ack",
      // Time-to-ack over the last ~100 jobs (received → inference_request frame
      // handed to the chosen worker's socket). The brokerage-latency headline:
      // how fast cocore routes a job to a live worker, excluding worker-side
      // model-load/prefill/generation (that's /ttft).
      Effect.sync(() => ok(ack.stats())).pipe(Effect.withSpan("advisor.ack")),
    ),
    HttpRouter.get(
      "/providers",
      Effect.sync(() =>
        ok(
          registry.list().map((p) => ({
            did: p.did,
            // Per-machine identity (the agent's provider-record rkey). The
            // console joins live standing onto its fleet UI by this. A DID can
            // now appear in multiple rows — one per connected machine.
            machineId: p.machineId,
            machineLabel: p.machineLabel,
            chip: p.chip,
            ramGb: p.ramGb,
            supportedModels: p.supportedModels,
            // Coarse, opt-in country (advisory self-claim) for country routing.
            region: p.region,
            // Agent binary version (null for a pre-version agent). The console
            // pre-filters by this for version-gated requests (e.g. image input)
            // before it seals + pins to a machine.
            binaryVersion: p.binaryVersion,
            encryptionPubKey: p.encryptionPubKey,
            attestationUri: p.attestationUri,
            lastSeen: new Date(p.lastSeen).toISOString(),
            attestedAt: p.attestedAt ? new Date(p.attestedAt).toISOString() : null,
            engineFault: p.engineFault,
            // Latest content-free crash signature (null until the machine
            // reports one) — lets an operator spot a flapping machine. A high
            // `count` is what excludes it from routing.
            crash: p.crash,
            // Owner's start/stop switch (from heartbeats) + whether bad
            // standing took it out of routing, and why — handy for debugging
            // "why isn't this machine getting jobs".
            active: p.active,
            unhealthy: p.unhealthyAt !== null,
            unhealthyReason: p.unhealthyReason,
            // Machine has been handed jobs but produced no completions —
            // it's failing silently (vs. openly crash-looping).
            silentFailure: p.silentFailure,
            // Confidential-tier routing hints (WS-COORDINATOR + P2). `trustTier`
            // is what the advisor computed; `cdHash` is the measured identity it
            // checked; `codeAttested` is the live APNs code-identity standing.
            trustTier: p.confidentialEligible ? "attested-confidential" : "best-effort",
            confidentialEligible: p.confidentialEligible,
            cdHash: p.cdHash,
            challengeVerifiedSip: p.challengeVerifiedSip,
            codeAttested: p.codeAttested,
            // The four legs of `confidentialEligible`, broken out so the
            // console can tell the operator WHICH one is blocking a machine
            // they asked to be confidential (vs. a bare "not eligible"). The
            // AND of these is `confidentialEligible` above.
            confidentialLegs: {
              selfTierConfidential: p.selfTier === "attested-confidential",
              cdHashKnownGood: p.cdHashKnownGood,
              challengeVerifiedSip: p.challengeVerifiedSip,
              codeAttested: p.codeAttested,
            },
            // Tool calling: verified by the provider's startup canary. The
            // per-model subset lets clients avoid treating one verified model
            // as capability for every model on the machine.
            supportsToolCalls: p.supportsToolCalls,
            toolCallModels: p.toolCallModels,
          })),
        ),
      ).pipe(Effect.withSpan("advisor.providers")),
    ),
    HttpRouter.get(
      "/verified-providers",
      // Read-only feed of confidential-eligible machines (accelerator over the
      // providers' signed PDS attestations — a requester still re-verifies the
      // attestation at seal time before trusting the tier).
      Effect.sync(() =>
        ok(
          registry.listConfidential().map((p) => ({
            did: p.did,
            machineId: p.machineId,
            machineLabel: p.machineLabel,
            chip: p.chip,
            supportedModels: p.supportedModels,
            encryptionPubKey: p.encryptionPubKey,
            attestationUri: p.attestationUri,
            cdHash: p.cdHash,
            trustTier: "attested-confidential",
            attestedAt: p.attestedAt ? new Date(p.attestedAt).toISOString() : null,
          })),
        ),
      ).pipe(Effect.withSpan("advisor.verified-providers")),
    ),
    HttpRouter.post(
      "/control",
      controlRoute(registry, {
        advisorDid: ADVISOR_DID,
        requireAuth: REQUIRE_AUTH,
      }).pipe(Effect.withSpan("advisor.control")),
    ),
    HttpRouter.post(
      "/jobs",
      jobsRoute({
        registry,
        sessions,
        generateId: () => randomUUID(),
        attestationMaxAgeMs: ATTESTATION_MAX_AGE_MS,
        preflightTimeoutMs: PREFLIGHT_TIMEOUT_MS,
        onDispatched: (ms) => {
          ack.record(ms);
          // Mirror the ack sample into a histogram for OTLP export (the /ack
          // route keeps serving the rolling in-memory window).
          record(runtime, Metric.update(ackMs, ms));
        },
      }),
    ),
  );

  const handler = await makeNodeHandler(app, SERVICE);
  const http = createServer(handler);

  // Node defaults `requestTimeout` to 300_000ms (Node 18+): the timer
  // armed on the upgrade GET can fire and destroy an upgraded WebSocket /
  // a long-lived `/jobs` SSE that runs past 5 minutes. Disable it — this
  // is a long-poll/stream-heavy service, not a public form handler, and
  // the WS keepalive + idle handling above is what bounds dead sockets.
  http.requestTimeout = 0;

  // --- WebSocket /v1/agent --------------------------------------
  // `perMessageDeflate: false`: compression is useless on our frames
  // (heartbeats + sealed/random-looking ciphertext don't compress) and
  // its sliding window desyncs through Railway's proxy as `TCP_OVERWIN`,
  // a documented cause of dropped WS connections. Off = one fewer way for
  // the edge to sever us.
  const wss = new WebSocketServer({
    server: http,
    path: "/v1/agent",
    perMessageDeflate: false,
    // M1: bound a single inbound frame. Our frames (heartbeats + sealed
    // ciphertext) are well under this; the `ws` default of 100 MiB let one
    // frame exhaust memory. Large multimodal payloads travel on the separate
    // HTTP `/jobs` path, which has its own 32 MiB body cap.
    maxPayload: WS_MAX_PAYLOAD_BYTES,
  });

  // M1: connection caps — total (always on) + per-IP (opt-in). Enforced on the
  // raw `connection` event (an accepted, upgraded socket) rather than the
  // upgrade handshake so we stay inside the `ws` library's flow: over cap we
  // immediately close the fresh socket (1013 "try again later") before it can
  // register or consume more than a transient slot. The counters are
  // decremented on close.
  //
  // The per-IP cap is DISABLED by default (WS_MAX_CONNECTIONS_PER_IP === 0)
  // because behind Railway's edge every provider shares one of a few proxy IPs
  // — a per-remote-IP cap would then reject the legitimate fleet. When it IS
  // enabled, we key on the forwarded client IP only if WS_TRUST_PROXY is set
  // (the direct peer is the proxy, not the client); otherwise trusting XFF
  // would let a client spoof its IP to dodge the cap.
  let openConnections = 0;
  const perIp = new Map<string, number>();
  const perIpEnabled = WS_MAX_CONNECTIONS_PER_IP > 0;
  const clientIpOf = (req: IncomingMessage): string => {
    if (WS_TRUST_PROXY) {
      const xff = req.headers["x-forwarded-for"];
      const first = (Array.isArray(xff) ? xff[0] : xff)?.split(",")[0]?.trim();
      if (first) return first;
    }
    return req.socket.remoteAddress ?? "?";
  };

  wss.on("connection", (socket, req) => {
    const ip = perIpEnabled ? clientIpOf(req) : (req.socket.remoteAddress ?? "?");
    const ipCount = perIp.get(ip) ?? 0;
    const overIp = perIpEnabled && ipCount >= WS_MAX_CONNECTIONS_PER_IP;
    if (openConnections >= WS_MAX_CONNECTIONS || overIp) {
      console.error(
        `[ws] over cap — refusing peer=${ip} (total=${openConnections}/${WS_MAX_CONNECTIONS}${perIpEnabled ? ` perIp=${ipCount}/${WS_MAX_CONNECTIONS_PER_IP}` : ""})`,
      );
      try {
        socket.close(1013, "over-capacity");
      } catch {
        // socket already gone
      }
      return;
    }
    openConnections += 1;
    if (perIpEnabled) perIp.set(ip, ipCount + 1);
    socket.once("close", () => {
      openConnections -= 1;
      if (perIpEnabled) {
        const n = (perIp.get(ip) ?? 1) - 1;
        if (n <= 0) perIp.delete(ip);
        else perIp.set(ip, n);
      }
    });

    // The `ws` library stays the transport; the connection's setup logic runs
    // as an Effect on the o11y runtime under an `advisor.ws.connection` span
    // (analogous to NodeHttpServer driving the HttpRouter above).
    record(
      runtime,
      Effect.sync(() =>
        handleConnection(socket, req, registry, sessions, {
          rechallengeIntervalMs: RECHALLENGE_INTERVAL_MS,
          responseTimeoutMs: CHALLENGE_RESPONSE_TIMEOUT_MS,
          keepaliveIntervalMs: WS_KEEPALIVE_INTERVAL_MS,
          keepaliveMaxMissed: WS_KEEPALIVE_MAX_MISSED,
          maxConnectionMs: WS_MAX_CONNECTION_MS,
          apns: apnsConfig,
          // C1: DID-bound registration. advisorDid unset → auth off.
          ...(ADVISOR_DID ? { advisorDid: ADVISOR_DID } : {}),
          requireAuth: REQUIRE_AUTH,
        }),
      ).pipe(Effect.withSpan("advisor.ws.connection")),
    );
  });

  // --- Janitor: evict machines we haven't heard from ------------
  const sweeper = setInterval(() => {
    const evicted = registry.sweep(HEARTBEAT_TIMEOUT_MS);
    for (const { did, machineId } of evicted) {
      console.error(`[sweeper] evicted stale machine did=${did} machine=${machineId}`);
    }
    // Refresh the online-providers gauge on the sweep cadence.
    record(runtime, Metric.set(onlineProviders, registry.size()));
  }, SWEEP_INTERVAL_MS);
  sweeper.unref();

  // --- Re-prober: auto-restore machines that have self-righted --
  // An unhealthy machine is EXCLUDED from routing, so it can't earn its
  // standing back through normal job traffic. Ping each excluded machine on
  // a short cadence; a machine whose serve loop is pumping again answers,
  // and we clear its bad standing so it rejoins the pool. (recordCompletion
  // and a fresh register also clear it; this covers the machine that
  // self-righted without re-registering and without a job to complete.)
  const reprober = setInterval(() => {
    for (const m of registry.listUnhealthy()) {
      void m
        .ping(REPROBE_TIMEOUT_MS)
        .then((alive) => {
          if (alive) {
            registry.markHealthy(m.did, m.machineId);
            try {
              m.send({ type: "health_notice", standing: "ok" });
            } catch {
              // socket gone; close hook will clean up
            }
            console.error(
              `[reprober] recovered did=${m.did} machine=${m.machineId}; restored to routing`,
            );
          }
        })
        .catch(() => {
          // still wedged / socket gone — leave it excluded
        });
    }
  }, REPROBE_INTERVAL_MS);
  reprober.unref();

  // --- Latency cache: flush the rolling windows to disk --------
  // Periodic + on graceful shutdown, so the public latency headline survives
  // a redeploy. Only active when a data dir is configured (prod volume).
  if (DATA_DIR) {
    const flushLatency = async (): Promise<void> => {
      const now = new Date().toISOString();
      await Promise.allSettled([
        ackLatencyPath ? persistLatencyWindow(ack, ackLatencyPath, now) : Promise.resolve(),
        ttftLatencyPath ? persistLatencyWindow(ttft, ttftLatencyPath, now) : Promise.resolve(),
      ]);
    };
    const latencyFlusher = setInterval(() => void flushLatency(), LATENCY_PERSIST_INTERVAL_MS);
    latencyFlusher.unref();
    // Railway sends SIGTERM on redeploy; flush the freshest samples first.
    for (const sig of ["SIGTERM", "SIGINT"] as const) {
      process.once(sig, () => {
        void flushLatency().finally(() => process.exit(0));
      });
    }
    console.error(
      `[advisor] latency cache ON dir=${DATA_DIR} flush-interval=${LATENCY_PERSIST_INTERVAL_MS}ms`,
    );
  } else {
    console.error("[advisor] latency cache OFF (no COCORE_ADVISOR_DATA_DIR / volume) — in-memory");
  }

  await new Promise<void>((r) => http.listen(PORT, r));
  console.error(
    `advisor: http+ws on :${PORT} (heartbeat-timeout=${HEARTBEAT_TIMEOUT_MS}ms, session-idle=${SESSION_IDLE_TIMEOUT_MS}ms, session-first-chunk=${SESSION_FIRST_CHUNK_TIMEOUT_MS}ms, rechallenge=${RECHALLENGE_INTERVAL_MS}ms, challenge-response-timeout=${CHALLENGE_RESPONSE_TIMEOUT_MS}ms, attestation-max-age=${ATTESTATION_MAX_AGE_MS}ms, ws-keepalive=${WS_KEEPALIVE_INTERVAL_MS}ms, ws-keepalive-max-missed=${WS_KEEPALIVE_MAX_MISSED}, ws-max-connection=${WS_MAX_CONNECTION_MS}ms, perMessageDeflate=off)`,
  );
  console.error(
    "advisor: WS connection-stability config tuned for Railway's edge (frequent keepalive under the idle cutoff, compression off, proactive recycle under the 15-min cap)",
  );
}

/** Simple fixed-window per-DID rate limiter for /control (M3): even an
 *  authenticated owner shouldn't be able to spam self-right / re-read nudges in
 *  a tight loop. `RATE_MAX` calls per `RATE_WINDOW_MS` per DID; over that we
 *  reply 429. In-memory (like the rest of the advisor); a restart resets it. */
const CONTROL_RATE_WINDOW_MS = 10_000;
const CONTROL_RATE_MAX = 20;
const controlRate = new Map<string, { count: number; windowStart: number }>();
function controlRateAllows(did: string, now = Date.now()): boolean {
  const e = controlRate.get(did);
  if (!e || now - e.windowStart >= CONTROL_RATE_WINDOW_MS) {
    controlRate.set(did, { count: 1, windowStart: now });
    return true;
  }
  if (e.count >= CONTROL_RATE_MAX) return false;
  e.count += 1;
  return true;
}

interface ControlAuthConfig {
  /** This advisor's DID (the JWT `aud`). Undefined → auth off (legacy). */
  advisorDid: string | undefined;
  /** Reject an unauthenticated call when true; when false, log a warning and
   *  allow it (staged rollout). Only meaningful when `advisorDid` is set. */
  requireAuth: boolean;
  /** Injectable DID resolver for tests; defaults to the real one. */
  didResolver?: DidDocumentResolver;
}

/** `POST /control` — relay an unprivileged nudge to an owner's machine(s):
 *    action "re-read-active" (default) — after flipping the `active` switch on
 *      the PDS, so a start/stop takes effect in ~a second instead of at the
 *      next 30s poll.
 *    action "self-right" — the owner clicked "Try to recover" on an unhealthy
 *      machine; ask the agent to run its recovery now.
 *  Either carries NO authority over the agent — it re-reads / re-checks its own
 *  authoritative state — but it can still be abused to bounce a victim's engine
 *  in a loop, so (M3) the caller must present a service-auth JWT
 *  (`lxm = dev.cocore.compute.control`) whose authenticated DID equals the
 *  target `did`. Gated behind the same COCORE_ADVISOR_REQUIRE_AUTH flag as
 *  registration: when off, an unauthenticated call is allowed but logged as a
 *  warning; when on, it's rejected. Targets a single machine when `machineId`
 *  is given, else every machine under the DID. */
function controlRoute(registry: ProviderRegistry, auth: ControlAuthConfig) {
  return Effect.gen(function* () {
    const token = yield* bearer;
    const parsed = yield* Effect.either(jsonBody);
    if (parsed._tag === "Left") return err(400, { error: "invalid JSON body" });
    const b = parsed.right as { did?: unknown; machineId?: unknown; action?: unknown };
    const did = b.did;
    if (typeof did !== "string" || did.length === 0) return err(400, { error: "did required" });
    if (b.machineId !== undefined && typeof b.machineId !== "string") {
      return err(400, { error: "machineId must be a string when provided" });
    }
    const action = b.action ?? "re-read-active";
    if (action !== "re-read-active" && action !== "self-right") {
      return err(400, { error: "action must be 're-read-active' or 'self-right'" });
    }

    // M3: authenticate + scope to the owner. The caller must prove control of
    // the target DID (service-auth JWT, iss == did) so a stranger can't loop-
    // bounce someone else's engine.
    if (auth.advisorDid) {
      if (token) {
        const res = yield* Effect.promise(() =>
          verifyServiceAuthToken(token, {
            audience: auth.advisorDid as string,
            lxm: LXM_CONTROL,
            resolver: auth.didResolver,
          }),
        );
        if (!res.ok) return err(res.status, { error: `${res.error}: ${res.message}` });
        if (res.did !== did) {
          return err(403, { error: "authenticated DID does not match target did" });
        }
      } else if (auth.requireAuth) {
        return err(401, { error: "service-auth JWT required" });
      } else {
        console.error(
          `[control] UNAUTHENTICATED call for did=${did} action=${action} allowed (requireAuth off) — flip COCORE_ADVISOR_REQUIRE_AUTH=true to enforce`,
        );
      }
    }

    // Per-DID rate limit (applies regardless of auth mode).
    if (!controlRateAllows(did)) {
      return err(429, { error: "rate limit exceeded for did" });
    }

    const targets =
      typeof b.machineId === "string"
        ? [registry.get(did, b.machineId)].filter((e): e is NonNullable<typeof e> => !!e)
        : registry.getMachines(did);
    if (targets.length === 0) return err(404, { error: "provider not connected" });
    let delivered = 0;
    for (const entry of targets) {
      try {
        entry.send(
          action === "self-right"
            ? { type: "recover_request", reason: "console-requested" }
            : { type: "control_changed" },
        );
        delivered += 1;
      } catch {
        // socket already gone; the sweeper will evict it
      }
    }
    return ok({ ok: true, delivered });
  });
}

// C2: last-resort process guards. A single malformed frame (or any other
// stray async fault) must degrade the one affected connection, not take the
// whole matchmaker down — log and stay up, mirroring infra/services/main.ts.
// The per-connection dispatch wrapper (connection.ts) already closes the
// offending socket; these catch anything that still escapes.
process.on("unhandledRejection", (reason) => {
  const e = reason instanceof Error ? reason : new Error(String(reason));
  console.error(`advisor: unhandledRejection — ${e.message}\n${e.stack ?? ""}`);
});
process.on("uncaughtException", (e) => {
  console.error(`advisor: uncaughtException — ${e.message}\n${e.stack ?? ""}`);
});

main().catch((e) => {
  console.error("advisor: fatal", e);
  process.exit(1);
});
