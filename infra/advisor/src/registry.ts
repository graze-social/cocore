// In-memory registry of currently-connected provider machines. Lost on
// restart; that's fine — the provider's `cocore agent serve`
// auto-reconnects, re-registers, and re-attests.
//
// One DID can have MANY machines connected at once (an owner who runs
// `cocore agent serve` on a laptop AND a desktop under the same identity).
// Entries are therefore keyed by `(provider_did, machine_id)`, not DID
// alone. A second Register from the SAME (did, machine) replaces that
// machine's previous entry (and closes its previous socket) — that keeps
// the agent reconnect path crisp — but a Register from a DIFFERENT machine
// under the same DID coexists rather than evicting its sibling. (Keying by
// DID alone is what produced the "register war" + spurious "BAD attestation
// signature" churn when two machines shared an identity: each Register
// closed the other's socket and swapped the socket↔attestation-key binding
// out from under an in-flight challenge.)

import { KnownGoodSet } from "./known-good.ts";
import type { AdvisorMessage, CrashSignature, EngineFault, Register } from "./protocol.ts";
import { meetsMinVersion } from "./version.ts";

/** A provider machine whose most recent heartbeat reported a crash count at
 *  or above this is treated as crash-looping and excluded from routing (see
 *  {@link ProviderRegistry.pickCandidates}). Set conservatively: a single
 *  crash that the agent recovered from shouldn't cost a machine its jobs; a
 *  machine that's panicked ≥3 times this session is almost certainly going to
 *  panic on the next job too. */
export const CRASH_LOOP_THRESHOLD = 3;

/** Number of jobs the advisor must have dispatched to a machine — within
 *  the current window — with zero completions observed before it flips the
 *  machine's {@link ProviderEntry.silentFailure} flag. A machine that
 *  accepts work and never produces a single completion is failing silently
 *  (vs. one that's openly crash-looping), so the operator needs a separate
 *  signal for it. Conservative so a couple of in-flight jobs don't trip it. */
export const SILENT_FAILURE_DISPATCH_THRESHOLD = 3;

/** Number of failures a machine must accumulate WITHIN {@link FAILURE_DECAY_MS}
 *  before it's pulled out of routing on a cooldown (see
 *  {@link ProviderRegistry.recordFailure}). Matches the two thresholds above:
 *  one blip shouldn't cost a machine its jobs, but a machine that fails a
 *  handful of user turns back-to-back is bad and should be steered around. */
export const FAILURE_COOLDOWN_THRESHOLD = 3;

/** Failures must CLUSTER to count. If a machine's previous failure was longer
 *  ago than this, its running failure count resets before the new one lands —
 *  so a machine that fails once an hour never trips a cooldown, but one that
 *  fails three chats in a row (seconds–minutes apart) does. ~2× the advisor's
 *  re-challenge cadence. */
export const FAILURE_DECAY_MS = 10 * 60_000;

/** First cooldown length once a machine trips the threshold (~⅔ of the 90s
 *  session idle budget) — long enough to route a chat to a healthy sibling for
 *  several turns, short enough to forgive a transient. */
export const COOLDOWN_BASE_MS = 60_000;

/** Escalation ceiling. Each successive trip doubles the cooldown
 *  (1→2→4→8→10 min) up to this cap. Because the ledger outlives the socket,
 *  this ceiling is actually reachable — a machine can't shed it by
 *  reconnecting. */
export const COOLDOWN_MAX_MS = 10 * 60_000;

/** How long a machine must go WITHOUT a failure before its escalation resets:
 *  the strike count (and running failure count) are cleared on the first clean
 *  completion after this much quiet, so a machine that had a bad hour starts
 *  fresh next time rather than jumping straight to a long cooldown. Longer than
 *  both {@link FAILURE_DECAY_MS} and {@link COOLDOWN_MAX_MS}. */
export const STRIKE_RESET_MS = 15 * 60_000;

/** How long a fresh code-attestation is honored across a RECONNECT of the same
 *  machine (same key + unchanged cdHash). Kept at/under the advisor's ~5-min
 *  code-challenge cadence so a carried attestation is re-verified within one
 *  cycle and never persists stale: it's a bridge over WS churn, not a grant. */
const CODE_ATTEST_RECONNECT_GRACE_MS = 5 * 60_000;

/** Field separator for the composite `(did, machineId)` map key. NUL never
 *  appears in a DID or a record rkey, so it's an unambiguous joiner. */
const KEY_SEP = "\u0000";

export interface ProviderEntry {
  did: string;
  /** Stable per-machine identifier (the agent's provider-record rkey, sent
   *  in the Register frame). Distinguishes two machines that share a DID.
   *  Falls back to the attestation pubkey for pre-`machine_id` agents — see
   *  {@link ProviderRegistry.upsert}. This is also the join key the console
   *  uses to map advisor live-standing onto a machine in its fleet UI. */
  machineId: string;
  machineLabel: string;
  chip: string;
  ramGb: number;
  supportedModels: string[];
  encryptionPubKey: string;
  attestationPubKey: string;
  attestationUri: string;
  /** Set when the provider reported it couldn't load one or more
   *  configured models (so it's connected but only serving `stub`).
   *  Diagnostic only — does not affect `pickFor`, since the failed
   *  models are already absent from `supportedModels`. Null on a
   *  healthy register. */
  engineFault: EngineFault | null;
  /** Latest crash signature folded into the machine's heartbeat, or null
   *  if it's never reported one. Diagnostic + flapping protection: when
   *  `crash.count >= CRASH_LOOP_THRESHOLD` the machine is excluded from
   *  `pickCandidates` (a crash-looping machine shouldn't get jobs). Null on
   *  a fresh register and until the first heartbeat carrying `crash`. */
  crash: CrashSignature | null;
  /** Count of `inference_request` frames the advisor has dispatched to this
   *  machine in the current window, and of `inference_complete` frames it
   *  has observed back. Used to detect a silent failure — a machine that's
   *  been handed work but produced no completions. Reset on a fresh
   *  register. */
  dispatched: number;
  completed: number;
  /** Set true once this machine has been dispatched
   *  >= SILENT_FAILURE_DISPATCH_THRESHOLD jobs with 0 completions observed.
   *  Diagnostic (surfaced on `GET /providers` + logged once on the flip);
   *  it does not by itself remove the machine from routing, but it flags a
   *  machine that's accepting work and silently dropping it. Cleared on a
   *  fresh register and whenever a completion is finally observed. */
  silentFailure: boolean;
  /** Last `heartbeat` arrival (epoch ms). Used by the sweeper. */
  lastSeen: number;
  /** Last successful attestation verify (epoch ms), or null. */
  attestedAt: number | null;
  /** Measured cdHash echoed from the provider's signed attestation (Register
   *  frame), or null. The advisor checks it against its known-good set. */
  cdHash: string | null;
  /** The provider's self-asserted tier from its attestation. Advisory only —
   *  {@link confidentialEligible} is what the advisor computes and trusts. */
  selfTier: string | null;
  /** Coarse, opt-in ISO 3166-1 alpha-2 country echoed from the provider's
   *  `region` (Register frame), or null when it isn't sharing location.
   *  Advisory self-claim; used for `country` routing on `GET /providers`. */
  region: string | null;
  /** This agent binary's version (e.g. `0.9.32`) from its Register frame, or
   *  null for a pre-version agent. Surfaced on `GET /providers` and used by
   *  version-gated routing: a job with a `minProviderVersion` floor excludes
   *  any machine below it — and a null here counts as below (fail-closed), so
   *  a feature request never lands on a machine that can't prove it has it. */
  binaryVersion: string | null;
  /** WS-COORDINATOR / darkbloom parity: true iff the MOST RECENT challenge
   *  response reported SIP enabled. Set on every challenge verify, so SIP
   *  can't drift unchecked between the 5-min cycles. A false here immediately
   *  drops {@link confidentialEligible}. */
  challengeVerifiedSip: boolean;
  /** Computed: the provider may be ROUTED confidential jobs. True iff its
   *  self-asserted tier is `attested-confidential` AND its cdHash is in the
   *  advisor's known-good set AND the latest challenge re-verified SIP. This is
   *  an accelerator/routing hint — a confidential requester still re-verifies
   *  the provider's signed PDS attestation at seal time (invariant #1). */
  confidentialEligible: boolean;
  /** Computed leg of {@link confidentialEligible}: the measured cdHash is in
   *  the advisor's known-good set. Stored alongside the AND so callers (the
   *  console status API) can report WHICH leg is blocking a desired-confidential
   *  machine, instead of a bare "not eligible". Recomputed with the others. */
  cdHashKnownGood: boolean;
  /** True iff this machine answered a live APNs code-identity challenge since
   *  it registered: the advisor pushed a nonce sealed to its X25519 key and got
   *  back a valid SE signature over the recovered nonce — proving the genuine,
   *  AMFI-gated binary is running, not a self-reported cdHash. Reset to false on
   *  (re)register; granted by {@link ProviderRegistry.markCodeAttested}. When
   *  the advisor has APNs configured (enforcement on), this gates
   *  {@link confidentialEligible}. */
  codeAttested: boolean;
  /** Epoch ms of the last successful code-attestation, or null. Lets a RECONNECT
   *  of the same machine (same key + same measured cdHash) within a short grace
   *  window carry `codeAttested` forward instead of resetting to false — the
   *  agent's WS churn (a network blip, a supervisor bounce) otherwise resets this
   *  every ~30s and the ~5-min challenge cycle never completes, so a genuine
   *  confidential machine can never earn eligibility. The carry is bridge-only:
   *  the advisor re-challenges on the fresh connection and revokes on failure. */
  lastCodeAttestedAt: number | null;
  /** APNs device token for this machine's measured agent, from its Register
   *  frame. Null on headless installs that couldn't register for push (they
   *  stay best-effort). */
  apnsDeviceToken: string | null;
  /** ADR-0005: true when the agent's signing key is Secure-Enclave-resident
   *  (from the Register frame). Observed always; only AND-ed into
   *  {@link confidentialEligible} when the SE gate is enforced (see
   *  {@link ProviderRegistry} `requireSeKey`). Old software-key agents omit it
   *  → false. */
  secureEnclaveAvailable: boolean;
  /** The agent's encryption-key scheme (`"p256-ecies-se"` or `"x25519"`), from
   *  the Register frame. Drives which codec the advisor seals the APNs
   *  code-challenge nonce with — NOT inferred from {@link secureEnclaveAvailable}.
   *  Null/absent → treated as x25519 (old agents). */
  encScheme: string | null;
  /** C1 (soft cutover): true iff this registration presented a valid DID-bound
   *  service-auth JWT proving it controls `did` — OR the advisor isn't running
   *  DID-bound auth at all (`advisorDid` unset), in which case there's no signal
   *  and we don't penalize. `false` means auth WAS expected and the frame
   *  carried none: the advisor admitted the socket (it still serves best-effort
   *  — we downgrade, never disconnect) but a consumer MUST NOT credit it an
   *  attested tier, because it hasn't proven it owns the attestation record a
   *  verifier would fetch under `did`. Defaults true (no signal); set by the
   *  connection handler right after upsert. */
  registrationAuthenticated: boolean;
  /** Coarse legacy tool-call capability. New providers set this true only
   *  after at least one model passes the startup forced-tool canary. */
  supportsToolCalls: boolean;
  /** Per-model verified tool-call capability. Undefined means the connected
   *  provider predates per-model reporting and callers should fall back to
   *  `supportsToolCalls`; present means only the listed models are verified. */
  toolCallModels: string[] | undefined;
  /** Highest supported stream-resume protocol version; 0 means legacy. */
  streamResumeVersion: number;
  /** Epoch ms the advisor last marked this machine unhealthy — it
   *  failed a preflight ping or went silent mid-job — or null when it's
   *  in good standing. An unhealthy machine is EXCLUDED from routing (not
   *  merely demoted): the owner explicitly wants jobs steered to a healthy
   *  sibling. It's auto-restored when it answers a re-probe ping, reports a
   *  completion, or freshly re-registers — so a machine that self-rights
   *  isn't stranded. */
  unhealthyAt: number | null;
  /** The reason this machine was last marked unhealthy (e.g.
   *  `preflight-no-response`, `job-idle-timeout`). Surfaced on
   *  `GET /providers` so the console can show the operator WHY a machine
   *  isn't taking jobs. Null when in good standing. */
  unhealthyReason: string | null;
  /** The machine owner's start/stop switch, as last reported by the
   *  machine's heartbeat (which reads it from the owner-written PDS
   *  record). `false` → the owner stopped this machine from the console;
   *  it's excluded from routing. Defaults to true until the first
   *  heartbeat. */
  active: boolean;
  /** Hook to close the underlying socket when the entry is replaced
   *  or evicted. Set by main.ts. */
  close: () => void;
  /** Send a JSON-serialisable advisor frame to this machine over
   *  its live WebSocket. Set by main.ts on connection open. */
  send: (msg: AdvisorMessage) => void;
  /** Send an app-level liveness ping and resolve true iff the machine
   *  answers `pong` within `timeoutMs`. Set by the connection handler,
   *  which correlates the pong by nonce. */
  ping: (timeoutMs: number) => Promise<boolean>;
}

/** Per-machine failure ledger, kept in a map whose lifetime is INDEPENDENT of
 *  the {@link ProviderEntry} (which `upsert`/`remove` churn every ~30-90s as the
 *  agent reconnects). Modeled on connection.ts's `codeAttestCache`: keyed by
 *  `(did, machineId)`, time-decayed, never reset on reconnect. This is what lets
 *  a cooldown accumulate and stick — an entry-scoped counter would be wiped
 *  before it ever reached the threshold, which is exactly why `unhealthyAt`
 *  fails to catch a machine that streams then drops. */
interface FailureRecord {
  /** Failures observed since the last decay/reset. Cleared when it trips a
   *  cooldown, when it decays (see {@link FAILURE_DECAY_MS}), or on a
   *  strike-reset. */
  recentFailures: number;
  /** Epoch ms of the most recent failure, or null. Drives decay + strike-reset. */
  lastFailureAt: number | null;
  /** Epoch ms until which this machine is EXCLUDED from routing, or null when
   *  it's routable. Purely time-gated: nothing clears an active cooldown, it
   *  only elapses — that's the whole point versus `unhealthyAt`, which any
   *  completion/reprobe wipes. */
  cooldownUntil: number | null;
  /** Why the machine was last put on cooldown (e.g. `stream-stalled`,
   *  `provider-disconnected`), surfaced on `GET /providers`. Null when never
   *  cooled. */
  cooldownReason: string | null;
  /** How many times this machine has tripped a cooldown. Each trip doubles the
   *  next cooldown length (up to {@link COOLDOWN_MAX_MS}); a clean
   *  {@link STRIKE_RESET_MS} stretch resets it. */
  cooldownStrikes: number;
}

/** True when a machine's most recent heartbeat reported a crash count at
 *  or above {@link CRASH_LOOP_THRESHOLD}. Used by `pickCandidates` to exclude
 *  a flapping machine. */
function isCrashLooping(e: ProviderEntry): boolean {
  return e.crash !== null && e.crash.count >= CRASH_LOOP_THRESHOLD;
}

/** True when a machine is currently on a routing cooldown. The single predicate
 *  every exclusion site shares (open-pool `pickCandidates`, the pinned filter in
 *  jobs.ts, and the `/providers` surface) so they can't drift apart the way the
 *  `unhealthyAt` check already has. Module-internal — all three sites reach it
 *  through the registry (the private map, the {@link ProviderRegistry.isCoolingDown}
 *  method, and {@link ProviderRegistry.getCooldown}), so it isn't exported. */
function isCoolingDown(rec: FailureRecord | undefined, now: number): boolean {
  return rec != null && rec.cooldownUntil != null && now < rec.cooldownUntil;
}

/** True when this machine has VERIFIED tool-call support for `model` — its
 *  engine passed the provider's forced-tool startup canary for that model.
 *  New providers report the canary-passed set per model (`toolCallModels`);
 *  legacy providers that predate per-model reporting fall back to the coarse
 *  `supportsToolCalls` boolean. Mirrors the console's preflight check — the
 *  gate that tells a requester "no provider supports tool calling" must
 *  agree with the filter that picks who actually gets the job, or a request
 *  that passes the gate can still land on a machine whose vLLM was started
 *  without tool calling and reject mid-stream. */
export function supportsToolCallsFor(e: ProviderEntry, model: string | undefined): boolean {
  if (Array.isArray(e.toolCallModels)) {
    return model === undefined ? e.toolCallModels.length > 0 : e.toolCallModels.includes(model);
  }
  return e.supportsToolCalls === true;
}

export class ProviderRegistry {
  /** Keyed by `did \0 machineId` so one DID can hold many machines. */
  private byKey = new Map<string, ProviderEntry>();

  /** Per-machine failure ledger (see {@link FailureRecord}). Keyed the same way
   *  as {@link byKey} but deliberately NOT tied to entry lifetime: `upsert` and
   *  `remove` must never touch it, or the ~30-90s reconnect churn would erase a
   *  machine's failure history before it could ever trip a cooldown. Records
   *  are pruned lazily once they've fully decayed. */
  private failureLedger = new Map<string, FailureRecord>();

  /** The blessed-build set used to compute {@link ProviderEntry.confidentialEligible}.
   *  Defaults to empty (fail-closed: nobody is confidential-eligible until a
   *  known-good set is configured). */
  private knownGood: KnownGoodSet;

  /** M1: hard cap on entries. A NEW (did, machine) registration is refused once
   *  the map is at this size, so a registration flood can't grow it unbounded.
   *  A re-register of an ALREADY-present machine is always allowed (it replaces,
   *  not grows). `Infinity` (default) = no cap; main.ts sets a finite value. */
  private maxSize: number;

  /** ADR-0005 soft-cutover lever. When false (default), the SE-resident-key leg
   *  is OBSERVED (recorded + exposed on `/providers`) but not enforced — the
   *  confidential set is unchanged, so ops can watch adoption at zero downgrade
   *  risk. When true (`COCORE_CONFIDENTIAL_REQUIRE_SE_KEY=1`), a machine without
   *  `secureEnclaveAvailable` drops from `confidentialEligible` to best-effort
   *  (still connected, still serving) — a per-machine downgrade, never a fleet
   *  switch, instantly reversible by flipping the lever back. */
  private requireSeKey: boolean;

  constructor(
    knownGood: KnownGoodSet = new KnownGoodSet(),
    maxSize = Number.POSITIVE_INFINITY,
    requireSeKey = false,
  ) {
    this.knownGood = knownGood;
    this.maxSize = maxSize;
    this.requireSeKey = requireSeKey;
  }

  /** Swap the known-good set (e.g. after a releases-feed refresh) and
   *  re-evaluate every connected machine's confidential eligibility. */
  setKnownGood(knownGood: KnownGoodSet): void {
    this.knownGood = knownGood;
    for (const e of this.byKey.values()) this.recomputeConfidential(e);
  }

  /** Recompute one entry's confidential eligibility — a PER-MACHINE earned
   *  status, never a fleet switch. A machine is confidential-routable iff it has
   *  earned EVERY leg: its self-asserted tier is `attested-confidential`, its
   *  measured cdHash is in the known-good set, the latest challenge re-verified
   *  SIP, AND it answered a live APNs code-identity challenge (`codeAttested`).
   *  The code-identity leg is ALWAYS required (a self-reported cdHash is
   *  forgeable — a fork could claim a blessed one). The advisor having APNs
   *  configured is the *capability* that lets a machine prove this; without it,
   *  no machine earns the code-identity leg and confidential is simply
   *  unavailable — fail-closed, not a cutover. */
  private recomputeConfidential(e: ProviderEntry): void {
    // Store the cdHash leg explicitly so the status API can name it as the
    // blocker; `knownGood` is private to the registry, so this is the only
    // place that knowledge can be captured for callers.
    e.cdHashKnownGood = this.knownGood.has(e.cdHash);
    // ADR-0005 SE-resident-key leg. No-op when the lever is off (observe-only) —
    // the value is still recorded on the entry + exposed on `/providers` so ops
    // can watch adoption. When enforced, a software-key agent (omits/false)
    // drops to best-effort. Independent of `encScheme`, which governs sealing.
    const seLegOk = !this.requireSeKey || e.secureEnclaveAvailable === true;
    e.confidentialEligible =
      e.selfTier === "attested-confidential" &&
      e.cdHashKnownGood &&
      e.challengeVerifiedSip &&
      e.codeAttested &&
      // C1: an un-DID-authenticated registration can't be routed confidential
      // even if it clears every measured leg — we can't confirm it owns the
      // identity whose attestation a requester would verify. Defense-in-depth
      // alongside the console/SDK tier recompute (the authority).
      e.registrationAuthenticated &&
      seLegOk;
  }

  /** Record whether this registration proved control of its DID (C1). `false`
   *  drops it from confidential routing (soft cutover — it still serves
   *  best-effort). Recomputes eligibility. Returns true if the entry exists. */
  setRegistrationAuthenticated(did: string, machineId: string, authenticated: boolean): boolean {
    const e = this.byKey.get(ProviderRegistry.key(did, machineId));
    if (!e) return false;
    e.registrationAuthenticated = authenticated;
    this.recomputeConfidential(e);
    return true;
  }

  /** Point a connected machine at its freshly republished attestation record
   *  (`attestation_refreshed`). Only the URI moves: the signing key is the same
   *  Secure-Enclave/software key the challenge cycle keeps verifying, so
   *  attested standing is untouched. Returns false for an unknown machine. */
  setAttestationUri(did: string, machineId: string, attestationUri: string): boolean {
    const e = this.byKey.get(ProviderRegistry.key(did, machineId));
    if (!e) return false;
    e.attestationUri = attestationUri;
    return true;
  }

  private static key(did: string, machineId: string): string {
    return `${did}${KEY_SEP}${machineId}`;
  }

  /** Resolve the machine identifier from a Register frame. Prefers the
   *  explicit `machine_id` (the agent's provider-record rkey); falls back to
   *  the per-machine attestation pubkey for pre-`machine_id` agents so two
   *  legacy machines under one DID still get distinct slots instead of
   *  warring over a single one. */
  static machineIdOf(reg: Register): string {
    const explicit = reg.machine_id?.trim();
    return explicit && explicit.length > 0 ? explicit : reg.attestation_pub_key;
  }

  /** Insert / replace the entry for ONE machine; returns the displaced
   *  entry if this same (did, machine) was already connected. A different
   *  machine under the same DID is untouched.
   *
   *  Returns `false` (and does NOT insert) when the map is at its size cap
   *  (M1) and this is a NEW machine — a re-register of an already-present
   *  machine always succeeds (it replaces rather than grows). Callers close
   *  the socket on a refusal. */
  upsert(
    reg: Register,
    close: () => void,
    send: (msg: AdvisorMessage) => void,
    ping: (timeoutMs: number) => Promise<boolean>,
    now = Date.now(),
  ): ProviderEntry | null | false {
    const machineId = ProviderRegistry.machineIdOf(reg);
    const key = ProviderRegistry.key(reg.provider_did, machineId);
    const previous = this.byKey.get(key) ?? null;
    // M1: refuse a NEW registration once at capacity (a replace is fine).
    if (!previous && this.byKey.size >= this.maxSize) {
      return false;
    }
    if (previous) {
      try {
        previous.close();
      } catch {
        // best-effort close; ignore
      }
    }
    // Bridge a fresh code-attestation across a RECONNECT of the same machine so
    // WS churn (a network blip, a supervisor bounce) doesn't reset it every ~30s
    // and starve the ~5-min challenge cycle. SAFE because it requires the SAME
    // (did, machineId) slot AND the SAME measured cdHash AND a recent attestation
    // (within the grace window) — a genuine binary that JUST proved code-identity
    // is still that binary a few seconds later. A changed cdHash, a new machine,
    // or a stale timestamp does NOT carry, and the advisor re-challenges on the
    // fresh connection and revokes on failure. Never a permanent grant.
    const carryCodeAttested =
      previous?.codeAttested === true &&
      previous.lastCodeAttestedAt !== null &&
      now - previous.lastCodeAttestedAt < CODE_ATTEST_RECONNECT_GRACE_MS &&
      (reg.cd_hash ?? null) === previous.cdHash;
    this.byKey.set(key, {
      did: reg.provider_did,
      machineId,
      machineLabel: reg.machine_label,
      chip: reg.chip,
      ramGb: reg.ram_gb,
      supportedModels: reg.supported_models,
      encryptionPubKey: reg.encryption_pub_key,
      attestationPubKey: reg.attestation_pub_key,
      attestationUri: reg.attestation_uri,
      engineFault: reg.engine_fault ?? null,
      // A fresh register is a clean slate — no crash history, no dispatch
      // counters, no silent-failure standing.
      crash: null,
      dispatched: 0,
      completed: 0,
      silentFailure: false,
      lastSeen: now,
      attestedAt: null,
      cdHash: reg.cd_hash ?? null,
      selfTier: reg.tier ?? null,
      region: reg.region ?? null,
      binaryVersion: reg.binary_version ?? null,
      // Eligibility starts false and is granted only once a challenge
      // re-verifies SIP (darkbloom never trusts a register-time SIP claim).
      challengeVerifiedSip: false,
      confidentialEligible: false,
      cdHashKnownGood: false,
      // Code-attestation is per-connection, BUT a same-machine + same-cdHash
      // reconnect within the grace window carries it forward (see above) so WS
      // churn doesn't starve the challenge cycle.
      codeAttested: carryCodeAttested,
      lastCodeAttestedAt: carryCodeAttested ? previous!.lastCodeAttestedAt : null,
      apnsDeviceToken: reg.apns_device_token ?? null,
      // ADR-0005 confidential evidence, echoed from the Register frame. Old
      // software-key agents omit both → false / x25519 (best-effort).
      secureEnclaveAvailable: reg.secure_enclave_available ?? false,
      encScheme: reg.enc_scheme ?? null,
      // Defaults true (no signal / auth not enforced); the connection handler
      // calls setRegistrationAuthenticated(false) when DID-bound auth is on and
      // this register carried no valid JWT.
      registrationAuthenticated: true,
      supportsToolCalls: reg.supports_tool_calls ?? false,
      toolCallModels: reg.tool_call_models,
      streamResumeVersion: reg.stream_resume_version ?? 0,
      // A fresh register is a clean slate — clear any prior bad standing.
      unhealthyAt: null,
      unhealthyReason: null,
      // Assume serving until the first heartbeat reports otherwise.
      active: true,
      close,
      send,
      ping,
    });
    return previous;
  }

  /** Pick an attested machine (optionally filtered by model) for a job
   *  dispatch. Returns the freshest-heartbeat eligible machine, or null if
   *  nothing matches. Thin wrapper over {@link pickCandidates}. */
  pickFor(
    model: string | undefined,
    attestedOnly = true,
    attestationMaxAgeMs: number = Number.POSITIVE_INFINITY,
    now: number = Date.now(),
    minProviderVersion: string | null = null,
    requireToolCalls = false,
  ): ProviderEntry | null {
    return (
      this.pickCandidates(
        model,
        attestedOnly,
        attestationMaxAgeMs,
        now,
        minProviderVersion,
        requireToolCalls,
      )[0] ?? null
    );
  }

  /** All eligible machines for a dispatch, best-first (freshest heartbeat
   *  first). Filters: owner-active, attested (and not stale), model-match,
   *  and — per the "avoid a sour machine" contract — EXCLUDES any machine in
   *  bad standing (`unhealthyAt !== null`), crash-looping, or on a routing
   *  cooldown (repeated recent failures — see {@link recordFailure}). Bad
   *  standing is auto-cleared the moment the machine recovers (answers a
   *  re-probe ping, reports a completion, or re-registers); a cooldown is
   *  purely time-gated and simply elapses. Either way a healthy sibling under
   *  the same DID transparently takes the work in the meantime.
   *
   *  `attestationMaxAgeMs` rejects machines whose last successful attestation
   *  is too old — defense against a machine that answered a challenge once
   *  then went silent on every subsequent one. Pass
   *  `Number.POSITIVE_INFINITY` to opt out (tests do this when not exercising
   *  the staleness path).
   *
   *  `requireToolCalls` restricts the pool to machines with verified
   *  tool-call support for the requested model (see
   *  {@link supportsToolCallsFor}) — set when the job carries `tools`. */
  pickCandidates(
    model: string | undefined,
    attestedOnly = true,
    attestationMaxAgeMs: number = Number.POSITIVE_INFINITY,
    now: number = Date.now(),
    minProviderVersion: string | null = null,
    requireToolCalls = false,
  ): ProviderEntry[] {
    const candidates = [...this.byKey.values()].filter((e) => {
      // Owner stopped this machine from the console — route it nothing.
      if (e.active === false) return false;
      // Bad standing / crash-looping — steer around it to a healthy machine.
      if (e.unhealthyAt !== null) return false;
      if (isCrashLooping(e)) return false;
      // Repeated recent failures (streamed-then-dropped, silent, disconnected
      // mid-job) → on a time-gated cooldown. Steer around it until it elapses.
      if (isCoolingDown(this.failureLedger.get(ProviderRegistry.key(e.did, e.machineId)), now)) {
        return false;
      }
      // Version floor (e.g. an image request needs a release that supports
      // messages-v1). Fail-closed: a machine that doesn't report a version
      // can't prove it has the feature, so it's excluded.
      if (minProviderVersion && !meetsMinVersion(e.binaryVersion, minProviderVersion)) return false;
      if (attestedOnly) {
        if (e.attestedAt === null) return false;
        if (now - e.attestedAt > attestationMaxAgeMs) return false;
      }
      // Job carries `tools` → only a machine whose engine passed the
      // forced-tool canary for this model may take it.
      if (requireToolCalls && !supportsToolCallsFor(e, model)) return false;
      // No model requested → any attested machine is fine.
      if (!model) return true;
      // M2: an explicit advertised model set is REQUIRED to be routed a model.
      // Empty supportedModels used to mean "matches everything", so a machine
      // advertising `[]` was selected for any open-pool job — a routing-capture
      // vector (an attacker advertises nothing and receives all traffic). Treat
      // empty as matching NO model instead: a machine must explicitly advertise
      // a model to be routed it.
      if (e.supportedModels.length === 0) return false;
      return e.supportedModels.includes(model);
    });
    candidates.sort((a, b) => b.lastSeen - a.lastSeen); // freshest heartbeat first
    return candidates;
  }

  /** Mark a machine as being in bad standing (failed preflight / went
   *  silent mid-job). Excludes it from {@link pickCandidates} until it
   *  recovers. */
  markUnhealthy(
    did: string,
    machineId: string,
    reason: string | null = null,
    now = Date.now(),
  ): boolean {
    const e = this.byKey.get(ProviderRegistry.key(did, machineId));
    if (!e) return false;
    e.unhealthyAt = now;
    e.unhealthyReason = reason;
    return true;
  }

  /** Clear a machine's bad standing (it answered a re-probe ping / recovered). */
  markHealthy(did: string, machineId: string): boolean {
    const e = this.byKey.get(ProviderRegistry.key(did, machineId));
    if (!e) return false;
    e.unhealthyAt = null;
    e.unhealthyReason = null;
    return true;
  }

  /** Record the owner's start/stop switch for a machine, as reported by
   *  its heartbeat. `active === false` takes it out of routing. */
  setActive(did: string, machineId: string, active: boolean): boolean {
    const e = this.byKey.get(ProviderRegistry.key(did, machineId));
    if (!e) return false;
    e.active = active;
    return true;
  }

  /** Record the latest crash signature a machine folded into its
   *  heartbeat. `null` (a heartbeat without `crash`) leaves any prior
   *  signature in place rather than clearing it — the machine only sends
   *  `crash` once it has crashed, and an omitted field on a later heartbeat
   *  means "no new info", not "recovered". A fresh register is what resets
   *  it. */
  setCrash(did: string, machineId: string, crash: CrashSignature | undefined): boolean {
    const e = this.byKey.get(ProviderRegistry.key(did, machineId));
    if (!e) return false;
    if (crash) e.crash = crash;
    return true;
  }

  /** Account for an `inference_request` dispatched to a machine. Returns
   *  true iff this dispatch is the one that flips the machine into the
   *  silent-failure state (>= SILENT_FAILURE_DISPATCH_THRESHOLD dispatches,
   *  still 0 completions) — so the caller can log the flip exactly once. */
  recordDispatch(did: string, machineId: string): boolean {
    const e = this.byKey.get(ProviderRegistry.key(did, machineId));
    if (!e) return false;
    e.dispatched += 1;
    if (
      !e.silentFailure &&
      e.completed === 0 &&
      e.dispatched >= SILENT_FAILURE_DISPATCH_THRESHOLD
    ) {
      e.silentFailure = true;
      return true;
    }
    return false;
  }

  /** Account for an `inference_complete` observed from a machine. Any
   *  completion clears a prior silent-failure flag AND restores standing —
   *  the machine is demonstrably producing output again.
   *
   *  It does NOT clear an active cooldown (that's purely time-gated), but a
   *  completion after a sustained {@link STRIKE_RESET_MS} quiet stretch resets
   *  the escalation so a machine that had a bad hour doesn't jump straight to a
   *  long cooldown next time. In practice this fires on the first clean
   *  completion once a cooldown has already elapsed (a cooling machine can't be
   *  routed a job to complete). */
  recordCompletion(did: string, machineId: string, now = Date.now()): boolean {
    const e = this.byKey.get(ProviderRegistry.key(did, machineId));
    if (!e) return false;
    e.completed += 1;
    e.silentFailure = false;
    e.unhealthyAt = null;
    e.unhealthyReason = null;
    const key = ProviderRegistry.key(did, machineId);
    const rec = this.failureLedger.get(key);
    if (rec && rec.lastFailureAt !== null && now - rec.lastFailureAt > STRIKE_RESET_MS) {
      rec.cooldownStrikes = 0;
      rec.recentFailures = 0;
    }
    return true;
  }

  /** Record a job-level FAILURE observed for a machine — it streamed tokens
   *  then stalled, went silent, or dropped its socket mid-job. Failures that
   *  cluster within {@link FAILURE_DECAY_MS} accumulate; once they reach
   *  {@link FAILURE_COOLDOWN_THRESHOLD} the machine is put on a time-gated
   *  cooldown (excluded from routing) whose length escalates with each
   *  successive trip. Returns true ONLY on the edge where this failure is the
   *  one that trips a NEW cooldown, so the caller can notify/log exactly once
   *  (mirrors {@link recordDispatch}'s flip-once contract).
   *
   *  The ledger is keyed independently of the connection, so a machine can't
   *  drop and reconnect to shed a cooldown. */
  recordFailure(did: string, machineId: string, reason: string, now = Date.now()): boolean {
    const key = ProviderRegistry.key(did, machineId);
    let rec = this.failureLedger.get(key);
    if (!rec) {
      rec = {
        recentFailures: 0,
        lastFailureAt: null,
        cooldownUntil: null,
        cooldownReason: null,
        cooldownStrikes: 0,
      };
      this.failureLedger.set(key, rec);
    }
    // Failures must cluster: a lone failure long ago doesn't count toward this
    // one. Reset the running count before adding the new failure.
    if (rec.lastFailureAt !== null && now - rec.lastFailureAt > FAILURE_DECAY_MS) {
      rec.recentFailures = 0;
    }
    rec.recentFailures += 1;
    rec.lastFailureAt = now;
    if (rec.recentFailures >= FAILURE_COOLDOWN_THRESHOLD) {
      rec.cooldownStrikes += 1;
      const backoff = Math.min(COOLDOWN_BASE_MS * 2 ** (rec.cooldownStrikes - 1), COOLDOWN_MAX_MS);
      rec.cooldownUntil = now + backoff;
      rec.cooldownReason = reason;
      // Start a fresh window; the next threshold-worth of failures escalates
      // the cooldown further rather than re-tripping on every single failure.
      rec.recentFailures = 0;
      return true;
    }
    return false;
  }

  /** True iff `(did, machineId)` is currently on a routing cooldown. Thin
   *  wrapper over the shared {@link isCoolingDown} predicate so the pinned
   *  dispatch path in jobs.ts checks cooldown identically to `pickCandidates`. */
  isCoolingDown(did: string, machineId: string, now = Date.now()): boolean {
    return isCoolingDown(this.failureLedger.get(ProviderRegistry.key(did, machineId)), now);
  }

  /** Cooldown status for a machine, for `GET /providers`. Prunes the ledger
   *  record if it has fully decayed (cooldown elapsed AND quiet longer than
   *  {@link STRIKE_RESET_MS}) so the map doesn't grow with every machine ever
   *  seen. Never pruned on `remove`/`sweep` — that would let a machine shed a
   *  live cooldown by dropping its socket. */
  getCooldown(
    did: string,
    machineId: string,
    now = Date.now(),
  ): { coolingDown: boolean; cooldownReason: string | null; cooldownUntil: number | null } {
    const key = ProviderRegistry.key(did, machineId);
    const rec = this.failureLedger.get(key);
    if (!rec) return { coolingDown: false, cooldownReason: null, cooldownUntil: null };
    const coolingDown = isCoolingDown(rec, now);
    if (!coolingDown && rec.lastFailureAt !== null && now - rec.lastFailureAt > STRIKE_RESET_MS) {
      this.failureLedger.delete(key);
      return { coolingDown: false, cooldownReason: null, cooldownUntil: null };
    }
    return {
      coolingDown,
      cooldownReason: coolingDown ? rec.cooldownReason : null,
      cooldownUntil: coolingDown ? rec.cooldownUntil : null,
    };
  }

  touch(did: string, machineId: string, now = Date.now()): boolean {
    const e = this.byKey.get(ProviderRegistry.key(did, machineId));
    if (!e) return false;
    e.lastSeen = now;
    return true;
  }

  markAttested(did: string, machineId: string, now = Date.now()): boolean {
    const e = this.byKey.get(ProviderRegistry.key(did, machineId));
    if (!e) return false;
    e.attestedAt = now;
    return true;
  }

  /** Record the SIP state from a verified challenge response and recompute
   *  confidential eligibility (WS-COORDINATOR / darkbloom continuous-SIP gate).
   *  A `false` here immediately drops the machine from confidential routing —
   *  SIP can only be disabled by a reboot that would kill the process, so a
   *  challenge that reports SIP off is a strong tamper signal. Returns true if
   *  the entry exists. */
  recordChallengeSip(did: string, machineId: string, sipEnabled: boolean): boolean {
    const e = this.byKey.get(ProviderRegistry.key(did, machineId));
    if (!e) return false;
    e.challengeVerifiedSip = sipEnabled;
    this.recomputeConfidential(e);
    return true;
  }

  /** Grant code-attestation after a verified APNs code-identity response and
   *  recompute confidential eligibility. The un-forgeable complement to a
   *  self-reported cdHash. Returns true if the entry exists. */
  markCodeAttested(did: string, machineId: string, now = Date.now()): boolean {
    const e = this.byKey.get(ProviderRegistry.key(did, machineId));
    if (!e) return false;
    e.codeAttested = true;
    e.lastCodeAttestedAt = now;
    this.recomputeConfidential(e);
    return true;
  }

  /** Revoke code-attestation (a challenge went unanswered or failed) and
   *  recompute — drops the machine from confidential routing when enforcement
   *  is on. */
  dropCodeAttested(did: string, machineId: string): boolean {
    const e = this.byKey.get(ProviderRegistry.key(did, machineId));
    if (!e) return false;
    e.codeAttested = false;
    this.recomputeConfidential(e);
    return true;
  }

  /** Machines the advisor will advertise as confidential-eligible. */
  listConfidential(): ProviderEntry[] {
    return [...this.byKey.values()].filter((e) => e.confidentialEligible);
  }

  /** Reset `attestedAt` to null — used when a periodic re-challenge
   *  goes unanswered past its response-deadline. The advisor will
   *  also close the underlying socket; this is the registry-side
   *  half so that any in-flight `pickFor` resolves correctly even
   *  during the window before the close hook fires. */
  clearAttested(did: string, machineId: string): boolean {
    const e = this.byKey.get(ProviderRegistry.key(did, machineId));
    if (!e) return false;
    e.attestedAt = null;
    return true;
  }

  remove(did: string, machineId: string): void {
    this.byKey.delete(ProviderRegistry.key(did, machineId));
  }

  get(did: string, machineId: string): ProviderEntry | undefined {
    return this.byKey.get(ProviderRegistry.key(did, machineId));
  }

  /** Every machine currently connected under a DID. Used by `/control` to
   *  broadcast a nudge / recover signal to all of an owner's machines when
   *  no specific machine is named. */
  getMachines(did: string): ProviderEntry[] {
    return [...this.byKey.values()].filter((e) => e.did === did);
  }

  list(): ProviderEntry[] {
    return [...this.byKey.values()];
  }

  /** Machines currently in bad standing (excluded from routing). Used by the
   *  re-probe sweep to ping them and restore the ones that have recovered. */
  listUnhealthy(): ProviderEntry[] {
    return [...this.byKey.values()].filter((e) => e.unhealthyAt !== null);
  }

  size(): number {
    return this.byKey.size;
  }

  /** Disconnect machines whose lastSeen is older than `staleMs`.
   *  Returns the `(did, machineId)` pairs that were evicted. */
  sweep(staleMs: number, now = Date.now()): Array<{ did: string; machineId: string }> {
    const evicted: Array<{ did: string; machineId: string }> = [];
    for (const [key, e] of this.byKey) {
      if (now - e.lastSeen > staleMs) {
        try {
          e.close();
        } catch {
          // ignore
        }
        this.byKey.delete(key);
        evicted.push({ did: e.did, machineId: e.machineId });
      }
    }
    return evicted;
  }
}

/** The production `onResumeExpired` hook (wired in main.ts): a provider that
 *  let a resumable session's reconnect grace lapse failed that job, so the
 *  lapse counts toward the machine's failure/cooldown ledger. Exported as a
 *  factory so the wiring is testable without booting main. */
export function resumeExpiredHandler(
  registry: ProviderRegistry,
): (providerDid: string, providerMachineId: string) => void {
  return (providerDid, providerMachineId) => {
    const tripped = registry.recordFailure(providerDid, providerMachineId, "resume-expired");
    console.error(
      `[sessions] resume-expired did=${providerDid} machine=${providerMachineId}${tripped ? ", repeated → cooldown" : ""}`,
    );
  };
}
