// Wire types for the advisor ↔ provider WebSocket. Mirrors
// provider/src/protocol.rs. Field naming is the Rust struct field
// name verbatim (snake_case for fields like `sip_enabled`); the
// `type` discriminator is snake_case too because the Rust enum
// has `#[serde(tag = "type", rename_all = "snake_case")]`.
//
// Bytes (Vec<u8> on the Rust side) are emitted by serde_json as a
// JSON array of integers. We accept both that shape and a base64
// string so a future wire change to base64 doesn't break us.

/** Diagnostic the provider sends when it couldn't bring one or more
 *  configured inference engines online after its startup recovery loop
 *  gave up. The failed models are already absent from
 *  {@link Register.supported_models}, so this does not affect matchmaking
 *  — it lets the advisor note (log + expose) that a connected machine is
 *  degraded (only serving `stub`). Mirror of the provider's
 *  `dev.cocore.compute.provider#engineFault`. */
export interface EngineFault {
  code: string;
  message: string;
  models?: string[];
  at: string;
}

export interface Register {
  provider_did: string;
  /** Stable per-machine identifier — the agent's `dev.cocore.compute.provider`
   *  record rkey. Distinguishes two machines that register under the same DID
   *  so the advisor holds both instead of evicting one. Optional / additive:
   *  pre-`machine_id` agents omit it and the advisor falls back to the
   *  per-machine `attestation_pub_key` (see registry.machineIdOf). */
  machine_id?: string;
  machine_label: string;
  chip: string;
  ram_gb: number;
  supported_models: string[];
  encryption_pub_key: string;
  attestation_pub_key: string;
  attestation_uri: string;
  /** Optional / additive — absent on a healthy serve. */
  engine_fault?: EngineFault;
  /** Measured cdHash echoed from the signed attestation — the advisor checks
   *  it against its known-good set when computing confidential eligibility.
   *  Additive. */
  cd_hash?: string;
  /** Provider's self-asserted tier (`attested-confidential` | `best-effort`),
   *  echoed from the signed attestation. Advisory — the advisor recomputes.
   *  Additive. */
  tier?: string;
  /** Coarse, opt-in ISO 3166-1 alpha-2 country echoed from the provider
   *  record's `region`, so the advisor's /providers list can route by
   *  country without a PDS read. Advisory self-claim; absent when the owner
   *  hasn't opted into location sharing. Additive. */
  region?: string;
  /** APNs device token (hex) for the measured agent process, when it could
   *  register for remote notifications (confidential build + GUI session). The
   *  advisor sends the code-identity challenge here. Omitted on headless
   *  installs, which therefore stay best-effort. Additive. */
  apns_device_token?: string;
  /** True only when at least one model passed the provider's startup
   *  forced-tool canary. `tool_call_models` carries the per-model verified
   *  subset for new clients. Additive — old advisors ignore it. */
  supports_tool_calls?: boolean;
  /** Model ids whose engines passed the provider's forced-tool startup canary.
   *  When absent, clients fall back to legacy `supports_tool_calls`; when
   *  present, tool-capability gating should require the requested model to be
   *  listed. Additive. */
  tool_call_models?: string[];
  /** This agent binary's version (e.g. `0.9.32`), echoed live so the advisor
   *  can route version-gated jobs (a request needing a feature only present
   *  from some release is steered to machines at/above a minimum version).
   *  Additive — pre-version agents omit it, and a version floor treats a
   *  machine that omits it as below the floor (fail-closed). */
  binary_version?: string;
}

/** Content-free crash signature the provider folds into its heartbeat
 *  after its inference worker panicked / aborted and was restarted. It
 *  carries no payload — just enough for the advisor to spot a machine
 *  that's crash-looping (high `count` in a short window) and stop feeding
 *  it jobs. Mirror of the provider's `Heartbeat.crash` (serde, snake_case
 *  field names). All fields but `count` are omitted when absent; a machine
 *  that never crashed omits the whole object. Additive — old agents never
 *  send it. */
export interface CrashSignature {
  count: number;
  last_at?: string;
  location?: string;
  signature?: string;
  version?: string;
}

interface Heartbeat {
  load: number;
  queue_depth: number;
  at: string;
  /** The owner's start/stop switch as the agent sees it on its PDS record.
   *  `false` → the owner stopped this machine; the advisor routes it no
   *  jobs. `true` / absent → serving. Additive. */
  active?: boolean;
  /** Latest crash signature, present only once the provider has crashed at
   *  least once this session. Absent on a machine that's never crashed.
   *  Additive — old agents omit it. */
  crash?: CrashSignature;
}

export interface AttestationChallenge {
  nonce: string;
  timestamp: string;
}

export interface AttestationResponse {
  nonce: string;
  timestamp: string;
  sip_enabled: boolean;
  hypervisor_present?: boolean;
  signature: number[] | string;
}

/** Provider → advisor: response to an APNs code-identity challenge. The
 *  challenge arrives out-of-band over APNs (a nonce sealed to the provider's
 *  X25519 key `K`); only the genuine, AMFI-gated binary can receive and open
 *  it. The provider echoes the recovered `nonce` and a Secure-Enclave P-256
 *  signature (DER) over the canonical `{ nonce }`. Mirror of the Rust
 *  `CodeAttestationResponse`. Additive. */
export interface CodeAttestationResponse {
  nonce: string;
  signature: number[] | string;
}

export interface InferenceRequest {
  job_uri: string;
  /** Optional CID half of the job strong-ref. The provider needs
   *  both halves to publish a receipt. The smoke
   *  `dispatch-job.sh` requester doesn't have a real job record;
   *  the console (which does) populates this. */
  job_cid?: string;
  requester_did: string;
  requester_pub_key: string;
  model: string;
  max_tokens_out: number;
  ciphertext: number[] | string;
  /** How the provider interprets the opened ciphertext: absent/"text"
   *  (raw prompt) or "messages-v1" (multimodal envelope). Forwarded from
   *  the `/jobs` body; the advisor never reads the plaintext. */
  input_format?: string;
  session_id: string;
  /** Optional JSON Schema constraining the model's output. When present,
   *  the provider passes it to the inference engine as response_format
   *  guided decoding. Forwarded from the `/jobs` body; the advisor never
   *  reads the plaintext. */
  output_schema?: { name: string; strict?: boolean; schema: Record<string, unknown> };
  /** Optional tool definitions the model may call. Forwarded from the
   *  `/jobs` body; the advisor never inspects the plaintext. */
  tools?: unknown;
  /** Optional tool-choice directive (e.g. "auto", "none", "required", or
   *  a provider-specific object). Forwarded from the `/jobs` body; the
   *  advisor never inspects it. */
  tool_choice?: unknown;
}

interface InferenceChunk {
  session_id: string;
  seq: number;
  /** Which channel this chunk's plaintext belongs to. Absent (older
   *  providers) means the answer. The advisor relays it opaquely. */
  channel?: "content" | "reasoning" | "tool_call";
  ciphertext: number[] | string;
}

interface InferenceComplete {
  session_id: string;
  tokens_in: number;
  tokens_out: number;
  receipt_uri: string;
}

/** Provider → advisor: "still generating" signal sent during a long job
 *  when no user-visible token has gone out for a while (slow prefill or a
 *  slow decode patch). Resets the session idle timer without being a token
 *  — keeps a slow-but-alive job from being killed as silent. Additive; an
 *  advisor that doesn't know this frame simply ignores it. */
interface InferenceKeepalive {
  session_id: string;
}

/** Advisor → provider liveness probe. The provider answers `pong` with
 *  the same nonce IMMEDIATELY from its serve loop (not behind an
 *  in-flight inference), so a pong proves the agent's request loop is
 *  actually pumping — a stronger signal than a WS-level pong, which the
 *  read half auto-sends even when the serve loop is wedged. Used by
 *  `/jobs` to preflight the chosen provider before committing a job. */
interface Ping {
  nonce: string;
}

/** Provider → advisor reply to {@link Ping}, echoing the nonce. */
interface Pong {
  nonce: string;
}

/** Advisor → provider standing change. `bad` means the advisor stopped
 *  routing jobs to this machine (it failed a preflight ping or went
 *  silent mid-job); the agent surfaces it to the operator (red tray
 *  ping). `ok` clears it. Additive — old agents ignore it. */
interface HealthNotice {
  standing: "ok" | "bad";
  reason?: string;
}

/** Advisor → provider nudge: "your owner-set control state changed —
 *  re-read it." Carries no authority; the agent re-reads the authoritative
 *  `active` from its own PDS and reports back in a heartbeat. Lets a
 *  console start/stop take effect in ~a second instead of at the next
 *  poll. Additive. */
interface ControlChanged {
  reason?: string;
}

/** Advisor → provider: "you've been flagged unhealthy — try to self-right
 *  NOW." The agent runs its in-process recovery (engine health-check +
 *  bounded restart, re-attest) immediately rather than waiting for its next
 *  scheduled health tick, then reports the outcome in {@link RecoverResult}.
 *  Sent automatically the moment the advisor marks a machine unhealthy, and
 *  on demand when the owner clicks "Try to recover" in the console. Carries
 *  no authority. Additive — old agents ignore it (they still get the
 *  `health_notice` that accompanies it). */
interface RecoverRequest {
  reason?: string;
}

/** Provider → advisor: outcome of a self-right attempt. `recovered: true`
 *  means the machine brought its engine(s) back and is ready for jobs again
 *  (the advisor clears its bad standing); `false` means it couldn't, and
 *  `detail` carries the human-readable reason the console + tray surface as
 *  remediation. Additive. */
interface RecoverResult {
  recovered: boolean;
  detail?: string;
}

export type AdvisorMessage =
  | ({ type: "register" } & Register)
  | ({ type: "heartbeat" } & Heartbeat)
  | ({ type: "attestation_challenge" } & AttestationChallenge)
  | ({ type: "attestation_response" } & AttestationResponse)
  | ({ type: "code_attestation_response" } & CodeAttestationResponse)
  | ({ type: "inference_request" } & InferenceRequest)
  | ({ type: "inference_chunk" } & InferenceChunk)
  | ({ type: "inference_keepalive" } & InferenceKeepalive)
  | ({ type: "inference_complete" } & InferenceComplete)
  | ({ type: "ping" } & Ping)
  | ({ type: "pong" } & Pong)
  | ({ type: "health_notice" } & HealthNotice)
  | ({ type: "control_changed" } & ControlChanged)
  | ({ type: "recover_request" } & RecoverRequest)
  | ({ type: "recover_result" } & RecoverResult);

export function bytesToBase64(b: number[] | string): string {
  if (typeof b === "string") return b;
  let bin = "";
  for (const byte of b) bin += String.fromCharCode(byte);
  return btoa(bin);
}
