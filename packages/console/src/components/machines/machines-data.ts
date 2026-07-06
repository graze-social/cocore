import type { VerifiedTier } from "@/lib/verified-standing.server.ts";

export type MachineState = "running" | "idle" | "paused" | "offline" | "provisioning";

/** Owner-facing label for a machine state chip. `provisioning` is agent
 *  jargon — the owner-facing story is "it's preparing: downloading model
 *  weights before it can serve", so the chip says "preparing" and the
 *  accompanying status line spells out the download. */
export function machineStateLabel(state: MachineState): string {
  return state === "provisioning" ? "preparing" : state;
}

/** One-line status description for a machine, shared by the fleet table and
 *  the narrow-screen cards so the copy can't drift between the two. */
export function machineStatusText(m: {
  state: MachineState;
  faultReason?: string;
  pausedReason?: string;
  offlineReason?: string;
  advisorFaultReason?: string;
  standingKnown?: boolean;
  advisorConnected?: boolean;
}): string {
  if (m.faultReason) return "Engine not loaded — only serving stub";
  if (advisorUnreachable(m)) return "Serving locally — can't reach the co/core network";
  switch (m.state) {
    case "provisioning":
      return "Preparing — downloading models before it can serve…";
    case "idle":
      return "Eligible for matching when active";
    case "paused":
      return m.pausedReason ?? "Paused";
    case "running":
      return "Served a job in the last 5 min";
    default:
      return m.offlineReason ?? "Offline";
  }
}

export interface Machine {
  id: string;
  /** The machine's Secure-Enclave attestation pubkey from its provider
   *  record. This is the machine's identity that does NOT depend on a
   *  successful boot-time PDS publish: when the agent couldn't publish
   *  (dead session → no rkey to echo), it registers with the advisor
   *  without a `machine_id` and the advisor keys it by this pubkey
   *  instead. The advisor-standing join falls back to it so such a
   *  machine still reads as connected. */
  attestationPubKey?: string;
  alias: string;
  state: MachineState;
  gpu: string;
  vram: number;
  ram: number;
  pairedAt: string;
  earnings24h: number;
  earnings7d: number;
  earningsLifetime: number;
  jobsCompleted: number;
  pausedReason?: string;
  offlineReason?: string;
  /** Machine-readable engine-load fault class published by the agent
   *  when it could not bring its configured inference engine online
   *  after exhausting startup recovery (e.g. "model-load-failed",
   *  "venv-missing"). Absent when the engine loaded cleanly. See the
   *  provider record's `engineFault` field. */
  faultCode?: string;
  /** Human-readable, content-safe fault summary with remediation
   *  guidance, shown to the operator. Present iff {@link faultCode} is. */
  faultReason?: string;
  /** The configured model ids that failed to load, if the agent
   *  reported them. */
  faultModels?: string[];
  /** Machine-readable advisor-connectivity fault class published by the
   *  agent when its WebSocket to the advisor keeps failing to connect
   *  (e.g. "upgrade-blocked", "dns-failure", "connect-timeout"). The
   *  machine is healthy and serving LOCALLY but invisible to the network —
   *  no jobs will reach it. Cleared by the agent on its next successful
   *  registration. See the provider record's `advisorFault` field. */
  advisorFaultCode?: string;
  /** Human-readable, content-safe summary of {@link advisorFaultCode} with
   *  remediation guidance (VPN / firewall / WebSocket filtering). Present
   *  iff the fault is. */
  advisorFaultReason?: string;
  /** RFC3339 timestamp of when the agent recorded the advisor fault. */
  advisorFaultAt?: string;
  /** How the machine's environment is attested (from the provider record):
   *  `self-attested` (software) or `hardware-attested` (genuine Apple hardware +
   *  SIP, via a bound MDA chain). Evidence-derived; the UI humanizes it. */
  trustLevel?: string;
  /** The machine's ACHIEVED confidentiality tier from its provider record
   *  (`attested-confidential` | `best-effort`). Evidence-derived; absent =
   *  best-effort. Distinct from {@link desiredTier} (the owner's intent). */
  tier?: string;
  /** The tier the OWNER opted this machine into via "Upgrade security" (written
   *  to the provider record's `desiredTier`). The agent reconciles toward it;
   *  the achieved {@link tier} only rises once earned. Absent = not opted in. */
  desiredTier?: string;
  /** Tier recomputed from the machine's ACTUAL signed attestation (proof-
   *  backed; see verified-standing.server.ts), overlaid from live advisor
   *  standing. Drives the fleet trust badge. Absent until standing is known. */
  verifiedTier?: VerifiedTier;
  /** When the machine was capped BELOW the tier it opted into (e.g. confidential
   *  downgraded to hardware-attested because its signing key isn't proven
   *  Secure-Enclave-bound, or best-effort because its registration wasn't
   *  DID-authenticated), a short operator-facing nudge explaining why + how to
   *  regain it. Undefined when the machine is at its ceiling. */
  verifiedTierReason?: string;
  /** The advisor's VERIFIED confidential standing — the machine passed every
   *  earned leg (known-good cdHash + challenge-verified SIP + code-identity).
   *  This is the honest "operator cannot read your prompt" signal, stricter
   *  than the self-asserted {@link tier}. Absent/false otherwise. */
  confidential?: boolean;
  chipMeta?: string;
  /** Model NSIDs the agent advertises in its provider record's
   *  `supportedModels` field. Mirrors what the engine registry
   *  actually loaded — see provider/src/main.rs build_engines. The
   *  /machines UI surfaces this so an operator can see which models
   *  each of their boxes is serving. */
  supportedModels?: string[];
  /** Model NSIDs the machine's owner has PINNED via the console's "Manage
   *  models" picker, written to the provider record's `desiredModels`
   *  field. The agent reconciles this against what it loads. Absent when
   *  the owner has never pinned a set — the machine then serves its own
   *  local default config (reflected in {@link supportedModels}). */
  desiredModels?: string[];
  /** Live operational standing from the advisor (the only component that
   *  knows the machine failed a preflight / went silent mid-job). This is
   *  separate from {@link state}, which is derived from the PDS record:
   *  a machine can be `running`/`idle` on PDS yet flagged `unhealthy` by
   *  the advisor. `true` → currently steered around (recovering); the agent
   *  has been asked to self-right. Absent when the advisor reports the
   *  machine as healthy. */
  unhealthy?: boolean;
  /** Why the advisor flagged the machine (e.g. "preflight-no-response",
   *  "job-idle-timeout"). Present iff {@link unhealthy}. */
  unhealthyReason?: string;
  /** The advisor has dispatched this machine jobs but observed no
   *  completions — failing silently. Diagnostic. */
  silentFailure?: boolean;
  /** Whether we could read live standing from the advisor at all. `false`
   *  means the advisor was unreachable, so {@link unhealthy} is unknown
   *  (NOT "healthy") — the UI shows "live status unavailable" rather than
   *  fabricating a green state. `true` means the overlay is authoritative. */
  standingKnown?: boolean;
  /** Whether the advisor currently holds a live connection to this machine
   *  (it appears in the advisor's registry). `false` with
   *  {@link standingKnown} true means the machine isn't connected to the
   *  grid right now. */
  advisorConnected?: boolean;
  /** Whether the owner opted this machine into publishing its coarse country
   *  (the provider record's `shareLocation` switch). Drives the "Share
   *  country" toggle in per-machine settings. Absent ≡ off. */
  shareLocation?: boolean;
  /** Coarse, opt-in ISO 3166-1 alpha-2 country the agent published when
   *  {@link shareLocation} is on (the provider record's `region`). Advisory
   *  self-claim; absent when not sharing or not yet resolved. */
  region?: string;
  /** The owner's pro-bono election from the provider record's `proBono`
   *  policy: `any` (serve everyone free) or `direct` (serve only the listed
   *  {@link proBonoDids} free). Absent ≡ pro bono off (every job billed). */
  proBonoMode?: "any" | "direct";
  /** Requester DIDs served pro bono under `direct` mode. Empty/absent under
   *  `direct` means no one is currently served free. */
  proBonoDids?: string[];
  /** Whether the owner opted this machine into serving tool/function calls
   *  (the provider record's `toolCalls` switch). When on, the agent enables
   *  vLLM automatic tool choice for the curated top models it knows a parser
   *  pairing for and verifies each with a startup canary before advertising it.
   *  Drives the "Tool calling" toggle in per-machine settings. Absent ≡ off. */
  toolCalls?: boolean;
}

/** Whether this machine looks cut off from the co/core network while
 *  serving locally: its agent published an `advisorFault` (repeated
 *  WebSocket connect failures), and/or its record says it's serving yet
 *  the advisor holds no live connection to it. Only meaningful for a
 *  machine that SHOULD be connected — a paused / offline / provisioning
 *  box is expected to be absent from the advisor's registry. */
export function advisorUnreachable(
  m: Pick<Machine, "state" | "advisorFaultReason" | "standingKnown" | "advisorConnected">,
): boolean {
  if (m.state !== "idle" && m.state !== "running") return false;
  // A live advisor connection outranks a fault the agent published earlier
  // and hasn't gotten around to clearing yet (it clears on registration).
  if (m.standingKnown === true && m.advisorConnected === true) return false;
  if (m.advisorFaultReason) return true;
  return m.standingKnown === true && m.advisorConnected === false;
}

/** The machine's live network standing for the "on network / not
 *  reachable" badge. `null` when a badge would be noise: the machine
 *  isn't expected on the network (paused/offline/provisioning) or the
 *  advisor overlay was unavailable and the agent reports no fault. */
export function machineNetworkStanding(m: Machine): "on-network" | "not-reachable" | null {
  if (m.state !== "idle" && m.state !== "running") return null;
  if (m.standingKnown === true && m.advisorConnected === true) return "on-network";
  if (advisorUnreachable(m)) return "not-reachable";
  return null;
}
