import type { VerifiedTier } from "@/lib/verified-standing.server.ts";

export type MachineState = "running" | "idle" | "paused" | "offline" | "provisioning";

export interface Machine {
  id: string;
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
}
