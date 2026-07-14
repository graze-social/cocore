// Proof-backed trust-tier resolution for providers.
//
// A provider record's `trustLevel` and a machine's claimed tier are
// SELF-ASSERTED — anyone can write them to their own PDS. This module
// recomputes the tier from the ACTUAL attestation, so a badge or a routing
// decision can never be faked by editing a record:
//
//   * hardware-attested — proven OFFLINE: the SDK verifier checks the
//     provider's signed attestation carries an Apple-rooted MDA chain that
//     verifies AND binds to the signing key (leaf-key or freshness-code).
//     No known-good set or coordinator needed — pure Apple-CA crypto.
//   * attested-confidential — the above PLUS the advisor's MEASURED standing
//     (`confidentialEligible`: a known-good cdHash + the un-forgeable,
//     AMFI-gated APNs code-attestation). The code-attestation is the one leg
//     an operator can't forge; it's advisor-asserted by design (the
//     documented coordinator-trust carve-out — see sdk/verify-provider.ts).
//
// The offline crypto (Apple cert-chain verification) is cached by attestation
// CID: a machine's attestation only changes when it re-attests (~daily), so
// the hot path is a cache hit. The LIVE confidential bit (which can flip with
// code-attestation) is layered on per-call, never cached.

import { verifyProviderForSeal } from "@cocore/sdk/verify-provider";
import type { AttestationRecord } from "@cocore/sdk/types";

import { cocoreConfig } from "@/lib/cocore-config.ts";

export type VerifiedTier = "best-effort" | "hardware-attested" | "attested-confidential";

/** The floor a requester can demand. `hardware-attested` accepts EITHER
 *  verified tier (confidential is strictly stronger); `attested-confidential`
 *  is strict. */
export type TrustFloor = "hardware-attested" | "attested-confidential";

export function meetsFloor(tier: VerifiedTier, floor: TrustFloor): boolean {
  if (floor === "attested-confidential") return tier === "attested-confidential";
  return tier === "hardware-attested" || tier === "attested-confidential";
}

/** Map a requester-facing param value to a TrustFloor, or null if invalid.
 *  Accepts `hardware-attested` and `confidential`/`attested-confidential`. */
export function parseTrustFloor(v: unknown): TrustFloor | null {
  if (typeof v !== "string") return null;
  const s = v.trim().toLowerCase();
  if (s === "hardware-attested" || s === "hardware") return "hardware-attested";
  if (s === "confidential" || s === "attested-confidential") return "attested-confidential";
  return null;
}

interface AdvisorRow {
  did: string;
  machineId?: string;
  supportedModels?: string[];
  attestationUri?: string | null;
  attestedAt?: string | null;
  confidentialEligible?: boolean;
  codeAttested?: boolean;
  /** C1: did the machine present a valid DID-bound service-auth JWT at
   *  register? `false` means the advisor admitted it (soft cutover — it still
   *  serves best-effort) but could not confirm it controls `did`, so we can't
   *  trust it's the genuine owner of the attestation we'd fetch. `undefined` =
   *  a pre-signal advisor; treated as authenticated so an advisor upgrade
   *  doesn't mass-downgrade a healthy fleet. Only an explicit `false`
   *  downgrades. */
  registrationAuthenticated?: boolean;
  /** ADR-0005: whether the machine's signing key is Secure-Enclave-resident,
   *  echoed by the advisor from the Register frame. `false`/`undefined` = a
   *  software key (or an older agent). Only downgrades when the SE gate is
   *  enforced (see {@link confidentialRequiresSeKey}). */
  secureEnclaveAvailable?: boolean;
}

/** ADR-0005 phase gate for the Secure-Enclave-resident-key requirement on the
 *  confidential tier (the workable macOS replacement for the retired App Attest
 *  gate — App Attest never functions on macOS, so its `keyHardwareBound` signal
 *  was always false and could never be enforced without downgrading the whole
 *  fleet). Default OFF (Phase 1 — deploy dormant while the fleet ships SE
 *  builds). Ops flips `COCORE_CONFIDENTIAL_REQUIRE_SE_KEY=true` for Phase 2: a
 *  machine that doesn't advertise `secureEnclaveAvailable` DOWNGRADES from
 *  confidential to hardware-attested (it keeps serving — nothing disconnects),
 *  and confidential requesters fail closed rather than route to a portable-key
 *  machine. The flip only affects un-upgraded machines, never healthy SE ones —
 *  the soft cutover. */
function confidentialRequiresSeKey(): boolean {
  return process.env["COCORE_CONFIDENTIAL_REQUIRE_SE_KEY"] === "true";
}

// Codes the SDK verifier emits when the OFFLINE hardware-attestation proof
// fails (self-signature, the Apple MDA chain, or its binding to the signing
// key). If NONE are present, genuine-Apple-hardware-bound-to-the-signing-key
// holds — i.e. at least hardware-attested.
export const HARDWARE_BLOCKER_CODES = new Set([
  "attestation-signature-invalid",
  "mda-invalid",
  "mda-unbound",
  "mda-no-binding-material",
  "no-mda-chain",
]);

/** The offline (Apple-crypto) evidence a fetched attestation yields, cached by
 *  attestation CID (immutable — a machine's attestation only changes when it
 *  re-attests). `hardware` is whether it proves genuine Apple hardware bound to
 *  the signing key; `keyHardwareBound` is whether that key is proven
 *  Secure-Enclave-resident (a valid bound App Attest object) rather than a
 *  possibly-exportable software key with only an MDA chain. */
interface OfflineEvidence {
  hardware: "hardware-attested" | "best-effort";
  keyHardwareBound: boolean;
}
const offlineTierCache = new Map<string, OfflineEvidence>();

function advisorBase(): string {
  return cocoreConfig().advisorUrl.replace(/\/$/, "");
}

/** Resolve a DID's PDS host (public, unauthenticated). */
async function resolvePds(did: string): Promise<string | null> {
  try {
    const r = await fetch(
      `https://slingshot.microcosm.blue/xrpc/com.bad-example.identity.resolveMiniDoc?identifier=${encodeURIComponent(did)}`,
      { headers: { Accept: "application/json" } },
    );
    if (!r.ok) return null;
    const mini = (await r.json()) as { pds?: string };
    return typeof mini.pds === "string" ? mini.pds.replace(/\/$/, "") : null;
  } catch {
    return null;
  }
}

/** Public getRecord of the provider's attestation. */
async function fetchAttestation(
  did: string,
  attestationUri: string,
): Promise<{ record: AttestationRecord; cid: string } | null> {
  const m = /^at:\/\/[^/]+\/([^/]+)\/([^/]+)$/.exec(attestationUri);
  if (!m) return null;
  const collection = m[1]!;
  const rkey = m[2]!;
  const pds = await resolvePds(did);
  if (!pds) return null;
  try {
    const r = await fetch(
      `${pds}/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(did)}` +
        `&collection=${encodeURIComponent(collection)}&rkey=${encodeURIComponent(rkey)}`,
      { headers: { Accept: "application/json" } },
    );
    if (!r.ok) return null;
    const body = (await r.json()) as { value?: unknown; cid?: unknown };
    if (!body.value || typeof body.cid !== "string") return null;
    return { record: body.value as AttestationRecord, cid: body.cid };
  } catch {
    return null;
  }
}

/** The offline half: does the signed attestation prove genuine Apple hardware
 *  bound to the signing key, and is that key proven Secure-Enclave-resident?
 *  Cached per attestation CID. */
async function offlineEvidence(did: string, attestationUri: string): Promise<OfflineEvidence> {
  const fetched = await fetchAttestation(did, attestationUri);
  if (!fetched) return { hardware: "best-effort", keyHardwareBound: false };
  const cached = offlineTierCache.get(fetched.cid);
  if (cached) return cached;

  const record = fetched.record;
  const mdaChain = (record as { mdaCertChain?: string[] }).mdaCertChain;
  let hardwareOk = false;
  let keyHardwareBound = false;
  try {
    // requireConfidential:false → compute without hard-failing; we read the
    // findings. requireHardwareBoundKey:true → the verifier always emits the
    // `key-not-hardware-bound` finding when there's no bound App Attest object,
    // so we can learn key residency here regardless of the production phase gate.
    const result = await verifyProviderForSeal(record, mdaChain, {
      requireConfidential: false,
      requireHardwareBoundKey: true,
    });
    hardwareOk = !result.findings.some((f) => HARDWARE_BLOCKER_CODES.has(f.code));
    keyHardwareBound = !result.findings.some((f) => f.code === "key-not-hardware-bound");
  } catch {
    hardwareOk = false;
    keyHardwareBound = false;
  }
  const evidence: OfflineEvidence = {
    hardware: hardwareOk ? "hardware-attested" : "best-effort",
    keyHardwareBound,
  };
  offlineTierCache.set(fetched.cid, evidence);
  return evidence;
}

/** A recomputed tier plus, when the machine was capped BELOW what it asked for,
 *  a short operator-facing reason (the "why not confidential / why best-effort"
 *  nudge). `reason` is undefined when the machine is at its ceiling. */
export interface ResolvedTier {
  tier: VerifiedTier;
  reason?: string;
}

/** Recompute a machine's tier from its actual attestation (offline proof) + the
 *  advisor's live measured standing. Never trusts the self-asserted trustLevel.
 *  Every shortfall is a DOWNGRADE with a reason, never a hard failure — the
 *  machine keeps whatever weaker tier it earned and keeps serving. */
export async function resolveVerifiedTier(row: AdvisorRow): Promise<ResolvedTier> {
  if (!row.attestationUri) return { tier: "best-effort", reason: "no attestation published" };

  // C1 (soft cutover): a registration the advisor couldn't DID-authenticate
  // can't be trusted to be the genuine owner of the attestation record we'd
  // fetch, so it can't earn an attested tier. It still serves best-effort — we
  // downgrade, we don't disconnect. `undefined` (pre-signal advisor) is treated
  // as authenticated so an advisor rollout doesn't mass-downgrade the fleet.
  if (row.registrationAuthenticated === false) {
    return {
      tier: "best-effort",
      reason: "registration not DID-authenticated — upgrade the agent so it mints a register token",
    };
  }

  const offline = await offlineEvidence(row.did, row.attestationUri);
  if (offline.hardware === "best-effort") {
    return { tier: "best-effort", reason: "attestation does not prove genuine Apple hardware" };
  }

  // Genuine Apple hardware bound to the signing key. Confidential additionally
  // needs the advisor's measured + code-attested standing (the un-forgeable
  // leg) AND — once the SE-key rollout is enforced (ADR-0005) — proof the
  // signing key is Secure-Enclave-resident (not a portable software key).
  if (row.confidentialEligible !== true) {
    return { tier: "hardware-attested" };
  }
  // ADR-0005: gate on the advisor-advertised `secureEnclaveAvailable` (the
  // truthful flag from the Register frame), NOT the dead App-Attest
  // `keyHardwareBound` signal — App Attest never works on macOS, so that would
  // downgrade the entire fleet. Per-machine downgrade with a calm upgrade nudge.
  if (confidentialRequiresSeKey() && row.secureEnclaveAvailable !== true) {
    return {
      tier: "hardware-attested",
      reason:
        "running an older agent without a Secure-Enclave signing key — upgrade the agent to regain the confidential tier",
    };
  }
  return { tier: "attested-confidential" };
}

/** Back-compat thin wrapper: the tier alone. */
export async function verifiedTierFor(row: AdvisorRow): Promise<VerifiedTier> {
  return (await resolveVerifiedTier(row)).tier;
}

/** Set of MACHINE keys (`${did}:${machineId}`) whose VERIFIED tier meets
 *  `floor` (optionally for a given model). This is the proof-backed allow-set
 *  the verified completions path routes against.
 *
 *  MUST be keyed per machine, not per owner DID. Tier is computed per row
 *  (each row carries its own `attestationUri` + advisor-measured
 *  `confidentialEligible`), but a DID can hold many machines: a genuinely
 *  attested Mac and an unattested Linux box under the SAME DID. A DID-scoped
 *  allow-set lets {@link filterByAllowedDids} widen from the attested machine
 *  to every sibling under that DID — so an `attested-confidential` request
 *  routes to the unattested node, which then reads the plaintext prompt and
 *  serves whatever model it likes. The composite `${did}:${machineId}` key is
 *  matched by {@link filterByAllowedDids} against the advisor row's
 *  `(did, machineId)`, exactly like the pro-bono path
 *  ({@link resolveProBonoProviderKeys}), so standing never leaks across an
 *  owner's machines.
 *
 *  Fail closed: a row that passes the tier check but carries no `machineId`
 *  can't be bound to a specific machine, so it is dropped rather than added as
 *  a bare DID (which would re-open the widening hole). */
export async function resolveVerifiedProviderKeys(
  floor: TrustFloor,
  model?: string,
): Promise<Set<string>> {
  const r = await fetch(`${advisorBase()}/providers`, { headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error(`advisor /providers ${r.status}`);
  const rows = (await r.json()) as AdvisorRow[];
  const online = rows.filter((p) => p.attestedAt);
  const keys = new Set<string>();
  await Promise.all(
    online.map(async (row) => {
      if (
        model &&
        row.supportedModels &&
        row.supportedModels.length > 0 &&
        !row.supportedModels.includes(model)
      ) {
        return;
      }
      // Can't machine-bind a row with no machineId → fail closed (drop it)
      // rather than fall back to a DID-scoped key that would re-admit the
      // owner's unattested siblings.
      if (!row.machineId) return;
      const tier = await verifiedTierFor(row);
      if (meetsFloor(tier, floor)) keys.add(`${row.did}:${row.machineId}`);
    }),
  );
  return keys;
}
