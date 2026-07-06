import { describe, expect, it, vi } from "vitest";

import { KnownGoodSet } from "./known-good.ts";
import {
  CRASH_LOOP_THRESHOLD,
  ProviderRegistry,
  SILENT_FAILURE_DISPATCH_THRESHOLD,
} from "./registry.ts";

const noop = (): void => {};
const noopSend = (): void => {};
const noopPing = (): Promise<boolean> => Promise.resolve(true);

const baseReg = {
  provider_did: "did:plc:test1",
  machine_id: "m1",
  machine_label: "mac-mini",
  chip: "Apple M4",
  ram_gb: 64,
  supported_models: ["llama-3.2"],
  encryption_pub_key: "x25519-pub",
  attestation_pub_key: "p256-pub",
  attestation_uri: "at://did:plc:test1/dev.cocore.compute.attestation/abc",
};

// The single-machine baseReg's identity, spelled out for the common case.
const DID = baseReg.provider_did;
const MID = baseReg.machine_id;

describe("ProviderRegistry confidential eligibility (WS-COORDINATOR)", () => {
  const GOOD_CD = "abc123".padEnd(40, "0");
  const confReg = { ...baseReg, cd_hash: GOOD_CD, tier: "attested-confidential" };

  it("is fail-closed: empty known-good set → never eligible", () => {
    const r = new ProviderRegistry(); // empty known-good
    r.upsert(confReg, noop, noopSend, noopPing, 1000);
    r.recordChallengeSip(DID, MID, true);
    expect(r.get(DID, MID)?.confidentialEligible).toBe(false);
  });

  it("grants eligibility only with known-good cdHash + tier + challenge-verified SIP", () => {
    const r = new ProviderRegistry(new KnownGoodSet([GOOD_CD]));
    r.upsert(confReg, noop, noopSend, noopPing, 1000);
    r.markCodeAttested(DID, MID); // the always-required code-identity leg
    // Before any challenge, SIP is unverified → not eligible.
    expect(r.get(DID, MID)?.confidentialEligible).toBe(false);
    // A challenge verifying SIP grants it (all legs now earned).
    r.recordChallengeSip(DID, MID, true);
    expect(r.get(DID, MID)?.confidentialEligible).toBe(true);
    expect(r.listConfidential().map((e) => e.machineId)).toEqual([MID]);
  });

  it("a challenge reporting SIP off immediately drops eligibility", () => {
    const r = new ProviderRegistry(new KnownGoodSet([GOOD_CD]));
    r.upsert(confReg, noop, noopSend, noopPing, 1000);
    r.markCodeAttested(DID, MID);
    r.recordChallengeSip(DID, MID, true);
    expect(r.get(DID, MID)?.confidentialEligible).toBe(true);
    r.recordChallengeSip(DID, MID, false); // SIP toggled off
    expect(r.get(DID, MID)?.confidentialEligible).toBe(false);
    expect(r.listConfidential()).toEqual([]);
  });

  it("an unknown cdHash is never eligible even with a confidential tier claim", () => {
    const r = new ProviderRegistry(new KnownGoodSet(["a-different-known-hash"]));
    r.upsert(confReg, noop, noopSend, noopPing, 1000);
    r.recordChallengeSip(DID, MID, true);
    expect(r.get(DID, MID)?.confidentialEligible).toBe(false);
  });

  it("a best-effort tier is never confidential-eligible", () => {
    const r = new ProviderRegistry(new KnownGoodSet([GOOD_CD]));
    r.upsert({ ...confReg, tier: "best-effort" }, noop, noopSend, noopPing, 1000);
    r.recordChallengeSip(DID, MID, true);
    expect(r.get(DID, MID)?.confidentialEligible).toBe(false);
  });

  it("setKnownGood re-evaluates connected machines", () => {
    const r = new ProviderRegistry(); // empty
    r.upsert(confReg, noop, noopSend, noopPing, 1000);
    r.markCodeAttested(DID, MID);
    r.recordChallengeSip(DID, MID, true);
    expect(r.get(DID, MID)?.confidentialEligible).toBe(false);
    r.setKnownGood(new KnownGoodSet([GOOD_CD]));
    expect(r.get(DID, MID)?.confidentialEligible).toBe(true);
  });

  it("exposes cdHashKnownGood as a standalone leg so callers can name the blocker", () => {
    // Unknown build: the cdHash leg is the one that's false, even after the
    // other legs are earned. This is what lets the status API tell the operator
    // "update to the latest secure build" instead of a bare "not eligible".
    const r = new ProviderRegistry(new KnownGoodSet(["a-different-known-hash"]));
    r.upsert(confReg, noop, noopSend, noopPing, 1000);
    r.markCodeAttested(DID, MID);
    r.recordChallengeSip(DID, MID, true);
    const e = r.get(DID, MID);
    expect(e?.confidentialEligible).toBe(false);
    expect(e?.cdHashKnownGood).toBe(false);
    // Bless the build → the leg (and overall eligibility) flips, in lockstep.
    r.setKnownGood(new KnownGoodSet([GOOD_CD]));
    const e2 = r.get(DID, MID);
    expect(e2?.cdHashKnownGood).toBe(true);
    expect(e2?.confidentialEligible).toBe(true);
  });

  // C1 soft cutover (ADR-0003): a registration that couldn't prove control of
  // its DID is dropped from confidential routing even with every measured leg.
  it("a registration marked un-DID-authenticated is never confidential-eligible", () => {
    const r = new ProviderRegistry(new KnownGoodSet([GOOD_CD]));
    r.upsert(confReg, noop, noopSend, noopPing, 1000);
    r.markCodeAttested(DID, MID);
    r.recordChallengeSip(DID, MID, true);
    // Defaults to authenticated (no signal) → eligible.
    expect(r.get(DID, MID)?.registrationAuthenticated).toBe(true);
    expect(r.get(DID, MID)?.confidentialEligible).toBe(true);
    // Marking it unauthenticated drops eligibility in lockstep…
    expect(r.setRegistrationAuthenticated(DID, MID, false)).toBe(true);
    expect(r.get(DID, MID)?.confidentialEligible).toBe(false);
    expect(r.listConfidential()).toEqual([]);
    // …and restoring it (e.g. a re-register that carried a valid JWT) re-grants.
    r.setRegistrationAuthenticated(DID, MID, true);
    expect(r.get(DID, MID)?.confidentialEligible).toBe(true);
  });

  it("a fresh register defaults registrationAuthenticated true (no signal)", () => {
    const r = new ProviderRegistry(new KnownGoodSet([GOOD_CD]));
    r.upsert(confReg, noop, noopSend, noopPing, 1000);
    expect(r.get(DID, MID)?.registrationAuthenticated).toBe(true);
  });
});

describe("ProviderRegistry", () => {
  it("upsert + touch + remove + list", () => {
    const r = new ProviderRegistry();
    expect(r.size()).toBe(0);
    r.upsert(baseReg, noop, noopSend, noopPing, 1000);
    expect(r.size()).toBe(1);
    expect(r.list()[0]?.machineLabel).toBe("mac-mini");
    expect(r.list()[0]?.machineId).toBe("m1");
    expect(r.touch(DID, MID, 2000)).toBe(true);
    expect(r.get(DID, MID)?.lastSeen).toBe(2000);
    expect(r.touch("did:plc:nope", "mX")).toBe(false);
    r.remove(DID, MID);
    expect(r.size()).toBe(0);
  });

  it("refuses NEW registrations over the size cap but allows a re-register (M1)", () => {
    const r = new ProviderRegistry(new KnownGoodSet(), 2);
    expect(
      r.upsert({ ...baseReg, provider_did: "did:plc:a" }, noop, noopSend, noopPing, 1000),
    ).not.toBe(false);
    expect(
      r.upsert({ ...baseReg, provider_did: "did:plc:b" }, noop, noopSend, noopPing, 1000),
    ).not.toBe(false);
    // At capacity → a NEW machine is refused.
    expect(
      r.upsert({ ...baseReg, provider_did: "did:plc:c" }, noop, noopSend, noopPing, 1000),
    ).toBe(false);
    expect(r.size()).toBe(2);
    // A re-register of an ALREADY-present machine is fine (it replaces).
    expect(
      r.upsert({ ...baseReg, provider_did: "did:plc:a" }, noop, noopSend, noopPing, 2000),
    ).not.toBe(false);
    expect(r.size()).toBe(2);
  });

  it("machineIdOf prefers machine_id, falls back to the attestation pubkey", () => {
    expect(ProviderRegistry.machineIdOf(baseReg)).toBe("m1");
    const { machine_id: _omit, ...noMachineId } = baseReg;
    expect(ProviderRegistry.machineIdOf(noMachineId)).toBe("p256-pub");
    expect(ProviderRegistry.machineIdOf({ ...baseReg, machine_id: "  " })).toBe("p256-pub");
  });

  it("carries engineFault from the Register, defaulting to null when absent", () => {
    const r = new ProviderRegistry();
    // Healthy register → no fault.
    r.upsert(baseReg, noop, noopSend, noopPing, 1000);
    expect(r.get(DID, MID)?.engineFault).toBeNull();
    // Degraded register → fault surfaced on the entry (and exposed via list()).
    const fault = {
      code: "model-load-failed",
      message: "engine for [qwen] did not come online after 3 attempts",
      models: ["qwen"],
      at: "2026-06-11T22:00:00.000Z",
    };
    r.upsert({ ...baseReg, engine_fault: fault }, noop, noopSend, noopPing, 2000);
    expect(r.get(DID, MID)?.engineFault).toEqual(fault);
    // A subsequent healthy re-register clears it.
    r.upsert(baseReg, noop, noopSend, noopPing, 3000);
    expect(r.get(DID, MID)?.engineFault).toBeNull();
  });

  it("re-registering the SAME (did, machine) closes the previous socket and replaces it", () => {
    const r = new ProviderRegistry();
    const close1 = vi.fn();
    const close2 = vi.fn();
    r.upsert(baseReg, close1, noopSend, noopPing, 1000);
    r.upsert({ ...baseReg, machine_label: "mac-mini-v2" }, close2, noopSend, noopPing, 2000);
    expect(close1).toHaveBeenCalledOnce();
    expect(r.size()).toBe(1);
    expect(r.get(DID, MID)?.machineLabel).toBe("mac-mini-v2");
    expect(close2).not.toHaveBeenCalled();
  });

  describe("multiple machines under one DID", () => {
    const laptop = { ...baseReg, machine_id: "laptop", machine_label: "air" };
    const desktop = { ...baseReg, machine_id: "desktop", machine_label: "studio" };

    it("two machines under the same DID coexist instead of evicting each other", () => {
      const r = new ProviderRegistry();
      const closeLaptop = vi.fn();
      const closeDesktop = vi.fn();
      r.upsert(laptop, closeLaptop, noopSend, noopPing, 1000);
      r.upsert(desktop, closeDesktop, noopSend, noopPing, 2000);
      // Neither socket was closed — they share an identity but are distinct.
      expect(closeLaptop).not.toHaveBeenCalled();
      expect(closeDesktop).not.toHaveBeenCalled();
      expect(r.size()).toBe(2);
      expect(
        r
          .getMachines(DID)
          .map((m) => m.machineId)
          .sort(),
      ).toEqual(["desktop", "laptop"]);
    });

    it("a re-register from one machine leaves its sibling untouched", () => {
      const r = new ProviderRegistry();
      const closeLaptop1 = vi.fn();
      const closeDesktop = vi.fn();
      const closeLaptop2 = vi.fn();
      r.upsert(laptop, closeLaptop1, noopSend, noopPing, 1000);
      r.upsert(desktop, closeDesktop, noopSend, noopPing, 2000);
      // The laptop reconnects.
      r.upsert(laptop, closeLaptop2, noopSend, noopPing, 3000);
      expect(closeLaptop1).toHaveBeenCalledOnce(); // its own prior socket closed
      expect(closeDesktop).not.toHaveBeenCalled(); // sibling untouched
      expect(r.size()).toBe(2);
    });

    it("routes around an unhealthy machine to a healthy sibling under the same DID", () => {
      const r = new ProviderRegistry();
      r.upsert(laptop, noop, noopSend, noopPing, 9000); // freshest
      r.upsert(desktop, noop, noopSend, noopPing, 1000);
      r.markAttested(DID, "laptop", 9000);
      r.markAttested(DID, "desktop", 1000);
      // The (freshest) laptop goes sour.
      r.markUnhealthy(DID, "laptop", "preflight-no-response", 9500);
      // Routing skips it entirely and lands on the healthy desktop.
      const order = r.pickCandidates(undefined).map((e) => e.machineId);
      expect(order).toEqual(["desktop"]);
      expect(r.pickFor(undefined)?.machineId).toBe("desktop");
    });

    it("getMachines is DID-scoped; listUnhealthy spans the whole registry", () => {
      const r = new ProviderRegistry();
      r.upsert(laptop, noop, noopSend, noopPing, 1000);
      r.upsert(desktop, noop, noopSend, noopPing, 1000);
      r.upsert(
        { ...baseReg, provider_did: "did:plc:other", machine_id: "m1" },
        noop,
        noopSend,
        noopPing,
        1000,
      );
      expect(r.getMachines(DID)).toHaveLength(2);
      expect(r.getMachines("did:plc:other")).toHaveLength(1);
      r.markUnhealthy(DID, "laptop", "preflight-no-response");
      r.markUnhealthy("did:plc:other", "m1", "job-idle-timeout");
      expect(
        r
          .listUnhealthy()
          .map((m) => `${m.did} ${m.machineId}`)
          .sort(),
      ).toEqual(["did:plc:other m1", "did:plc:test1 laptop"]);
    });
  });

  it("sweep evicts machines whose lastSeen is older than the timeout", () => {
    const r = new ProviderRegistry();
    const closeStale = vi.fn();
    const closeFresh = vi.fn();
    r.upsert({ ...baseReg, provider_did: "did:plc:stale" }, closeStale, noopSend, noopPing, 0);
    r.upsert(
      { ...baseReg, provider_did: "did:plc:fresh" },
      closeFresh,
      noopSend,
      noopPing,
      100_000,
    );
    const evicted = r.sweep(60_000, 100_000);
    expect(evicted).toEqual([{ did: "did:plc:stale", machineId: "m1" }]);
    expect(closeStale).toHaveBeenCalledOnce();
    expect(closeFresh).not.toHaveBeenCalled();
    expect(r.size()).toBe(1);
  });

  it("markAttested flips attestedAt; survives subsequent touches", () => {
    const r = new ProviderRegistry();
    r.upsert(baseReg, noop, noopSend, noopPing, 1000);
    expect(r.get(DID, MID)?.attestedAt).toBeNull();
    r.markAttested(DID, MID, 1500);
    expect(r.get(DID, MID)?.attestedAt).toBe(1500);
    r.touch(DID, MID, 1700);
    expect(r.get(DID, MID)?.attestedAt).toBe(1500);
    expect(r.get(DID, MID)?.lastSeen).toBe(1700);
  });

  describe("pickFor", () => {
    it("returns null when no machines are connected", () => {
      const r = new ProviderRegistry();
      expect(r.pickFor("anything")).toBeNull();
    });

    it("requires attestation by default", () => {
      const r = new ProviderRegistry();
      r.upsert(baseReg, noop, noopSend, noopPing, 1000);
      // Not attested yet.
      expect(r.pickFor(undefined)).toBeNull();
      r.markAttested(DID, MID, 1100);
      expect(r.pickFor(undefined)?.did).toBe(DID);
    });

    it("filters by model when supportedModels is non-empty", () => {
      const r = new ProviderRegistry();
      r.upsert({ ...baseReg, provider_did: "did:plc:llama" }, noop, noopSend, noopPing, 1000);
      r.upsert(
        {
          ...baseReg,
          provider_did: "did:plc:gpt",
          supported_models: ["gpt-x"],
        },
        noop,
        noopSend,
        noopPing,
        2000,
      );
      r.markAttested("did:plc:llama", MID, 1100);
      r.markAttested("did:plc:gpt", MID, 2100);
      expect(r.pickFor("llama-3.2")?.did).toBe("did:plc:llama");
      expect(r.pickFor("gpt-x")?.did).toBe("did:plc:gpt");
      expect(r.pickFor("nonexistent-model")).toBeNull();
    });

    it("enforces minProviderVersion fail-closed (excludes below-floor + unknown-version)", () => {
      const r = new ProviderRegistry();
      // new: reports a version at/above the floor.
      r.upsert(
        { ...baseReg, provider_did: "did:plc:new", binary_version: "0.9.32" },
        noop,
        noopSend,
        noopPing,
        1000,
      );
      // old: reports a version below the floor.
      r.upsert(
        { ...baseReg, provider_did: "did:plc:old", binary_version: "0.9.31" },
        noop,
        noopSend,
        noopPing,
        1000,
      );
      // legacy: reports no version at all.
      r.upsert({ ...baseReg, provider_did: "did:plc:legacy" }, noop, noopSend, noopPing, 1000);
      r.markAttested("did:plc:new", MID, 1100);
      r.markAttested("did:plc:old", MID, 1100);
      r.markAttested("did:plc:legacy", MID, 1100);

      // No floor → all three are eligible.
      expect(r.pickCandidates("llama-3.2").length).toBe(3);

      // Floor 0.9.32 → only the new machine; old + legacy (unknown) excluded.
      const gated = r.pickCandidates("llama-3.2", true, Number.POSITIVE_INFINITY, 2000, "0.9.32");
      expect(gated.map((e) => e.did)).toEqual(["did:plc:new"]);

      // A floor nobody meets → empty (never falls open).
      expect(r.pickCandidates("llama-3.2", true, Number.POSITIVE_INFINITY, 2000, "1.0.0")).toEqual(
        [],
      );
    });

    it("does NOT treat empty supportedModels as a wildcard for a requested model (M2)", () => {
      // An attacker advertising `[]` used to be selected for any open-pool job
      // (empty == "matches everything"). Empty now matches NO requested model,
      // so it must explicitly advertise a model to be routed it.
      const r = new ProviderRegistry();
      r.upsert({ ...baseReg, supported_models: [] }, noop, noopSend, noopPing, 1000);
      r.markAttested(DID, MID, 1100);
      expect(r.pickFor("anything")).toBeNull();
      // With no model requested, any attested machine is still eligible.
      expect(r.pickFor(undefined)?.did).toBe(DID);
    });

    it("breaks ties by lastSeen (freshest wins)", () => {
      const r = new ProviderRegistry();
      r.upsert({ ...baseReg, provider_did: "did:plc:older" }, noop, noopSend, noopPing, 1000);
      r.upsert({ ...baseReg, provider_did: "did:plc:newer" }, noop, noopSend, noopPing, 5000);
      r.markAttested("did:plc:older", MID, 1500);
      r.markAttested("did:plc:newer", MID, 5500);
      expect(r.pickFor(undefined)?.did).toBe("did:plc:newer");
    });

    it("rejects machines whose last attestation is older than attestationMaxAgeMs", () => {
      const r = new ProviderRegistry();
      const NOW = 1_000_000;
      const MAX_AGE = 5 * 60_000;
      r.upsert({ ...baseReg, provider_did: "did:plc:stale" }, noop, noopSend, noopPing, 1000);
      r.upsert({ ...baseReg, provider_did: "did:plc:fresh" }, noop, noopSend, noopPing, 1000);
      r.markAttested("did:plc:stale", MID, 0);
      r.markAttested("did:plc:fresh", MID, NOW - 30_000);
      expect(r.pickFor(undefined, /*attestedOnly=*/ true, /*maxAgeMs=*/ MAX_AGE, NOW)?.did).toBe(
        "did:plc:fresh",
      );
    });

    it("treats POSITIVE_INFINITY (the default) as no staleness check", () => {
      const r = new ProviderRegistry();
      r.upsert(baseReg, noop, noopSend, noopPing, 1000);
      r.markAttested(DID, MID, 0);
      expect(r.pickFor(undefined)?.did).toBe(DID);
    });
  });

  describe("clearAttested", () => {
    it("nulls attestedAt for a known machine; no-op for unknown", () => {
      const r = new ProviderRegistry();
      r.upsert(baseReg, noop, noopSend, noopPing, 1000);
      r.markAttested(DID, MID, 1500);
      expect(r.get(DID, MID)?.attestedAt).toBe(1500);
      expect(r.clearAttested(DID, MID)).toBe(true);
      expect(r.get(DID, MID)?.attestedAt).toBeNull();
      expect(r.clearAttested("did:plc:nope", "mX")).toBe(false);
    });

    it("makes pickFor reject the machine until re-attestation", () => {
      const r = new ProviderRegistry();
      r.upsert(baseReg, noop, noopSend, noopPing, 1000);
      r.markAttested(DID, MID, 1500);
      expect(r.pickFor(undefined)?.did).toBe(DID);
      r.clearAttested(DID, MID);
      expect(r.pickFor(undefined)).toBeNull();
      r.markAttested(DID, MID, 2000);
      expect(r.pickFor(undefined)?.did).toBe(DID);
    });
  });

  describe("pickCandidates + health (exclude-and-restore)", () => {
    it("EXCLUDES an unhealthy machine from candidates", () => {
      const r = new ProviderRegistry();
      r.upsert({ ...baseReg, provider_did: "did:plc:unhealthy" }, noop, noopSend, noopPing, 9000);
      r.upsert({ ...baseReg, provider_did: "did:plc:healthy" }, noop, noopSend, noopPing, 1000);
      r.markAttested("did:plc:unhealthy", MID, 9000);
      r.markAttested("did:plc:healthy", MID, 1000);
      r.markUnhealthy("did:plc:unhealthy", MID, "preflight-no-response", 9500);

      const order = r.pickCandidates(undefined).map((e) => e.did);
      // The unhealthy machine is gone from the list entirely, not just last.
      expect(order).toEqual(["did:plc:healthy"]);
      expect(r.pickFor(undefined)?.did).toBe("did:plc:healthy");
    });

    it("excludes an unhealthy machine even when it's the only one", () => {
      const r = new ProviderRegistry();
      r.upsert(baseReg, noop, noopSend, noopPing, 1000);
      r.markAttested(DID, MID, 1000);
      r.markUnhealthy(DID, MID, "preflight-no-response");
      expect(r.pickFor(undefined)).toBeNull();
      expect(r.pickCandidates(undefined)).toEqual([]);
    });

    it("markUnhealthy records the reason; markHealthy clears standing + reason", () => {
      const r = new ProviderRegistry();
      r.upsert(baseReg, noop, noopSend, noopPing, 1000);
      r.markAttested(DID, MID, 1000);
      r.markUnhealthy(DID, MID, "job-idle-timeout");
      expect(r.get(DID, MID)?.unhealthyAt).not.toBeNull();
      expect(r.get(DID, MID)?.unhealthyReason).toBe("job-idle-timeout");
      r.markHealthy(DID, MID);
      expect(r.get(DID, MID)?.unhealthyAt).toBeNull();
      expect(r.get(DID, MID)?.unhealthyReason).toBeNull();
    });

    it("a completion restores a machine that was flagged unhealthy", () => {
      const r = new ProviderRegistry();
      r.upsert(baseReg, noop, noopSend, noopPing, 1000);
      r.markAttested(DID, MID, 1000);
      r.markUnhealthy(DID, MID, "job-idle-timeout");
      expect(r.pickFor(undefined)).toBeNull();
      r.recordCompletion(DID, MID);
      expect(r.get(DID, MID)?.unhealthyAt).toBeNull();
      expect(r.pickFor(undefined)?.did).toBe(DID);
    });

    it("a fresh re-register resets standing to healthy", () => {
      const r = new ProviderRegistry();
      r.upsert(baseReg, noop, noopSend, noopPing, 1000);
      r.markUnhealthy(DID, MID, "preflight-no-response");
      r.upsert(baseReg, noop, noopSend, noopPing, 2000);
      expect(r.get(DID, MID)?.unhealthyAt).toBeNull();
      expect(r.get(DID, MID)?.unhealthyReason).toBeNull();
    });
  });

  describe("crash signatures", () => {
    it("stores a crash signature from a heartbeat and surfaces it on the entry", () => {
      const r = new ProviderRegistry();
      r.upsert(baseReg, noop, noopSend, noopPing, 1000);
      expect(r.get(DID, MID)?.crash).toBeNull();
      const crash = {
        count: 2,
        last_at: "2026-06-14T22:00:00.000Z",
        location: "engine/worker.rs:142",
        signature: "deadbeef",
        version: "0.1.0",
      };
      expect(r.setCrash(DID, MID, crash)).toBe(true);
      expect(r.get(DID, MID)?.crash).toEqual(crash);
      // An undefined crash (heartbeat without `crash`) is "no new info".
      r.setCrash(DID, MID, undefined);
      expect(r.get(DID, MID)?.crash).toEqual(crash);
      expect(r.setCrash("did:plc:nope", "mX", crash)).toBe(false);
    });

    it("a fresh re-register clears crash history", () => {
      const r = new ProviderRegistry();
      r.upsert(baseReg, noop, noopSend, noopPing, 1000);
      r.setCrash(DID, MID, { count: 5 });
      expect(r.get(DID, MID)?.crash).not.toBeNull();
      r.upsert(baseReg, noop, noopSend, noopPing, 2000);
      expect(r.get(DID, MID)?.crash).toBeNull();
    });

    it("EXCLUDES a crash-looping machine, routing to a healthy alternative", () => {
      const r = new ProviderRegistry();
      r.upsert({ ...baseReg, provider_did: "did:plc:looping" }, noop, noopSend, noopPing, 9000);
      r.upsert({ ...baseReg, provider_did: "did:plc:healthy" }, noop, noopSend, noopPing, 1000);
      r.markAttested("did:plc:looping", MID, 9000);
      r.markAttested("did:plc:healthy", MID, 1000);
      r.setCrash("did:plc:looping", MID, { count: CRASH_LOOP_THRESHOLD });

      const order = r.pickCandidates(undefined).map((e) => e.did);
      expect(order).toEqual(["did:plc:healthy"]);
      expect(r.pickFor(undefined)?.did).toBe("did:plc:healthy");
    });

    it("excludes a crash-looping machine even when it's the only candidate", () => {
      const r = new ProviderRegistry();
      r.upsert(baseReg, noop, noopSend, noopPing, 1000);
      r.markAttested(DID, MID, 1000);
      r.setCrash(DID, MID, { count: CRASH_LOOP_THRESHOLD + 1 });
      // A machine panicking on job after job is steered around entirely.
      expect(r.pickFor(undefined)).toBeNull();
    });

    it("a crash count below the threshold does not exclude the machine", () => {
      const r = new ProviderRegistry();
      r.upsert({ ...baseReg, provider_did: "did:plc:recovered" }, noop, noopSend, noopPing, 9000);
      r.upsert({ ...baseReg, provider_did: "did:plc:other" }, noop, noopSend, noopPing, 1000);
      r.markAttested("did:plc:recovered", MID, 9000);
      r.markAttested("did:plc:other", MID, 1000);
      r.setCrash("did:plc:recovered", MID, { count: CRASH_LOOP_THRESHOLD - 1 });
      expect(r.pickFor(undefined)?.did).toBe("did:plc:recovered");
    });
  });

  describe("silent-failure detection", () => {
    it("flips silentFailure after N dispatches with 0 completions", () => {
      const r = new ProviderRegistry();
      r.upsert(baseReg, noop, noopSend, noopPing, 1000);
      expect(r.get(DID, MID)?.silentFailure).toBe(false);
      for (let i = 0; i < SILENT_FAILURE_DISPATCH_THRESHOLD - 1; i += 1) {
        expect(r.recordDispatch(DID, MID)).toBe(false);
        expect(r.get(DID, MID)?.silentFailure).toBe(false);
      }
      expect(r.recordDispatch(DID, MID)).toBe(true);
      expect(r.get(DID, MID)?.silentFailure).toBe(true);
      expect(r.recordDispatch(DID, MID)).toBe(false);
      expect(r.get(DID, MID)?.silentFailure).toBe(true);
    });

    it("does not flip when completions keep pace with dispatches", () => {
      const r = new ProviderRegistry();
      r.upsert(baseReg, noop, noopSend, noopPing, 1000);
      for (let i = 0; i < SILENT_FAILURE_DISPATCH_THRESHOLD + 2; i += 1) {
        r.recordDispatch(DID, MID);
        r.recordCompletion(DID, MID);
      }
      expect(r.get(DID, MID)?.silentFailure).toBe(false);
    });

    it("a completion clears a prior silent-failure flag", () => {
      const r = new ProviderRegistry();
      r.upsert(baseReg, noop, noopSend, noopPing, 1000);
      for (let i = 0; i < SILENT_FAILURE_DISPATCH_THRESHOLD; i += 1) {
        r.recordDispatch(DID, MID);
      }
      expect(r.get(DID, MID)?.silentFailure).toBe(true);
      r.recordCompletion(DID, MID);
      expect(r.get(DID, MID)?.silentFailure).toBe(false);
    });

    it("a fresh re-register resets the dispatch/completion counters and flag", () => {
      const r = new ProviderRegistry();
      r.upsert(baseReg, noop, noopSend, noopPing, 1000);
      for (let i = 0; i < SILENT_FAILURE_DISPATCH_THRESHOLD; i += 1) {
        r.recordDispatch(DID, MID);
      }
      expect(r.get(DID, MID)?.silentFailure).toBe(true);
      r.upsert(baseReg, noop, noopSend, noopPing, 2000);
      const e = r.get(DID, MID);
      expect(e?.silentFailure).toBe(false);
      expect(e?.dispatched).toBe(0);
      expect(e?.completed).toBe(0);
    });

    it("recordDispatch / recordCompletion are no-ops for an unknown machine", () => {
      const r = new ProviderRegistry();
      expect(r.recordDispatch("did:plc:nope", "mX")).toBe(false);
      expect(r.recordCompletion("did:plc:nope", "mX")).toBe(false);
    });
  });

  describe("setActive (owner start/stop)", () => {
    it("excludes a stopped machine from routing; restores it on start", () => {
      const r = new ProviderRegistry();
      r.upsert(baseReg, noop, noopSend, noopPing, 1000);
      r.markAttested(DID, MID, 1000);
      expect(r.pickFor(undefined)?.did).toBe(DID);
      r.setActive(DID, MID, false);
      expect(r.pickFor(undefined)).toBeNull();
      expect(r.pickCandidates(undefined)).toEqual([]);
      r.setActive(DID, MID, true);
      expect(r.pickFor(undefined)?.did).toBe(DID);
    });

    it("defaults to active:true until a heartbeat says otherwise", () => {
      const r = new ProviderRegistry();
      r.upsert(baseReg, noop, noopSend, noopPing, 1000);
      expect(r.get(DID, MID)?.active).toBe(true);
    });
  });

  describe("pickCandidates tool-call filter (requireToolCalls)", () => {
    // Three machines all serving the same model: one with the model in its
    // canary-passed set, one that opted out (empty set semantics via a set
    // that lists a DIFFERENT model), and a legacy machine reporting only the
    // coarse boolean.
    const setup = () => {
      const r = new ProviderRegistry();
      r.upsert(
        {
          ...baseReg,
          provider_did: "did:plc:verified",
          tool_call_models: ["llama-3.2"],
          supports_tool_calls: true,
        },
        noop,
        noopSend,
        noopPing,
        1000,
      );
      r.upsert(
        {
          ...baseReg,
          provider_did: "did:plc:other-model",
          supported_models: ["llama-3.2", "qwen-x"],
          tool_call_models: ["qwen-x"],
          supports_tool_calls: true,
        },
        noop,
        noopSend,
        noopPing,
        1000,
      );
      r.upsert(
        { ...baseReg, provider_did: "did:plc:legacy-bool", supports_tool_calls: true },
        noop,
        noopSend,
        noopPing,
        1000,
      );
      r.upsert({ ...baseReg, provider_did: "did:plc:no-tools" }, noop, noopSend, noopPing, 1000);
      for (const did of [
        "did:plc:verified",
        "did:plc:other-model",
        "did:plc:legacy-bool",
        "did:plc:no-tools",
      ]) {
        r.markAttested(did, MID, 1100);
      }
      return r;
    };

    it("without the flag, tool capability is ignored (back-compat)", () => {
      const r = setup();
      expect(r.pickCandidates("llama-3.2").length).toBe(4);
    });

    it("with the flag, only machines canary-verified FOR THIS MODEL survive (plus legacy boolean)", () => {
      const r = setup();
      const picked = r
        .pickCandidates("llama-3.2", true, Number.POSITIVE_INFINITY, 2000, null, true)
        .map((e) => e.did)
        .sort();
      // `verified` lists the model; `legacy-bool` predates per-model
      // reporting so its coarse boolean is honored; `other-model` verified a
      // different model and `no-tools` never opted in — both excluded.
      expect(picked).toEqual(["did:plc:legacy-bool", "did:plc:verified"]);
    });

    it("returns empty when no connected machine can serve tools for the model", () => {
      const r = setup();
      // qwen-x is served tool-capably only by `other-model`… but ask for a
      // model nobody verified.
      r.setActive("did:plc:legacy-bool", MID, false);
      r.setActive("did:plc:verified", MID, false);
      expect(
        r.pickCandidates("llama-3.2", true, Number.POSITIVE_INFINITY, 2000, null, true),
      ).toEqual([]);
    });
  });
});
