import { describe, expect, it } from "vitest";

import { ownMachineCandidates } from "./provider-selection.ts";

describe("ownMachineCandidates", () => {
  const ME = "did:plc:alice";
  const mineOld = { did: ME, supportedModels: ["m"], lastSeen: "2026-01-01T00:00:00Z" };
  const mineFresh = { did: ME, supportedModels: ["m"], lastSeen: "2026-01-02T00:00:00Z" };
  const mineOtherModel = { did: ME, supportedModels: ["other"], lastSeen: "2026-01-03T00:00:00Z" };
  const foreign = { did: "did:plc:bob", supportedModels: ["m"], lastSeen: "2026-01-09T00:00:00Z" };

  it("returns only the requester's own machines serving the model, freshest first", () => {
    expect(ownMachineCandidates([mineOld, foreign, mineFresh], ME, "m", new Set())).toEqual([
      mineFresh,
      mineOld,
    ]);
  });

  it("is empty when the requester owns no machine serving this model", () => {
    expect(ownMachineCandidates([foreign], ME, "m", new Set())).toEqual([]);
    // Owns a machine, but it serves a different model.
    expect(ownMachineCandidates([mineOtherModel], ME, "m", new Set())).toEqual([]);
  });

  it("treats a machine advertising no models as serving everything", () => {
    const wildcard = { did: ME, supportedModels: [], lastSeen: "2026-01-05T00:00:00Z" };
    expect(ownMachineCandidates([wildcard], ME, "m", new Set())).toEqual([wildcard]);
  });

  it("excludes own DIDs already burned by a prior failover attempt", () => {
    expect(ownMachineCandidates([mineFresh, foreign], ME, "m", new Set([ME]))).toEqual([]);
  });
});
