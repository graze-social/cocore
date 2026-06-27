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

  it("does NOT prefer an own machine that advertises no models (must match explicitly)", () => {
    // An empty supportedModels means the agent has no health-gated engine to
    // serve, so self-preference must NOT grab it — that would route the job to
    // a box that hits its for_model miss and completes without a receipt
    // (the job then sits pending → expired; graze-social/cocore#103). Falling
    // through to [] lets the open pool find a provider that actually serves it.
    const empty = { did: ME, supportedModels: [], lastSeen: "2026-01-05T00:00:00Z" };
    expect(ownMachineCandidates([empty], ME, "m", new Set())).toEqual([]);
  });

  it("excludes own DIDs already burned by a prior failover attempt", () => {
    expect(ownMachineCandidates([mineFresh, foreign], ME, "m", new Set([ME]))).toEqual([]);
  });
});
