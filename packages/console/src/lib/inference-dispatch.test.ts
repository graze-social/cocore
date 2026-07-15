// Unit tests for the eligibility filter used in pickProvider.
// The fetch-bound paths (advisor /providers, AppView listProviders)
// are exercised by the e2e stack; this file only covers the pure
// filtering logic so we can iterate on it without standing up a
// pair of HTTP servers.

import assert from "node:assert/strict";
import { describe, test } from "vitest";

import {
  classifyDispatchError,
  filterByAllowedDids,
  filterByCountry,
  filterByMinVersion,
  filterByPayoutsEligibility,
  filterByToolCalls,
  machineSupportsToolCallsFor,
  meetsMinVersion,
  NoFriendsAvailableError,
  NoFriendsForModelError,
  NoProvidersConnectedError,
  NoProvidersForCountryError,
  NoProvidersForModelError,
  NoProvidersForToolCallsError,
  NoProvidersForVersionError,
  ProviderPayoutsNotEligibleError,
  TargetProviderNotConnectedError,
} from "./inference-dispatch.server.ts";

const A = { did: "did:plc:alice" };
const B = { did: "did:plc:bob" };
const C = { did: "did:plc:carol" };

test("payoutsEligibleDids=null disables filtering entirely", () => {
  const out = filterByPayoutsEligibility([A, B, C], {
    payoutsEligibleDids: null,
    selfLoopExempt: null,
  });
  assert.deepEqual(out, [A, B, C]);
});

test("filters out candidates not in the eligibility set", () => {
  const out = filterByPayoutsEligibility([A, B, C], {
    payoutsEligibleDids: new Set(["did:plc:bob"]),
    selfLoopExempt: null,
  });
  assert.deepEqual(out, [B]);
});

test("self-loop exempt DID is allowed even when not in the eligibility set", () => {
  const out = filterByPayoutsEligibility([A, B, C], {
    payoutsEligibleDids: new Set(["did:plc:bob"]),
    selfLoopExempt: "did:plc:alice",
  });
  // Alice is the requester running her own machine — exempt.
  // Bob is in the set — passes. Carol is not — filtered.
  assert.deepEqual(out, [A, B]);
});

test("self-loop exempt DID is allowed even with empty eligibility set", () => {
  const out = filterByPayoutsEligibility([A, B], {
    payoutsEligibleDids: new Set(),
    selfLoopExempt: "did:plc:alice",
  });
  assert.deepEqual(out, [A]);
});

test("empty eligibility set with no self-loop exemption filters everything", () => {
  const out = filterByPayoutsEligibility([A, B, C], {
    payoutsEligibleDids: new Set(),
    selfLoopExempt: null,
  });
  assert.deepEqual(out, []);
});

test("preserves the input order (advisor's freshest-first sort happens after this)", () => {
  const out = filterByPayoutsEligibility([C, A, B], {
    payoutsEligibleDids: new Set(["did:plc:alice", "did:plc:bob", "did:plc:carol"]),
    selfLoopExempt: null,
  });
  assert.deepEqual(out, [C, A, B]);
});

describe("filterByAllowedDids", () => {
  test("undefined means no constraint — passes everything through", () => {
    assert.deepEqual(filterByAllowedDids([A, B, C], undefined), [A, B, C]);
  });

  test("empty set filters everything (distinct from undefined)", () => {
    assert.deepEqual(filterByAllowedDids([A, B, C], new Set()), []);
  });

  test("retains only candidates in the set, preserving order", () => {
    const out = filterByAllowedDids([A, B, C], new Set(["did:plc:carol", "did:plc:alice"]));
    assert.deepEqual(out, [A, C]);
  });

  test("set member with no matching candidate is a no-op (not an error)", () => {
    const out = filterByAllowedDids([A, B], new Set(["did:plc:carol", "did:plc:alice"]));
    assert.deepEqual(out, [A]);
  });

  test("a `did:machineId` composite matches only that machine (pro-bono granularity)", () => {
    // Same owner DID, two machines — one pro bono, one not. A composite key
    // must match ONLY the pro-bono machine, never widen to the billed one.
    const m1 = { did: "did:plc:alice", machineId: "rkeyA" };
    const m2 = { did: "did:plc:alice", machineId: "rkeyB" };
    const out = filterByAllowedDids([m1, m2], new Set(["did:plc:alice:rkeyA"]));
    assert.deepEqual(out, [m1]);
  });

  test("a bare DID still matches every machine of that owner (friends path)", () => {
    // Friends routing is owner-granular by design: a friend vouches for the
    // person, not a specific box. The verified/confidential path must NOT use
    // bare DIDs (see the attestation-binding regression below).
    const m1 = { did: "did:plc:alice", machineId: "rkeyA" };
    const m2 = { did: "did:plc:alice", machineId: "rkeyB" };
    const out = filterByAllowedDids([m1, m2], new Set(["did:plc:alice"]));
    assert.deepEqual(out, [m1, m2]);
  });

  test("attestation binding: confidential standing never widens to an unattested sibling", () => {
    // The exploit: an attested Mac and an unattested Linux box register under
    // ONE DID. resolveVerifiedProviderKeys emits a composite key ONLY for the
    // machine that actually passes the tier check (the Mac). Dispatch must then
    // route confidential traffic to the Mac alone — the Linux box, which shares
    // the DID, must be filtered out. A DID-scoped set (the old behavior) would
    // have admitted BOTH, sending the confidential prompt to the unattested node.
    const mac = { did: "did:plc:astra", machineId: "mac-rkey" };
    const linux = { did: "did:plc:astra", machineId: "linux-rkey" };
    const verifiedKeys = new Set(["did:plc:astra:mac-rkey"]);
    assert.deepEqual(filterByAllowedDids([mac, linux], verifiedKeys), [mac]);
    // Regression guard: the old bare-DID form would have leaked to Linux too.
    assert.deepEqual(filterByAllowedDids([mac, linux], new Set(["did:plc:astra"])), [mac, linux]);
  });
});

describe("classifyDispatchError", () => {
  test("maps each structured error to its stable code", () => {
    assert.equal(classifyDispatchError(new NoProvidersConnectedError()), "no-providers-connected");
    assert.equal(
      classifyDispatchError(new NoProvidersForModelError("foo", 3)),
      "no-providers-for-model",
    );
    assert.equal(classifyDispatchError(new NoFriendsAvailableError(2)), "no-friends-available");
    assert.equal(
      classifyDispatchError(new NoFriendsForModelError("foo", 5, 2)),
      "no-friends-for-model",
    );
    assert.equal(
      classifyDispatchError(new TargetProviderNotConnectedError("did:plc:alice")),
      "target-provider-not-connected",
    );
    assert.equal(
      classifyDispatchError(new ProviderPayoutsNotEligibleError("did:plc:alice")),
      "provider-payouts-not-eligible",
    );
    assert.equal(
      classifyDispatchError(new NoProvidersForToolCallsError("gemma-3", "detail")),
      "no-providers-for-tool-calls",
    );
  });

  test("unknown errors fall through to advisor-transport", () => {
    assert.equal(classifyDispatchError(new Error("connection refused")), "advisor-transport");
    assert.equal(classifyDispatchError("plain string"), "advisor-transport");
    assert.equal(classifyDispatchError(null), "advisor-transport");
  });
});

describe("structured error messages carry operational context", () => {
  test("NoProvidersForModelError mentions the model and connected count", () => {
    const e = new NoProvidersForModelError("gemma-3", 7);
    assert.match(e.message, /gemma-3/);
    assert.match(e.message, /7 providers/);
  });

  test("NoFriendsAvailableError distinguishes empty-friend-list from offline-friends", () => {
    assert.match(new NoFriendsAvailableError(0).message, /no friends/);
    assert.match(new NoFriendsAvailableError(3).message, /3 friends/);
    // Word boundary — "1 friend " (singular), not "1 friends".
    assert.match(new NoFriendsAvailableError(1).message, /1 friend\b/);
    assert.doesNotMatch(new NoFriendsAvailableError(1).message, /1 friends/);
  });

  test("NoFriendsForModelError surfaces both friend counts", () => {
    const e = new NoFriendsForModelError("gemma-3", 5, 2);
    assert.match(e.message, /gemma-3/);
    assert.match(e.message, /2 connected friends/);
    assert.match(e.message, /5 friends total/);
  });

  test("NoProvidersForCountryError mentions the model, country, and model-fit count", () => {
    const e = new NoProvidersForCountryError("gemma-3", "US", 4);
    assert.match(e.message, /gemma-3/);
    assert.match(e.message, /US/);
    assert.match(e.message, /4 serve the model/);
    assert.equal(classifyDispatchError(e), "no-providers-for-country");
  });
});

describe("filterByCountry — country routing", () => {
  const US = { did: "did:plc:alice", region: "US" };
  const DE = { did: "did:plc:bob", region: "DE" };
  const noRegion: { did: string; region?: string } = { did: "did:plc:carol" };

  test("undefined country passes the list through verbatim", () => {
    assert.deepEqual(filterByCountry([US, DE, noRegion], undefined), [US, DE, noRegion]);
  });

  test("keeps only candidates whose region matches", () => {
    assert.deepEqual(filterByCountry([US, DE, noRegion], "US"), [US]);
    assert.deepEqual(filterByCountry([US, DE, noRegion], "DE"), [DE]);
  });

  test("a provider with no region is never matched by a country filter", () => {
    assert.deepEqual(filterByCountry([noRegion], "US"), []);
  });

  test("no provider in the requested country yields an empty list", () => {
    assert.deepEqual(filterByCountry([US, DE], "FR"), []);
  });
});

describe("filterByMinVersion — version-gated routing", () => {
  const NEW = { did: "did:plc:new", binaryVersion: "0.9.32" };
  const OLD = { did: "did:plc:old", binaryVersion: "0.9.31" };
  const LEGACY: { did: string; binaryVersion?: string } = { did: "did:plc:legacy" };

  test("undefined floor passes the list through verbatim", () => {
    assert.deepEqual(filterByMinVersion([NEW, OLD, LEGACY], undefined), [NEW, OLD, LEGACY]);
  });

  test("keeps only machines at or above the floor", () => {
    assert.deepEqual(filterByMinVersion([NEW, OLD, LEGACY], "0.9.32"), [NEW]);
  });

  test("fail-closed: a machine reporting no version never passes a floor", () => {
    assert.deepEqual(filterByMinVersion([LEGACY], "0.9.32"), []);
  });

  test("meetsMinVersion is fail-closed on a missing version", () => {
    assert.equal(meetsMinVersion(undefined, "0.9.32"), false);
    assert.equal(meetsMinVersion("0.9.32", "0.9.32"), true);
    assert.equal(meetsMinVersion("0.9.31", "0.9.32"), false);
  });

  test("classifyDispatchError maps the version error to a stable code", () => {
    assert.equal(
      classifyDispatchError(new NoProvidersForVersionError("0.9.32", "none at version")),
      "no-providers-for-version",
    );
  });
});

describe("filterByToolCalls — tool-calling routing", () => {
  const MODEL = "mlx-community/Qwen3.5-4B-MLX-4bit";
  const OTHER = "mlx-community/Qwen3.5-9B-MLX-4bit";
  // Passed the per-model forced-tool canary for MODEL.
  const CANARY = { did: "did:plc:canary", toolCallModels: [MODEL] };
  // Serves MODEL but reports an empty canary set (didn't pass for any model) —
  // this is the common fleet shape that used to get pinned and then 503'd.
  const NOCANARY = { did: "did:plc:nocanary", toolCallModels: [] as string[] };
  // Passed the canary, but for a DIFFERENT model than the one requested.
  const CANARY_OTHER = { did: "did:plc:other", toolCallModels: [OTHER] };
  // Legacy machine that predates toolCallModels — falls back to the boolean.
  const LEGACY_ON: { did: string; toolCallModels?: string[]; supportsToolCalls?: boolean } = {
    did: "did:plc:legacy-on",
    supportsToolCalls: true,
  };
  const LEGACY_OFF: { did: string; toolCallModels?: string[]; supportsToolCalls?: boolean } = {
    did: "did:plc:legacy-off",
  };

  test("wantsToolCalls=false passes the list through verbatim", () => {
    assert.deepEqual(filterByToolCalls([CANARY, NOCANARY, LEGACY_OFF], MODEL, false), [
      CANARY,
      NOCANARY,
      LEGACY_OFF,
    ]);
  });

  test("keeps only machines that passed the canary for the requested model", () => {
    assert.deepEqual(
      filterByToolCalls([CANARY, NOCANARY, CANARY_OTHER], MODEL, true),
      [CANARY],
    );
  });

  test("a machine whose canary set omits the model is excluded (the 503 bug)", () => {
    // NOCANARY serves MODEL but never passed the forced-tool canary; pinning it
    // is exactly what produced the advisor's "no machine with verified
    // tool-calling" 503. It must not survive the filter.
    assert.deepEqual(filterByToolCalls([NOCANARY], MODEL, true), []);
  });

  test("legacy machines fall back to the supportsToolCalls boolean", () => {
    assert.deepEqual(filterByToolCalls([LEGACY_ON, LEGACY_OFF], MODEL, true), [LEGACY_ON]);
  });

  test("machineSupportsToolCallsFor mirrors the advisor's per-model semantics", () => {
    assert.equal(machineSupportsToolCallsFor(CANARY, MODEL), true);
    assert.equal(machineSupportsToolCallsFor(CANARY, OTHER), false);
    assert.equal(machineSupportsToolCallsFor(NOCANARY, MODEL), false);
    assert.equal(machineSupportsToolCallsFor(LEGACY_ON, MODEL), true);
    assert.equal(machineSupportsToolCallsFor(LEGACY_OFF, MODEL), false);
  });

  test("NoProvidersForToolCallsError carries model + code", () => {
    const e = new NoProvidersForToolCallsError(MODEL, "3 serve the model but none passed the canary");
    assert.match(e.message, /Qwen3\.5-4B/);
    assert.match(e.message, /verified tool-calling/);
    assert.equal(classifyDispatchError(e), "no-providers-for-tool-calls");
  });
});
