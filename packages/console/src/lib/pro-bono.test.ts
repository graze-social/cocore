// Unit tests for the pure pro-bono policy predicate. The AppView-bound
// `resolveProBonoProviderDids` is exercised by the e2e stack; this file
// only covers `proBonoApplies` so we can iterate without a live AppView.

import assert from "node:assert/strict";
import { test } from "vitest";

import { proBonoApplies } from "./pro-bono.server.ts";

const ALICE = "did:plc:alice";
const BOB = "did:plc:bob";

test("absent / undefined policy is never pro bono (fail closed to paid)", () => {
  assert.equal(proBonoApplies(undefined, ALICE), false);
  assert.equal(proBonoApplies({}, ALICE), false);
});

test("mode 'any' serves every requester", () => {
  assert.equal(proBonoApplies({ mode: "any" }, ALICE), true);
  assert.equal(proBonoApplies({ mode: "any", dids: [] }, BOB), true);
});

test("mode 'direct' serves only listed DIDs", () => {
  const policy = { mode: "direct", dids: [ALICE] };
  assert.equal(proBonoApplies(policy, ALICE), true);
  assert.equal(proBonoApplies(policy, BOB), false);
});

test("mode 'direct' with no/empty list serves no one", () => {
  assert.equal(proBonoApplies({ mode: "direct" }, ALICE), false);
  assert.equal(proBonoApplies({ mode: "direct", dids: [] }, ALICE), false);
});

test("an unknown mode fails closed (paid)", () => {
  assert.equal(proBonoApplies({ mode: "everyone" }, ALICE), false);
});
