import { test } from "vitest";
import assert from "node:assert/strict";

import type { ApiKeyRow } from "./api-keys.server.ts";

import { apiKeyView, resolveXrpcCaller } from "./xrpc-key-auth.server.ts";

const baseRow: ApiKeyRow = {
  id: "key-1",
  did: "did:plc:alice",
  name: "laptop",
  prefix: "cocore-AbCd1234",
  createdAt: "2026-06-19T00:00:00.000Z",
  expiresAt: null,
  revokedAt: null,
  lastUsedAt: null,
};

test("apiKeyView exposes required fields and never the secret/hash", () => {
  const view = apiKeyView(baseRow);
  assert.deepEqual(view, {
    id: "key-1",
    did: "did:plc:alice",
    name: "laptop",
    prefix: "cocore-AbCd1234",
    createdAt: "2026-06-19T00:00:00.000Z",
  });
  // No secret-bearing fields ever leak onto the wire.
  assert.equal("hash" in view, false);
  assert.equal("secret" in view, false);
});

test("apiKeyView omits null optionals but includes present ones", () => {
  const view = apiKeyView({
    ...baseRow,
    expiresAt: "2027-01-01T00:00:00.000Z",
    revokedAt: "2026-07-01T00:00:00.000Z",
    lastUsedAt: "2026-06-20T00:00:00.000Z",
  });
  assert.equal(view.expiresAt, "2027-01-01T00:00:00.000Z");
  assert.equal(view.revokedAt, "2026-07-01T00:00:00.000Z");
  assert.equal(view.lastUsedAt, "2026-06-20T00:00:00.000Z");
});

test("resolveXrpcCaller returns null when no credential is presented", async () => {
  const req = new Request("https://console.cocore.dev/api/xrpc/dev.cocore.account.listApiKeys");
  assert.equal(await resolveXrpcCaller(req), null);
});
