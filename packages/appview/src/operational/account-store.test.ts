import { describe, expect, it } from "vitest";

import { AccountStore } from "./account-store.ts";

function freshStore(): AccountStore {
  return new AccountStore(":memory:");
}

const DID = "did:plc:alice";
const OTHER = "did:plc:mallory";

describe("AccountStore api keys", () => {
  it("creates a key, returns the secret once, and persists only the hash", () => {
    const s = freshStore();
    const { key, secret } = s.createKey({ did: DID, name: "laptop" });
    expect(secret.startsWith("cocore-")).toBe(true);
    expect(key.prefix).toBe(secret.slice(0, "cocore-".length + 8));
    expect(key.did).toBe(DID);
    // The plaintext secret is never stored.
    const stored = s.db.prepare("SELECT hash, prefix FROM api_keys WHERE id = ?").get(key.id) as {
      hash: string;
      prefix: string;
    };
    expect(stored.hash).not.toContain(secret);
    expect(stored.prefix).toBe(key.prefix);
  });

  it("resolves a valid bearer key to its owning DID and bumps last_used_at", () => {
    const s = freshStore();
    const { secret } = s.createKey({ did: DID, name: "k" });
    const resolved = s.resolveBearerKey(secret);
    expect(resolved?.did).toBe(DID);
    const [row] = s.listKeysForDid(DID);
    expect(row?.lastUsedAt).not.toBeNull();
  });

  it("rejects malformed, revoked, and expired keys", () => {
    const s = freshStore();
    expect(s.resolveBearerKey("not-a-cocore-key")).toBeNull();

    const revoked = s.createKey({ did: DID, name: "r" });
    expect(s.revokeKey({ id: revoked.key.id, did: DID })).toBe(true);
    expect(s.resolveBearerKey(revoked.secret)).toBeNull();

    const expired = s.createKey({
      did: DID,
      name: "e",
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    });
    expect(s.resolveBearerKey(expired.secret)).toBeNull();
  });

  it("scopes revoke/delete to the owning DID", () => {
    const s = freshStore();
    const { key } = s.createKey({ did: DID, name: "k" });
    expect(s.revokeKey({ id: key.id, did: OTHER })).toBe(false);
    expect(s.deleteKey({ id: key.id, did: OTHER })).toBe(false);
    expect(s.deleteKey({ id: key.id, did: DID })).toBe(true);
    expect(s.listKeysForDid(DID)).toHaveLength(0);
  });

  it("lists a DID's keys newest-first and never another DID's", () => {
    const s = freshStore();
    s.createKey({ did: DID, name: "a" });
    s.createKey({ did: OTHER, name: "b" });
    const mine = s.listKeysForDid(DID);
    expect(mine).toHaveLength(1);
    expect(mine[0]?.name).toBe("a");
  });

  it("revokeAllKeysForDid revokes only the DID's active keys and is idempotent", () => {
    const s = freshStore();
    const a = s.createKey({ did: DID, name: "a" });
    const b = s.createKey({ did: DID, name: "b" });
    s.createKey({ did: OTHER, name: "c" });

    // Revokes both of DID's keys, leaving OTHER's untouched.
    expect(s.revokeAllKeysForDid(DID)).toBe(2);
    expect(s.resolveBearerKey(a.secret)).toBeNull();
    expect(s.resolveBearerKey(b.secret)).toBeNull();
    expect(s.listKeysForDid(OTHER)[0]?.revokedAt).toBeNull();

    // Already-revoked keys aren't counted again.
    expect(s.revokeAllKeysForDid(DID)).toBe(0);
  });
});

describe("AccountStore oauth sessions", () => {
  it("upserts and reads back an opaque session blob", () => {
    const s = freshStore();
    expect(s.getOAuthSession(DID)).toBeNull();
    s.putOAuthSession(DID, '{"dpop":"v1"}');
    expect(s.getOAuthSession(DID)).toBe('{"dpop":"v1"}');
    s.putOAuthSession(DID, '{"dpop":"v2"}');
    expect(s.getOAuthSession(DID)).toBe('{"dpop":"v2"}');
    s.deleteOAuthSession(DID);
    expect(s.getOAuthSession(DID)).toBeNull();
  });
});
