// API key generation, lookup, and lifecycle.
//
// Keys look like `cocore-<43 base64url chars>` (32 random bytes,
// ~256 bits of entropy, encoded url-safe with no padding).
//
// On creation we return the full key exactly once; only the SHA-256
// hash is persisted. The first 16 chars (`cocore-AbCd1234`) are also
// stored in plaintext as `prefix` so the UI can show the user which
// key is which after creation.
//
// SHA-256 without a salt is fine here — the input is already 256 bits
// of entropy, so there's no slow-hash story to gain. (Bcrypt/argon2
// exist to slow down brute force on low-entropy passwords.)

import { createHash, randomBytes, randomUUID } from "node:crypto";

import { consoleDb } from "@/lib/console-db.server.ts";

export interface ApiKeyRow {
  id: string;
  did: string;
  name: string;
  prefix: string;
  createdAt: string;
  expiresAt: string | null;
  revokedAt: string | null;
  lastUsedAt: string | null;
}

interface DbRow {
  id: string;
  did: string;
  name: string;
  prefix: string;
  hash: string;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
}

function rowFromDb(r: DbRow): ApiKeyRow {
  return {
    id: r.id,
    did: r.did,
    name: r.name,
    prefix: r.prefix,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
    revokedAt: r.revoked_at,
    lastUsedAt: r.last_used_at,
  };
}

const KEY_PREFIX = "cocore-";

function base64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function hashKey(full: string): string {
  return createHash("sha256").update(full).digest("hex");
}

export function generateApiKey(): { full: string; prefix: string; hash: string } {
  const body = base64url(randomBytes(32));
  const full = `${KEY_PREFIX}${body}`;
  return {
    full,
    prefix: full.slice(0, KEY_PREFIX.length + 8),
    hash: hashKey(full),
  };
}

export interface CreateKeyInput {
  did: string;
  name: string;
  expiresAt?: string | null;
}

export interface CreateKeyOutput {
  key: ApiKeyRow;
  secret: string;
}

export function createKey(input: CreateKeyInput): CreateKeyOutput {
  const { full, prefix, hash } = generateApiKey();
  const id = randomUUID();
  const createdAt = new Date().toISOString();
  consoleDb()
    .prepare(
      `INSERT INTO api_keys (id, did, name, prefix, hash, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(id, input.did, input.name, prefix, hash, createdAt, input.expiresAt ?? null);
  return {
    key: {
      id,
      did: input.did,
      name: input.name,
      prefix,
      createdAt,
      expiresAt: input.expiresAt ?? null,
      revokedAt: null,
      lastUsedAt: null,
    },
    secret: full,
  };
}

export function listKeysForDid(did: string): ApiKeyRow[] {
  const rows = consoleDb()
    .prepare(
      `SELECT id, did, name, prefix, hash, created_at, expires_at, revoked_at, last_used_at
       FROM api_keys WHERE did = ? ORDER BY created_at DESC`,
    )
    .all(did) as DbRow[];
  return rows.map(rowFromDb);
}

/** Revoke a key. Returns true if a row was updated. Scoped to the
 *  caller's DID so users can't revoke each other's keys. The row
 *  stays in the table with `revoked_at` set so the audit trail and
 *  the UI's "revoked" status survive. Use {@link deleteKey} to
 *  fully remove the row. */
export function revokeKey(input: { id: string; did: string }): boolean {
  const result = consoleDb()
    .prepare(
      `UPDATE api_keys SET revoked_at = ?
       WHERE id = ? AND did = ? AND revoked_at IS NULL`,
    )
    .run(new Date().toISOString(), input.id, input.did);
  return result.changes > 0;
}

/** Hard-delete a key row. Scoped to the caller's DID. Use this for
 *  cleaning up revoked or expired keys when the user no longer wants
 *  them in their list — there's no audit trail recovery after this
 *  runs. Returns true if a row was deleted. */
export function deleteKey(input: { id: string; did: string }): boolean {
  const result = consoleDb()
    .prepare(`DELETE FROM api_keys WHERE id = ? AND did = ?`)
    .run(input.id, input.did);
  return result.changes > 0;
}

/** Revoke every still-active key for a DID in one shot. Used by the
 *  "reset connection" repair flow to invalidate a wedged agent key
 *  without the user hunting through their key list. Revoked rows stay
 *  with `revoked_at` set so the audit trail survives. Returns the count
 *  revoked. */
export function revokeAllKeysForDid(did: string): number {
  const result = consoleDb()
    .prepare(`UPDATE api_keys SET revoked_at = ? WHERE did = ? AND revoked_at IS NULL`)
    .run(new Date().toISOString(), did);
  return result.changes;
}

export interface ResolvedKey {
  id: string;
  did: string;
  name: string;
}

/** Validate a presented bearer token: format, hash lookup, expiry,
 *  revocation. On success, bumps `last_used_at` and returns the
 *  owning DID. Returns null on any failure (caller should respond
 *  401, since success vs. each failure mode isn't user-distinguishable). */
export function resolveBearerKey(presented: string): ResolvedKey | null {
  if (!presented.startsWith(KEY_PREFIX)) return null;
  const hash = hashKey(presented);
  const row = consoleDb()
    .prepare(
      `SELECT id, did, name, hash, expires_at, revoked_at
       FROM api_keys WHERE hash = ?`,
    )
    .get(hash) as
    | {
        id: string;
        did: string;
        name: string;
        expires_at: string | null;
        revoked_at: string | null;
      }
    | undefined;
  if (!row) return null;
  if (row.revoked_at) return null;
  if (row.expires_at && Date.parse(row.expires_at) <= Date.now()) return null;
  consoleDb()
    .prepare(`UPDATE api_keys SET last_used_at = ? WHERE id = ?`)
    .run(new Date().toISOString(), row.id);
  return { id: row.id, did: row.did, name: row.name };
}
