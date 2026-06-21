// AppView operational store: API keys + OAuth sessions.
//
// This is the AppView's *authoritative operational state* — distinct
// from the firehose-indexed receipt cache (`Store`). It must NOT share
// a database file with that cache: the cache can be dropped and rebuilt
// from the relay at any time, whereas these rows (a user's API keys and
// their DPoP-bound OAuth session) cannot be reconstructed and must
// survive a cache rebuild. So this opens its own SQLite file
// (`COCORE_ACCOUNT_DB`).
//
// Invariant note: holding operational account state here does not
// violate "AppViews are caches, never ledgers" — that invariant is
// about *receipts* (the record of computational work). API keys and
// OAuth sessions are operational credentials, not a ledger of work.
//
// The API-key scheme is ported verbatim from the console's
// api-keys.server.ts: `cocore-<43 base64url chars>` (32 random bytes),
// SHA-256 of the full key persisted, first 16 chars kept as `prefix`
// for display. SHA-256 without a salt is fine — the input is already
// 256 bits of entropy.

import Database from "better-sqlite3";
import type { Database as DB } from "better-sqlite3";
import { createHash, randomBytes, randomUUID } from "node:crypto";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  did TEXT NOT NULL,
  name TEXT NOT NULL,
  prefix TEXT NOT NULL,
  hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT,
  last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS api_keys_did ON api_keys (did);

CREATE TABLE IF NOT EXISTS oauth_sessions (
  did TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`;

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

function hashKey(full: string): string {
  return createHash("sha256").update(full).digest("hex");
}

function generateApiKey(): { full: string; prefix: string; hash: string } {
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

export interface ResolvedKey {
  id: string;
  did: string;
  name: string;
}

export class AccountStore {
  readonly db: DB;

  constructor(path: string) {
    this.db = new Database(path);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA);
  }

  // ---- API keys -----------------------------------------------------

  createKey(input: CreateKeyInput): CreateKeyOutput {
    const { full, prefix, hash } = generateApiKey();
    const id = randomUUID();
    const createdAt = new Date().toISOString();
    this.db
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

  listKeysForDid(did: string): ApiKeyRow[] {
    const rows = this.db
      .prepare(
        `SELECT id, did, name, prefix, hash, created_at, expires_at, revoked_at, last_used_at
         FROM api_keys WHERE did = ? ORDER BY created_at DESC`,
      )
      .all(did) as DbRow[];
    return rows.map(rowFromDb);
  }

  /** Revoke a key. Returns true if a row was updated. Scoped to the
   *  caller's DID so users can't revoke each other's keys. The row stays
   *  with `revoked_at` set so the audit trail + "revoked" UI status
   *  survive; use {@link deleteKey} to fully remove it. */
  revokeKey(input: { id: string; did: string }): boolean {
    const result = this.db
      .prepare(
        `UPDATE api_keys SET revoked_at = ?
         WHERE id = ? AND did = ? AND revoked_at IS NULL`,
      )
      .run(new Date().toISOString(), input.id, input.did);
    return result.changes > 0;
  }

  /** Hard-delete a key row. Scoped to the caller's DID. Returns true if a
   *  row was deleted; no audit-trail recovery after this runs. */
  deleteKey(input: { id: string; did: string }): boolean {
    const result = this.db
      .prepare(`DELETE FROM api_keys WHERE id = ? AND did = ?`)
      .run(input.id, input.did);
    return result.changes > 0;
  }

  /** Revoke every still-active key for a DID. Used by the "reset
   *  connection" repair flow: a wedged agent key is invalidated in one
   *  shot without hunting per-key. Revoked rows stay (with `revoked_at`
   *  set) so the audit trail survives. Returns the number revoked. */
  revokeAllKeysForDid(did: string): number {
    const result = this.db
      .prepare(`UPDATE api_keys SET revoked_at = ? WHERE did = ? AND revoked_at IS NULL`)
      .run(new Date().toISOString(), did);
    return result.changes;
  }

  /** Validate a presented bearer token: format, hash lookup, expiry,
   *  revocation. On success, bumps `last_used_at` and returns the owning
   *  DID. Returns null on any failure (caller should respond 401; the
   *  failure modes aren't user-distinguishable). */
  resolveBearerKey(presented: string): ResolvedKey | null {
    if (!presented.startsWith(KEY_PREFIX)) return null;
    const hash = hashKey(presented);
    const row = this.db
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
    this.db
      .prepare(`UPDATE api_keys SET last_used_at = ? WHERE id = ?`)
      .run(new Date().toISOString(), row.id);
    return { id: row.id, did: row.did, name: row.name };
  }

  // ---- OAuth sessions ----------------------------------------------
  //
  // Opaque per-DID session blob. The console's atproto OAuth client
  // owns the serialization (DPoP keypair + tokens); we persist it
  // verbatim so the AppView can restore a DPoP-bound session for PDS
  // writes. The console's login callback writes here at sign-in time.

  putOAuthSession(did: string, data: string): void {
    this.db
      .prepare(
        `INSERT INTO oauth_sessions (did, data, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(did) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`,
      )
      .run(did, data, new Date().toISOString());
  }

  getOAuthSession(did: string): string | null {
    const row = this.db.prepare(`SELECT data FROM oauth_sessions WHERE did = ?`).get(did) as
      | { data: string }
      | undefined;
    return row?.data ?? null;
  }

  deleteOAuthSession(did: string): void {
    this.db.prepare(`DELETE FROM oauth_sessions WHERE did = ?`).run(did);
  }

  clearOAuthSessions(): void {
    this.db.prepare(`DELETE FROM oauth_sessions`).run();
  }
}
