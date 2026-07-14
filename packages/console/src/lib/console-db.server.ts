// SQLite store for console-owned state.
//
// Today this holds:
//   * api_keys           — API keys for the OpenAI-compatible endpoint
//   * oauth_sessions     — ATProto OAuth sessions (DPoP key + tokens),
//                          keyed by DID. Survives restart so API keys
//                          keep working without forcing the user to
//                          re-OAuth on every console deploy.
//   * app_sessions       — opaque cookie token -> DID. Without this
//                          on disk, every console redeploy logs every
//                          signed-in user out (the cookie is still
//                          valid; the in-memory map that resolves it
//                          is gone), which is what you'd see if every
//                          deploy left you back on /login.
//   * pending_disputes   — Stripe-era dispute bridge state, kept for
//                          historical operator review; not written
//                          under closed-loop.
//   * console_user_prefs — per-DID console UI flags (e.g. start-guide
//                          seen) that stay off the user's PDS.
//
// The pair-code store still lives in process memory; once we want pair
// codes to survive a redeploy, they can move here too.
//
// Path resolution (in order):
//   1. $COCORE_CONSOLE_DB if set — explicit override.
//   2. $RAILWAY_VOLUME_MOUNT_PATH/console.sqlite — Railway populates
//      this env var when an attached volume exists, so any deploy
//      that mounts a volume gets durable sessions for free.
//   3. ":memory:" with a loud warning. Dev / CI / any container
//      without an attached volume; OAuth sessions die on restart
//      and the operator sees the warning at boot.
//
// Schema evolution: every CREATE TABLE is `IF NOT EXISTS`, so a
// fresh DB picks up the latest layout. For DBs that predate a
// later column add, runMigrations() detects missing columns via
// pragma(table_info) and runs ALTER TABLE ADD COLUMN. Each
// migration is idempotent — repeated runs are no-ops.

import Database from "better-sqlite3";
import { existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { Database as DB } from "better-sqlite3";

// Tables come first; indexes (which can reference columns added by
// runMigrations) run AFTER migrations. Splitting the two avoids the
// "CREATE INDEX on a column that doesn't exist yet" crash on a
// legacy DB whose old shape predates a later column add.
const TABLES_SCHEMA = `
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

CREATE TABLE IF NOT EXISTS oauth_sessions (
  did TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS app_sessions (
  -- Opaque cookie token (uuid). The user's browser presents this in
  -- the auth-session cookie; we resolve it to a DID + check expiry.
  token TEXT PRIMARY KEY,
  did TEXT NOT NULL,
  created_at TEXT NOT NULL,
  -- Epoch milliseconds. Stored as INTEGER so the resolve query can
  -- WHERE-filter without a string-date dance. Match the cookie's
  -- Max-Age (30 days) at issue time.
  expires_at_ms INTEGER NOT NULL
);

-- payment_accounts + charge_log were dropped in the 2026-05-11
-- closed-loop pivot. The runMigrations() block below issues a
-- one-shot DROP TABLE IF EXISTS for any existing rows, so a deploy
-- that previously held Stripe state cleans itself up on first boot.

CREATE TABLE IF NOT EXISTS pending_disputes (
  -- Stripe Dispute id (du_*). Idempotency key for the bridge:
  -- a duplicate webhook event for the same dispute is dropped.
  stripe_dispute_id TEXT PRIMARY KEY,
  payment_intent_id TEXT NOT NULL,
  stripe_reason TEXT NOT NULL,
  -- Bridge state machine:
  --   "no-settlement-match" — webhook fired before the matching
  --                           cocore settlement was published, or the
  --                           charge was for a non-cocore receipt.
  --                           Operator-review path.
  --   "opened"              — dispute record published; dispute_uri
  --                           points at it.
  --   future:
  --   "resolved"            — the operator has called the resolver.
  status TEXT NOT NULL,
  -- at://... of the published dev.cocore.compute.dispute record,
  -- when status="opened" or later.
  dispute_uri TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS console_user_prefs (
  did TEXT PRIMARY KEY,
  -- ISO 8601; NULL until the user hits /start or dismisses the guide.
  start_guide_seen_at TEXT,
  updated_at TEXT NOT NULL DEFAULT ''
);

-- One row per uploaded provider diagnostic bundle ("Send bug report").
-- Metadata ONLY — the bundle bytes live on the filesystem next to the
-- DB (see bug-reports.server.ts). We deliberately never persist bundle
-- contents in the DB; a row points at a file and records who uploaded
-- it so an operator can correlate a ticket id with a DID.
CREATE TABLE IF NOT EXISTS bug_reports (
  -- Short, human-quotable ticket id (e.g. "br_k3f9q2"). Primary key.
  ticket_id TEXT PRIMARY KEY,
  -- Uploader's DID (resolved from the bearer API key at upload time).
  did TEXT NOT NULL,
  -- Absolute path to the stored .tar.gz bundle on disk.
  file_path TEXT NOT NULL,
  -- Bundle size in bytes, as received (post size-limit check).
  size_bytes INTEGER NOT NULL,
  created_at TEXT NOT NULL
);

-- Captured Apple x5c attestation chains for Secure Mode (MDA), keyed by
-- the device hardware serial. step-ca runs ACME device-attest-01 during
-- enrollment and forwards the validated Apple attestation chain to the
-- coordinator's authenticated ingest endpoint, which writes a row here.
-- The agent later GETs /api/agent/mdm/attestation-chain?serial=… to
-- staple the chain onto its dev.cocore.compute.attestation record. We
-- store ONLY the public x5c chain (a JSON array of base64 DER certs) —
-- no private key material ever lands here.
CREATE TABLE IF NOT EXISTS mdm_attestation_chains (
  serial TEXT PRIMARY KEY,
  -- JSON array of base64-encoded DER certs, leaf-first (att.mdaCertChain).
  chain_json TEXT NOT NULL,
  captured_at TEXT NOT NULL
);

-- The signing key most recently requested for a device's MDA attestation. Set
-- when the coordinator enqueues a DeviceInformation attestation (nonce =
-- sha256(pubkey)); read when a chain is captured so we only STORE a chain whose
-- freshness binds the currently-requested key. This is the fix for the
-- signing-key rotation trap: stale queued commands (old-key nonces) drained by
-- the device FIFO produced chains bound to a dead key, which then got served and
-- rejected by the agent forever. We now discard those captures instead. Keyed
-- by serial; a fresh request overwrites the expected key.
CREATE TABLE IF NOT EXISTS mdm_attestation_expected (
  serial TEXT PRIMARY KEY,
  pubkey TEXT NOT NULL,
  requested_at TEXT NOT NULL
);
`;

// Indexes run after runMigrations() so they can reference columns
// the migrator just ALTER'd in. Each is IF NOT EXISTS — safe to
// re-run on every boot.
const INDEXES_SCHEMA = `
CREATE INDEX IF NOT EXISTS api_keys_did_idx ON api_keys(did);
CREATE INDEX IF NOT EXISTS api_keys_hash_idx ON api_keys(hash);

CREATE INDEX IF NOT EXISTS app_sessions_did_idx ON app_sessions(did);
CREATE INDEX IF NOT EXISTS app_sessions_expires_idx ON app_sessions(expires_at_ms);

CREATE INDEX IF NOT EXISTS pending_disputes_status_idx
  ON pending_disputes(status);

CREATE INDEX IF NOT EXISTS bug_reports_did_idx ON bug_reports(did);
`;

// ── Schema migrations ─────────────────────────────────────────────────
//
// Each entry says "table T MUST have column C of type TY (with this
// default and nullability)". On boot we read pragma(table_info) for
// each table and ALTER TABLE ADD COLUMN any missing entries. Order
// within each list matters only when SQLite needs a non-NULL
// default (we always provide one).
//
// Adding a new column to an existing table → append here AND to the
// CREATE TABLE block above. The CREATE block keeps fresh DBs
// correct; this list catches existing DBs that predate the column.

interface ColumnSpec {
  name: string;
  /** ALTER TABLE sql tail, e.g. "TEXT" or "INTEGER NOT NULL DEFAULT 0". */
  defSql: string;
}

interface TableSpec {
  table: string;
  columns: ColumnSpec[];
}

const REQUIRED_COLUMNS: TableSpec[] = [
  {
    table: "pending_disputes",
    columns: [
      { name: "stripe_dispute_id", defSql: "TEXT PRIMARY KEY" },
      { name: "payment_intent_id", defSql: "TEXT NOT NULL DEFAULT ''" },
      { name: "stripe_reason", defSql: "TEXT NOT NULL DEFAULT ''" },
      { name: "status", defSql: "TEXT NOT NULL DEFAULT 'unknown'" },
      { name: "dispute_uri", defSql: "TEXT" },
      { name: "created_at", defSql: "TEXT NOT NULL DEFAULT ''" },
      { name: "updated_at", defSql: "TEXT NOT NULL DEFAULT ''" },
    ],
  },
];

interface PragmaTableInfoRow {
  cid: number;
  name: string;
  type: string;
  notnull: number;
  dflt_value: string | null;
  pk: number;
}

function tableExists(db: DB, table: string): boolean {
  const r = db
    .prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`)
    .get(table) as { name: string } | undefined;
  return !!r;
}

function existingColumns(db: DB, table: string): Set<string> {
  const rows = db.pragma(`table_info(${table})`) as PragmaTableInfoRow[];
  return new Set(rows.map((r) => r.name));
}

/** Walk REQUIRED_COLUMNS and ALTER any missing columns into place.
 *  Skips PRIMARY KEY entries (SQLite can't ADD COLUMN with PK; if
 *  the table has a different PK we have a deeper problem the
 *  CREATE block + a fresh DB would fix). Logs once per ALTER so
 *  operators see what migrated. */
function runMigrations(db: DB): void {
  // One-shot Stripe-table cleanup. The 2026-05-11 closed-loop pivot
  // dropped `payment_accounts` and `charge_log` from the schema;
  // existing deploys still carry the rows. Drop them so the DB stops
  // referencing Stripe-era data. Idempotent on subsequent boots.
  try {
    db.exec(`DROP TABLE IF EXISTS payment_accounts; DROP TABLE IF EXISTS charge_log;`);
  } catch (e) {
    console.error(`[console-db] Stripe-table drop failed (non-fatal): ${(e as Error).message}`);
  }

  for (const spec of REQUIRED_COLUMNS) {
    if (!tableExists(db, spec.table)) continue;
    const have = existingColumns(db, spec.table);
    for (const col of spec.columns) {
      if (have.has(col.name)) continue;
      // PRIMARY KEY columns can't be ALTER-added; skip and trust
      // the CREATE block on a fresh DB.
      if (col.defSql.includes("PRIMARY KEY")) continue;
      const stmt = `ALTER TABLE ${spec.table} ADD COLUMN ${col.name} ${col.defSql}`;
      try {
        db.exec(stmt);
        console.error(`[console-db] migrated: ${stmt}`);
      } catch (e) {
        // ALTER failures shouldn't crash boot — surface and move
        // on. The next column may still apply, and a real read
        // will throw a clearer error than a startup crash.
        console.error(
          `[console-db] migration failed for ${spec.table}.${col.name}: ${(e as Error).message}`,
        );
      }
    }
  }
}

/** Resolve the SQLite path the console should open.
 *
 *  Order:
 *    1. COCORE_CONSOLE_DB — explicit operator choice; honored as-is
 *       even when ":memory:".
 *    2. RAILWAY_VOLUME_MOUNT_PATH/console.sqlite — Railway sets this
 *       env var when a volume is attached (any path). Ensures the
 *       directory exists; warns once if it isn't writable.
 *    3. ":memory:" with a loud warning so an operator running in
 *       production without a volume notices: every redeploy logs
 *       every signed-in user out.
 *
 *  The "loud warning" matters: previously the silent default to
 *  :memory: produced "everyone's logged out after every deploy"
 *  with no signal. Now boot logs a yellow-flag line that anyone
 *  scanning Railway logs will see.
 */
export function resolveConsoleDbPath(): string {
  const explicit = process.env["COCORE_CONSOLE_DB"]?.trim();
  if (explicit) return explicit;

  const volume = process.env["RAILWAY_VOLUME_MOUNT_PATH"]?.trim();
  if (volume) {
    const candidate = `${volume.replace(/\/$/, "")}/console.sqlite`;
    try {
      mkdirSync(dirname(candidate), { recursive: true });
      console.error(`[console-db] using Railway volume at ${candidate}`);
      return candidate;
    } catch (e) {
      console.error(
        `[console-db] RAILWAY_VOLUME_MOUNT_PATH=${volume} but could not create dir: ${(e as Error).message}; falling back to :memory:`,
      );
    }
  }

  // Last resort: a dev path under cwd if it looks like a long-lived
  // process (NODE_ENV=production), otherwise pure :memory:. We
  // distinguish so `vitest` + ad-hoc scripts stay ephemeral, but
  // `node start.js` in a Docker image without a volume at least
  // attempts persistence under /tmp before evaporating.
  if (process.env["NODE_ENV"] === "production" && existsSync("/data")) {
    const candidate = "/data/console.sqlite";
    console.error(`[console-db] using /data/console.sqlite (Railway-style mount detected)`);
    return candidate;
  }

  // In production, a :memory: DB silently makes API keys and OAuth/app
  // sessions ephemeral — a durability *and* security footgun (auth state
  // that evaporates on restart). Fail closed rather than boot into that
  // state; keep the in-memory fallback for dev/CI/test only.
  if (process.env["NODE_ENV"] === "production") {
    throw new Error(
      "[console-db] refusing to start in production without a durable database. " +
        "Set COCORE_CONSOLE_DB=/path/to/console.sqlite, or attach a Railway volume " +
        "(RAILWAY_VOLUME_MOUNT_PATH is auto-detected), or provide a /data mount.",
    );
  }

  console.error(
    `[console-db] WARNING: using :memory:. OAuth sessions, app sessions, and API keys\n` +
      `[console-db]   will not survive process restart — every signed-in user gets bounced\n` +
      `[console-db]   back to /login on every deploy.\n` +
      `[console-db]   Set COCORE_CONSOLE_DB=/path/to/console.sqlite, or attach a Railway volume\n` +
      `[console-db]   (RAILWAY_VOLUME_MOUNT_PATH gets auto-detected).`,
  );
  return ":memory:";
}

let cached: DB | null = null;

export function consoleDb(): DB {
  if (cached) return cached;
  const path = resolveConsoleDbPath();
  const db = new Database(path);
  if (path !== ":memory:") {
    db.pragma("journal_mode = WAL");
  }
  db.exec(TABLES_SCHEMA);
  runMigrations(db);
  // Indexes go LAST so the migrator has a chance to ALTER missing
  // columns onto pre-existing tables before any
  // `CREATE INDEX ... ON x(new_col)` runs.
  db.exec(INDEXES_SCHEMA);
  cached = db;
  return db;
}

/** Test-only: drop the cached connection so the next consoleDb()
 *  call re-opens (and re-migrates) the DB. Vitest tests that mutate
 *  COCORE_CONSOLE_DB to point at a tmp file rely on this. */
export function _resetConsoleDbCache(): void {
  if (cached) {
    cached.close();
    cached = null;
  }
}
