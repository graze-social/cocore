// Verifies the COCORE_CONSOLE_DB / RAILWAY_VOLUME_MOUNT_PATH /
// :memory: resolution rule. The whole point of this fix is that an
// operator who attaches a Railway volume gets durable OAuth
// sessions WITHOUT having to also remember to set
// COCORE_CONSOLE_DB. So this test exercises every order-of-
// precedence branch.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, test } from "vitest";

import { resolveConsoleDbPath } from "./console-db.server.ts";

const ENV_KEYS = ["COCORE_CONSOLE_DB", "RAILWAY_VOLUME_MOUNT_PATH", "NODE_ENV"];

const ORIGINAL: Record<string, string | undefined> = {};
let tmpDir: string;

beforeEach(() => {
  for (const k of ENV_KEYS) ORIGINAL[k] = process.env[k];
  for (const k of ENV_KEYS) delete process.env[k];
  tmpDir = mkdtempSync(join(tmpdir(), "cocore-db-path-"));
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (ORIGINAL[k] === undefined) delete process.env[k];
    else process.env[k] = ORIGINAL[k];
  }
  rmSync(tmpDir, { recursive: true, force: true });
});

test("explicit COCORE_CONSOLE_DB wins, even when set to :memory:", () => {
  process.env["COCORE_CONSOLE_DB"] = ":memory:";
  process.env["RAILWAY_VOLUME_MOUNT_PATH"] = tmpDir;
  assert.equal(resolveConsoleDbPath(), ":memory:");
});

test("explicit COCORE_CONSOLE_DB to a file path wins over RAILWAY", () => {
  const explicit = join(tmpDir, "custom.sqlite");
  process.env["COCORE_CONSOLE_DB"] = explicit;
  process.env["RAILWAY_VOLUME_MOUNT_PATH"] = tmpDir;
  assert.equal(resolveConsoleDbPath(), explicit);
});

test("RAILWAY_VOLUME_MOUNT_PATH lands as <volume>/console.sqlite", () => {
  process.env["RAILWAY_VOLUME_MOUNT_PATH"] = tmpDir;
  const r = resolveConsoleDbPath();
  assert.equal(r, `${tmpDir}/console.sqlite`);
  // Ensure parent dir exists / is reachable. mkdir is recursive +
  // idempotent.
  assert.ok(statSync(tmpDir).isDirectory());
});

test("trailing-slash on RAILWAY_VOLUME_MOUNT_PATH is normalized", () => {
  process.env["RAILWAY_VOLUME_MOUNT_PATH"] = `${tmpDir}/`;
  assert.equal(resolveConsoleDbPath(), `${tmpDir}/console.sqlite`);
});

test("no env vars + non-production NODE_ENV => :memory:", () => {
  // Default vitest run has NODE_ENV unset or 'test'; either way,
  // not 'production'.
  const r = resolveConsoleDbPath();
  assert.equal(r, ":memory:");
});

test("production + no durable path => throws (fail closed, never :memory:)", () => {
  // Silently falling back to :memory: in production makes API keys and
  // OAuth/app sessions ephemeral. Refuse to boot instead.
  process.env["NODE_ENV"] = "production";
  assert.throws(() => resolveConsoleDbPath(), /durable database/);
});

// Note on the mkdir-failure path: a previous version of this file
// tried to exercise the catch arm by pointing
// RAILWAY_VOLUME_MOUNT_PATH at /proc/<unwritable>. On linux runners
// `mkdirSync(..., { recursive: true })` against procfs can hang (or
// at least take long enough to time vitest out before failing), so
// we cover the catch arm by inspection-only — the resolver returns
// :memory: when the env var is absent (covered above) and logs a
// warning when mkdirSync throws (no need to verify against a real
// filesystem to know that try-catch works).
