// Persistence for provider diagnostic bundles ("Send bug report").
//
// The macOS tray app shells out to `cocore agent diag --out <path>`,
// which writes a content-safe `.tar.gz` (crash logs, redacted session,
// system profile, macOS crash reports — NO prompts, NO api key, NO
// signing key) and then uploads it to the console at
// /api/agent/bug-report with the same `Authorization: Bearer <apiKey>`
// the agent already uses for status/whoami.
//
// Storage layout:
//   * The bundle BYTES go to the filesystem, never the DB. We store
//     them in a `bug-reports/` directory that sits next to the console
//     SQLite file, so anywhere the DB is durable (a Railway volume, an
//     explicit COCORE_CONSOLE_DB path) the bundles are durable too.
//   * A single `bug_reports` row (see console-db.server.ts) records the
//     ticket id, uploader DID, on-disk path, size, and the reporter's
//     own note — metadata only.
//
// We never read, log, or inspect bundle contents here: the bytes land
// on disk and the row points at them. An operator triages by ticket id
// out of band.

import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { consoleDb, resolveConsoleDbPath } from "@/lib/console-db.server.ts";

/** Hard ceiling on an accepted bundle. The diag bundle is content-safe
 *  and small in practice (logs + a system profile); 25 MB is generous
 *  headroom while still bounding what an authenticated client can push
 *  in one request. The route rejects anything larger with a 413. */
export const MAX_BUNDLE_BYTES = 25 * 1024 * 1024;

/** The only content-type we accept. The agent always uploads a gzipped
 *  tarball; reject anything else at the edge. */
export const BUNDLE_CONTENT_TYPE = "application/gzip";

/** Cap on the stored reporter note. The tray sends it as an HTTP header
 *  (`X-Cocore-Note`), so it's inherently short; truncating keeps a
 *  hostile client from parking arbitrary text in the DB. */
export const MAX_NOTE_CHARS = 2000;

/** Normalise the reporter's note: it arrives as an HTTP header, so drop the
 *  C0 control characters that transport can carry (CR/LF/TAB from a
 *  multi-line note), collapse whitespace runs, trim, and truncate. Returns
 *  "" when there's nothing usable, so the column is never null. */
export function normalizeNote(raw: string | null | undefined): string {
  if (!raw) return "";
  const stripped = Array.from(raw, (ch) => {
    const code = ch.codePointAt(0) ?? 0;
    return code < 0x20 || code === 0x7f ? " " : ch;
  }).join("");
  return stripped.replace(/\s+/g, " ").trim().slice(0, MAX_NOTE_CHARS);
}

export interface StoredBugReport {
  ticketId: string;
  did: string;
  filePath: string;
  sizeBytes: number;
  createdAt: string;
  /** What the reporter typed, normalised + truncated; "" when absent. */
  note: string;
}

/** Resolve the directory bundles are written under. Mirrors the DB
 *  path resolution so durable-DB deployments get durable bundles for
 *  free:
 *    * COCORE_CONSOLE_DB / RAILWAY_VOLUME_MOUNT_PATH → a `bug-reports/`
 *      sibling of the SQLite file.
 *    * `:memory:` DB (dev / CI / volume-less container) → a local
 *      `bug-reports/` under the process cwd. Clearly ephemeral, but a
 *      real on-disk location so the upload path is exercised end-to-end
 *      rather than silently dropping bytes.
 *  The directory is created idempotently on first use. */
function resolveBugReportDir(): string {
  const dbPath = resolveConsoleDbPath();
  const baseDir = dbPath === ":memory:" ? process.cwd() : dirname(dbPath);
  const dir = join(baseDir, "bug-reports");
  mkdirSync(dir, { recursive: true });
  return dir;
}

/** Generate a short, human-quotable ticket id, e.g. `br_k3f9q2x1`.
 *  8 base32-ish chars off 5 random bytes — enough entropy that an
 *  operator can paste it into a chat without collision worries, short
 *  enough to read aloud. */
function generateTicketId(): string {
  // Lowercase, no vowels-only ambiguity needed; base36 keeps it terse.
  const body = randomBytes(5).toString("hex").slice(0, 8);
  return `br_${body}`;
}

/** Persist an uploaded diagnostic bundle. Writes the bytes to the
 *  bug-report dir under a filename derived from the ticket id + a hash
 *  of the DID (so two uploads from different providers never collide
 *  on disk) and records a metadata row. Returns the stored record.
 *
 *  Does NOT validate size/content-type — the route does that before
 *  buffering, so this stays a pure persistence step. */
export function storeBugReport(input: {
  did: string;
  bytes: Buffer;
  note?: string | null;
}): StoredBugReport {
  const { did, bytes } = input;
  const note = normalizeNote(input.note);
  const ticketId = generateTicketId();
  const createdAt = new Date().toISOString();

  const dir = resolveBugReportDir();
  // Filename: ticket id + short DID fingerprint. Keeps the DID out of
  // the visible path while still namespacing per-uploader.
  const didFp = createHash("sha256").update(did).digest("hex").slice(0, 12);
  const fileName = `${ticketId}-${didFp}.tar.gz`;
  const filePath = join(dir, fileName);

  writeFileSync(filePath, bytes);

  consoleDb()
    .prepare(
      `INSERT INTO bug_reports (ticket_id, did, file_path, size_bytes, created_at, note)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .run(ticketId, did, filePath, bytes.byteLength, createdAt, note);

  return { ticketId, did, filePath, sizeBytes: bytes.byteLength, createdAt, note };
}
