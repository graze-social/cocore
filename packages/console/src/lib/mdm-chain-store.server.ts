// Durable store for captured Apple x5c attestation chains (Secure Mode /
// MDA), keyed by device serial. Backed by the same SQLite DB as the rest
// of console-owned state (console-db.server.ts), so chains survive a
// console redeploy as long as the Railway volume is attached.
//
// SECURITY: we persist ONLY the public x5c chain (base64 DER certs). No
// private key, no SCEP secret, no PKCS12 ever reaches this table — the
// device's keys are SEP-resident and never leave the Mac.

import { consoleDb } from "@/lib/console-db.server.ts";

/** Persist (or replace) the captured Apple attestation chain for a serial.
 *  `chain` is leaf-first base64 DER certs (att.mdaCertChain shape). */
export function putAttestationChain(serial: string, chain: string[], capturedAt: string): void {
  consoleDb()
    .prepare(
      `INSERT INTO mdm_attestation_chains (serial, chain_json, captured_at)
       VALUES (?, ?, ?)
       ON CONFLICT(serial) DO UPDATE SET
         chain_json = excluded.chain_json,
         captured_at = excluded.captured_at`,
    )
    .run(serial, JSON.stringify(chain), capturedAt);
}

/** Return the captured chain for a serial, or null when none is stored. */
export function getAttestationChain(
  serial: string,
): { chain: string[]; capturedAt: string } | null {
  const row = consoleDb()
    .prepare(`SELECT chain_json, captured_at FROM mdm_attestation_chains WHERE serial = ?`)
    .get(serial) as { chain_json: string; captured_at: string } | undefined;
  if (!row) return null;
  try {
    const parsed = JSON.parse(row.chain_json) as unknown;
    if (Array.isArray(parsed) && parsed.every((c) => typeof c === "string")) {
      return { chain: parsed as string[], capturedAt: row.captured_at };
    }
  } catch {
    /* fall through to null on a corrupt row */
  }
  return null;
}

/** Record the signing key we just requested an MDA attestation for. Read at
 *  capture time so we only store a chain whose freshness binds THIS key. */
export function putExpectedAttestationKey(
  serial: string,
  pubkeyB64: string,
  requestedAt: string,
): void {
  consoleDb()
    .prepare(
      `INSERT INTO mdm_attestation_expected (serial, pubkey, requested_at)
       VALUES (?, ?, ?)
       ON CONFLICT(serial) DO UPDATE SET
         pubkey = excluded.pubkey,
         requested_at = excluded.requested_at`,
    )
    .run(serial, pubkeyB64, requestedAt);
}

/** The signing key most recently requested for this device's attestation, or
 *  null when none has been recorded (legacy captures — validation is skipped). */
export function getExpectedAttestationKey(serial: string): string | null {
  const row = consoleDb()
    .prepare(`SELECT pubkey FROM mdm_attestation_expected WHERE serial = ?`)
    .get(serial) as { pubkey: string } | undefined;
  return row?.pubkey ?? null;
}

/** The key AND when it was requested — used to make DeviceInformation enqueue
 *  idempotent (don't pile a second command for the same key onto NanoMDM's FIFO
 *  queue while the first is still pending). Null when none recorded. */
export function getExpectedAttestation(
  serial: string,
): { pubkey: string; requestedAt: string } | null {
  const row = consoleDb()
    .prepare(`SELECT pubkey, requested_at FROM mdm_attestation_expected WHERE serial = ?`)
    .get(serial) as { pubkey: string; requested_at: string } | undefined;
  return row ? { pubkey: row.pubkey, requestedAt: row.requested_at } : null;
}
