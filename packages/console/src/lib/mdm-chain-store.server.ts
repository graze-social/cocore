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

// ── Device → owner (DID) provisioning binding ─────────────────────────
//
// SECURITY (cross-tenant IDOR fix): the attestation-chain store is keyed
// by serial alone, so without an owner binding any authenticated agent
// could read ANY device's Apple attestation chain by guessing a serial.
// We record which authenticated DID provisioned a serial (at
// request-attestation time) and enforce it on the chain read: a caller may
// only read the chain for a serial it owns. See getDeviceProvisioningDid
// and its use in routes/api/agent.mdm.attestation-chain.ts.

/** Bind (or re-bind) a device serial to the authenticated DID that
 *  provisioned it. Idempotent; a re-provision by the same owner just
 *  refreshes `provisioned_at`. */
export function putDeviceProvisioning(serial: string, did: string, provisionedAt: string): void {
  consoleDb()
    .prepare(
      `INSERT INTO mdm_device_provisioning (serial, did, provisioned_at)
       VALUES (?, ?, ?)
       ON CONFLICT(serial) DO UPDATE SET
         did = excluded.did,
         provisioned_at = excluded.provisioned_at`,
    )
    .run(serial, did, provisionedAt);
}

/** Return the owning DID for a provisioned serial, or null when the serial
 *  has never been provisioned (fail-closed: callers treat null as "not
 *  authorized"). */
export function getDeviceProvisioningDid(serial: string): string | null {
  const row = consoleDb()
    .prepare(`SELECT did FROM mdm_device_provisioning WHERE serial = ?`)
    .get(serial) as { did: string } | undefined;
  return row ? row.did : null;
}
