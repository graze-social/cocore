// GET  /api/agent/mdm/attestation-chain?serial=...   (agent reads the chain)
// POST /api/agent/mdm/attestation-chain               (step-ca webhook ingests)
//
// Coordinator step 3 of guided MDM enrollment.
//
// GET returns the captured Apple x5c attestation chain for a device
// (keyed by serial) as JSON {chain: string[] | null, status, ...}. The
// chain is captured by step-ca during the ACME device-attest-01
// challenge; the agent reads it here to staple onto its attestation
// record (att.mdaCertChain) and earn `hardware-attested`. Auth: the
// agent's bearer API key — same surface as the other /api/agent/* routes.
//
// POST is the capture ingest: step-ca's attestation webhook forwards the
// validated Apple x5c chain here keyed by serial; we persist it to the
// console's durable store. Auth: the shared COCORE_MDM_CHAIN_INGEST_KEY
// bearer (step-ca infra, not an agent). Fail-closed when the key is unset.
//
// Until either the webhook posts a chain or COCORE_MDM_CHAIN_STORE_URL is
// configured, GET returns {chain:null, status:"pending"}.

import { createFileRoute } from "@tanstack/react-router";

import {
  authenticateAgent,
  authenticateChainIngest,
  fetchAttestationChain,
  getDeviceProvisioningDid,
  ingestAttestationChain,
  isValidSerial,
  mdmJson,
  WEBHOOK_DEBUG_SERIAL,
  webhookDebugEnabled,
} from "@/lib/mdm-coordinator.server.ts";

// We STORE the chain as base64 DER (the ingest contract below), but the agent's
// reader runs every entry through a PEM block parser — so a base64-DER entry
// yields ZERO certs and the agent, despite a 200 with a real chain, parses
// nothing, never embeds it, and stays self-attested. Wrap each cert in PEM
// markers on the way out so the agent's PEM parser sees real certificates.
// (The wizard's reader only checks the array is non-empty, so it's unaffected.)
function derB64ToPem(entry: string): string {
  if (entry.includes("-----BEGIN")) return entry; // already PEM
  const b64 = entry.replace(/\s+/g, "");
  const wrapped = b64.match(/.{1,64}/g)?.join("\n") ?? b64;
  return `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----`;
}

export const Route = createFileRoute("/api/agent/mdm/attestation-chain")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const auth = authenticateAgent(request);
        if (!auth.ok) return auth.response;
        const callerDid = auth.caller.did;

        const serial = new URL(request.url).searchParams.get("serial");
        if (!isValidSerial(serial)) {
          return mdmJson({ error: "serial query param required (8–24 alphanumeric chars)" }, 400);
        }

        // Debug seam: the reserved WEBHOOK_DEBUG_SERIAL stashes raw NanoMDM
        // bodies and has no owning DID. It is a bring-up-only inspection
        // aid, so refuse it entirely unless the debug stash is enabled
        // (which webhookDebugEnabled() hard-disables in production).
        if (serial === WEBHOOK_DEBUG_SERIAL && !webhookDebugEnabled()) {
          return mdmJson({ error: "not found" }, 404);
        }

        // SECURITY (cross-tenant IDOR fix): a serial may only be read by the
        // DID that provisioned it (bound at request-attestation time). This
        // gate is enforced BEFORE fetchAttestationChain so it applies no
        // matter where the chain data comes from (local SQLite OR the
        // external COCORE_MDM_CHAIN_STORE_URL fallback). Fail-closed: an
        // unprovisioned serial (no owner row) is treated as not authorized,
        // so a guessed serial never leaks a chain. The debug serial above is
        // the only ownerless serial that can be read, and only in non-prod.
        if (serial !== WEBHOOK_DEBUG_SERIAL) {
          const owner = getDeviceProvisioningDid(serial);
          if (owner !== callerDid) {
            return mdmJson({ error: "forbidden: serial not provisioned to this caller" }, 403);
          }
        }

        const result = await fetchAttestationChain(serial);
        const status = result.status === "error" ? 502 : 200;
        const chain = result.chain ? result.chain.map(derB64ToPem) : result.chain;
        return mdmJson({ ...result, chain }, status);
      },

      POST: async ({ request }) => {
        if (!authenticateChainIngest(request)) {
          return mdmJson({ error: "invalid or missing chain-ingest bearer" }, 401);
        }
        let body: { serial?: unknown; chain?: unknown };
        try {
          body = (await request.json()) as typeof body;
        } catch {
          return mdmJson({ error: "body must be JSON" }, 400);
        }
        if (!isValidSerial(body.serial)) {
          return mdmJson({ error: "serial required (8–24 alphanumeric chars)" }, 400);
        }
        if (
          !Array.isArray(body.chain) ||
          body.chain.length === 0 ||
          !body.chain.every((c) => typeof c === "string" && c.length > 0)
        ) {
          return mdmJson({ error: "chain required (non-empty array of base64 DER certs)" }, 400);
        }
        ingestAttestationChain(body.serial, body.chain as string[], new Date().toISOString());
        return mdmJson({ ok: true, serial: body.serial, certs: body.chain.length });
      },
    },
  },
});
