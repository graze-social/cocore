// POST /api/agent/mdm/nanomdm-webhook
//
// Capture sink for the option-B DeviceInformation attestation flow. NanoMDM is
// configured (`-webhook-url`) to POST MDM events here; when a device's
// DeviceInformation command result carries a `DevicePropertiesAttestation`
// chain (the Apple x5c we requested with a key-bound nonce in
// agent.mdm.request-attestation), we persist it keyed by serial — the same
// store the agent polls via agent.mdm.attestation-chain.
//
// Non-attestation events (Authenticate, TokenUpdate, other command results) are
// acknowledged and ignored. Auth: COCORE_NANOMDM_WEBHOOK_KEY bearer
// (constant-time, fail-closed when unset) — NanoMDM infra, not an agent.
//
// This mirrors the step-ca attestation webhook (agent.mdm.attestation-chain
// POST) for the ACME flow; the DeviceInformation flow's chain comes back over
// MDM instead of out-of-band from the CA.

import { createFileRoute } from "@tanstack/react-router";

import {
  authenticateNanomdmWebhook,
  ingestAttestationChain,
  isValidSerial,
  mdmJson,
  parseNanomdmAttestationWebhook,
} from "@/lib/mdm-coordinator.server.ts";

export const Route = createFileRoute("/api/agent/mdm/nanomdm-webhook")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        if (!authenticateNanomdmWebhook(request)) {
          return mdmJson({ error: "invalid or missing nanomdm-webhook bearer" }, 401);
        }
        let body: unknown;
        try {
          body = await request.json();
        } catch {
          return mdmJson({ error: "body must be JSON" }, 400);
        }

        const parsed = parseNanomdmAttestationWebhook(body);
        // Not an attestation result → ACK so NanoMDM doesn't retry.
        if (!parsed) return mdmJson({ ok: true, captured: false });

        if (!isValidSerial(parsed.serial)) {
          // We got a chain but couldn't tie it to a serial — don't store
          // unkeyed; report so the operator can inspect the webhook shape.
          return mdmJson(
            { ok: false, captured: false, detail: "attestation chain present but no valid serial" },
            422,
          );
        }
        ingestAttestationChain(parsed.serial, parsed.chain, new Date().toISOString());
        return mdmJson({
          ok: true,
          captured: true,
          serial: parsed.serial,
          certs: parsed.chain.length,
        });
      },
    },
  },
});
