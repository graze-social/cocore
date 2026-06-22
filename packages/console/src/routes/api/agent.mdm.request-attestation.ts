// POST /api/agent/mdm/request-attestation
//
// Option-B (freshness-code) hardware attestation. The agent supplies its
// receipt-signing public key; the coordinator sends an MDM `DeviceInformation`
// attestation command (via NanoMDM) with `DeviceAttestationNonce =
// sha256(publicKey)`, so the Apple attestation Apple returns has its freshness
// OID committed to the signing key. The captured chain arrives via the NanoMDM
// webhook (agent.mdm.nanomdm-webhook), is stored keyed by serial, and the agent
// reads it from agent.mdm.attestation-chain — where the freshness binding earns
// `hardware-attested`.
//
// This is the MDM-free-of-App-Attest path: it needs no step-ca challenge
// control, unlike the bundled ACME flow whose freshness = sha256(challenge
// token). Apple rate-limits DeviceInformation attestation to ~1/device/7 days,
// so the agent calls this at most weekly (the bound chain is reused across the
// 24h attestation publishes).
//
// Auth: the agent's bearer API key (same surface as the other /api/agent/*).

import { createFileRoute } from "@tanstack/react-router";

import {
  authenticateAgent,
  isValidSerial,
  isValidUdid,
  mdmJson,
  requestDeviceInformationAttestation,
} from "@/lib/mdm-coordinator.server.ts";

/** Accept a base64 raw 64-byte P-256 X‖Y public key (the value the agent
 *  publishes as attestation.publicKey). */
function isValidPublicKey(v: unknown): v is string {
  if (typeof v !== "string" || v.length === 0) return false;
  try {
    return Buffer.from(v, "base64").length === 64;
  } catch {
    return false;
  }
}

export const Route = createFileRoute("/api/agent/mdm/request-attestation")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const auth = authenticateAgent(request);
        if (!auth.ok) return auth.response;

        let body: { serial?: unknown; udid?: unknown; publicKey?: unknown };
        try {
          body = (await request.json()) as typeof body;
        } catch {
          return mdmJson({ error: "body must be JSON" }, 400);
        }
        if (!isValidSerial(body.serial)) {
          return mdmJson({ error: "serial required (8–24 alphanumeric chars)" }, 400);
        }
        if (!isValidUdid(body.udid)) {
          return mdmJson({ error: "udid required (40-hex or UUID form; the NanoMDM target)" }, 400);
        }
        if (!isValidPublicKey(body.publicKey)) {
          return mdmJson({ error: "publicKey required (base64 of a raw 64-byte P-256 key)" }, 400);
        }

        const result = await requestDeviceInformationAttestation(
          body.serial,
          body.udid,
          body.publicKey,
        );
        const status = result.status === "error" ? 502 : 200;
        return mdmJson(result, status);
      },
    },
  },
});
