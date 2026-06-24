// POST /v1/verified/images/generations — route ONLY to providers whose
// attestation is cryptographically verified to meet a trust floor
// (optional `min_trust` form/body field). Fails closed (503) when no
// verified provider serves the model.

import { createFileRoute } from "@tanstack/react-router";

import { handleVerifiedImagesGenerations } from "@/lib/openai-routes.server.ts";

export const Route = createFileRoute("/v1/verified/images/generations")({
  server: {
    handlers: {
      POST: ({ request }) => handleVerifiedImagesGenerations(request),
    },
  },
});
