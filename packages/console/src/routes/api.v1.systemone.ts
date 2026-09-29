// POST /api/v1/systemone
//
// cocore's historical `/api/v1/*` mount for the System-One decision
// endpoint. Same handler as the canonical `/v1/systemone`, so the two mounts
// cannot drift.

import { createFileRoute } from "@tanstack/react-router";

import { handleSystemOne } from "@/lib/openai-routes.server.ts";

export const Route = createFileRoute("/api/v1/systemone")({
  server: {
    handlers: {
      POST: ({ request }) => handleSystemOne(request),
    },
  },
});
