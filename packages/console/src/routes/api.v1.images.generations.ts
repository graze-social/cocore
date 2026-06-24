// POST /api/v1/images/generations — legacy mount of the canonical
// /v1/images/generations endpoint. Same shared handler.

import { createFileRoute } from "@tanstack/react-router";

import { handleImagesGenerations } from "@/lib/openai-routes.server.ts";

export const Route = createFileRoute("/api/v1/images/generations")({
  server: {
    handlers: {
      POST: ({ request }) => handleImagesGenerations(request),
    },
  },
});
