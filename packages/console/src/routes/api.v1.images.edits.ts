// POST /api/v1/images/edits — legacy mount of /v1/images/edits.

import { createFileRoute } from "@tanstack/react-router";

import { handleImagesEdits } from "@/lib/openai-routes.server.ts";

export const Route = createFileRoute("/api/v1/images/edits")({
  server: {
    handlers: {
      POST: ({ request }) => handleImagesEdits(request),
    },
  },
});
