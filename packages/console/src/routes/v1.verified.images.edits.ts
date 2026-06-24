// POST /v1/verified/images/edits — verified-pool img2img.

import { createFileRoute } from "@tanstack/react-router";

import { handleVerifiedImagesEdits } from "@/lib/openai-routes.server.ts";

export const Route = createFileRoute("/v1/verified/images/edits")({
  server: {
    handlers: {
      POST: ({ request }) => handleVerifiedImagesEdits(request),
    },
  },
});
