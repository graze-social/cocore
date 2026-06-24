// POST /v1/private/images/edits — friends-only img2img.

import { createFileRoute } from "@tanstack/react-router";

import { handlePrivateImagesEdits } from "@/lib/openai-routes.server.ts";

export const Route = createFileRoute("/v1/private/images/edits")({
  server: {
    handlers: {
      POST: ({ request }) => handlePrivateImagesEdits(request),
    },
  },
});
