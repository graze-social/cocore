// POST /v1/private/images/generations — friends-only text-to-image.
// Identical wire format to /v1/images/generations, but the candidate
// provider pool is constrained to DIDs the caller has friended.

import { createFileRoute } from "@tanstack/react-router";

import { handlePrivateImagesGenerations } from "@/lib/openai-routes.server.ts";

export const Route = createFileRoute("/v1/private/images/generations")({
  server: {
    handlers: {
      POST: ({ request }) => handlePrivateImagesGenerations(request),
    },
  },
});
