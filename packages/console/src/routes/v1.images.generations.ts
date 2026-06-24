// POST /v1/images/generations — OpenAI-compatible text-to-image.
//
// Point an OpenAI SDK at `base_url="https://cocore.dev/v1"` and call
// `images.generate({ model, prompt, n })`. Authed by an API key
// (`Authorization: Bearer cocore-…`). Returns inline base64 only
// (`response_format: "b64_json"`); `"url"` is a 400. Routes against the
// whole open network; private/verified variants live at the sibling paths.
// Handler is shared with the legacy `/api/v1/images/generations` mount.

import { createFileRoute } from "@tanstack/react-router";

import { handleImagesGenerations } from "@/lib/openai-routes.server.ts";

export const Route = createFileRoute("/v1/images/generations")({
  server: {
    handlers: {
      POST: ({ request }) => handleImagesGenerations(request),
    },
  },
});
