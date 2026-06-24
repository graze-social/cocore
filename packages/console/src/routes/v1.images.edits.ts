// POST /v1/images/edits — OpenAI-compatible img2img (image edit).
//
// multipart/form-data: `model`, `prompt`, `image` (the reference), `n`.
// The reference image is sealed into a messages-v1 envelope alongside the
// prompt. Returns inline base64 only. Handler shared with the legacy
// `/api/v1/images/edits` mount.

import { createFileRoute } from "@tanstack/react-router";

import { handleImagesEdits } from "@/lib/openai-routes.server.ts";

export const Route = createFileRoute("/v1/images/edits")({
  server: {
    handlers: {
      POST: ({ request }) => handleImagesEdits(request),
    },
  },
});
