// POST /v1/chat/completions
//
// The canonical OpenAI-compatible chat-completions endpoint. Point any
// OpenAI SDK / LiteLLM / etc. at
// `base_url="https://cocore.dev/v1"` and it appends
// `/chat/completions` exactly as it would for `https://api.openai.com/v1`.
//
// Authed by an API key (`Authorization: Bearer cocore-…`). The key
// resolves to a DID; the shared dispatch core publishes the job under
// that DID and runs the in-app dispatch flow, translated to OpenAI's
// chat-completions wire format. `temperature`, `top_p`, `n`, `tools`,
// `presence_penalty`, `frequency_penalty` are accepted-and-ignored
// until the real engine honors them.
//
// Streaming (`stream: true`): text/event-stream of OpenAI-shaped
// chunks, terminated with `data: [DONE]`. Non-streaming: one buffered
// JSON object.
//
// Errors:
//   * 401 — missing/invalid Authorization or API key
//   * 404 (model_not_found) — no provider serves the requested model
//   * 503 (no_providers_connected) — no attested providers connected
//   * 424 (pds_publish_failed) — the requester's PDS refused the job records
//   * 502 — pipeline failures (provider key shape, SSE)
//
// The friends-only variant lives at `/v1/private/chat/completions`.
// This endpoint routes against the whole open network. The handler is
// shared with the legacy `/api/v1/chat/completions` mount.

import { createFileRoute } from "@tanstack/react-router";

import { handleChatCompletions } from "@/lib/openai-routes.server.ts";

export const Route = createFileRoute("/v1/chat/completions")({
  server: {
    handlers: {
      POST: ({ request }) => handleChatCompletions(request),
    },
  },
});
