// POST /v1/systemone
//
// The System-One decision endpoint — wire-identical to TypeSafe's Jev API
// and to what `ollaya serve` / Unsloth Desktop answer on localhost. An
// existing Jev client reaches the cocore network by pointing at
// `https://cocore.dev`:
//
//   TYPESAFE_BASE_URL=https://cocore.dev
//
// Authed by an API key (`Authorization: Bearer cocore-…`) or an AT Protocol
// service-auth JWT, exactly like the chat surface.
//
// Body: `{ model, state, questions }`, where each question is a `noul`,
// `choice`, or `score`. Reply: `{ model, answers, usage }` plus cocore's
// `x_cocore` block naming who ran it and where the receipt is.
//
// Errors:
//   * 401 — missing/invalid Authorization
//   * 404 (model_not_found) — no provider serves a System-One model
//   * 422 (validation_error) — malformed request
//   * 529 — no capacity right now (the status Jev SDKs back off and retry)
//   * 502 — pipeline failures (pds publish, malformed decision)
//
// Not streamed: a System-One model is non-autoregressive and answers every
// question in one encoder pass. The handler is shared with the legacy
// `/api/v1/systemone` mount.

import { createFileRoute } from "@tanstack/react-router";

import { handleSystemOne } from "@/lib/openai-routes.server.ts";

export const Route = createFileRoute("/v1/systemone")({
  server: {
    handlers: {
      POST: ({ request }) => handleSystemOne(request),
    },
  },
});
