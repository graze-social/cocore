// POST /api/v1/probono/chat/completions
//
// Pro-bono sibling of `/api/v1/chat/completions`: same OpenAI wire format, but
// routing is constrained to providers whose `proBono` policy serves THIS
// requester for free. See the canonical `/v1/probono/chat/completions` mount
// for the full contract; both routes call the same handler in
// `@/lib/openai-routes.server.ts`.

import { createFileRoute } from "@tanstack/react-router";

import { handleProBonoChatCompletions } from "@/lib/openai-routes.server.ts";

export const Route = createFileRoute("/api/v1/probono/chat/completions")({
  server: {
    handlers: {
      POST: ({ request }) => handleProBonoChatCompletions(request),
    },
  },
});
