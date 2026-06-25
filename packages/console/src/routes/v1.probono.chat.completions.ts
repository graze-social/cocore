// POST /v1/probono/chat/completions
//
// The pro-bono completion path: same OpenAI wire format as
// `/v1/chat/completions`, but routing is constrained to providers whose
// `proBono` policy elects to serve THIS requester for free (`mode: any`, or
// `mode: direct` with the caller's DID listed). A matched job is unmetered,
// zero-price, and takes no exchange cut, so a balance-less requester can still
// get a completion. Fails closed (503 `no_pro_bono_providers`) when no
// connected provider currently offers the caller pro bono. `country` still
// narrows by region. The handler is shared with the legacy
// `/api/v1/probono/chat/completions` mount.

import { createFileRoute } from "@tanstack/react-router";

import { handleProBonoChatCompletions } from "@/lib/openai-routes.server.ts";

export const Route = createFileRoute("/v1/probono/chat/completions")({
  server: {
    handlers: {
      POST: ({ request }) => handleProBonoChatCompletions(request),
    },
  },
});
