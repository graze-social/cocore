// POST /api/pds/getServiceAuth
//
// Canonical internal endpoint that mints a short-lived atproto service-auth
// JWT on the caller's PDS via the console's DPoP-bound OAuth session. Bearer-key
// auth resolves the key → DID; the token is signed by that DID's repo key, so a
// caller can only mint a token asserting its own identity. Body: `{ aud, lxm }`.
// Returns `{ token }`. See lib/pds-write.server.ts for the implementation and
// the rationale (the Rust agent can't mint DPoP/service-auth tokens itself, so
// it posts here — this is what backs the advisor's DID-bound registration).

import { createFileRoute } from "@tanstack/react-router";

import { pdsGetServiceAuth } from "@/lib/pds-write.server.ts";

export const Route = createFileRoute("/api/pds/getServiceAuth")({
  server: {
    handlers: {
      POST: ({ request }) => pdsGetServiceAuth(request),
    },
  },
});
