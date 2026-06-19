// GET /.well-known/did.json
//
// did:web DID document for the cocore console itself. Publishing it is
// what lets a requester's PDS reach our XRPC surface via service
// proxying: the client sends `atproto-proxy: <consoleDid>#cocore_console`
// to its own PDS, the PDS resolves this document, finds the matching
// service entry, mints a JWT signed by the user's repo key, and POSTs
// to `<serviceEndpoint>/xrpc/<nsid>`. We verify that JWT in
// service-auth.server.ts (the `aud` must equal this document's `id`).
//
// did:web:<host> (no path) resolves to https://<host>/.well-known/did.json,
// so the `id` is derived from CONSOLE_PUBLIC_URL and MUST match the host
// the resolver hit. The exchange's document (see exchange.did[.]json.ts)
// is the path-form sibling (did:web:<host>:exchange).
//
// No verificationMethod block: the console doesn't sign anything with
// this DID, it only *verifies* inbound JWTs (whose signing keys live in
// the requester's DID document, not ours).

import { createFileRoute } from "@tanstack/react-router";

function consoleDidFor(request: Request): string {
  const explicit = process.env["CONSOLE_PUBLIC_URL"];
  const url = explicit ?? request.url;
  const host = new URL(url).host;
  // host with `:port` becomes `%3Aport` per did:web spec.
  const encoded = host.replace(":", "%3A");
  return `did:web:${encoded}`;
}

export const Route = createFileRoute("/.well-known/did.json")({
  server: {
    handlers: {
      GET: ({ request }) => {
        const did = consoleDidFor(request);
        const baseUrl =
          process.env["CONSOLE_PUBLIC_URL"]?.replace(/\/$/, "") ?? new URL(request.url).origin;

        const doc = {
          id: did,
          // The fragment a client names in `atproto-proxy`. The PDS
          // appends `/xrpc/<nsid>` to serviceEndpoint, so our account
          // endpoints live at <baseUrl>/xrpc/dev.cocore.account.*.
          service: [
            {
              id: "#cocore_console",
              type: "CocoreConsole",
              serviceEndpoint: baseUrl,
            },
          ],
        };
        return new Response(JSON.stringify(doc), {
          status: 200,
          headers: {
            "content-type": "application/did+json",
            "cache-control": "public, max-age=300",
          },
        });
      },
    },
  },
});
