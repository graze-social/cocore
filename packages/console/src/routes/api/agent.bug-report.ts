// POST /api/agent/bug-report
//
// Bearer-key authed upload of a provider diagnostic bundle for the
// menu-bar app's one-click "Send bug report". The tray app shells out
// to `cocore agent diag --out <path>`, which writes a content-safe
// `.tar.gz` (crash logs, redacted session, system profile, macOS crash
// reports — NO prompts, NO api key, NO signing key), then POSTs the
// bytes here with the same `Authorization: Bearer <apiKey>` (the
// session.json apiKey) the agent already uses for /api/agent/status and
// /api/agent/whoami.
//
// The handler validates content-type + size, stores the bundle on the
// filesystem next to the console DB (see bug-reports.server.ts), records
// a metadata row keyed by the uploader's DID — including the reporter's
// own note from `X-Cocore-Note`, which the tray has always sent and this
// route used to discard — and returns { ticketId }.
//
// We deliberately never read or log the bundle's contents — the bytes
// land on disk untouched and the response carries only the ticket id.

import { createFileRoute } from "@tanstack/react-router";

import { resolveBearerKey } from "@/lib/api-keys.server.ts";
import { BUNDLE_CONTENT_TYPE, MAX_BUNDLE_BYTES, storeBugReport } from "@/lib/bug-reports.server.ts";

function readBearer(request: Request): string | null {
  const h = request.headers.get("authorization");
  if (!h) return null;
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1]!.trim() : null;
}

function jsonError(status: number, message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

// Accept the canonical gzip type plus the couple of equivalents
// different HTTP clients emit for a .tar.gz, so a correctly-formed
// upload isn't rejected on a content-type technicality.
const ACCEPTED_CONTENT_TYPES = new Set([
  BUNDLE_CONTENT_TYPE,
  "application/x-gzip",
  "application/x-tar",
  "application/octet-stream",
]);

export const Route = createFileRoute("/api/agent/bug-report")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const bearer = readBearer(request);
        if (!bearer) return jsonError(401, "missing Authorization: Bearer header");
        const resolved = resolveBearerKey(bearer);
        if (!resolved) return jsonError(401, "invalid API key");

        // Content-type gate: only gzipped tarballs. The agent always
        // sends application/gzip; the extra accepted types cover clients
        // that label a .tar.gz differently.
        const contentType = (request.headers.get("content-type") ?? "")
          .split(";")[0]!
          .trim()
          .toLowerCase();
        if (!ACCEPTED_CONTENT_TYPES.has(contentType)) {
          return jsonError(
            415,
            `unsupported content-type ${contentType || "(none)"}; expected ${BUNDLE_CONTENT_TYPE}`,
          );
        }

        // Cheap pre-check on the declared length so we can reject an
        // oversized upload before buffering it. Not authoritative (a
        // client can lie or omit it), so we re-check the actual byte
        // count after reading.
        const declaredLen = Number(request.headers.get("content-length") ?? "");
        if (Number.isFinite(declaredLen) && declaredLen > MAX_BUNDLE_BYTES) {
          return jsonError(
            413,
            `bundle too large: ${declaredLen} bytes exceeds ${MAX_BUNDLE_BYTES}`,
          );
        }

        let bytes: Buffer;
        try {
          const ab = await request.arrayBuffer();
          bytes = Buffer.from(ab);
        } catch {
          return jsonError(400, "could not read request body");
        }

        if (bytes.byteLength === 0) return jsonError(400, "empty bundle");
        // Authoritative size check against the bytes we actually read.
        if (bytes.byteLength > MAX_BUNDLE_BYTES) {
          return jsonError(
            413,
            `bundle too large: ${bytes.byteLength} bytes exceeds ${MAX_BUNDLE_BYTES}`,
          );
        }

        // The reporter's description of what went wrong. The tray sends it
        // as a header alongside the bundle; persisting it is the difference
        // between triaging a symptom and guessing at one from logs.
        const stored = storeBugReport({
          did: resolved.did,
          bytes,
          note: request.headers.get("x-cocore-note"),
        });

        return new Response(JSON.stringify({ ticketId: stored.ticketId }), {
          status: 201,
          headers: { "content-type": "application/json" },
        });
      },
    },
  },
});
