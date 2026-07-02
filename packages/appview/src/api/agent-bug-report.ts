// POST /agent/bug-report (+ /api/agent/bug-report alias)
//
// Bearer-key authed upload of a provider diagnostic bundle from the
// menu-bar app's one-click "Send bug report", served by the AppView for
// device-pair'd agents whose apiBase points here (the console serves the
// same route for console-paired agents — each resolves the keys it
// minted). Mirrors the console handler: validate content-type + size,
// store the gzip bytes on the AppView volume, record a metadata row keyed
// by DID, return { ticketId }.
//
// We deliberately never read or log the bundle's contents — the bytes land
// on disk untouched and the response carries only the ticket id.

import { HttpRouter, HttpServerRequest, HttpServerResponse } from "@effect/platform";
import { Effect } from "effect";

import { bearer, err, header } from "@cocore/o11y/http";

import type { AccountStore } from "../operational/account-store.ts";

export interface AgentBugReportContext {
  accounts: AccountStore;
}

/** Hard ceiling on an accepted bundle (matches the console). The diag
 *  bundle is content-safe and small in practice; 25 MB is generous
 *  headroom while bounding what an authenticated client can push. */
const MAX_BUNDLE_BYTES = 25 * 1024 * 1024;
const BUNDLE_CONTENT_TYPE = "application/gzip";
// Per-DID rolling-window quota (L8). Without it any key holder can push
// unlimited 25 MB bundles and fill the volume. A day's window with these caps
// still leaves ample room for a genuine "send a few bug reports" flow while
// bounding the worst case to ~250 MB/DID/day.
const QUOTA_WINDOW_MS = 24 * 60 * 60 * 1000;
const QUOTA_MAX_COUNT = 10;
const QUOTA_MAX_BYTES = 250 * 1024 * 1024;
// Accept the canonical gzip type plus equivalents different HTTP clients
// emit for a .tar.gz, so a correct upload isn't rejected on a technicality.
const ACCEPTED_CONTENT_TYPES = new Set([
  BUNDLE_CONTENT_TYPE,
  "application/x-gzip",
  "application/x-tar",
  "application/octet-stream",
]);

export function buildAgentBugReportRouter(
  ctx: AgentBugReportContext,
): HttpRouter.HttpRouter<never, never> {
  return HttpRouter.empty.pipe(
    HttpRouter.post(
      "/agent/bug-report",
      Effect.gen(function* () {
        const token = yield* bearer;
        if (!token)
          return err(401, {
            error: "AuthRequired",
            message: "missing Authorization: Bearer header",
          });
        const resolved = ctx.accounts.resolveBearerKey(token);
        if (!resolved) return err(401, { error: "AuthRequired", message: "invalid API key" });

        // Content-type gate: only gzipped tarballs.
        const contentType = ((yield* header("content-type")) ?? "")
          .split(";")[0]!
          .trim()
          .toLowerCase();
        if (!ACCEPTED_CONTENT_TYPES.has(contentType)) {
          return err(415, {
            error: "UnsupportedMediaType",
            message: `unsupported content-type ${contentType || "(none)"}; expected ${BUNDLE_CONTENT_TYPE}`,
          });
        }

        // Cheap pre-check on the declared length before buffering. Not
        // authoritative (a client can lie or omit it); re-checked below.
        const declaredLen = Number((yield* header("content-length")) ?? "");
        if (Number.isFinite(declaredLen) && declaredLen > MAX_BUNDLE_BYTES) {
          return err(413, {
            error: "PayloadTooLarge",
            message: `bundle too large: ${declaredLen} bytes exceeds ${MAX_BUNDLE_BYTES}`,
          });
        }

        const req = yield* HttpServerRequest.HttpServerRequest;
        const body = yield* Effect.either(req.arrayBuffer);
        if (body._tag === "Left")
          return err(400, { error: "InvalidRequest", message: "could not read request body" });
        const bytes = Buffer.from(body.right);

        if (bytes.byteLength === 0)
          return err(400, { error: "InvalidRequest", message: "empty bundle" });
        // Authoritative size check against the bytes we actually read.
        if (bytes.byteLength > MAX_BUNDLE_BYTES) {
          return err(413, {
            error: "PayloadTooLarge",
            message: `bundle too large: ${bytes.byteLength} bytes exceeds ${MAX_BUNDLE_BYTES}`,
          });
        }

        // Per-DID quota (L8): reject once this DID's rolling-window count or
        // total bytes (including this upload) would exceed the cap.
        const sinceIso = new Date(Date.now() - QUOTA_WINDOW_MS).toISOString();
        const usage = ctx.accounts.bugReportUsageForDid(resolved.did, sinceIso);
        if (
          usage.count + 1 > QUOTA_MAX_COUNT ||
          usage.totalBytes + bytes.byteLength > QUOTA_MAX_BYTES
        ) {
          return err(429, {
            error: "TooManyRequests",
            message: "bug-report upload quota exceeded; try again later",
          });
        }

        const stored = ctx.accounts.storeBugReport({ did: resolved.did, bytes });
        return HttpServerResponse.text(JSON.stringify({ ticketId: stored.ticketId }), {
          contentType: "application/json",
          status: 201,
        });
      }).pipe(Effect.withSpan("appview.agent.bugReport")),
    ),
  );
}
