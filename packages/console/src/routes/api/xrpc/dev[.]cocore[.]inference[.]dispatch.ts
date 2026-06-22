// POST /xrpc/dev.cocore.inference.dispatch
//
// Browser-facing dispatch endpoint. Authenticates via the OAuth session
// cookie, then EITHER forwards the dispatch to the AppView's SSE XRPC
// endpoint (when COCORE_APPVIEW_INTERNAL_URL + COCORE_APPVIEW_DID are set —
// the AppView now owns the dispatch core, OAuth session, and Store) OR runs
// the in-process dispatch core (`@/lib/inference-dispatch.server.ts`) as a
// legacy fallback. Either way the response is the same SSE shape. The
// OpenAI-compatible shim at `/api/v1/chat/completions` still uses the local
// core with API-key auth.
//
// Output: text/event-stream. Events:
//   * `meta`     — { jobUri, jobCid, authUri, inputCommitment, providerDid }
//   * `chunk`    — { seq, text }   (plaintext, decrypted)
//   * `complete` — { tokensIn, tokensOut, receiptUri }
//   * `error`    — { reason, code }   (code: DispatchErrorCode)

import { createFileRoute } from "@tanstack/react-router";

import {
  forwardDispatch,
  isDispatchForwardConfigured,
} from "@/lib/inference-dispatch-forward.server.ts";
import { runDispatch } from "@/lib/inference-dispatch.server.ts";
import { getAtprotoSessionForRequest } from "@/middleware/auth.server.ts";

interface DispatchBody {
  model?: unknown;
  prompt?: unknown;
  maxTokensOut?: unknown;
  priceCeiling?: unknown;
  targetProviderDid?: unknown;
}

interface ParsedDispatch {
  model: string;
  prompt: string;
  maxTokensOut: number;
  priceCeiling: { amount: number; currency: string };
  targetProviderDid?: string;
}

function parseDispatch(body: DispatchBody): ParsedDispatch | string {
  if (typeof body.model !== "string" || body.model.length === 0) return "model required";
  if (typeof body.prompt !== "string" || body.prompt.length === 0) return "prompt required";
  if (
    typeof body.maxTokensOut !== "number" ||
    !Number.isInteger(body.maxTokensOut) ||
    body.maxTokensOut < 1
  ) {
    return "maxTokensOut must be a positive integer";
  }
  const pc = body.priceCeiling as { amount?: unknown; currency?: unknown } | undefined;
  if (
    !pc ||
    typeof pc.amount !== "number" ||
    !Number.isInteger(pc.amount) ||
    pc.amount < 0 ||
    typeof pc.currency !== "string" ||
    pc.currency.length === 0
  ) {
    return "priceCeiling must be { amount: int, currency: string }";
  }
  if (body.targetProviderDid !== undefined && typeof body.targetProviderDid !== "string") {
    return "targetProviderDid must be a string when provided";
  }
  return {
    model: body.model,
    prompt: body.prompt,
    maxTokensOut: body.maxTokensOut,
    priceCeiling: { amount: pc.amount, currency: pc.currency },
    ...(typeof body.targetProviderDid === "string"
      ? { targetProviderDid: body.targetProviderDid }
      : {}),
  };
}

function sseFrame(event: string, data: string): Uint8Array {
  return new TextEncoder().encode(`event: ${event}\ndata: ${data}\n\n`);
}

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export const Route = createFileRoute("/api/xrpc/dev.cocore.inference.dispatch")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const session = await getAtprotoSessionForRequest(request);
        if (!session) return json({ error: "not authenticated" }, 401);

        let body: DispatchBody;
        try {
          body = (await request.json()) as DispatchBody;
        } catch {
          return json({ error: "bad json" }, 400);
        }
        const parsed = parseDispatch(body);
        if (typeof parsed === "string") return json({ error: parsed }, 400);

        // Forward to the AppView when configured (it owns the dispatch core +
        // the requester's OAuth session); otherwise run the legacy in-process
        // core below. Both yield the same SSE shape.
        if (isDispatchForwardConfigured()) {
          return forwardDispatch({ oauthSession: session.oauthSession, body: { ...parsed } });
        }

        const events = runDispatch({
          did: session.did,
          oauthSession: session.oauthSession,
          ...parsed,
        });

        const stream = new ReadableStream<Uint8Array>({
          async start(controller) {
            try {
              for await (const ev of events) {
                if (ev.kind === "meta") {
                  controller.enqueue(
                    sseFrame(
                      "meta",
                      JSON.stringify({
                        jobUri: ev.jobUri,
                        jobCid: ev.jobCid,
                        authUri: ev.authUri,
                        inputCommitment: ev.inputCommitment,
                        providerDid: ev.providerDid,
                        sessionId: ev.sessionId,
                      }),
                    ),
                  );
                } else if (ev.kind === "chunk") {
                  controller.enqueue(
                    sseFrame(
                      "chunk",
                      JSON.stringify({ seq: ev.seq, channel: ev.channel, text: ev.text }),
                    ),
                  );
                } else if (ev.kind === "complete") {
                  controller.enqueue(
                    sseFrame(
                      "complete",
                      JSON.stringify({
                        tokensIn: ev.tokensIn,
                        tokensOut: ev.tokensOut,
                        receiptUri: ev.receiptUri,
                        ...(ev.providerCredit ? { providerCredit: ev.providerCredit } : {}),
                      }),
                    ),
                  );
                } else if (ev.kind === "error") {
                  controller.enqueue(
                    sseFrame("error", JSON.stringify({ reason: ev.reason, code: ev.code })),
                  );
                }
              }
            } finally {
              controller.close();
            }
          },
        });

        return new Response(stream, {
          status: 200,
          headers: {
            "content-type": "text/event-stream; charset=utf-8",
            "cache-control": "no-cache, no-transform",
            "x-accel-buffering": "no",
          },
        });
      },
    },
  },
});
