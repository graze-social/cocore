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
  buildEnvelopeBytes,
  coerceEnvelopeMessages,
  type EnvelopeMessage,
  hasImageParts,
  MESSAGES_V1,
} from "@cocore/sdk/multimodal-envelope";

import {
  forwardDispatch,
  isDispatchForwardConfigured,
} from "@/lib/inference-dispatch-forward.server.ts";
import { runDispatch } from "@/lib/inference-dispatch.server.ts";
import { resolveProBonoProviderKeys } from "@/lib/pro-bono.server.ts";
import { getAtprotoSessionForRequest } from "@/middleware/auth.server.ts";

interface DispatchBody {
  model?: unknown;
  prompt?: unknown;
  /** Optional structured multimodal turns. When present and carrying any
   *  image part, the dispatch seals the canonical messages-v1 envelope
   *  instead of the flattened `prompt`. */
  messages?: unknown;
  maxTokensOut?: unknown;
  priceCeiling?: unknown;
  targetProviderDid?: unknown;
  targetMachineId?: unknown;
  /** Optional ISO 3166-1 alpha-2 country to route by (advisory region match). */
  country?: unknown;
  /** When true, route ONLY to providers whose `proBono` policy serves this
   *  requester for free (the pro-bono completion path). */
  proBono?: unknown;
}

interface ParsedDispatch {
  model: string;
  prompt: string;
  /** Validated multimodal turns, only set when the client sent images. */
  messages?: EnvelopeMessage[];
  maxTokensOut: number;
  priceCeiling: { amount: number; currency: string };
  targetProviderDid?: string;
  /** Specific machine under targetProviderDid. Only forwarded when
   *  targetProviderDid is also set. */
  targetMachineId?: string;
  /** Normalized ISO 3166-1 alpha-2 country filter (uppercased). */
  country?: string;
  /** True when the caller requested the pro-bono path. Resolved to an
   *  `allowedProviderDids` allow-set in the handler (needs the requester DID). */
  proBono: boolean;
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
  if (body.targetMachineId !== undefined && typeof body.targetMachineId !== "string") {
    return "targetMachineId must be a string when provided";
  }
  let country: string | undefined;
  // `null` (an explicit "no country") is treated the same as absent, so a
  // client that sends `country: null` isn't rejected with a misleading 400.
  if (body.country !== undefined && body.country !== null) {
    if (typeof body.country !== "string" || !/^[A-Za-z]{2}$/.test(body.country.trim())) {
      return "country must be a 2-letter ISO 3166-1 alpha-2 code";
    }
    country = body.country.trim().toUpperCase();
  }
  if (body.proBono !== undefined && typeof body.proBono !== "boolean") {
    return "proBono must be a boolean when provided";
  }
  // `messages` is optional; only validated (and only matters) when images
  // ride along. An explicitly-present-but-malformed value is a 400.
  let messages: EnvelopeMessage[] | undefined;
  if (body.messages !== undefined) {
    const coerced = coerceEnvelopeMessages(body.messages);
    if (!coerced) return "messages must be an array of { role, content } turns";
    if (hasImageParts(coerced)) messages = coerced;
  }
  return {
    model: body.model,
    prompt: body.prompt,
    ...(messages ? { messages } : {}),
    maxTokensOut: body.maxTokensOut,
    priceCeiling: { amount: pc.amount, currency: pc.currency },
    ...(typeof body.targetProviderDid === "string"
      ? { targetProviderDid: body.targetProviderDid }
      : {}),
    ...(typeof body.targetProviderDid === "string" && typeof body.targetMachineId === "string"
      ? { targetMachineId: body.targetMachineId }
      : {}),
    ...(country ? { country } : {}),
    proBono: body.proBono === true,
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

        // The pro-bono path: route ONLY to the specific machines whose policy
        // serves this requester free. We resolve WHICH machines offer them pro
        // bono here (the console has the AppView read + the requester DID) as
        // composite `did:machineId` keys, then forward / pass the allow-set so
        // either core just filters. Machine-granular (not DID-granular) so an
        // owner's other, billed machines never satisfy the pro-bono request.
        // Fail closed if nobody does.
        const { proBono, ...rest } = parsed;
        let allowedProviderDids: string[] | undefined;
        if (proBono) {
          try {
            const set = await resolveProBonoProviderKeys(session.did);
            if (set.size === 0) {
              return json(
                {
                  error:
                    "no provider currently offers you pro-bono compute; turn off pro bono for a normal (billed) request",
                  // snake_case to match the documented `no_pro_bono_providers`
                  // code emitted by /v1/probono/chat/completions + openapi.yaml,
                  // so the same failure has one spelling across both endpoints.
                  code: "no_pro_bono_providers",
                },
                503,
              );
            }
            allowedProviderDids = [...set];
          } catch (e) {
            return json({ error: `pro-bono lookup failed: ${(e as Error).message}` }, 502);
          }
        }

        // Forward to the AppView when configured (it owns the dispatch core +
        // the requester's OAuth session); otherwise run the legacy in-process
        // core below. Both yield the same SSE shape. The forwarded body carries
        // the RAW `messages` (JSON-serializable) — the AppView route rebuilds
        // the envelope on its side; we don't ship binary payloadBytes.
        if (isDispatchForwardConfigured()) {
          return forwardDispatch({
            oauthSession: session.oauthSession,
            body: { ...rest, ...(allowedProviderDids ? { allowedProviderDids } : {}) },
          });
        }

        // Local in-process core: seal the canonical multimodal envelope when
        // images are present, else the flattened prompt.
        const { messages, ...textInputs } = rest;
        const envelope = messages
          ? { payloadBytes: buildEnvelopeBytes(messages), inputFormat: MESSAGES_V1 }
          : {};
        const events = runDispatch({
          did: session.did,
          oauthSession: session.oauthSession,
          ...textInputs,
          ...envelope,
          ...(allowedProviderDids ? { allowedProviderDids: new Set(allowedProviderDids) } : {}),
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
