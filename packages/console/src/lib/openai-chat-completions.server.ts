// Shared bits between `/api/v1/chat/completions` (open network) and
// `/api/v1/private/chat/completions` (friends-only). Both routes
// authenticate the same way, parse the same OpenAI request shape,
// stream / buffer the same response shape, and differ only in
// whether they pass `allowedProviderDids` to runDispatch.
//
// Splitting them was originally tempting but the body of the two
// routes was 95% identical; lifting the shared logic here keeps a
// single error-mapping table (the source of truth for which
// DispatchErrorCode → which HTTP status the OpenAI client sees).

import {
  buildEnvelopeBytes,
  type EnvelopeContentPart,
  type EnvelopeImagePart,
  type EnvelopeMessage,
  hasImageParts,
  MESSAGES_V1,
} from "@cocore/sdk/multimodal-envelope";

import type {
  DispatchErrorCode,
  DispatchEvent,
  ProviderCredit,
} from "@/lib/inference-dispatch.server.ts";

/** A remote (http/https) image that still needs fetching before it can go
 *  into the sealed envelope. Produced by the sync `normalizeMessageContent`
 *  and resolved to an inline `EnvelopeImagePart` by `resolveImages`. */
interface RemoteImagePart {
  type: "image_remote";
  url: string;
}

/** Content after sync normalization: a plain string (text-only), or an
 *  ordered list of parts where images may still be remote. */
type NormalizedPart = EnvelopeContentPart | RemoteImagePart;
type NormalizedContent = string | NormalizedPart[];

interface ChatMessage {
  role: string;
  content: NormalizedContent;
}

export interface OpenAiChatRequest {
  model?: unknown;
  messages?: unknown;
  stream?: unknown;
  max_tokens?: unknown;
  user?: unknown;
  /** Optional ISO 3166-1 alpha-2 country code (e.g. "US"). When set, the
   *  request is routed only to providers that publish a matching coarse
   *  `region` on their provider record. Advisory routing, not a guarantee:
   *  the region is a provider self-claim (see the provider lexicon). */
  country?: unknown;
}

export interface ParsedRequest {
  model: string;
  messages: ChatMessage[];
  stream: boolean;
  maxTokens: number;
  /** Normalized ISO 3166-1 alpha-2 country filter (uppercased), or
   *  undefined when the caller didn't request country routing. */
  country?: string;
}

const DEFAULT_MAX_TOKENS = 1024;
// Upper bounds so a single request can't exhaust the console/provider or
// drive an uncapped per-call spend. Generous for real chat use; reject
// early with a 400 past them rather than sealing + dispatching a giant job.
const MAX_MESSAGES = 256;
const MAX_PROMPT_BYTES = 1024 * 1024; // 1 MiB of total TEXT content
// Images are inlined (base64) into the sealed envelope, so they need their
// own, larger budget separate from text. 20 MiB of decoded image bytes
// covers several high-res photos while still bounding a single request
// (the advisor's /jobs body cap is sized to match — see jobs.ts).
const MAX_IMAGE_BYTES = 20 * 1024 * 1024;
const MAX_OUTPUT_TOKENS = 32_768;

/** Parse an OpenAI `image_url` URL into an envelope image part (data
 *  URIs, resolved inline) or a remote part to fetch later (http/https).
 *  Returns null for anything we can't turn into an image. */
function parseImageUrl(url: unknown): EnvelopeImagePart | RemoteImagePart | null {
  if (typeof url !== "string" || url.length === 0) return null;
  // data:<mime>;base64,<payload>
  const dataMatch = /^data:([^;,]+);base64,(.*)$/s.exec(url);
  if (dataMatch) {
    const mime = dataMatch[1]!;
    const data = dataMatch[2]!;
    if (!mime.startsWith("image/")) return null;
    return { type: "image", mime, data };
  }
  if (url.startsWith("http://") || url.startsWith("https://")) {
    return { type: "image_remote", url };
  }
  return null;
}

/** Normalize OpenAI `message.content` into the canonical form. Accepts:
 *    * the plain string form (simple clients),
 *    * the array-of-parts form Cursor / the modern OpenAI SDK emit:
 *        [{ type: "text", text: "…" },
 *         { type: "image_url", image_url: { url: "data:image/png;base64,…" } }]
 *  A text-only message collapses to a plain string (byte-identical to the
 *  legacy path). A message carrying any image returns an ordered parts
 *  array (images may still be remote — see `resolveImages`). Returns null
 *  for a part shape we can't interpret (e.g. an unknown type, or an
 *  unparseable image url). */
export function normalizeMessageContent(content: unknown): NormalizedContent | null {
  if (typeof content === "string") return content;
  if (content === null || content === undefined) return "";
  if (!Array.isArray(content)) return null;

  const parts: NormalizedPart[] = [];
  let sawImage = false;
  let sawUnsupported = false;
  for (const part of content) {
    if (!part || typeof part !== "object") continue;
    const p = part as { type?: unknown; text?: unknown; image_url?: unknown };
    if (p.type === "text" && typeof p.text === "string") {
      parts.push({ type: "text", text: p.text });
      continue;
    }
    if (p.type === "image_url") {
      const urlObj = p.image_url as { url?: unknown } | undefined;
      const img = parseImageUrl(urlObj?.url);
      if (!img) {
        sawUnsupported = true;
        continue;
      }
      parts.push(img);
      sawImage = true;
      continue;
    }
    if (typeof p.type === "string") {
      sawUnsupported = true;
    }
  }
  // Any image present → keep the structured parts (multimodal path).
  if (sawImage) return parts;
  // No image: an unsupported/unparseable part with no text is a reject,
  // matching the historical text-only contract.
  if (sawUnsupported) return null;
  // Text-only: collapse to a plain string so the sealed bytes are
  // identical to the legacy flattened path.
  const text = parts
    .filter((p): p is { type: "text"; text: string } => p.type === "text")
    .map((p) => p.text)
    .join("\n");
  return text;
}

export function parseRequest(raw: OpenAiChatRequest): ParsedRequest | string {
  if (typeof raw.model !== "string" || raw.model.length === 0) return "model required";
  if (!Array.isArray(raw.messages) || raw.messages.length === 0) {
    return "messages must be a non-empty array";
  }
  if (raw.messages.length > MAX_MESSAGES) {
    return `too many messages (max ${MAX_MESSAGES})`;
  }
  const messages: ChatMessage[] = [];
  let promptBytes = 0;
  let imageBytes = 0;
  for (const m of raw.messages as Array<{ role?: unknown; content?: unknown }>) {
    if (typeof m.role !== "string") {
      return "each message must include a string role";
    }
    const content = normalizeMessageContent(m.content);
    if (content === null) {
      return 'message content must be a string or an array of { type: "text", text } / { type: "image_url", image_url: { url } } parts';
    }
    // Budget text and images separately — images are large and inlined.
    if (typeof content === "string") {
      promptBytes += Buffer.byteLength(content, "utf-8");
    } else {
      for (const part of content) {
        if (part.type === "text") {
          promptBytes += Buffer.byteLength(part.text, "utf-8");
        } else if (part.type === "image") {
          // base64 → decoded size ≈ len * 3/4.
          imageBytes += Math.floor((part.data.length * 3) / 4);
        }
        // remote images are budgeted after fetch in resolveImages.
      }
    }
    if (promptBytes > MAX_PROMPT_BYTES) {
      return `prompt too large (max ${MAX_PROMPT_BYTES} bytes)`;
    }
    if (imageBytes > MAX_IMAGE_BYTES) {
      return `images too large (max ${MAX_IMAGE_BYTES} bytes total)`;
    }
    messages.push({ role: m.role, content });
  }
  let maxTokens = DEFAULT_MAX_TOKENS;
  if (raw.max_tokens !== undefined) {
    if (
      typeof raw.max_tokens !== "number" ||
      !Number.isInteger(raw.max_tokens) ||
      raw.max_tokens < 1
    ) {
      return "max_tokens must be a positive integer";
    }
    if (raw.max_tokens > MAX_OUTPUT_TOKENS) {
      return `max_tokens exceeds limit (max ${MAX_OUTPUT_TOKENS})`;
    }
    maxTokens = raw.max_tokens;
  }
  const stream = typeof raw.stream === "boolean" ? raw.stream : false;
  let country: string | undefined;
  // `null` (an explicit "no country") is treated the same as absent, so a
  // client that sends `country: null` isn't rejected with a misleading 400.
  if (raw.country !== undefined && raw.country !== null) {
    if (typeof raw.country !== "string" || !/^[A-Za-z]{2}$/.test(raw.country.trim())) {
      return "country must be a 2-letter ISO 3166-1 alpha-2 code";
    }
    country = raw.country.trim().toUpperCase();
  }
  return { model: raw.model, messages, stream, maxTokens, country };
}

/** The flattened text of one message's content (image parts contribute
 *  their text only). */
function messageText(content: NormalizedContent): string {
  if (typeof content === "string") return content;
  return content
    .filter((p): p is { type: "text"; text: string } => p.type === "text")
    .map((p) => p.text)
    .join("\n");
}

/** Flatten OpenAI `messages` into a single prompt string (legacy text
 *  path). Images are ignored here; a request carrying images takes the
 *  envelope path (`buildJobInput`) instead. */
function flattenMessages(messages: ChatMessage[]): string {
  return messages.map((m) => `${m.role}: ${messageText(m.content)}`).join("\n");
}

/** True when any message carries an image (the request must travel as a
 *  messages-v1 envelope). */
export function requestHasImages(messages: ChatMessage[]): boolean {
  return messages.some((m) => typeof m.content !== "string");
}

/** Fetch every remote (http/https) image into an inline base64 part, so
 *  the whole input can be sealed as one self-contained envelope. Enforces
 *  the same total image budget as inline data URIs. Returns the canonical
 *  `EnvelopeMessage[]` or throws on a fetch/size failure. */
async function resolveImages(messages: ChatMessage[]): Promise<EnvelopeMessage[]> {
  let imageBytes = 0;
  const out: EnvelopeMessage[] = [];
  for (const m of messages) {
    if (typeof m.content === "string") {
      out.push({ role: m.role, content: m.content });
      continue;
    }
    const resolved: EnvelopeContentPart[] = [];
    for (const part of m.content) {
      if (part.type === "text") {
        resolved.push(part);
        continue;
      }
      if (part.type === "image") {
        imageBytes += Math.floor((part.data.length * 3) / 4);
        resolved.push(part);
        continue;
      }
      // Remote image: fetch + inline.
      const res = await fetch(part.url);
      if (!res.ok) throw new Error(`failed to fetch image ${part.url}: ${res.status}`);
      const mime = res.headers.get("content-type")?.split(";")[0]?.trim() || "image/jpeg";
      if (!mime.startsWith("image/")) {
        throw new Error(`image url ${part.url} returned non-image content-type ${mime}`);
      }
      const buf = new Uint8Array(await res.arrayBuffer());
      imageBytes += buf.byteLength;
      if (imageBytes > MAX_IMAGE_BYTES) {
        throw new Error(`images too large (max ${MAX_IMAGE_BYTES} bytes total)`);
      }
      resolved.push({ type: "image", mime, data: Buffer.from(buf).toString("base64") });
    }
    out.push({ role: m.role, content: resolved });
  }
  return out;
}

/** Build the sealed-payload bytes + the job's `inputFormat` for a parsed
 *  request. Text-only requests use the legacy flattened-string bytes (so
 *  `inputCommitment` is unchanged); requests with images resolve remote
 *  images and serialize the canonical messages-v1 envelope. */
export async function buildJobInput(
  messages: ChatMessage[],
): Promise<{ payloadBytes: Uint8Array; inputFormat?: typeof MESSAGES_V1 }> {
  if (!requestHasImages(messages)) {
    return { payloadBytes: new TextEncoder().encode(flattenMessages(messages)) };
  }
  const envelopeMessages = await resolveImages(messages);
  if (!hasImageParts(envelopeMessages)) {
    // All images turned out to be unresolved/empty — fall back to text.
    return { payloadBytes: new TextEncoder().encode(flattenMessages(messages)) };
  }
  return { payloadBytes: buildEnvelopeBytes(envelopeMessages), inputFormat: MESSAGES_V1 };
}

export function jsonError(
  status: number,
  message: string,
  type = "invalid_request_error",
  code: string | null = null,
): Response {
  // OpenAI error envelope so SDK error handling lights up correctly.
  // We include the `code` field in the body when known — OpenAI's
  // own API populates this for some errors (`model_not_found`,
  // `invalid_api_key`, etc.) and clients often switch on it.
  return new Response(JSON.stringify({ error: { message, type, code, param: null } }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export function readBearer(request: Request): string | null {
  const h = request.headers.get("authorization");
  if (!h) return null;
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1]!.trim() : null;
}

interface OpenAiChunkChoice {
  index: 0;
  delta: { role?: "assistant"; content?: string; reasoning_content?: string };
  finish_reason: null | "stop";
}

function chunkPayload(
  id: string,
  model: string,
  delta: OpenAiChunkChoice["delta"],
  finishReason: OpenAiChunkChoice["finish_reason"],
  extra?: Record<string, unknown>,
): string {
  return JSON.stringify({
    id,
    object: "chat.completion.chunk",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [{ index: 0, delta, finish_reason: finishReason }],
    ...extra,
  });
}

/** The non-standard `x_cocore` block we staple onto chat completions
 *  so a response can say *who* ran it — the human + machine behind the
 *  result, plus the on-chain receipt. OpenAI clients ignore unknown
 *  top-level fields, so this is invisible to vanilla SDKs but available
 *  to anyone who looks. */
function cocoreMeta(
  credit: ProviderCredit | undefined,
  receiptUri: string | null,
): { x_cocore: Record<string, unknown> } | undefined {
  if (!credit && !receiptUri) return undefined;
  return {
    x_cocore: {
      ...(credit
        ? {
            credit: credit.line,
            provider: {
              did: credit.did,
              handle: credit.handle,
              displayName: credit.displayName,
              machineLabel: credit.machineLabel,
            },
          }
        : {}),
      ...(receiptUri ? { receiptUri } : {}),
    },
  };
}

/** Map a DispatchErrorCode to the (HTTP status, OpenAI error type,
 *  OpenAI error code) tuple. The string `code` is what OpenAI's own
 *  API would populate; we re-use their vocabulary where it exists
 *  (`model_not_found`) and coin our own for cocore-specific cases
 *  (`no_friends_available`).
 *
 *  Centralized so the two route handlers and the test suite all
 *  agree on the mapping. */
export function dispatchErrorToHttpResponse(errorCode: DispatchErrorCode): {
  status: number;
  type: string;
  code: string;
} {
  switch (errorCode) {
    case "no-providers-connected":
      return {
        status: 503,
        type: "service_unavailable_error",
        code: "no_providers_connected",
      };
    case "no-providers-for-model":
      // OpenAI's own vocab for "the model isn't a thing." Returning
      // 404 here lines up with what clients expect when they ask
      // for a model the API doesn't know about.
      return { status: 404, type: "invalid_request_error", code: "model_not_found" };
    case "no-providers-for-country":
      // The model exists but no provider in the requested country serves it.
      // 503 (capacity-shaped, retryable) rather than 404 — the model IS known,
      // there's just no provider in that region right now.
      return {
        status: 503,
        type: "service_unavailable_error",
        code: "no_providers_for_country",
      };
    case "no-friends-available":
      return {
        status: 503,
        type: "service_unavailable_error",
        code: "no_friends_available",
      };
    case "no-friends-for-model":
      // 404 because from the user's perspective this is "no
      // (trusted) provider has the model" — same shape as the
      // open-network not-found case.
      return {
        status: 404,
        type: "invalid_request_error",
        code: "no_friends_for_model",
      };
    case "target-provider-not-connected":
      return {
        status: 503,
        type: "service_unavailable_error",
        code: "provider_offline",
      };
    case "provider-payouts-not-eligible":
      return { status: 403, type: "permission_error", code: "provider_not_eligible" };
    case "pds-publish-failed":
      return { status: 502, type: "server_error", code: "pds_publish_failed" };
    case "provider-encryption-key-malformed":
      return { status: 502, type: "server_error", code: "provider_key_malformed" };
    case "chunk-decrypt-failed":
      return { status: 502, type: "server_error", code: "chunk_decrypt_failed" };
    case "advisor-rejected":
      return { status: 502, type: "server_error", code: "advisor_rejected" };
    case "advisor-transport":
      return { status: 502, type: "server_error", code: "advisor_transport" };
    case "no-capacity":
      // Failover tried several providers and none accepted in time
      // (transient capacity churn). 503 + a retryable, OpenAI-shaped
      // code — the message is already generic at the dispatch layer.
      return { status: 503, type: "service_unavailable_error", code: "model_unavailable" };
    case "unknown":
      return { status: 502, type: "server_error", code: "unknown" };
  }
  // Exhaustiveness check — TypeScript narrows the switch above so
  // this is unreachable; the fallback is for runtime safety if a
  // new code is added without updating this switch.
  const _exhaustive: never = errorCode;
  void _exhaustive;
  return { status: 502, type: "server_error", code: "unknown" };
}

export function streamingResponse(
  id: string,
  model: string,
  events: AsyncIterable<DispatchEvent>,
): Response {
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (s: string) => controller.enqueue(encoder.encode(`data: ${s}\n\n`));
      // OpenAI clients expect a leading role-only delta.
      send(chunkPayload(id, model, { role: "assistant" }, null));

      try {
        for await (const ev of events) {
          if (ev.kind === "chunk") {
            // Reasoning ("thinking") rides delta.reasoning_content, the
            // vLLM/DeepSeek convention; the answer rides delta.content.
            const delta =
              ev.channel === "reasoning" ? { reasoning_content: ev.text } : { content: ev.text };
            send(chunkPayload(id, model, delta, null));
          } else if (ev.kind === "complete") {
            // The final `stop` chunk carries the x_cocore credit so a
            // streaming client gets the same "who ran it" metadata the
            // buffered path returns.
            send(chunkPayload(id, model, {}, "stop", cocoreMeta(ev.providerCredit, ev.receiptUri)));
            controller.enqueue(encoder.encode("data: [DONE]\n\n"));
            return;
          } else if (ev.kind === "error") {
            const mapped = dispatchErrorToHttpResponse(ev.code);
            // Emit the error on the DEFAULT SSE event (a `data:` frame),
            // not a named `event: error`. This is the de-facto OpenAI
            // mid-stream error shape (an `{ error: {...} }` object on the
            // default event, HTTP stays 200) honored by the OpenAI SDKs
            // and OpenAI-compatible servers (vLLM/SGLang/etc.). Minimal
            // SSE clients (e.g. Apollo) only read default-event `data:`
            // frames, so a named `event: error` is silently dropped —
            // the stream then appears to end with no chunk, which the
            // client reports as "the response is not a stream."
            //
            // No `[DONE]` follows: OpenAI interrupts the stream with the
            // error frame and closes, rather than emitting the normal
            // terminator. The `finally` closes the controller (EOF).
            send(
              JSON.stringify({
                error: {
                  message: ev.reason,
                  type: mapped.type,
                  code: mapped.code,
                  param: null,
                },
              }),
            );
            return;
          }
          // `meta` is internal — not surfaced to OpenAI clients.
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
}

export async function bufferedResponse(
  id: string,
  model: string,
  events: AsyncIterable<DispatchEvent>,
): Promise<Response> {
  let content = "";
  let reasoning = "";
  let tokensIn = 0;
  let tokensOut = 0;
  let providerCredit: ProviderCredit | undefined;
  let receiptUri: string | null = null;
  let errored: { reason: string; code: DispatchErrorCode } | null = null;

  for await (const ev of events) {
    if (ev.kind === "chunk") {
      if (ev.channel === "reasoning") reasoning += ev.text;
      else content += ev.text;
    } else if (ev.kind === "complete") {
      tokensIn = ev.tokensIn;
      tokensOut = ev.tokensOut;
      providerCredit = ev.providerCredit;
      receiptUri = ev.receiptUri;
    } else if (ev.kind === "error") {
      errored = { reason: ev.reason, code: ev.code };
      break;
    }
  }

  if (errored !== null) {
    const mapped = dispatchErrorToHttpResponse(errored.code);
    return jsonError(mapped.status, errored.reason, mapped.type, mapped.code);
  }

  return new Response(
    JSON.stringify({
      id,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model,
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content,
            ...(reasoning ? { reasoning_content: reasoning } : {}),
          },
          finish_reason: "stop",
        },
      ],
      usage: {
        prompt_tokens: tokensIn,
        completion_tokens: tokensOut,
        total_tokens: tokensIn + tokensOut,
      },
      ...cocoreMeta(providerCredit, receiptUri),
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}
