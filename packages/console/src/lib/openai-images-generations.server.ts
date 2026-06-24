// Shared logic for the OpenAI-compatible images surface:
//   POST /v1/images/generations  (text-to-image)
//   POST /v1/images/edits        (img2img)
// across the open / friends-only / verified trust tiers.
//
// Parallel to openai-chat-completions.server.ts (not bolted onto it):
// images are request/response JSON with a different request shape, a
// different response shape, and no streaming. What IS shared — auth,
// provider-pool resolution, the DispatchErrorCode→HTTP table — is imported
// from the chat module rather than duplicated.
//
// Output invariant: the provider returns images on the image channel and
// the receipt's outputCommitment covers the images-v1 envelope (see
// provider/src/images_envelope.rs). This module only collects the decoded
// { mime, data } parts the dispatch layer already produced and shapes them
// into OpenAI's `data: [{ b64_json }]` response.

import { buildEnvelopeBytes, MESSAGES_V1 } from "@cocore/sdk/multimodal-envelope";

import type {
  DispatchErrorCode,
  DispatchEvent,
  ProviderCredit,
} from "@/lib/inference-dispatch.server.ts";

/** Steps to request for an image job. Carried opaquely in the job's
 *  `maxTokensOut` until a lexicon step field lands (the provider's image
 *  engine reinterprets `max_tokens` as the diffusion step count). 4 is the
 *  FLUX-schnell sweet spot; the stub ignores it. */
export const DEFAULT_IMAGE_STEPS = 4;

/** OpenAI caps `n` at 10 for images; cocore caps at 4 to bound fan-out
 *  spend (one job + receipt per image — see Phase 11). */
const MAX_IMAGE_N = 4;

const MAX_PROMPT_BYTES = 64 * 1024; // image prompts are short
const MAX_EDIT_IMAGE_BYTES = 20 * 1024 * 1024; // matches the chat image budget

export interface ParsedGenerationsRequest {
  model: string;
  prompt: string;
  n: number;
}

export interface ParsedEditsRequest {
  model: string;
  prompt: string;
  n: number;
  /** The reference image to edit, normalized to an inline part. */
  image: { mime: string; data: string };
}

/** Validate an OpenAI `POST /v1/images/generations` body. Returns the
 *  parsed request or a human-readable error string (→ 400). */
export function parseGenerationsRequest(raw: unknown): ParsedGenerationsRequest | string {
  if (!raw || typeof raw !== "object") return "Body must be a JSON object";
  const b = raw as Record<string, unknown>;

  if (typeof b.model !== "string" || b.model.length === 0) return "model is required";
  if (typeof b.prompt !== "string" || b.prompt.length === 0) return "prompt is required";
  if (new TextEncoder().encode(b.prompt).length > MAX_PROMPT_BYTES) {
    return "prompt is too long";
  }

  const formatErr = checkResponseFormat(b.response_format);
  if (formatErr) return formatErr;

  const n = parseN(b.n);
  if (typeof n === "string") return n;

  // size / quality / style / user are accepted but ignored (cocore's image
  // path doesn't plumb them yet); unknown fields OpenAI clients send are
  // tolerated rather than rejected.
  return { model: b.model, prompt: b.prompt, n };
}

/** Validate an OpenAI `POST /v1/images/edits` multipart form (img2img).
 *  Returns the parsed request or an error string (→ 400). */
export async function parseEditsRequest(form: FormData): Promise<ParsedEditsRequest | string> {
  const model = form.get("model");
  const prompt = form.get("prompt");
  if (typeof model !== "string" || model.length === 0) return "model is required";
  if (typeof prompt !== "string" || prompt.length === 0) return "prompt is required";
  if (new TextEncoder().encode(prompt).length > MAX_PROMPT_BYTES) return "prompt is too long";

  const formatErr = checkResponseFormat(form.get("response_format"));
  if (formatErr) return formatErr;

  const n = parseN(form.get("n") === null ? undefined : Number(form.get("n")));
  if (typeof n === "string") return n;

  const image = form.get("image");
  const parsed = await normalizeUploadedImage(image);
  if (typeof parsed === "string") return parsed;

  return { model, prompt, n, image: parsed };
}

/** `response_format: "url"` is rejected with a clear message rather than
 *  silently upgraded — cocore returns inline base64 only, and a fake URL
 *  would break clients that fetch it. Returns an error string or null. */
function checkResponseFormat(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (value === "b64_json") return null;
  if (value === "url") {
    return 'response_format "url" is not supported; cocore returns inline base64 only — use "b64_json"';
  }
  return 'response_format must be "b64_json"';
}

function parseN(value: unknown): number | string {
  if (value === undefined || value === null) return 1;
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(n) || n < 1 || n > MAX_IMAGE_N) {
    return `n must be an integer between 1 and ${MAX_IMAGE_N}`;
  }
  return n;
}

/** Normalize an uploaded edit image (a File/Blob or a data: URI string)
 *  into an inline `{ mime, data }` part. */
async function normalizeUploadedImage(
  image: unknown,
): Promise<{ mime: string; data: string } | string> {
  if (typeof image === "string") {
    const m = /^data:([^;,]+);base64,(.*)$/s.exec(image);
    if (!m) return "image must be a file upload or a base64 data URI";
    const mime = m[1]!;
    const data = m[2]!;
    if (!mime.startsWith("image/")) return "image must be an image/* type";
    if (estimateBase64Bytes(data) > MAX_EDIT_IMAGE_BYTES) return "image is too large";
    return { mime, data };
  }
  if (image && typeof image === "object" && "arrayBuffer" in image) {
    const blob = image as Blob;
    const mime = blob.type || "image/png";
    if (!mime.startsWith("image/")) return "image must be an image/* type";
    const buf = new Uint8Array(await blob.arrayBuffer());
    if (buf.byteLength > MAX_EDIT_IMAGE_BYTES) return "image is too large";
    return { mime, data: base64FromBytes(buf) };
  }
  return "image is required";
}

function estimateBase64Bytes(b64: string): number {
  return Math.floor((b64.length * 3) / 4);
}

function base64FromBytes(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin);
}

/** Sealed-payload bytes for a generations (t2i) job — the raw prompt on
 *  the text path. */
export function generationsJobInput(prompt: string): {
  payloadBytes: Uint8Array;
  inputFormat?: typeof MESSAGES_V1;
} {
  return { payloadBytes: new TextEncoder().encode(prompt) };
}

/** Sealed-payload bytes for an edits (img2img) job — a single-turn
 *  messages-v1 envelope carrying the prompt text + the reference image. */
export function editsJobInput(req: ParsedEditsRequest): {
  payloadBytes: Uint8Array;
  inputFormat: typeof MESSAGES_V1;
} {
  const messages = [
    {
      role: "user",
      content: [
        { type: "text" as const, text: req.prompt },
        { type: "image" as const, mime: req.image.mime, data: req.image.data },
      ],
    },
  ];
  return { payloadBytes: buildEnvelopeBytes(messages), inputFormat: MESSAGES_V1 };
}

/** One image slot's outcome (one job + one receipt — see Phase 11). */
export interface ImageSlotResult {
  images: { mime: string; data: string }[];
  receiptUri: string | null;
  providerCredit?: ProviderCredit;
  error?: DispatchErrorCode;
}

/** Drain a single dispatch's events into an {@link ImageSlotResult}:
 *  every image chunk's bytes, plus the terminal receipt/credit (or the
 *  first error). Non-throwing — a dispatch error is captured in `error`. */
export async function collectImageDispatch(
  events: AsyncIterable<DispatchEvent>,
): Promise<ImageSlotResult> {
  const images: { mime: string; data: string }[] = [];
  let receiptUri: string | null = null;
  let providerCredit: ProviderCredit | undefined;
  let error: DispatchErrorCode | undefined;

  for await (const ev of events) {
    if (ev.kind === "chunk") {
      if (ev.channel === "image") images.push({ mime: ev.mime, data: ev.data });
      // text/reasoning chunks are ignored on the image path.
    } else if (ev.kind === "complete") {
      receiptUri = ev.receiptUri || null;
      providerCredit = ev.providerCredit;
    } else if (ev.kind === "error") {
      error = ev.code;
      break;
    }
  }
  return { images, receiptUri, providerCredit, error };
}

/** Shape collected slots into the OpenAI `images/generations` JSON. Each
 *  successful image becomes a `data[]` entry; `x_cocore` carries one
 *  receipt + credit per slot. Partial success (some slots failed) still
 *  returns 200 with `x_cocore.partial: true` and the images that landed. */
export function generationsResponse(slots: ImageSlotResult[]): Response {
  const data: { b64_json: string; revised_prompt: null }[] = [];
  const receiptUris: string[] = [];
  const credits: ProviderCredit["line"][] = [];
  let anyError = false;
  for (const slot of slots) {
    if (slot.error) anyError = true;
    for (const img of slot.images) {
      data.push({ b64_json: img.data, revised_prompt: null });
    }
    if (slot.receiptUri) receiptUris.push(slot.receiptUri);
    if (slot.providerCredit) credits.push(slot.providerCredit.line);
  }

  const partial = anyError && data.length > 0;
  const body = {
    created: Math.floor(Date.now() / 1000),
    data,
    ...(receiptUris.length > 0 || credits.length > 0 || partial
      ? {
          x_cocore: {
            ...(receiptUris.length > 0 ? { receiptUris } : {}),
            ...(credits.length > 0 ? { credits } : {}),
            ...(partial ? { partial: true } : {}),
          },
        }
      : {}),
  };
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}
