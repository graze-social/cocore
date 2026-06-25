// Browser-side client for the existing cookie-authed dispatch SSE
// endpoint (`/api/xrpc/dev.cocore.inference.dispatch`). No chat
// content is persisted server-side — the endpoint publishes the job
// records to the user's PDS, routes via the advisor, and streams
// decrypted chunks straight back; this module just parses that
// stream into callbacks for the UI.

/** An image attached to the outgoing turn: source media type + the raw
 *  bytes base64-encoded (no data: prefix). Built by the chat composer from
 *  dropped/pasted files. */
export interface ChatDispatchImage {
  mime: string;
  data: string;
}

export interface ChatDispatchInputs {
  model: string;
  /** Flattened transcript. Mirrors the server's `flattenMessages`
   *  ("role: content" lines) so in-app chat and API chat hit the
   *  provider with the same prompt shape. */
  prompt: string;
  /** The structured turns behind `prompt`. Only needed when `images` are
   *  attached — used to build the messages-v1 multimodal envelope, with the
   *  images appended to the latest user turn. */
  transcript?: Array<{ role: string; text: string }>;
  /** Images to attach to the latest user turn. When non-empty, the dispatch
   *  sends a structured `messages` payload (sealed as the canonical
   *  envelope) instead of the flattened prompt. */
  images?: ChatDispatchImage[];
  maxTokensOut: number;
  targetProviderDid?: string | null;
  /** Specific machine under targetProviderDid. null/undefined → any machine
   *  for that DID. Ignored when targetProviderDid is not set. */
  targetMachineId?: string | null;
  /** Optional ISO 3166-1 alpha-2 country (e.g. "US"). When set, routes only to
   *  providers advertising that coarse region. Advisory. */
  country?: string | null;
  /** When true, route ONLY to providers whose pro-bono policy serves this
   *  requester for free (the pro-bono completion path). */
  proBono?: boolean;
  signal?: AbortSignal;
  onMeta?: (meta: { providerDid: string; jobUri: string }) => void;
  onChunk?: (text: string) => void;
  /** Reasoning ("thinking") deltas, streamed on a separate channel from
   *  the answer so the UI can render them in a collapsible block. */
  onReasoning?: (text: string) => void;
}

/** Build the structured messages-v1 turns for a multimodal send: each
 *  transcript turn becomes a message, and the images ride on the LAST turn
 *  (the user's new message). Text-only turns stay plain strings so the
 *  sealed bytes match the flattened path for those turns. */
function buildMessages(
  transcript: Array<{ role: string; text: string }>,
  images: ChatDispatchImage[],
): Array<{ role: string; content: unknown }> {
  return transcript.map((t, i) => {
    const isLast = i === transcript.length - 1;
    if (!isLast || images.length === 0) return { role: t.role, content: t.text };
    const parts: Array<Record<string, unknown>> = [];
    if (t.text) parts.push({ type: "text", text: t.text });
    for (const img of images) parts.push({ type: "image", mime: img.mime, data: img.data });
    return { role: t.role, content: parts };
  });
}

export interface ChatDispatchResult {
  text: string;
  reasoning: string;
  tokensIn: number;
  tokensOut: number;
  receiptUri: string | null;
  providerDid: string | null;
  durationMs: number;
}

export class ChatDispatchError extends Error {
  readonly code: string;
  readonly partialText: string;
  constructor(reason: string, code: string, partialText: string) {
    super(reason);
    this.name = "ChatDispatchError";
    this.code = code;
    this.partialText = partialText;
  }
}

/** Flatten chat turns into the prompt string the dispatch core
 *  expects — identical format to the OpenAI shim's flattenMessages. */
export function flattenTranscript(turns: Array<{ role: string; text: string }>): string {
  return turns.map((t) => `${t.role}: ${t.text}`).join("\n");
}

interface SseFrame {
  event: string;
  data: string;
}

async function* readSse(
  body: ReadableStream<Uint8Array>,
  signal?: AbortSignal,
): AsyncGenerator<SseFrame> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  while (true) {
    if (signal?.aborted) {
      await reader.cancel();
      throw new DOMException("The operation was aborted.", "AbortError");
    }
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buf.indexOf("\n\n")) !== -1) {
      const block = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      let event = "message";
      let data = "";
      for (const line of block.split("\n")) {
        if (line.startsWith("event: ")) event = line.slice(7);
        else if (line.startsWith("data: ")) data += line.slice(6);
      }
      yield { event, data };
    }
  }
}

const PRICE_CEILING = { amount: 100_000, currency: "CC" };

/** Run one inference turn. Resolves with the full reply once the
 *  provider's `complete` event lands; rejects with ChatDispatchError
 *  (carrying any partial text) on a structured dispatch error. */
export async function dispatchChatTurn(inputs: ChatDispatchInputs): Promise<ChatDispatchResult> {
  const t0 = Date.now();
  // Attach images as structured `messages` (sealed as the multimodal
  // envelope server-side). `prompt` is still sent as the required field +
  // the text fallback when there are no images.
  const hasImages = (inputs.images?.length ?? 0) > 0 && (inputs.transcript?.length ?? 0) > 0;
  const messages = hasImages ? buildMessages(inputs.transcript!, inputs.images!) : undefined;
  const res = await fetch("/api/xrpc/dev.cocore.inference.dispatch", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      model: inputs.model,
      prompt: inputs.prompt,
      ...(messages ? { messages } : {}),
      maxTokensOut: inputs.maxTokensOut,
      priceCeiling: PRICE_CEILING,
      ...(inputs.targetProviderDid ? { targetProviderDid: inputs.targetProviderDid } : {}),
      ...(inputs.targetProviderDid && inputs.targetMachineId
        ? { targetMachineId: inputs.targetMachineId }
        : {}),
      ...(inputs.country ? { country: inputs.country } : {}),
      ...(inputs.proBono ? { proBono: true } : {}),
    }),
    ...(inputs.signal ? { signal: inputs.signal } : {}),
  });

  if (!res.ok || !res.body) {
    let reason = `dispatch failed (${res.status})`;
    try {
      const body = (await res.json()) as { error?: string };
      if (body.error) reason = body.error;
    } catch {
      // keep the status-line reason
    }
    throw new ChatDispatchError(reason, "http-error", "");
  }

  let text = "";
  let reasoning = "";
  let providerDid: string | null = null;

  for await (const frame of readSse(res.body, inputs.signal)) {
    if (frame.event === "meta") {
      try {
        const meta = JSON.parse(frame.data) as { providerDid: string; jobUri: string };
        providerDid = meta.providerDid;
        inputs.onMeta?.(meta);
      } catch {
        // malformed meta is non-fatal
      }
    } else if (frame.event === "chunk") {
      try {
        const chunk = JSON.parse(frame.data) as {
          text: string;
          channel?: "content" | "reasoning";
        };
        if (chunk.channel === "reasoning") {
          reasoning += chunk.text;
          inputs.onReasoning?.(chunk.text);
        } else {
          text += chunk.text;
          inputs.onChunk?.(chunk.text);
        }
      } catch {
        // skip malformed chunk
      }
    } else if (frame.event === "complete") {
      const parsed = JSON.parse(frame.data) as {
        tokensIn: number;
        tokensOut: number;
        receiptUri: string;
      };
      return {
        text,
        reasoning,
        tokensIn: parsed.tokensIn,
        tokensOut: parsed.tokensOut,
        receiptUri: parsed.receiptUri ?? null,
        providerDid,
        durationMs: Date.now() - t0,
      };
    } else if (frame.event === "error") {
      let reason = frame.data;
      let code = "unknown";
      try {
        const e = JSON.parse(frame.data) as { reason?: string; code?: string };
        if (e.reason) reason = e.reason;
        if (e.code) code = e.code;
      } catch {
        // raw string reason
      }
      throw new ChatDispatchError(reason, code, text);
    }
  }
  // Stream ended without a terminal event — treat as transport drop.
  throw new ChatDispatchError("stream ended before completion", "stream-truncated", text);
}
