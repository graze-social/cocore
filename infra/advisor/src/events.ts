// Server-Sent Events (SSE) framing for the advisor's job-dispatch
// stream. Each event is rendered as `event: <type>\ndata: <json>\n\n`
// per the SSE spec. The `data:` payload is a JSON object — that
// makes the wire trivially parseable in browsers (`new EventSource`)
// and command-line clients (`curl --no-buffer`).
//
// We keep the event types narrow on purpose: `open`, `chunk`,
// `complete`, `error`. Every event includes the `sessionId` so a
// requester multiplexing several jobs through one HTTP/2 connection
// can route events without parsing the SSE `event:` line.

export type AttestedSseEvent =
  | {
      type: "open";
      sessionId: string;
      providerDid: string;
    }
  | {
      type: "chunk";
      sessionId: string;
      seq: number;
      /** "content" (the answer) or "reasoning" (thinking). Omitted for
       *  answer chunks so existing wire bytes are unchanged. */
      channel?: "content" | "reasoning";
      ciphertext: number[] | string;
    }
  | {
      type: "complete";
      sessionId: string;
      tokensIn: number;
      tokensOut: number;
      receiptUri: string;
    }
  | {
      type: "error";
      sessionId: string;
      reason: string;
    };

export function renderSseEvent(ev: AttestedSseEvent): string {
  const data = JSON.stringify(ev);
  return `event: ${ev.type}\ndata: ${data}\n\n`;
}
