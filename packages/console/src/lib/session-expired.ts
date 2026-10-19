// Recognize the error a server fn throws when the user's underlying ATProto
// session is dead. The console's PDS helpers surface upstream failures as
// `Error("<op> 401: <body>")`, and the AppView's dead-session body carries
// `"error":"AuthRequired"` — so the message is the only signal that crosses
// the server-fn boundary. Used by UI that should send the user back through
// login instead of rendering the raw 401.
export function isSessionExpiredError(e: unknown): boolean {
  const msg = e instanceof Error ? e.message : typeof e === "string" ? e : "";
  return /\b401\b/.test(msg) && msg.includes("AuthRequired");
}
