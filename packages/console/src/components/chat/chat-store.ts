// Browser-local persistence for the /chat page.
//
// Chat transcripts deliberately never touch the console's server or
// database: prompts are sealed to the provider at dispatch time and
// the console must not become a store of user conversations. The
// only durable records of the WORK are the provider-signed receipts
// on the provider's PDS — messages here keep `receiptUri` pointers
// to those, never a substitute for them.
//
// Storage shape: one encrypted localStorage entry per DID
// (`cocore:chat:v2:<did>`) holding every session + message for that
// account. The AES-256-GCM key is derived server-side and returned
// only to the signed-in session, so another account on the same
// browser cannot decrypt a user's blob from DevTools alone. Writes
// are throttled by the caller (see ChatPage) — streaming updates
// arrive many times a second.

import { decryptChatPayload, encryptChatPayload } from "@/components/chat/chat-crypto.ts";

interface ChatMessageMeta {
  tokensIn: number;
  tokensOut: number;
  durationMs: number;
  receiptUri: string | null;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  text: string;
  /** Assistant turns: the model's reasoning ("thinking") trace, streamed
   *  on a separate channel from `text`. Rendered in a collapsible block. */
  reasoning?: string;
  /** Assistant turns: model + provider that actually served the
   *  reply (the session's settings may have changed since). */
  modelId?: string;
  providerDid?: string;
  providerLabel?: string;
  /** Set when the turn completed and the receipt came back. */
  meta?: ChatMessageMeta;
  /** DispatchErrorCode when the turn failed; `text` holds whatever
   *  partial output streamed before the failure. */
  errorCode?: string;
  errorReason?: string;
  /** User turns: how many images rode this turn. The image BYTES live in
   *  IndexedDB (see chat-images.ts), not in this localStorage blob — this
   *  count is the durable marker so we always know images existed even after
   *  the cached bytes are evicted (then we show a "had image" indicator). */
  imageCount?: number;
  createdAt: string;
}

export interface ChatSession {
  id: string;
  title: string;
  modelId: string;
  /** null → the advisor routes to any eligible machine. */
  targetProviderDid: string | null;
  maxTokensOut: number;
  /** Display-only running sum of tokensIn+tokensOut. The exchange
   *  ledger owns the real balance. */
  spentTokens: number;
  createdAt: string;
  updatedAt: string;
  messages: ChatMessage[];
}

const STORAGE_VERSION = 2;
const LEGACY_STORAGE_VERSION = 1;
const storageKey = (did: string, version = STORAGE_VERSION) => `cocore:chat:v${version}:${did}`;
const activeKey = (did: string, version = STORAGE_VERSION) =>
  `cocore:chat:active:v${version}:${did}`;

/** In-memory cache survives SPA route changes so /chat → elsewhere →
 *  /chat does not flash empty or rely on a race with localStorage. */
const memorySessions = new Map<string, ChatSession[]>();
const memoryActiveId = new Map<string, string | null>();

const DEFAULT_MAX_TOKENS_OUT = 4096;
export const MAX_TOKENS_CHOICES = [1024, 4096, 16384] as const;

export function newSessionId(): string {
  return typeof crypto !== "undefined" && "randomUUID" in crypto
    ? crypto.randomUUID()
    : `c-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

export function createSession(modelId: string): ChatSession {
  const now = new Date().toISOString();
  return {
    id: newSessionId(),
    title: "new session",
    modelId,
    targetProviderDid: null,
    maxTokensOut: DEFAULT_MAX_TOKENS_OUT,
    spentTokens: 0,
    createdAt: now,
    updatedAt: now,
    messages: [],
  };
}

/** Derive a sidebar title from the first user message. */
export function titleFromText(text: string): string {
  const t = text.trim().replace(/\s+/g, " ");
  return t.length > 38 ? `${t.slice(0, 38)}…` : t;
}

function isMessage(m: unknown): m is ChatMessage {
  if (typeof m !== "object" || m === null) return false;
  const r = m as Record<string, unknown>;
  return (
    typeof r["id"] === "string" &&
    (r["role"] === "user" || r["role"] === "assistant") &&
    typeof r["text"] === "string" &&
    typeof r["createdAt"] === "string"
  );
}

function isSession(s: unknown): s is ChatSession {
  if (typeof s !== "object" || s === null) return false;
  const r = s as Record<string, unknown>;
  return (
    typeof r["id"] === "string" &&
    typeof r["title"] === "string" &&
    typeof r["modelId"] === "string" &&
    typeof r["maxTokensOut"] === "number" &&
    typeof r["spentTokens"] === "number" &&
    typeof r["updatedAt"] === "string" &&
    Array.isArray(r["messages"]) &&
    (r["messages"] as unknown[]).every(isMessage)
  );
}

function memoryCacheKey(did: string, storageKeyBase64Url: string | null): string {
  return `${did}:${storageKeyBase64Url ?? "none"}`;
}

function parseSessionsJson(raw: string): ChatSession[] {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isSession);
  } catch {
    return [];
  }
}

async function writeSessionsToStorage(
  did: string,
  sessions: ChatSession[],
  storageKeyBase64Url: string,
): Promise<void> {
  const encrypted = await encryptChatPayload(JSON.stringify(sessions), storageKeyBase64Url);
  window.localStorage.setItem(storageKey(did), encrypted);
}

async function readSessionsFromStorage(
  did: string,
  storageKeyBase64Url: string,
): Promise<ChatSession[]> {
  if (typeof window === "undefined") return [];

  try {
    const rawV2 = window.localStorage.getItem(storageKey(did));
    if (rawV2) {
      const plaintext = await decryptChatPayload(rawV2, storageKeyBase64Url);
      if (plaintext) return parseSessionsJson(plaintext);
      return [];
    }

    const rawV1 = window.localStorage.getItem(storageKey(did, LEGACY_STORAGE_VERSION));
    if (!rawV1) return [];

    const sessions = parseSessionsJson(rawV1);
    if (sessions.length > 0) {
      await writeSessionsToStorage(did, sessions, storageKeyBase64Url);
    }
    window.localStorage.removeItem(storageKey(did, LEGACY_STORAGE_VERSION));
    window.localStorage.removeItem(activeKey(did, LEGACY_STORAGE_VERSION));
    return sessions;
  } catch {
    return [];
  }
}

/** Read every session for a DID. Tolerates a missing/corrupt entry
 *  by returning [] — chat history is convenience state, never worth
 *  blocking the page over. SSR-safe (no window → []). */
export async function loadSessions(
  did: string,
  storageKeyBase64Url: string | null,
): Promise<ChatSession[]> {
  const cacheKey = memoryCacheKey(did, storageKeyBase64Url);
  const cached = memorySessions.get(cacheKey);
  if (cached) return cached;

  if (!storageKeyBase64Url) {
    memorySessions.set(cacheKey, []);
    return [];
  }

  const loaded = await readSessionsFromStorage(did, storageKeyBase64Url);
  memorySessions.set(cacheKey, loaded);
  return loaded;
}

/** Last-open session id for a DID (sidebar selection). */
export function loadActiveSessionId(did: string): string | null {
  if (memoryActiveId.has(did)) return memoryActiveId.get(did) ?? null;
  if (typeof window === "undefined") return null;
  try {
    const id =
      window.localStorage.getItem(activeKey(did)) ??
      window.localStorage.getItem(activeKey(did, LEGACY_STORAGE_VERSION));
    memoryActiveId.set(did, id);
    return id;
  } catch {
    return null;
  }
}

export function saveActiveSessionId(did: string, id: string | null): void {
  memoryActiveId.set(did, id);
  if (typeof window === "undefined") return;
  try {
    if (id) window.localStorage.setItem(activeKey(did), id);
    else window.localStorage.removeItem(activeKey(did));
  } catch {
    // Best effort.
  }
}

/** Persist every session for a DID. Quota/availability failures are
 *  swallowed: the in-memory state stays correct for the tab and the
 *  next successful write catches history back up. */
export async function saveSessions(
  did: string,
  sessions: ChatSession[],
  storageKeyBase64Url: string | null,
): Promise<void> {
  const cacheKey = memoryCacheKey(did, storageKeyBase64Url);
  memorySessions.set(cacheKey, sessions);
  if (typeof window === "undefined" || !storageKeyBase64Url) return;
  try {
    await writeSessionsToStorage(did, sessions, storageKeyBase64Url);
  } catch {
    // Best effort — quota exceeded or storage disabled.
  }
}

/** Drop in-memory chat state (e.g. on logout). localStorage blobs stay
 *  encrypted until the same user signs back in. */
export function clearChatStoreMemory(): void {
  memorySessions.clear();
  memoryActiveId.clear();
}
