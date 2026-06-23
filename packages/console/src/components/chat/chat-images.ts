// IndexedDB-backed cache for chat images.
//
// Why not localStorage: the per-DID session blob lives in localStorage,
// which is ~5 MB and holds ALL sessions + messages — image bytes would blow
// that quota fast. IndexedDB is a much larger, longer-lived browser store,
// so images cached here survive reloads and navigation without bloating (or
// being capped by) the session blob.
//
// Privacy: images are encrypted with the SAME per-DID AES key the session
// text uses (see chat-crypto.ts), so the model is identical — another
// account on the same browser can't read them from DevTools.
//
// Durability: best-effort. IndexedDB can be evicted under storage pressure
// or cleared by the user. When an image is gone we fall back to the durable
// `imageCount` marker persisted on the message and show a "there was an
// image" indicator — never an error.

import { decryptChatPayload, encryptChatPayload } from "@/components/chat/chat-crypto.ts";

export interface StoredChatImage {
  mime: string;
  /** base64 of the raw image bytes (no data: prefix). */
  data: string;
}

const DB_NAME = "cocore-chat-images";
const STORE = "images";
const DB_VERSION = 1;

function openDb(): Promise<IDBDatabase | null> {
  return new Promise((resolve) => {
    if (typeof indexedDB === "undefined") {
      resolve(null);
      return;
    }
    let req: IDBOpenDBRequest;
    try {
      req = indexedDB.open(DB_NAME, DB_VERSION);
    } catch {
      resolve(null);
      return;
    }
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => resolve(null);
  });
}

/** Keyed per (DID, message) so one account's images never collide with
 *  another's and a message's images are addressable on its own. */
function recordKey(did: string, messageId: string): string {
  return `${did}:${messageId}`;
}

/** Encrypt + store a message's images. Best-effort: resolves (never throws)
 *  even when IndexedDB is unavailable or the write fails. */
export async function saveChatImages(
  did: string,
  messageId: string,
  images: StoredChatImage[],
  storageKeyBase64Url: string,
): Promise<void> {
  if (images.length === 0) return;
  try {
    const blob = await encryptChatPayload(JSON.stringify(images), storageKeyBase64Url);
    const db = await openDb();
    if (!db) return;
    await new Promise<void>((resolve) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(blob, recordKey(did, messageId));
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
      tx.onabort = () => resolve();
    });
    db.close();
  } catch {
    // best-effort — the durable imageCount still records that images existed.
  }
}

/** Load + decrypt a message's images, or null when absent/undecryptable
 *  (evicted, cleared, or a different key). */
export async function loadChatImages(
  did: string,
  messageId: string,
  storageKeyBase64Url: string,
): Promise<StoredChatImage[] | null> {
  try {
    const db = await openDb();
    if (!db) return null;
    const blob = await new Promise<string | null>((resolve) => {
      const tx = db.transaction(STORE, "readonly");
      const req = tx.objectStore(STORE).get(recordKey(did, messageId));
      req.onsuccess = () => resolve((req.result as string | undefined) ?? null);
      req.onerror = () => resolve(null);
    });
    db.close();
    if (!blob) return null;
    const plain = await decryptChatPayload(blob, storageKeyBase64Url);
    if (!plain) return null;
    const parsed: unknown = JSON.parse(plain);
    if (!Array.isArray(parsed)) return null;
    return parsed.filter(
      (p): p is StoredChatImage =>
        !!p &&
        typeof p === "object" &&
        typeof (p as Record<string, unknown>).mime === "string" &&
        typeof (p as Record<string, unknown>).data === "string",
    );
  } catch {
    return null;
  }
}

/** Build a data URI for rendering a stored image as a thumbnail. */
export function chatImageDataUrl(img: StoredChatImage): string {
  return `data:${img.mime};base64,${img.data}`;
}
