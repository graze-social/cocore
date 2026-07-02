// Read + write `dev.cocore.account.profile` records on the user's PDS.
//
// Provisioning model:
//   * On first sign-in (or first /account page load for users who
//     pre-date this feature), `ensureMyProfile` creates a profile
//     record at `rkey=self` populated from the user's Bluesky public
//     profile (avatar URL + displayName + handle) so the card on
//     /account isn't empty.
//   * Subsequent edits flow through `updateMyProfile` which does a
//     read-modify-putRecord at the same `rkey=self`. Because the
//     lexicon's `key` is `literal:self`, there's exactly one profile
//     record per DID — no dedup logic needed.
//   * Users without a Bluesky profile (rare) get an empty record;
//     they can fill it in from the UI.
//
// Avatar storage: the lexicon has two avatar fields. `avatar` is an
// atproto blob (preferred for new writes); `avatarUrl` is a legacy URL
// string retained for records provisioned before the blob field
// existed. Reads derive a single display URL — from the blob when
// present, falling back to the legacy URL — so the rest of the app
// only ever consumes `CocoreProfile.avatarUrl`.
//
// Server-only: this file runs inside the OAuth-callback handler and
// signed-in server fns. Never imported client-side.

import type { OAuthSession } from "@atcute/oauth-node-client";

import { runTraced } from "@/lib/o11y.server.ts";

import { fetchBlueskyPublicProfileFieldsEffect } from "@/lib/bluesky-public-profile.server.ts";
import { bridgeHeaders, cocoreConfig } from "@/lib/cocore-config.ts";

const COLLECTION = "dev.cocore.account.profile";
const RKEY = "self";

/** Best-effort mirror to the local AppView indexer so profile
 *  edits show up immediately in the discovery directory + the
 *  user's own profile page. Same shape as the friends/compute
 *  bridge-mirror calls; failures swallowed because the relay
 *  subscription is the durable backstop. */
function mirrorProfileToBridge(
  did: string,
  uri: string,
  cid: string,
  record: Record<string, unknown>,
): void {
  const bridgeUrl = cocoreConfig().bridgeUrl?.replace(/\/$/, "");
  if (!bridgeUrl) return;
  void fetch(`${bridgeUrl}/xrpc/dev.cocore.bridge.publish`, {
    method: "POST",
    headers: bridgeHeaders(),
    body: JSON.stringify({
      uri,
      cid,
      collection: COLLECTION,
      repo: did,
      rkey: RKEY,
      body: record,
    }),
  }).catch(() => {});
}

interface AvatarBlobRef {
  cid: string;
  mimeType: string;
  size: number;
}

export interface CocoreProfile {
  did: string;
  displayName: string | null;
  bio: string | null;
  /** Display URL for the avatar. Derived from `avatar` (PDS blob) when
   *  present on the record, otherwise from the legacy `avatarUrl`
   *  field. */
  avatarUrl: string | null;
  /** Raw avatar blob ref when the user has uploaded one to their PDS. */
  avatar: AvatarBlobRef | null;
  handle: string | null;
  createdAt: string;
  updatedAt: string | null;
}

interface RawProfile {
  displayName?: unknown;
  bio?: unknown;
  avatar?: unknown;
  avatarUrl?: unknown;
  handle?: unknown;
  createdAt?: unknown;
  updatedAt?: unknown;
}

function readField(v: unknown): string | null {
  return typeof v === "string" && v.trim().length > 0 ? v : null;
}

function readAvatarBlob(v: unknown): AvatarBlobRef | null {
  if (typeof v !== "object" || v === null) return null;
  const o = v as { $type?: unknown; ref?: unknown; mimeType?: unknown; size?: unknown };
  if (o.$type !== "blob") return null;
  const ref = o.ref as { $link?: unknown } | undefined;
  const cid = typeof ref?.$link === "string" ? ref.$link : null;
  const mimeType = typeof o.mimeType === "string" ? o.mimeType : null;
  const size = typeof o.size === "number" ? o.size : null;
  if (cid === null || mimeType === null || size === null) return null;
  return { cid, mimeType, size };
}

function blobToDisplayUrl(pdsUrl: string, did: string, blob: AvatarBlobRef): string {
  return `${pdsUrl}/xrpc/com.atproto.sync.getBlob?did=${encodeURIComponent(
    did,
  )}&cid=${encodeURIComponent(blob.cid)}`;
}

function rowToProfile(did: string, pdsUrl: string, value: RawProfile): CocoreProfile {
  const avatar = readAvatarBlob(value.avatar);
  const legacyUrl = readField(value.avatarUrl);
  const avatarUrl = avatar ? blobToDisplayUrl(pdsUrl, did, avatar) : legacyUrl;
  return {
    did,
    displayName: readField(value.displayName),
    bio: readField(value.bio),
    avatarUrl,
    avatar,
    handle: readField(value.handle),
    createdAt: typeof value.createdAt === "string" ? value.createdAt : "",
    updatedAt: typeof value.updatedAt === "string" ? value.updatedAt : null,
  };
}

/** Resolves the user's PDS URL from the OAuth session's audience claim. */
async function getPdsUrl(session: OAuthSession): Promise<string> {
  const info = await session.getTokenInfo();
  return info.aud.replace(/\/$/, "");
}

interface RawProfileWithRaw {
  profile: CocoreProfile;
  /** Raw record value as returned by getRecord — needed to round-trip
   *  fields like `avatar` (a blob ref) across read-modify-write
   *  without lossy reserialization. */
  raw: RawProfile;
}

/** Fetch the user's profile record. Returns null when the record
 *  doesn't exist yet (the typical first-sign-in case before
 *  `ensureMyProfile` has run). */
async function getMyProfileRaw(session: OAuthSession): Promise<RawProfileWithRaw | null> {
  const params = new URLSearchParams({
    repo: session.did,
    collection: COLLECTION,
    rkey: RKEY,
  });
  const r = await session.handle(`/xrpc/com.atproto.repo.getRecord?${params}`, {
    method: "GET",
  });
  if (r.status === 404) return null;
  if (!r.ok) return null;
  const body = (await r.json()) as { value?: RawProfile };
  if (!body.value) return null;
  const pdsUrl = await getPdsUrl(session);
  return { profile: rowToProfile(session.did, pdsUrl, body.value), raw: body.value };
}

async function getMyProfile(session: OAuthSession): Promise<CocoreProfile | null> {
  const result = await getMyProfileRaw(session);
  return result ? result.profile : null;
}

/** Idempotent: returns the user's existing profile or provisions a
 *  fresh one from their Bluesky public profile. Safe to call from
 *  the OAuth callback (best-effort there) AND on every /account
 *  page load (one extra getRecord for users who already have a
 *  profile, no PDS write). */
export async function ensureMyProfile(session: OAuthSession): Promise<CocoreProfile> {
  const existing = await getMyProfile(session);
  if (existing) return existing;
  const bsky = await runTraced(
    "bsky.fetchPublicProfile",
    fetchBlueskyPublicProfileFieldsEffect(session.did),
  );
  const now = new Date().toISOString();
  const record: Record<string, unknown> = { createdAt: now };
  if (bsky?.displayName) record.displayName = bsky.displayName;
  if (bsky?.avatarUrl) record.avatarUrl = bsky.avatarUrl;
  if (bsky?.handle) record.handle = bsky.handle;
  await putProfileRecord(session, record);
  return (
    (await getMyProfile(session)) ?? {
      did: session.did,
      displayName: bsky?.displayName ?? null,
      avatarUrl: bsky?.avatarUrl ?? null,
      avatar: null,
      handle: bsky?.handle ?? null,
      bio: null,
      createdAt: now,
      updatedAt: null,
    }
  );
}

export interface UpdateProfileInputs {
  /** undefined = leave alone, "" or null = clear the field. */
  displayName?: string | null;
  bio?: string | null;
  avatarUrl?: string | null;
}

const ALLOWED_AVATAR_MIME_TYPES = new Set(["image/png", "image/jpeg", "image/webp"]);

const MAX_AVATAR_BYTES = 2 * 1000 * 1000; // 2 MB — matches the lexicon's `maxSize`.

interface UploadBlobResponse {
  blob?: {
    $type?: string;
    ref?: { $link?: string };
    mimeType?: string;
    size?: number;
  };
}

function parseDataUrl(dataUrl: string): { mimeType: string; bytes: Uint8Array } {
  const match = /^data:([^;,]+);base64,(.+)$/.exec(dataUrl);
  if (!match) {
    throw new Error("Avatar must be a base64 data URL (e.g. data:image/png;base64,…).");
  }
  const mimeType = match[1]!.toLowerCase();
  if (!ALLOWED_AVATAR_MIME_TYPES.has(mimeType)) {
    throw new Error(`Unsupported avatar type ${mimeType}. Use png, jpeg, or webp.`);
  }
  const bytes = Uint8Array.from(globalThis.atob(match[2]!), (c) => c.codePointAt(0) ?? 0);
  if (bytes.byteLength > MAX_AVATAR_BYTES) {
    throw new Error(
      `Avatar is too large (${String(bytes.byteLength)} bytes). Max ${String(MAX_AVATAR_BYTES)} bytes.`,
    );
  }
  return { mimeType, bytes };
}

/** Upload an image data URL as a blob to the user's PDS, then write
 *  the blob ref into the profile record's `avatar` field. Clears the
 *  legacy `avatarUrl` so reads return the freshly-uploaded blob.
 *  Returns the updated profile. */
export async function uploadMyAvatar(
  session: OAuthSession,
  imageDataUrl: string,
): Promise<CocoreProfile> {
  const { mimeType, bytes } = parseDataUrl(imageDataUrl);
  const uploadRes = await session.handle(`/xrpc/com.atproto.repo.uploadBlob`, {
    method: "POST",
    headers: { "Content-Type": mimeType },
    body: bytes as BodyInit,
  });
  if (!uploadRes.ok) {
    const body = await uploadRes.text().catch(() => "");
    throw new Error(`uploadBlob returned ${String(uploadRes.status)}: ${body.slice(0, 300)}`);
  }
  const uploadBody = (await uploadRes.json()) as UploadBlobResponse;
  const blob = uploadBody.blob;
  const cid = blob?.ref?.$link;
  if (typeof cid !== "string" || cid.length === 0) {
    throw new Error("uploadBlob response missing blob.ref.$link");
  }

  const existingRaw = await getMyProfileRaw(session);
  const existingValue: RawProfile = existingRaw?.raw ?? { createdAt: new Date().toISOString() };
  const merged: Record<string, unknown> = { ...existingValue };
  merged.avatar = {
    $type: "blob",
    ref: { $link: cid },
    mimeType: typeof blob?.mimeType === "string" ? blob.mimeType : mimeType,
    size: typeof blob?.size === "number" ? blob.size : bytes.byteLength,
  };
  // Drop the legacy URL so future reads pick up the new blob.
  delete merged.avatarUrl;
  merged.updatedAt = new Date().toISOString();
  if (typeof merged.createdAt !== "string" || merged.createdAt.length === 0) {
    merged.createdAt = new Date().toISOString();
  }

  await putProfileRecord(session, merged);
  return (
    (await getMyProfile(session)) ??
    rowToProfile(session.did, await getPdsUrl(session), merged as RawProfile)
  );
}

/** Read-modify-putRecord. Only the fields present in `inputs` move;
 *  the rest are preserved from the existing record. Empty / null
 *  inputs explicitly clear the corresponding field. */
export async function updateMyProfile(
  session: OAuthSession,
  inputs: UpdateProfileInputs,
): Promise<CocoreProfile> {
  const existingRaw = await getMyProfileRaw(session);
  const existing = existingRaw?.profile ?? (await ensureMyProfile(session));
  const existingValue = existingRaw?.raw ?? {};
  const merged: Record<string, unknown> = {
    createdAt: existing.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  if (existing.handle !== null) merged.handle = existing.handle;
  // Preserve avatar blob across updates. Callers use `uploadMyAvatar`
  // (not this function) to mutate it.
  if (existingValue.avatar !== undefined) merged.avatar = existingValue.avatar;
  // displayName
  if (inputs.displayName === undefined) {
    if (existing.displayName !== null) merged.displayName = existing.displayName;
  } else if (inputs.displayName && inputs.displayName.trim().length > 0) {
    merged.displayName = inputs.displayName.trim().slice(0, 256);
  }
  // bio
  if (inputs.bio === undefined) {
    if (existing.bio !== null) merged.bio = existing.bio;
  } else if (inputs.bio && inputs.bio.trim().length > 0) {
    merged.bio = inputs.bio.trim().slice(0, 2560);
  }
  // avatarUrl (legacy field). Only meaningful when no `avatar` blob is
  // set on the record; the read path prefers blob over URL.
  if (inputs.avatarUrl === undefined) {
    if (typeof existingValue.avatarUrl === "string" && existingValue.avatarUrl.length > 0) {
      merged.avatarUrl = existingValue.avatarUrl;
    }
  } else if (inputs.avatarUrl && inputs.avatarUrl.trim().length > 0) {
    merged.avatarUrl = inputs.avatarUrl.trim().slice(0, 2048);
  }
  await putProfileRecord(session, merged);
  return (
    (await getMyProfile(session)) ??
    rowToProfile(session.did, await getPdsUrl(session), merged as RawProfile)
  );
}

async function putProfileRecord(
  session: OAuthSession,
  record: Record<string, unknown>,
): Promise<void> {
  const r = await session.handle(`/xrpc/com.atproto.repo.putRecord`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      repo: session.did,
      collection: COLLECTION,
      rkey: RKEY,
      record,
    }),
  });
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    // The OAuth scope for `dev.cocore.account.profile` was added
    // after some users had already signed in, so their existing
    // tokens lack the grant. Surface a clear next step instead of
    // the raw PDS error — re-auth (sign out + sign back in) is the
    // only fix; tokens don't retroactively gain scopes.
    if (r.status === 403 && body.includes("ScopeMissingError")) {
      throw new Error(
        "Your sign-in is missing the profile scope. Sign out and back in to re-authorize.",
      );
    }
    throw new Error(`putRecord ${COLLECTION} returned ${r.status}: ${body.slice(0, 300)}`);
  }
  // Pick up the uri/cid the PDS assigned so the bridge mirror has
  // both halves. putRecord returns them as JSON; we ignore parse
  // errors and skip the mirror in that case.
  let out: { uri?: string; cid?: string } = {};
  try {
    out = (await r.json()) as typeof out;
  } catch {
    return;
  }
  if (typeof out.uri === "string") {
    mirrorProfileToBridge(session.did, out.uri, out.cid ?? "", record);
  }
}
