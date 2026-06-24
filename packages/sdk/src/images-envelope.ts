// The `images-v1` canonical image OUTPUT envelope.
//
// cocore's inference path historically committed `outputCommitment` over
// the UTF-8 bytes of the answer text. Image-generation models produce
// image bytes instead, so a job that emits images commits to a
// CANONICAL-JSON envelope of those images, and the provider's receipt
// sets `outputFormat` to "images-v1" to say so.
//
// The load-bearing property mirrors the `messages-v1` INPUT envelope
// (multimodal-envelope.ts): `outputCommitment` is the SHA-256 over the
// EXACT canonical envelope bytes. The provider builds these bytes and
// hashes them; a verifier holding the logical images reconstructs the
// identical bytes and recomputes the commitment. Neither side parses the
// payload to compute the hash, so it stays self-consistent.
//
// Canonicalization MUST match provider/src/images_envelope.rs (sorted
// keys, no insignificant whitespace) so the Rust provider and this TS
// verifier produce byte-identical output.

import { canonicalBytes } from "./canonical.ts";

/** Wire value for `dev.cocore.compute.receipt.outputFormat` (and the
 *  `dev.cocore.compute.job.outputFormat` hint) when the committed output
 *  bytes are this envelope rather than UTF-8 answer text. */
export const IMAGES_V1 = "images-v1" as const;

/** Schema version carried in the envelope so a verifier can reject a
 *  shape it doesn't understand rather than mis-reading it. */
export const IMAGES_ENVELOPE_VERSION = 1 as const;

/** A single generated image. `data` is the raw image bytes,
 *  base64-encoded, carried inline (no external fetch needed to verify the
 *  commitment). `mime` is the media type (e.g. "image/png"). */
export interface EnvelopeImage {
  mime: string;
  data: string;
}

export interface ImagesEnvelope {
  v: typeof IMAGES_ENVELOPE_VERSION;
  images: EnvelopeImage[];
}

/** Canonical bytes of the images envelope — the exact payload that
 *  `outputCommitment` is computed over. Reuses the shared `canonicalBytes`
 *  so the serialization matches the Rust provider byte for byte. */
export function buildImagesEnvelopeBytes(images: EnvelopeImage[]): Uint8Array {
  const envelope: ImagesEnvelope = { v: IMAGES_ENVELOPE_VERSION, images };
  return canonicalBytes(envelope as unknown as Record<string, unknown>);
}

/** Parse + minimally validate envelope bytes back into the structured
 *  form. Used by verifiers and tests; the provider has its own Rust
 *  parser. Throws on a malformed or unknown-version envelope. */
export function parseImagesEnvelope(bytes: Uint8Array): ImagesEnvelope {
  const obj = JSON.parse(new TextDecoder().decode(bytes)) as unknown;
  if (!obj || typeof obj !== "object") throw new Error("images envelope is not an object");
  const e = obj as Record<string, unknown>;
  if (e.v !== IMAGES_ENVELOPE_VERSION) {
    throw new Error(`unsupported images envelope version: ${String(e.v)}`);
  }
  if (!Array.isArray(e.images)) throw new Error("images envelope.images must be an array");
  const images: EnvelopeImage[] = e.images.map((im, i) => {
    if (!im || typeof im !== "object") throw new Error(`image ${i} is not an object`);
    const img = im as Record<string, unknown>;
    if (typeof img.mime !== "string") throw new Error(`image ${i} mime must be a string`);
    if (typeof img.data !== "string") throw new Error(`image ${i} data must be a string`);
    return { mime: img.mime, data: img.data };
  });
  return { v: IMAGES_ENVELOPE_VERSION, images };
}
