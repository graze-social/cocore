// Shared model-kind heuristic over an opaque model id. The provider's pricing
// catalog is the AUTHORITATIVE classifier on the serving side
// (provider/src/pricing.rs `Modality` + `is_image_model`); this is the
// lightweight TS mirror the dispatch routes + UI use to guard image-only
// behavior (e.g. multi-output fan-out) without a round-trip.

/** True when the model produces images (text-to-image / img2img) rather than
 *  text. Mirrors the Rust `IMAGE_MODEL_MARKERS` + the console `inferModelKind`
 *  image branch. The chat `stub` is excluded; `stub-flux` matches (FLUX). */
export function isImageModel(modelId: string): boolean {
  const m = modelId.toLowerCase();
  if (m === "stub") return false;
  return /(flux|sdxl|\bsd[\d.-]|stable|diffusion|dall|midjourney|imagen|\bimg\b)/.test(m);
}
