// Shared model-kind heuristic for classifying a model id by what it
// produces. Used by the models directory (badges/filter tabs) and the chat
// composer (to adapt the send behavior for image models). One source of
// truth so the two surfaces never disagree.
//
// This is a CLIENT-side display/UX heuristic over an opaque model id. The
// provider's pricing catalog is the authoritative classifier on the serving
// side (see provider/src/pricing.rs `Modality` + `is_image_model`); this
// mirrors it for ids the console only knows as strings.

const MODEL_KINDS = ["text", "image", "audio", "video", "test", "other"] as const;
export type ModelKind = (typeof MODEL_KINDS)[number];

/** Classify a model id by the kind of output it produces. Mirrors the Rust
 *  provider heuristic; image markers stay in sync with `IMAGE_MODEL_MARKERS`
 *  in `provider/src/engines/mod.rs`. */
export function inferModelKind(modelId: string): ModelKind {
  const m = modelId.toLowerCase();
  // The `stub` model is the network's hello-world health check, not a real
  // inference target. `stub-flux` is its image-gen counterpart and IS an
  // image model, so it must be classified before the "test" short-circuit.
  if (m === "stub") return "test";
  if (/(whisper|wav2lip|\btts\b|audio|speech)/.test(m)) return "audio";
  if (/(video|cogvideo|svd|animate|\bwan\b)/.test(m)) return "video";
  if (/(flux|sdxl|\bsd[\d.-]|stable|diffusion|dall|midjourney|imagen|\bimg\b)/.test(m))
    return "image";
  if (/(llama|mistral|gpt|qwen|gemma|phi|mixtral|chat|instruct|claude|\bo1\b|embed)/.test(m))
    return "text";
  return "other";
}

/** True when the model produces images (text-to-image / img2img). */
export function isImageModel(modelId: string): boolean {
  return inferModelKind(modelId) === "image";
}
