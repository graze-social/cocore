// Shared model-kind heuristic for classifying a model id by what it
// produces. Used by the models directory (badges/filter tabs) and the chat
// composer (to adapt the send behavior for image models). One source of
// truth so the two surfaces never disagree.
//
// This is a CLIENT-side display/UX heuristic over an opaque model id. The
// provider's pricing catalog is the authoritative classifier on the serving
// side (see provider/src/pricing.rs `Modality` + `is_image_model`); this
// mirrors it for ids the console only knows as strings.

import { isImageModel } from "@cocore/sdk/model-kind";

// Re-export the SDK's `isImageModel` so the image heuristic has ONE source of
// truth shared with the dispatch routes (console + appview).
export { isImageModel };

const MODEL_KINDS = ["text", "image", "audio", "video", "test", "other"] as const;
export type ModelKind = (typeof MODEL_KINDS)[number];

/** Classify a model id by the kind of output it produces. Mirrors the Rust
 *  provider heuristic; the image branch defers to the shared `isImageModel`. */
export function inferModelKind(modelId: string): ModelKind {
  const m = modelId.toLowerCase();
  // The `stub` model is the network's hello-world health check, not a real
  // inference target. `stub-flux` is its image-gen counterpart and IS an
  // image model (handled by `isImageModel` below).
  if (m === "stub") return "test";
  if (/(whisper|wav2lip|\btts\b|audio|speech)/.test(m)) return "audio";
  if (/(video|cogvideo|svd|animate|\bwan\b)/.test(m)) return "video";
  if (isImageModel(modelId)) return "image";
  if (/(llama|mistral|gpt|qwen|gemma|phi|mixtral|chat|instruct|claude|\bo1\b|embed)/.test(m))
    return "text";
  return "other";
}
