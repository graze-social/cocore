import {
  INFERENCE_API_CATALOG,
  INFERENCE_API_ERROR_SECTIONS,
  INFERENCE_API_TOPIC_SECTIONS,
} from "./catalog.ts";

export const INFERENCE_API_INTRO_ID = "inference-api-intro";

export function inferenceApiScrollSpyIds(): Array<string> {
  return [
    INFERENCE_API_INTRO_ID,
    ...INFERENCE_API_CATALOG.map((entry) => entry.id),
    ...INFERENCE_API_TOPIC_SECTIONS.map((section) => section.id),
    ...INFERENCE_API_ERROR_SECTIONS.map((section) => section.id),
  ];
}

export const INFERENCE_API_SCROLL_SPY_IDS = inferenceApiScrollSpyIds();

export const LEGACY_INFERENCE_API_SLUG_REDIRECTS: Record<string, string> = {
  "chat-completions": "inference-api-chat-completions",
  models: "inference-api-models",
  "friends-only": "inference-api-private-chat-completions",
  "dispatch-errors": "inference-api-dispatch-errors",
  errors: "inference-api-http-errors",
};

export function inferenceApiReferenceHref(fragmentId?: string): string {
  return fragmentId
    ? `/docs/inference/api-reference#${fragmentId}`
    : "/docs/inference/api-reference";
}
