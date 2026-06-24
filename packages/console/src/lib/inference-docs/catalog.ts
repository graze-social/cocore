export type InferenceApiAuth = "none" | "required";

export type InferenceApiParamControl =
  | { kind: "text"; param: string; label?: string; placeholder?: string }
  | {
      kind: "select";
      param: string;
      label?: string;
      options: Array<{ id: string; label: string }>;
    };

export type InferenceApiCatalogEntry = {
  id: string;
  navLabel: string;
  method: "GET" | "POST";
  path: string;
  description: string;
  auth: InferenceApiAuth;
  params: Array<{ name: string; type: string; required?: boolean }>;
  controls: Array<InferenceApiParamControl>;
  example: {
    query?: Record<string, string>;
    body?: Record<string, unknown>;
    /** Defaults to true for unauthenticated GET endpoints. */
    canRun?: boolean;
  };
};

const CHAT_BODY = {
  model: "stub",
  messages: [{ role: "user", content: "Hello" }],
  stream: false,
  max_tokens: 256,
};

const IMAGE_GEN_BODY = {
  model: "stub-flux",
  prompt: "a watercolor fox",
  n: 1,
};

export const INFERENCE_API_CATALOG: Array<InferenceApiCatalogEntry> = [
  {
    id: "inference-api-chat-completions",
    navLabel: "chat/completions",
    method: "POST",
    path: "/chat/completions",
    description:
      "OpenAI-compatible chat completion. Routes to an attested provider serving the requested model.",
    auth: "required",
    params: [
      { name: "model", type: "string", required: true },
      { name: "messages", type: "array", required: true },
      { name: "stream", type: "boolean" },
      { name: "max_tokens", type: "integer" },
    ],
    controls: [
      { kind: "text", param: "model", label: "model", placeholder: "stub" },
      {
        kind: "text",
        param: "message",
        label: "user message",
        placeholder: "Hello",
      },
      { kind: "text", param: "max_tokens", label: "max_tokens", placeholder: "256" },
    ],
    example: { body: CHAT_BODY, canRun: false },
  },
  {
    id: "inference-api-models",
    navLabel: "models",
    method: "GET",
    path: "/models",
    description:
      "Public model directory. Default response matches OpenAI's list shape; use view for co/core-specific detail.",
    auth: "none",
    params: [{ name: "view", type: "string", required: false }],
    controls: [
      {
        kind: "select",
        param: "view",
        label: "view",
        options: [
          { id: "default", label: "openai (default)" },
          { id: "summary", label: "summary" },
          { id: "directory", label: "directory" },
        ],
      },
    ],
    example: { query: {}, canRun: true },
  },
  {
    id: "inference-api-private-chat-completions",
    navLabel: "private/chat/completions",
    method: "POST",
    path: "/private/chat/completions",
    description:
      "Same request shape as chat/completions, but routing is limited to providers run by DIDs on your friends list.",
    auth: "required",
    params: [
      { name: "model", type: "string", required: true },
      { name: "messages", type: "array", required: true },
      { name: "stream", type: "boolean" },
      { name: "max_tokens", type: "integer" },
    ],
    controls: [
      { kind: "text", param: "model", label: "model", placeholder: "stub" },
      {
        kind: "text",
        param: "message",
        label: "user message",
        placeholder: "Hello",
      },
      { kind: "text", param: "max_tokens", label: "max_tokens", placeholder: "256" },
    ],
    example: { body: CHAT_BODY, canRun: false },
  },
  {
    id: "inference-api-verified-chat-completions",
    navLabel: "verified/chat/completions",
    method: "POST",
    path: "/verified/chat/completions",
    description:
      'Same request shape as chat/completions, but routing is limited to providers whose attestation is cryptographically verified (recomputed from the signed Apple-rooted attestation, not the self-asserted label). Set min_trust to "hardware-attested" (default) or "confidential" to pick the floor. Fails closed with no_verified_providers when none qualify.',
    auth: "required",
    params: [
      { name: "model", type: "string", required: true },
      { name: "messages", type: "array", required: true },
      { name: "min_trust", type: "string" },
      { name: "stream", type: "boolean" },
      { name: "max_tokens", type: "integer" },
    ],
    controls: [
      { kind: "text", param: "model", label: "model", placeholder: "stub" },
      {
        kind: "text",
        param: "message",
        label: "user message",
        placeholder: "Hello",
      },
      {
        kind: "text",
        param: "min_trust",
        label: "min_trust",
        placeholder: "hardware-attested",
      },
      { kind: "text", param: "max_tokens", label: "max_tokens", placeholder: "256" },
    ],
    example: { body: CHAT_BODY, canRun: false },
  },
  {
    id: "inference-api-images-generations",
    navLabel: "images/generations",
    method: "POST",
    path: "/images/generations",
    description:
      'OpenAI-compatible text-to-image. Routes to an attested provider serving the requested image model. Returns inline base64 only (response_format "b64_json"); "url" is rejected. n (1–4) fans out one job + receipt per image. The provider/machine that served each image is named in x_cocore.',
    auth: "required",
    params: [
      { name: "model", type: "string", required: true },
      { name: "prompt", type: "string", required: true },
      { name: "n", type: "integer" },
    ],
    controls: [
      { kind: "text", param: "model", label: "model", placeholder: "stub-flux" },
      { kind: "text", param: "prompt", label: "prompt", placeholder: "a watercolor fox" },
      { kind: "text", param: "n", label: "n", placeholder: "1" },
    ],
    example: { body: IMAGE_GEN_BODY, canRun: false },
  },
  {
    id: "inference-api-images-edits",
    navLabel: "images/edits",
    method: "POST",
    path: "/images/edits",
    description:
      "OpenAI-compatible image edit (img2img). multipart/form-data with model, prompt, image (the reference), and n. The reference image is sealed into a messages-v1 envelope alongside the prompt. Returns inline base64 only.",
    auth: "required",
    params: [
      { name: "model", type: "string", required: true },
      { name: "prompt", type: "string", required: true },
      { name: "image", type: "file", required: true },
      { name: "n", type: "integer" },
    ],
    controls: [
      { kind: "text", param: "model", label: "model", placeholder: "stub-flux" },
      { kind: "text", param: "prompt", label: "prompt", placeholder: "make it a watercolor" },
    ],
    example: { body: { model: "stub-flux", prompt: "make it a watercolor" }, canRun: false },
  },
  {
    id: "inference-api-private-images-generations",
    navLabel: "private/images/generations",
    method: "POST",
    path: "/private/images/generations",
    description:
      "Same request shape as images/generations, but routing is limited to providers run by DIDs on your friends list.",
    auth: "required",
    params: [
      { name: "model", type: "string", required: true },
      { name: "prompt", type: "string", required: true },
      { name: "n", type: "integer" },
    ],
    controls: [
      { kind: "text", param: "model", label: "model", placeholder: "stub-flux" },
      { kind: "text", param: "prompt", label: "prompt", placeholder: "a watercolor fox" },
      { kind: "text", param: "n", label: "n", placeholder: "1" },
    ],
    example: { body: IMAGE_GEN_BODY, canRun: false },
  },
  {
    id: "inference-api-verified-images-generations",
    navLabel: "verified/images/generations",
    method: "POST",
    path: "/verified/images/generations",
    description:
      'Same request shape as images/generations, but routing is limited to providers whose attestation is cryptographically verified. Set min_trust to "hardware-attested" (default) or "confidential". Fails closed with no_verified_providers when none qualify.',
    auth: "required",
    params: [
      { name: "model", type: "string", required: true },
      { name: "prompt", type: "string", required: true },
      { name: "min_trust", type: "string" },
      { name: "n", type: "integer" },
    ],
    controls: [
      { kind: "text", param: "model", label: "model", placeholder: "stub-flux" },
      { kind: "text", param: "prompt", label: "prompt", placeholder: "a watercolor fox" },
      {
        kind: "text",
        param: "min_trust",
        label: "min_trust",
        placeholder: "hardware-attested",
      },
      { kind: "text", param: "n", label: "n", placeholder: "1" },
    ],
    example: { body: IMAGE_GEN_BODY, canRun: false },
  },
];

export const INFERENCE_API_ERROR_SECTIONS = [
  {
    id: "inference-api-dispatch-errors",
    navLabel: "errors/dispatch",
    title: "Dispatch errors",
    description: "Returned when the exchange cannot place your request with a provider.",
  },
  {
    id: "inference-api-http-errors",
    navLabel: "errors/http",
    title: "HTTP errors",
    description: "Authentication, validation, and upstream failure responses.",
  },
] as const;
