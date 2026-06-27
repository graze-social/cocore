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

export const INFERENCE_API_CATALOG: Array<InferenceApiCatalogEntry> = [
  {
    id: "inference-api-chat-completions",
    navLabel: "chat/completions",
    method: "POST",
    path: "/chat/completions",
    description:
      "OpenAI-compatible chat completion. Routes to an attested provider serving the requested model. Set country to an ISO 3166-1 alpha-2 code (e.g. US) to route only to providers advertising that region — an advisory provider self-claim — failing closed with no_providers_for_country when none match.",
    auth: "required",
    params: [
      { name: "model", type: "string", required: true },
      { name: "messages", type: "array", required: true },
      { name: "stream", type: "boolean" },
      { name: "max_tokens", type: "integer" },
      { name: "country", type: "string" },
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
      { kind: "text", param: "country", label: "country", placeholder: "US" },
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
      "Same request shape as chat/completions, but routing is limited to providers run by DIDs on your friends list. country still narrows by region.",
    auth: "required",
    params: [
      { name: "model", type: "string", required: true },
      { name: "messages", type: "array", required: true },
      { name: "stream", type: "boolean" },
      { name: "max_tokens", type: "integer" },
      { name: "country", type: "string" },
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
      { kind: "text", param: "country", label: "country", placeholder: "US" },
    ],
    example: { body: CHAT_BODY, canRun: false },
  },
  {
    id: "inference-api-verified-chat-completions",
    navLabel: "verified/chat/completions",
    method: "POST",
    path: "/verified/chat/completions",
    description:
      'Same request shape as chat/completions, but routing is limited to providers whose attestation is cryptographically verified (recomputed from the signed Apple-rooted attestation, not the self-asserted label). Set min_trust to "hardware-attested" (default) or "confidential" to pick the floor. Fails closed with no_verified_providers when none qualify. country still narrows by region.',
    auth: "required",
    params: [
      { name: "model", type: "string", required: true },
      { name: "messages", type: "array", required: true },
      { name: "min_trust", type: "string" },
      { name: "stream", type: "boolean" },
      { name: "max_tokens", type: "integer" },
      { name: "country", type: "string" },
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
      { kind: "text", param: "country", label: "country", placeholder: "US" },
    ],
    example: { body: CHAT_BODY, canRun: false },
  },
  {
    id: "inference-api-probono-chat-completions",
    navLabel: "probono/chat/completions",
    method: "POST",
    path: "/probono/chat/completions",
    description:
      "Same request shape as chat/completions, but routing is limited to providers whose proBono policy elects to serve YOU for free (mode any, or mode direct with your DID listed). A matched job is unmetered, zero-price, and takes no exchange cut, so a balance-less requester can still get a completion. Fails closed with no_pro_bono_providers (503) when no connected provider currently offers you pro bono, or pro_bono_lookup_failed (502) when the provider lookup itself fails. country still narrows by region.",
    auth: "required",
    params: [
      { name: "model", type: "string", required: true },
      { name: "messages", type: "array", required: true },
      { name: "stream", type: "boolean" },
      { name: "max_tokens", type: "integer" },
      { name: "country", type: "string" },
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
      { kind: "text", param: "country", label: "country", placeholder: "US" },
    ],
    example: { body: CHAT_BODY, canRun: false },
  },
];

export const INFERENCE_API_TOPIC_SECTIONS = [
  {
    id: "inference-api-image-input",
    navLabel: "image input",
    title: "Image input",
    description:
      "Vision-capable models accept images alongside text using OpenAI's multimodal content parts. Carried inline as base64 or fetched from a URL; no separate upload step.",
  },
] as const;

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
