"use client";

import * as stylex from "@stylexjs/stylex";
import { Link } from "@tanstack/react-router";

import { InferenceApiEndpoint } from "@/components/inference-docs/inference-api-endpoint.tsx";
import { docsStyles } from "@/components/docs/docs-page.stylex.tsx";
import {
  HighlightedBlock,
  inferenceDocsSharedStyles,
} from "@/components/inference-docs/shared.tsx";
import {
  INFERENCE_API_CATALOG,
  INFERENCE_API_ERROR_SECTIONS,
} from "@/lib/inference-docs/catalog.ts";
import { INFERENCE_API_INTRO_ID } from "@/lib/inference-docs/navigation-api.ts";

export function InferenceApiReferencePage({ baseUrl }: { baseUrl: string }) {
  return (
    <>
      <div {...stylex.props(docsStyles.masthead)} id={INFERENCE_API_INTRO_ID}>
        <div {...stylex.props(docsStyles.kicker)}>API reference</div>
        <h1 {...stylex.props(docsStyles.title)}>Inference API</h1>
        <p {...stylex.props(docsStyles.dek)}>
          OpenAI-compatible HTTP endpoints at{" "}
          <code {...stylex.props(docsStyles.codeInline)}>{baseUrl}</code>. Authenticated routes
          accept a co/core API key as{" "}
          <code {...stylex.props(docsStyles.codeInline)}>Authorization: Bearer …</code>.
        </p>
        <div {...stylex.props(docsStyles.baseUrl)}>
          <span {...stylex.props(docsStyles.baseUrlLabel)}>Base URL</span>
          <span>{baseUrl}</span>
        </div>
      </div>

      {INFERENCE_API_CATALOG.map((entry, index) => (
        <InferenceApiEndpoint key={entry.id} entry={entry} baseUrl={baseUrl} first={index === 0} />
      ))}

      {INFERENCE_API_ERROR_SECTIONS.map((section) => (
        <section key={section.id} id={section.id} {...stylex.props(docsStyles.endpoint)}>
          <div {...stylex.props(docsStyles.endpointGrid)}>
            <div {...stylex.props(docsStyles.endpointLeft)}>
              <h2 {...stylex.props(docsStyles.h2)}>{section.title}</h2>
              <p {...stylex.props(docsStyles.endpointDesc)}>{section.description}</p>
              {section.id === "inference-api-dispatch-errors" ? (
                <HighlightedBlock
                  lang="json"
                  code={`// 404 — no provider is serving this model
{ "error": { "type": "invalid_request_error", "code": "model_not_found", "message": "..." } }

// 503 — no providers are connected
{ "error": { "type": "service_unavailable_error", "code": "no_providers_connected", "message": "..." } }

// 503 — friends-only, but no friends are online
{ "error": { "type": "service_unavailable_error", "code": "no_friends_available", "message": "..." } }

// 404 — friends-only, but no friend serves this model
{ "error": { "type": "invalid_request_error", "code": "no_friends_for_model", "message": "..." } }

// 503 — country set, but no provider in that region serves this model
{ "error": { "type": "service_unavailable_error", "code": "no_providers_for_country", "message": "..." } }

// 503 — pro-bono route, but no connected provider currently serves you free
{ "error": { "type": "service_unavailable_error", "code": "no_pro_bono_providers", "message": "..." } }

// 502 — pro-bono route, the provider lookup itself failed (try again)
{ "error": { "type": "server_error", "code": "pro_bono_lookup_failed", "message": "..." } }`}
                />
              ) : (
                <>
                  <HighlightedBlock
                    lang="json"
                    code={`{
  "error": {
    "message": "Missing Authorization: Bearer header",
    "type": "authentication_error",
    "code": null,
    "param": null
  }
}`}
                  />
                  <ul {...stylex.props(inferenceDocsSharedStyles.list)}>
                    <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
                      <code {...stylex.props(docsStyles.codeInline)}>401 authentication_error</code>{" "}
                      — missing or invalid API key. Create a new key on{" "}
                      <Link to="/account" {...stylex.props(docsStyles.proseLink)}>
                        /account
                      </Link>
                      .
                    </li>
                    <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
                      <code {...stylex.props(docsStyles.codeInline)}>
                        400 invalid_request_error
                      </code>{" "}
                      — malformed body (missing model, messages, etc.).
                    </li>
                    <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
                      <code {...stylex.props(docsStyles.codeInline)}>502 server_error</code> —
                      provider disconnected mid-stream. Retrying usually succeeds.
                    </li>
                  </ul>
                </>
              )}
            </div>
          </div>
        </section>
      ))}
    </>
  );
}
