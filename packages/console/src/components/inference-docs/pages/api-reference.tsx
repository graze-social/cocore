"use client";

import * as stylex from "@stylexjs/stylex";
import { Link } from "@tanstack/react-router";

import { InferenceApiEndpoint } from "@/components/inference-docs/inference-api-endpoint.tsx";
import { InferenceApiDocLink } from "@/components/inference-docs/inference-doc-link.tsx";
import { docsStyles } from "@/components/docs/docs-page.stylex.tsx";
import {
  HighlightedBlock,
  inferenceDocsSharedStyles,
} from "@/components/inference-docs/shared.tsx";
import {
  INFERENCE_API_CATALOG,
  INFERENCE_API_ERROR_SECTIONS,
  INFERENCE_API_TOPIC_SECTIONS,
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

      {INFERENCE_API_TOPIC_SECTIONS.map((section) => (
        <section key={section.id} id={section.id} {...stylex.props(docsStyles.endpoint)}>
          <div {...stylex.props(docsStyles.endpointGrid)}>
            <div {...stylex.props(docsStyles.endpointLeft)}>
              <h2 {...stylex.props(docsStyles.h2)}>{section.title}</h2>
              <p {...stylex.props(docsStyles.endpointDesc)}>{section.description}</p>
              <p {...stylex.props(docsStyles.prose)}>
                Any <code {...stylex.props(docsStyles.codeInline)}>chat/completions</code> route
                (open, <code {...stylex.props(docsStyles.codeInline)}>private</code>, and{" "}
                <code {...stylex.props(docsStyles.codeInline)}>verified</code>) accepts the OpenAI
                array-of-parts <code {...stylex.props(docsStyles.codeInline)}>content</code> shape.
                A message is either a plain string (text only) or an ordered list of{" "}
                <code {...stylex.props(docsStyles.codeInline)}>text</code> and{" "}
                <code {...stylex.props(docsStyles.codeInline)}>image_url</code> parts. There is no
                separate upload endpoint — images travel inside the request body.
              </p>
              <HighlightedBlock
                lang="json"
                code={`{
  "model": "your-vision-model",
  "messages": [
    {
      "role": "user",
      "content": [
        { "type": "text", "text": "What's in this image?" },
        {
          "type": "image_url",
          "image_url": {
            "url": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg..."
          }
        }
      ]
    }
  ]
}`}
              />
              <p {...stylex.props(docsStyles.prose)}>
                The <code {...stylex.props(docsStyles.codeInline)}>image_url.url</code> field takes
                one of two forms:
              </p>
              <ul {...stylex.props(inferenceDocsSharedStyles.list)}>
                <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
                  <strong>Inline base64 data URI</strong> —{" "}
                  <code {...stylex.props(docsStyles.codeInline)}>
                    data:&lt;mime&gt;;base64,&lt;payload&gt;
                  </code>
                  . The MIME type must be{" "}
                  <code {...stylex.props(docsStyles.codeInline)}>image/*</code> (e.g.{" "}
                  <code {...stylex.props(docsStyles.codeInline)}>image/png</code>,{" "}
                  <code {...stylex.props(docsStyles.codeInline)}>image/jpeg</code>). The bytes are
                  sealed directly into the signed job, so the receipt verifies offline with no extra
                  fetch.
                </li>
                <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
                  <strong>Remote URL</strong> — an{" "}
                  <code {...stylex.props(docsStyles.codeInline)}>http(s)://</code> link. co/core
                  fetches it server-side, verifies the response is{" "}
                  <code {...stylex.props(docsStyles.codeInline)}>image/*</code>, and inlines it as
                  base64 before sealing, so the input stays self-contained.
                </li>
              </ul>
              <h3 {...stylex.props(docsStyles.h2)}>Limits</h3>
              <ul {...stylex.props(inferenceDocsSharedStyles.list)}>
                <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
                  Up to <strong>20 MiB</strong> of decoded image bytes per request, budgeted
                  separately from the <strong>1 MiB</strong> text limit.
                </li>
                <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
                  Up to <strong>256</strong> messages per request; images may be spread across them.
                </li>
                <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
                  <strong>Images only.</strong> Non-image MIME types and arbitrary file attachments
                  (PDFs, documents, audio) are rejected — there is no general file-upload part
                  today.
                </li>
              </ul>
              <h3 {...stylex.props(docsStyles.h2)}>Model support</h3>
              <p {...stylex.props(docsStyles.prose)}>
                Image input is not gated per model: any{" "}
                <code {...stylex.props(docsStyles.codeInline)}>model</code> id you can route to will
                accept an image-bearing request. Whether the image is actually understood depends on
                the model — send images to a vision/multimodal model (the{" "}
                <InferenceApiDocLink fragment="inference-api-models">
                  models directory
                </InferenceApiDocLink>{" "}
                flags vision-capable models). A bad or unparseable{" "}
                <code {...stylex.props(docsStyles.codeInline)}>image_url</code> with no accompanying
                text returns{" "}
                <code {...stylex.props(docsStyles.codeInline)}>400 invalid_request_error</code>.
              </p>
            </div>
          </div>
        </section>
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
