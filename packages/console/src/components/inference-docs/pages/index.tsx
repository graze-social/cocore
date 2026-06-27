"use client";

import * as stylex from "@stylexjs/stylex";
import { Link } from "@tanstack/react-router";

import { docsStyles } from "@/components/docs/docs-page.stylex.tsx";
import {
  InferenceDocsOverview,
  InferenceDocsPage,
} from "@/components/inference-docs/inference-docs-page.tsx";
import { InferenceApiReferencePage } from "@/components/inference-docs/pages/api-reference.tsx";
import { InferenceQuickstartPage } from "@/components/inference-docs/pages/quickstart.tsx";
import {
  InferenceApiDocLink,
  InferenceDocLink,
} from "@/components/inference-docs/inference-doc-link.tsx";
import {
  HighlightedBlock,
  inferenceDocsSharedStyles,
} from "@/components/inference-docs/shared.tsx";
import { type InferenceDocsSlug } from "@/lib/inference-docs/navigation.ts";

export function InferenceDocsOverviewPage({ baseUrl }: { baseUrl: string }) {
  return (
    <InferenceDocsOverview baseUrl={baseUrl}>
      <h2 {...stylex.props(docsStyles.h2, docsStyles.h2First)}>What you get</h2>
      <p {...stylex.props(docsStyles.prose)}>
        co/core exposes an OpenAI-compatible HTTP API at{" "}
        <code {...stylex.props(docsStyles.codeInline)}>{baseUrl}</code>. Use it with the OpenAI SDK,
        curl, or any client that speaks{" "}
        <code {...stylex.props(docsStyles.codeInline)}>/v1/chat/completions</code>. Each request is
        matched to an online, attested provider and settled with a signed receipt.
      </p>
      <p {...stylex.props(docsStyles.prose)}>
        Requests can carry text or images: vision-capable models accept inline base64 or remote{" "}
        <code {...stylex.props(docsStyles.codeInline)}>image_url</code> parts. See{" "}
        <InferenceApiDocLink fragment="inference-api-image-input">image input</InferenceApiDocLink>{" "}
        for the request shape and limits.
      </p>

      <h2 {...stylex.props(docsStyles.h2)}>Before your first request</h2>
      <ol {...stylex.props(inferenceDocsSharedStyles.list)}>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          Follow the <InferenceDocLink slug="quickstart">quickstart</InferenceDocLink> to create an
          API key and wire up your client.
        </li>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          Pick a model from the{" "}
          <InferenceApiDocLink fragment="inference-api-models">
            models directory
          </InferenceApiDocLink>{" "}
          or use <code {...stylex.props(docsStyles.codeInline)}>stub</code> while testing.
        </li>
      </ol>

      <h2 {...stylex.props(docsStyles.h2)}>Using an editor or agent</h2>
      <p {...stylex.props(docsStyles.prose)}>
        OpenCode, Cursor, and Claude Code each need slightly different setup. See the{" "}
        <InferenceDocLink slug="opencode">tool setup</InferenceDocLink> pages for step-by-step
        configuration. Community-maintained extensions are listed on the{" "}
        <Link to="/docs/community-tools" {...stylex.props(docsStyles.proseLink)}>
          community tools
        </Link>{" "}
        page.
      </p>
    </InferenceDocsOverview>
  );
}

export function InferenceDocsSlugPage({
  slug,
  baseUrl,
}: {
  slug: InferenceDocsSlug;
  baseUrl: string;
}) {
  switch (slug) {
    case "quickstart":
      return <InferenceQuickstartPage baseUrl={baseUrl} />;
    case "api-reference":
      return <InferenceApiReferencePage baseUrl={baseUrl} />;
    case "opencode":
      return <OpenCodePage baseUrl={baseUrl} />;
    case "cursor":
      return <CursorPage baseUrl={baseUrl} />;
    case "claude-code":
      return <ClaudeCodePage baseUrl={baseUrl} />;
    default:
      return null;
  }
}

function OpenCodePage({ baseUrl }: { baseUrl: string }) {
  return (
    <InferenceDocsPage
      kicker="Tool setup"
      title="OpenCode"
      description="Add co/core as a custom OpenAI-compatible provider."
    >
      <p {...stylex.props(docsStyles.prose)}>
        OpenCode can target any OpenAI-compatible endpoint. Browse{" "}
        <Link to="/models" {...stylex.props(docsStyles.proseLink)}>
          /models
        </Link>{" "}
        for live model IDs, then add a{" "}
        <code {...stylex.props(docsStyles.codeInline)}>opencode.json</code> to your project or home
        directory with the models you want available:
      </p>
      <HighlightedBlock
        lang="json"
        code={`{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "cocore": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "co/core",
      "options": {
        "baseURL": "${baseUrl}"
      },
      "models": {
        "stub": {
          "name": "stub (test model)"
        }
      }
    }
  }
}`}
      />
      <p {...stylex.props(docsStyles.prose)}>
        Replace <code {...stylex.props(docsStyles.codeInline)}>stub</code> with any model ID from{" "}
        <Link to="/models" {...stylex.props(docsStyles.proseLink)}>
          /models
        </Link>
        . Add one entry per model under <code {...stylex.props(docsStyles.codeInline)}>models</code>{" "}
        — the key is the model ID OpenCode sends in requests.
      </p>
      <ol {...stylex.props(inferenceDocsSharedStyles.list)}>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          Pick model IDs on{" "}
          <Link to="/models" {...stylex.props(docsStyles.proseLink)}>
            /models
          </Link>{" "}
          and add them to the <code {...stylex.props(docsStyles.codeInline)}>models</code> block
          above.
        </li>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          Run <code {...stylex.props(docsStyles.codeInline)}>opencode</code> and type{" "}
          <code {...stylex.props(docsStyles.codeInline)}>/connect</code>.
        </li>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          Choose <strong>Other</strong> and paste your co/core API key.
        </li>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          Select the co/core provider and a model from the picker.
        </li>
      </ol>
      <p {...stylex.props(docsStyles.prose)}>
        Full reference:{" "}
        <a
          href="https://opencode.ai/docs/providers#custom-provider"
          target="_blank"
          rel="noreferrer"
          {...stylex.props(docsStyles.proseLink)}
        >
          OpenCode custom providers
        </a>
        .
      </p>
    </InferenceDocsPage>
  );
}

function CursorPage({ baseUrl }: { baseUrl: string }) {
  return (
    <InferenceDocsPage
      kicker="Tool setup"
      title="Cursor"
      description="Route Cursor's OpenAI integration through co/core."
    >
      <ol {...stylex.props(inferenceDocsSharedStyles.list)}>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          Open <strong>Cursor Settings → Models</strong>.
        </li>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          Paste your co/core API key under <strong>OpenAI API Key</strong>.
        </li>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          Enable <strong>Override OpenAI Base URL</strong> and set{" "}
          <code {...stylex.props(docsStyles.codeInline)}>{baseUrl}</code>.
        </li>
        <li {...stylex.props(inferenceDocsSharedStyles.bullet)}>
          Choose a model ID from the{" "}
          <InferenceApiDocLink fragment="inference-api-models">
            models directory
          </InferenceApiDocLink>{" "}
          or use <code {...stylex.props(docsStyles.codeInline)}>stub</code> for testing.
        </li>
      </ol>
      <p {...stylex.props(docsStyles.prose)}>
        The override applies to OpenAI-backed chat requests. Some Cursor features (like plan mode)
        may still use Cursor's own models — use agent or chat mode with an OpenAI-compatible model
        selected when you want co/core inference.
      </p>
    </InferenceDocsPage>
  );
}

function ClaudeCodePage({ baseUrl }: { baseUrl: string }) {
  return (
    <InferenceDocsPage
      kicker="Tool setup"
      title="Claude Code"
      description="Claude Code speaks Anthropic's API — use a local proxy to reach co/core."
    >
      <p {...stylex.props(docsStyles.prose)}>
        Claude Code calls Anthropic's{" "}
        <code {...stylex.props(docsStyles.codeInline)}>/v1/messages</code> endpoint. co/core
        implements OpenAI's{" "}
        <code {...stylex.props(docsStyles.codeInline)}>/v1/chat/completions</code>, so you need a
        local proxy that translates between the two protocols.
      </p>
      <p {...stylex.props(docsStyles.prose)}>
        One option is{" "}
        <a
          href="https://github.com/fuergaosi233/claude-code-proxy"
          target="_blank"
          rel="noreferrer"
          {...stylex.props(docsStyles.proseLink)}
        >
          claude-code-proxy
        </a>
        :
      </p>
      <HighlightedBlock
        lang="bash"
        code={`# Terminal 1 — start the proxy
export OPENAI_BASE_URL="${baseUrl}"
export OPENAI_API_KEY=cocore-your-key-here
python start_proxy.py

# Terminal 2 — point Claude Code at the proxy
export ANTHROPIC_BASE_URL=http://localhost:8082
export ANTHROPIC_API_KEY=unused
claude`}
      />
      <p {...stylex.props(docsStyles.prose)}>
        Adjust the port to match your proxy. For native OpenAI-compatible tooling without a proxy,
        see the <InferenceDocLink slug="opencode">OpenCode</InferenceDocLink> setup page.
      </p>
    </InferenceDocsPage>
  );
}
