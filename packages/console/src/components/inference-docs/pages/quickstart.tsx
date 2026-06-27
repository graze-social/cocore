"use client";

import * as stylex from "@stylexjs/stylex";
import { useQueries, useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useMemo, useState } from "react";

import { modelDirectoryQueryOptions } from "@/components/api-docs/models.functions.ts";
import { highlightCodeQueryOptions } from "@/components/account/account.functions.ts";
import {
  type SnippetLang,
  SNIPPET_LANGS,
  SNIPPET_LANG_LABELS,
  SNIPPET_LANG_TO_SHIKI,
  buildSnippet,
} from "@/components/api-docs/snippets.ts";
import { docsStyles } from "@/components/docs/docs-page.stylex.tsx";
import { InferenceDocsPage } from "@/components/inference-docs/inference-docs-page.tsx";
import {
  CreateApiKeyOrLoginButton,
  HighlightedBlock,
  inferenceDocsSharedStyles,
} from "@/components/inference-docs/shared.tsx";
import { InferenceApiDocLink } from "@/components/inference-docs/inference-doc-link.tsx";
import { CopyToClipboardButton } from "@/design-system/copy-to-clipboard-button";
import { Flex } from "@/design-system/flex";
import { SegmentedControl, SegmentedControlItem } from "@/design-system/segmented-control";
import { Select, SelectItem } from "@/design-system/select";
import { verticalSpace } from "@/design-system/theme/semantic-spacing.stylex";
import { InlineCode, SmallBody } from "@/design-system/typography";

const styles = stylex.create({
  modelSelect: {
    maxWidth: "100%",
    minWidth: 240,
    width: "fit-content",
  },
  modelHint: {
    marginTop: verticalSpace.md,
  },
  snippetRow: {
    marginTop: verticalSpace["2xl"],
  },
});

export function InferenceQuickstartPage({ baseUrl }: { baseUrl: string }) {
  const [lang, setLang] = useState<SnippetLang>("typescript");
  const [model, setModel] = useState<string>("stub");
  const directory = useQuery(modelDirectoryQueryOptions);

  const modelItems = useMemo<Array<{ id: string; label: string }>>(() => {
    const items = (directory.data?.models ?? []).map((m) => ({
      id: m.modelId,
      label:
        m.machineCount > 0
          ? `${m.modelId} — ${m.machineCount} ${m.machineCount === 1 ? "machine" : "machines"}`
          : m.modelId,
    }));
    if (!items.some((i) => i.id === "stub")) {
      items.push({ id: "stub", label: "stub (test model)" });
    }
    return items;
  }, [directory.data]);

  const snippets = useMemo<Record<SnippetLang, string>>(() => {
    const out = {} as Record<SnippetLang, string>;
    for (const l of SNIPPET_LANGS) out[l] = buildSnippet(l, baseUrl, model);
    return out;
  }, [baseUrl, model]);

  const highlights = useQueries({
    queries: SNIPPET_LANGS.map((l) => ({
      ...highlightCodeQueryOptions({
        code: snippets[l],
        lang: SNIPPET_LANG_TO_SHIKI[l] as
          | "python"
          | "typescript"
          | "java"
          | "go"
          | "csharp"
          | "bash"
          | "json",
      }),
    })),
  });

  const snippet = snippets[lang];
  const highlighted = highlights[SNIPPET_LANGS.indexOf(lang)]?.data;

  return (
    <InferenceDocsPage
      kicker="Getting started"
      title="Quickstart"
      description="Create an API key, then point your OpenAI client at co/core."
    >
      <h2 {...stylex.props(docsStyles.h2, docsStyles.h2First)}>Authentication</h2>
      <p {...stylex.props(docsStyles.prose)}>
        Every request needs a co/core API key in the{" "}
        <code {...stylex.props(docsStyles.codeInline)}>Authorization</code> header, using the same
        Bearer format as OpenAI. Keys are shown once when you create them — store yours somewhere
        safe.
      </p>
      <HighlightedBlock code="Authorization: Bearer cocore-..." lang="bash" />
      <CreateApiKeyOrLoginButton redirectTo="/docs/inference/quickstart" />
      <p {...stylex.props(docsStyles.prose)}>
        Building on top of AT Protocol? Skip key provisioning entirely: mint a service-auth token
        from the caller&apos;s PDS (
        <code {...stylex.props(docsStyles.codeInline)}>com.atproto.server.getServiceAuth</code> with{" "}
        <code {...stylex.props(docsStyles.codeInline)}>aud=did:web:console.cocore.dev</code> and{" "}
        <code {...stylex.props(docsStyles.codeInline)}>lxm=dev.cocore.inference.dispatch</code>) and
        pass it as the Bearer token. Inference then runs on behalf of the token&apos;s issuer DID.
        The DID must have connected co/core once so a session exists to publish the job to its PDS;
        otherwise the request returns{" "}
        <code {...stylex.props(docsStyles.codeInline)}>401 onboarding_required</code>.
      </p>
      <p {...stylex.props(docsStyles.prose)}>
        Invalid or missing credentials return{" "}
        <code {...stylex.props(docsStyles.codeInline)}>401 authentication_error</code>. See{" "}
        <InferenceApiDocLink fragment="inference-api-http-errors">HTTP errors</InferenceApiDocLink>{" "}
        for the full envelope.
      </p>

      <h2 {...stylex.props(docsStyles.h2)}>Make a request</h2>
      <p {...stylex.props(docsStyles.prose)}>
        Point your client at <code {...stylex.props(docsStyles.codeInline)}>{baseUrl}</code> and
        pass your API key. Pick a model from the directory below, or use{" "}
        <code {...stylex.props(docsStyles.codeInline)}>stub</code> while testing.
      </p>

      <Flex direction="column" gap="2xl">
        <Select
          label="Model"
          size="lg"
          items={modelItems}
          value={model}
          style={styles.modelSelect}
          onChange={(key) => {
            if (typeof key === "string") setModel(key);
          }}
        >
          {(item) => <SelectItem>{item.label}</SelectItem>}
        </Select>
        <SmallBody style={styles.modelHint}>
          {directory.isLoading ? (
            "Loading the live model directory…"
          ) : directory.isError || !directory.data ? (
            "Could not reach the model directory — using the test model."
          ) : modelItems.length <= 1 ? (
            "No providers are online right now — only the test model is available."
          ) : (
            <>
              Usage is metered in model tokens. Each receipt debits{" "}
              <InlineCode>tokens.in + tokens.out</InlineCode> from your balance. See{" "}
              <Link to="/models" {...stylex.props(docsStyles.proseLink)}>
                /models
              </Link>{" "}
              for live pricing.
            </>
          )}
        </SmallBody>
        <SegmentedControl
          aria-label="Snippet language"
          size="sm"
          selectedKeys={new Set([lang])}
          onSelectionChange={(selection) => {
            const id = selection.values().next().value;
            if (typeof id !== "string") return;
            if ((SNIPPET_LANGS as readonly string[]).includes(id)) {
              setLang(id as SnippetLang);
            }
          }}
        >
          {SNIPPET_LANGS.map((id) => (
            <SegmentedControlItem key={id} id={id}>
              {SNIPPET_LANG_LABELS[id]}
            </SegmentedControlItem>
          ))}
        </SegmentedControl>
        <Flex direction="row" align="start" gap="sm" style={styles.snippetRow}>
          {highlighted ? (
            <div
              {...stylex.props(inferenceDocsSharedStyles.highlightedSnippet)}
              dangerouslySetInnerHTML={{ __html: highlighted }}
            />
          ) : (
            <pre {...stylex.props(inferenceDocsSharedStyles.usage)}>{snippet}</pre>
          )}
          <CopyToClipboardButton text={snippet} />
        </Flex>
      </Flex>
    </InferenceDocsPage>
  );
}
