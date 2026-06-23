"use client";

import * as stylex from "@stylexjs/stylex";
import { useMutation, useQuery } from "@tanstack/react-query";
import { createLink, useRouter } from "@tanstack/react-router";
import { useMemo, useState } from "react";

import { highlightCodeQueryOptions } from "@/components/account/account.functions.ts";
import { markStartGuideSeenMutationOptions } from "@/components/start/start-guide.functions.ts";
import { CreateApiKeyButton } from "@/components/api-keys/CreateApiKeyButton.tsx";
import { modelDirectoryQueryOptions } from "@/components/api-docs/models.functions.ts";
import {
  type SnippetLang,
  SNIPPET_LANG_TO_SHIKI,
  buildSnippet,
} from "@/components/api-docs/snippets.ts";
// Stripe-flavored payments query went away in the 2026-05-11
// closed-loop pivot. The onboarding cards below no longer pitch
// "set up payouts" or "add a card" — there's nothing to set up.
import { Button } from "@/design-system/button";
import { Card, CardBody, CardDescription, CardHeader, CardTitle } from "@/design-system/card";
import { CopyToClipboardButton } from "@/design-system/copy-to-clipboard-button";
import { Flex } from "@/design-system/flex";
import { Page } from "@/design-system/page/index.tsx";
import { SegmentedControl, SegmentedControlItem } from "@/design-system/segmented-control";
import { Select, SelectItem } from "@/design-system/select";
import { uiColor } from "@/design-system/theme/color.stylex";
import { verticalSpace } from "@/design-system/theme/semantic-spacing.stylex";
import { fontFamily, fontSize, fontWeight } from "@/design-system/theme/typography.stylex";
import { Body, Heading1, InlineCode } from "@/design-system/typography";

const REQUESTER_SNIPPET_LANG: SnippetLang = "typescript";

const styles = stylex.create({
  header: {
    marginBottom: 0,
  },
  headerContent: {
    width: "100%",
  },
  pageRoot: {
    display: "flex",
    flexDirection: "column",
    fontFamily: fontFamily.mono,
    gap: verticalSpace["2xl"],
    paddingBottom: verticalSpace["12xl"],
    width: "100%",
  },
  headingMono: {
    fontFamily: fontFamily.mono,
  },
  titlePrompt: {
    color: uiColor.text1,
    fontWeight: fontWeight.normal,
  },
  sections: {
    display: "flex",
    flexDirection: "column",
    gap: verticalSpace["2xl"],
  },
  cardTitleMono: {
    fontSize: fontSize.base,
    fontWeight: fontWeight.medium,
    color: uiColor.text2,
    textTransform: "lowercase",
  },
  cardDescription: {
    fontSize: fontSize.xs,
    color: uiColor.text1,
    fontWeight: fontWeight.normal,
  },
  usage: {
    fontFamily: fontFamily.mono,
    fontSize: "0.8125rem",
    whiteSpace: "pre",
    overflowX: "auto",
    padding: "1rem 1.25rem",
    borderRadius: "0.5rem",
    background: "rgba(0,0,0,0.05)",
    marginTop: verticalSpace.md,
    marginBottom: 0,
  },
  highlightedSnippet: {
    flexGrow: 1,
    minWidth: 0,
    borderColor: uiColor.border1,
    borderRadius: "0.5rem",
    borderStyle: "solid",
    borderWidth: 1,
    overflow: "hidden",
    marginTop: verticalSpace.md,
  },
  modelSelect: {
    width: "fit-content",
    minWidth: 240,
    maxWidth: "100%",
    marginTop: verticalSpace.md,
  },
  bodySpaced: {
    marginTop: verticalSpace.sm,
  },
  subtleNote: {
    fontSize: fontSize.xs,
    color: uiColor.text1,
    marginTop: verticalSpace.xl,
  },
  downloadCol: {
    marginTop: verticalSpace.lg,
  },
  footerActions: {
    display: "flex",
    justifyContent: "flex-end",
    marginTop: verticalSpace["4xl"],
    paddingTop: verticalSpace["2xl"],
  },
});

const ButtonLink = createLink(Button);

type Track = "provider" | "requester";

export function StartGuide() {
  const router = useRouter();
  const markSeenM = useMutation(markStartGuideSeenMutationOptions);

  const [trackOverride, setTrackOverride] = useState<Track | null>(null);
  const activeTrack = trackOverride ?? "requester";

  const [model, setModel] = useState<string>("stub");
  const directory = useQuery(modelDirectoryQueryOptions);

  // Directory drives the "Make a request" model picker. "stub" is
  // always present so the snippet has a sensible default while the
  // directory is loading, empty, or unreachable.
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

  const baseUrl =
    typeof window !== "undefined" ? `${window.location.origin}/v1` : "https://cocore.dev/v1";
  const snippet = useMemo(
    () => buildSnippet(REQUESTER_SNIPPET_LANG, baseUrl, model),
    [baseUrl, model],
  );
  const shikiLang = SNIPPET_LANG_TO_SHIKI[REQUESTER_SNIPPET_LANG] as
    | "python"
    | "typescript"
    | "java"
    | "go"
    | "csharp"
    | "bash"
    | "json";
  const highlightQ = useQuery(highlightCodeQueryOptions({ code: snippet, lang: shikiLang }));

  // Closed-loop has no fiat-flavored onboarding states — the
  // "Set up payouts" and "Add a card" cards below are conditioned
  // on `false` literals so they don't render. Keep them in the
  // tree for a moment in case we want to bring them back as
  // pure-token "claim your grant" / "redeem patronage rebate"
  // affordances later.

  return (
    <Page.Root variant="small" style={styles.pageRoot}>
      <Page.Header style={styles.header}>
        <Flex direction="column" gap="6xl" style={styles.headerContent}>
          <Heading1 style={styles.headingMono}>
            <span {...stylex.props(styles.titlePrompt)}>~/</span>welcome
          </Heading1>
          <SegmentedControl
            aria-label="Getting started track"
            size="lg"
            selectedKeys={new Set([activeTrack])}
            onSelectionChange={(selection) => {
              const id = selection.values().next().value;
              if (id === "provider" || id === "requester") setTrackOverride(id);
            }}
          >
            <SegmentedControlItem id="requester">I use machines</SegmentedControlItem>
            <SegmentedControlItem id="provider">I run machines</SegmentedControlItem>
          </SegmentedControl>
        </Flex>
      </Page.Header>

      <div {...stylex.props(styles.sections)}>
        {activeTrack === "provider" ? (
          <>
            <Card size="md">
              <CardHeader hasBorder>
                <CardTitle style={styles.cardTitleMono}>Run a machine</CardTitle>
                <CardDescription style={styles.cardDescription}>
                  Download the co/core app for your Apple Silicon Mac — it pairs with this account
                  and serves inference.
                </CardDescription>
              </CardHeader>
              <CardBody>
                <Body>
                  The app does everything for you — sign in, pick a model that fits your Mac, set up
                  the runtime, and start serving. No Terminal, no commands to paste.
                </Body>

                <Flex direction="column" gap="sm" style={styles.downloadCol}>
                  <Button
                    variant="primary"
                    onPress={() => {
                      window.location.href = "/agent/app";
                    }}
                  >
                    Download for macOS (Apple Silicon)
                  </Button>
                  <Body style={styles.subtleNote}>
                    Notarized — opens with no Gatekeeper warning. Apple Silicon only.
                  </Body>
                </Flex>

                <Body style={styles.bodySpaced}>
                  Drag <InlineCode>cocore.app</InlineCode> to Applications and open it. It walks you
                  through signing in (approve in your browser), picking a model that fits your Mac's
                  memory — it installs the <InlineCode>vllm-mlx</InlineCode> runtime for you — and
                  starting to serve.
                </Body>

                <Flex direction="row" gap="md" style={styles.bodySpaced} wrap>
                  <ButtonLink to="/machines" variant="secondary" size="sm">
                    Open /machines
                  </ButtonLink>
                </Flex>
              </CardBody>
            </Card>
          </>
        ) : (
          <>
            <Card size="md">
              <CardHeader hasBorder>
                <CardTitle style={styles.cardTitleMono}>Make a request</CardTitle>
                <CardDescription style={styles.cardDescription}>
                  OpenAI-compatible chat completions — swap base URL + API key.
                </CardDescription>
              </CardHeader>
              <CardBody>
                <Body>
                  Base URL: <InlineCode>{baseUrl}</InlineCode>
                </Body>
                <Body style={styles.bodySpaced}>
                  Pass your key in the <InlineCode>Authorization: Bearer cocore-…</InlineCode>{" "}
                  header.
                </Body>
                <Select
                  label="Model"
                  items={modelItems}
                  value={model}
                  style={styles.modelSelect}
                  onChange={(key) => {
                    if (typeof key === "string") setModel(key);
                  }}
                >
                  {(item) => <SelectItem>{item.label}</SelectItem>}
                </Select>
                <Flex direction="row" align="start" gap="sm">
                  {highlightQ.data ? (
                    <div
                      {...stylex.props(styles.highlightedSnippet)}
                      dangerouslySetInnerHTML={{ __html: highlightQ.data }}
                    />
                  ) : (
                    <pre {...stylex.props(styles.usage)}>{snippet}</pre>
                  )}
                  <CopyToClipboardButton text={snippet} />
                </Flex>
                <Flex direction="row" gap="md" style={styles.bodySpaced} wrap>
                  <CreateApiKeyButton size="sm" label="Create API key" />
                  <ButtonLink to="/docs/inference" variant="tertiary" size="sm">
                    Full API reference
                  </ButtonLink>
                </Flex>
              </CardBody>
            </Card>

            {/* "Add a card" card removed in the 2026-05-11 closed-loop pivot. */}
          </>
        )}
      </div>

      <div {...stylex.props(styles.footerActions)}>
        <Button
          variant="primary"
          size="lg"
          isDisabled={markSeenM.isPending}
          onPress={() => {
            markSeenM.mutate(undefined, {
              onSettled: () => {
                void router.navigate({ to: "/machines", replace: true });
              },
            });
          }}
        >
          Ok
        </Button>
      </div>
    </Page.Root>
  );
}
