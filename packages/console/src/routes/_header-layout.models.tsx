// Public model directory at /models.
//
// Explorer layout: catalog (filter + selectable cards) and a detail
// pane (stats, machines table, OpenAI snippet by language). Data comes
// from `buildModelDirectory` — same source as `/api/v1/models`.

import * as stylex from "@stylexjs/stylex";
import { useQueries, useQuery } from "@tanstack/react-query";
import { Link, createFileRoute, createLink } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";

import { highlightCodeQueryOptions } from "@/components/account/account.functions.ts";
import {
  type SnippetLang,
  SNIPPET_LANGS,
  SNIPPET_LANG_LABELS,
  SNIPPET_LANG_TO_SHIKI,
  buildSnippet,
} from "@/components/api-docs/snippets.ts";
import { modelDirectoryRouteQueryOptions } from "@/components/models/models.functions.ts";
import { OperatorChip } from "@/components/profile/OperatorChip.tsx";
import { TrustTierBadge } from "@/components/TrustTierBadge.tsx";
import { Button } from "@/design-system/button";
import { CopyToClipboardButton } from "@/design-system/copy-to-clipboard-button";
import { Flex } from "@/design-system/flex";
import { SegmentedControl, SegmentedControlItem } from "@/design-system/segmented-control";
import { Page } from "@/design-system/page";
import { TextField } from "@/design-system/text-field";
import { brown } from "@/design-system/theme/colors/brown.stylex";
import { successColor, uiColor } from "@/design-system/theme/color.stylex";
import { breakpoints } from "@/design-system/theme/media-queries.stylex";
import { radius } from "@/design-system/theme/radius.stylex";
import { shadow } from "@/design-system/theme/shadow.stylex";
import { ui } from "@/design-system/theme/semantic-color.stylex";
import { gap, horizontalSpace, verticalSpace } from "@/design-system/theme/semantic-spacing.stylex";
import {
  fontFamily,
  fontSize,
  fontWeight,
  lineHeight,
} from "@/design-system/theme/typography.stylex";
import { Body, Heading1, Heading4, InlineCode, SmallBody } from "@/design-system/typography";
import type { ModelDirectoryEntry } from "@/lib/model-directory.server.ts";

const ButtonLink = createLink(Button);

const DEFAULT_API_V1_BASE = "https://cocore.dev/v1";

const KIND_TABS = ["all", "text", "image", "audio", "video", "test", "other"] as const;
type ModelKind = (typeof KIND_TABS)[number];

const styles = stylex.create({
  header: {
    marginBottom: {
      default: 0,
      ":is([data-sticky-header=true] *)": 0,
    },
  },
  root: {
    display: "flex",
    flexDirection: "column",
    gap: verticalSpace["2xl"],
    fontFamily: fontFamily.mono,
    marginLeft: "auto",
    marginRight: "auto",
    maxWidth: "1600px",
    paddingBottom: verticalSpace["12xl"],
  },
  metaRow: {
    alignItems: "center",
    color: uiColor.text1,
    display: "flex",
    flexWrap: "wrap",
    fontSize: fontSize.sm,
    gap: horizontalSpace.lg,
    marginTop: verticalSpace.sm,
    lineHeight: lineHeight["lg"],
  },
  metaSep: {
    color: uiColor.border2,
  },
  metaRowDim: {
    color: uiColor.text1,
    fontSize: fontSize.sm,
  },
  headingMono: {
    fontFamily: fontFamily.mono,
  },
  titlePrompt: {
    color: uiColor.text1,
    fontWeight: fontWeight.normal,
  },
  explorer: {
    alignItems: "flex-start",
    display: "grid",
    gap: gap["2xl"],
    gridTemplateColumns: {
      default: "1fr",
      [breakpoints.md]: "minmax(17.5rem, 0.42fr) 1fr",
    },
    marginTop: 0,
  },
  panel: {
    backgroundColor: uiColor.bg,
    borderColor: uiColor.border1,
    borderRadius: radius.md,
    borderStyle: "solid",
    borderWidth: 1,
    boxShadow: shadow.sm,
    overflow: "hidden",
  },
  catalogSticky: {
    maxHeight: {
      default: "none",
      [breakpoints.md]: "calc(100vh - 16px)",
    },
    position: {
      default: "static",
      [breakpoints.md]: "sticky",
    },
    top: {
      default: "auto",
      [breakpoints.md]: "8px",
    },
    display: "flex",
    flexDirection: "column",
    minHeight: 0,
  },
  catalogHead: {
    borderBottomColor: uiColor.border1,
    borderBottomStyle: "dashed",
    borderBottomWidth: 1,
    display: "flex",
    flexDirection: "column",
    gap: gap.md,
    paddingBottom: verticalSpace.lg,
    paddingLeft: horizontalSpace["2xl"],
    paddingRight: horizontalSpace["2xl"],
    paddingTop: verticalSpace.lg,
  },
  catalogHeadRow: {
    alignItems: "center",
    display: "flex",
    flexWrap: "wrap",
    gap: gap.md,
    justifyContent: "space-between",
  },
  catalogTitleRow: {
    alignItems: "baseline",
    flexWrap: "wrap",
    gap: gap.sm,
  },
  catalogCount: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
    fontWeight: fontWeight.normal,
  },
  filterField: {
    minWidth: "10rem",
    flexGrow: {
      default: 1,
      [breakpoints.sm]: 0,
    },
    maxWidth: "20rem",
  },
  tabRow: {
    display: "flex",
    flexWrap: "wrap",
    gap: gap.xs,
  },
  tab: {
    alignItems: "center",
    appearance: "none",
    backgroundColor: "transparent",
    borderColor: uiColor.border1,
    borderRadius: radius.sm,
    borderStyle: "solid",
    borderWidth: 1,
    color: uiColor.text1,
    cursor: "pointer",
    display: "inline-flex",
    fontFamily: fontFamily.mono,
    fontSize: fontSize.xs,
    gap: gap.xs,
    paddingBlock: verticalSpace.xs,
    paddingInline: horizontalSpace.md,
  },
  tabActive: {
    backgroundColor: uiColor.solid1,
    borderColor: uiColor.solid1,
    color: uiColor.bg,
  },
  tabCount: {
    fontSize: fontSize.xs,
    opacity: 0.7,
  },
  modelGrid: {
    display: "flex",
    flexDirection: "column",
    gap: gap.sm,
    overflowY: "auto",
    padding: horizontalSpace.md,
  },
  catalogEmpty: {
    borderColor: uiColor.border1,
    borderRadius: radius.sm,
    borderStyle: "dashed",
    borderWidth: 1,
    color: uiColor.text1,
    fontSize: fontSize.sm,
    margin: horizontalSpace.md,
    padding: verticalSpace["3xl"],
    textAlign: "center",
  },
  catalogCard: {
    alignItems: "stretch",
    appearance: "none",
    backgroundColor: uiColor.bg,
    borderColor: uiColor.border1,
    borderRadius: radius.sm,
    borderStyle: "solid",
    borderWidth: 1,
    cursor: "pointer",
    display: "flex",
    flexDirection: "column",
    gap: gap.sm,
    outline: "none",
    paddingBlock: verticalSpace.md,
    paddingInline: horizontalSpace.lg,
    textAlign: "left",
    transitionDuration: "120ms",
    transitionProperty: "border-color, background-color, box-shadow",
    transitionTimingFunction: "ease-out",
    ":hover": {
      backgroundColor: uiColor.bgSubtle,
      borderColor: uiColor.border2,
    },
  },
  catalogCardHead: {
    alignItems: "flex-start",
    display: "flex",
    justifyContent: "space-between",
    gap: gap.md,
  },
  catalogCardTitle: {
    alignItems: "baseline",
    display: "flex",
    flexDirection: "row",
    flexWrap: "wrap",
    gap: gap.sm,
    minWidth: 0,
  },
  catalogModelId: {
    color: uiColor.text2,
    flexShrink: 1,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.sm,
    fontWeight: fontWeight.semibold,
    minWidth: 0,
    overflowWrap: "anywhere",
  },
  catalogMeta: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
  },
  catalogStats: {
    borderTopColor: uiColor.border1,
    borderTopStyle: "dashed",
    borderTopWidth: 1,
    display: "grid",
    gap: gap.xs,
    gridTemplateColumns: "repeat(2, 1fr)",
    paddingTop: verticalSpace.sm,
  },
  catalogStatCell: {
    display: "flex",
    flexDirection: "column",
    gap: 2,
  },
  catalogStatLbl: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
    letterSpacing: "0.04em",
    textTransform: "lowercase",
  },
  catalogStatVal: {
    color: uiColor.text2,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.sm,
    fontVariantNumeric: "tabular-nums",
    fontWeight: fontWeight.medium,
  },
  detailPane: {
    display: "flex",
    flexDirection: "column",
    minWidth: 0,
  },
  detailHead: {
    borderBottomColor: uiColor.border1,
    borderBottomStyle: "dashed",
    borderBottomWidth: 1,
    display: "flex",
    flexDirection: "column",
    gap: gap["2xl"],
    paddingBlock: verticalSpace["4xl"],
    paddingInline: horizontalSpace["2xl"],
  },
  detailTitleRow: {
    alignItems: "baseline",
    display: "flex",
    flexWrap: "wrap",
    gap: gap["2xl"],
  },
  detailName: {
    color: uiColor.text2,
    fontFamily: fontFamily.mono,
    fontSize: fontSize["2xl"],
    fontWeight: fontWeight.semibold,
    letterSpacing: "-0.02em",
    overflowWrap: "anywhere",
  },
  kindBadge: {
    borderRadius: radius.sm,
    borderStyle: "solid",
    borderWidth: 1,
    flexShrink: 0,
    fontSize: fontSize.xs,
    letterSpacing: "0.04em",
    paddingBlock: 2,
    paddingInline: horizontalSpace.sm,
    textTransform: "lowercase",
  },
  kindText: {
    backgroundColor: uiColor.bgSubtle,
    borderColor: uiColor.border2,
    color: uiColor.text2,
  },
  kindImage: {
    backgroundColor: uiColor.bgSubtle,
    borderColor: successColor.solid1,
    color: successColor.solid1,
  },
  kindAudio: {
    backgroundColor: uiColor.bgSubtle,
    borderColor: uiColor.border2,
    color: uiColor.text2,
  },
  kindVideo: {
    backgroundColor: uiColor.bgSubtle,
    borderColor: uiColor.border2,
    color: uiColor.text2,
  },
  kindOther: {
    backgroundColor: uiColor.bgSubtle,
    borderColor: uiColor.border1,
    color: uiColor.text1,
  },
  kindTest: {
    // Visually distinct from the real-model kinds so a user
    // browsing the catalog doesn't think the stub is something
    // they'd want to dispatch real work to.
    backgroundColor: uiColor.bgSubtle,
    borderColor: brown.solid1,
    color: brown.solid1,
  },
  tagRow: {
    display: "flex",
    flexWrap: "wrap",
    gap: gap.sm,
  },
  tag: {
    backgroundColor: uiColor.bgSubtle,
    borderColor: uiColor.border1,
    borderRadius: radius.sm,
    borderStyle: "solid",
    borderWidth: 1,
    color: uiColor.text1,
    fontSize: fontSize.xs,
    letterSpacing: "0.03em",
    paddingBlock: 2,
    paddingInline: horizontalSpace.sm,
    textTransform: "lowercase",
  },
  statsRow: {
    borderBottomColor: uiColor.border1,
    borderBottomStyle: "dashed",
    borderBottomWidth: 1,
    display: "grid",
    gap: 0,
    gridTemplateColumns: {
      default: "repeat(2, 1fr)",
      [breakpoints.sm]: "repeat(3, 1fr)",
      [breakpoints.lg]: "repeat(6, 1fr)",
    },
  },
  statCell: {
    borderRightColor: uiColor.border1,
    borderRightStyle: "dashed",
    borderRightWidth: {
      default: 0,
      [breakpoints.lg]: 1,
    },
    display: "flex",
    flexDirection: "column",
    gap: gap.sm,
    paddingBlock: verticalSpace["2xl"],
    paddingInline: horizontalSpace["2xl"],
  },
  statLbl: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
    letterSpacing: "0.04em",
    textTransform: "lowercase",
  },
  statVal: {
    alignItems: "baseline",
    color: uiColor.text2,
    display: "flex",
    fontFamily: fontFamily.mono,
    fontSize: fontSize.lg,
    fontVariantNumeric: "tabular-nums",
    fontWeight: fontWeight.medium,
    gap: gap.xs,
  },
  statUnit: {
    color: uiColor.text1,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.xs,
    fontWeight: fontWeight.normal,
  },
  section: {
    borderBottomColor: uiColor.border1,
    borderBottomStyle: "dashed",
    borderBottomWidth: 1,
    display: "flex",
    flexDirection: "column",
    gap: gap["4xl"],
    paddingBlock: verticalSpace["6xl"],
    paddingInline: horizontalSpace["2xl"],
  },
  sectionLast: {
    borderBottomWidth: 0,
  },
  sectionHead: {
    alignItems: "baseline",
    display: "flex",
    flexWrap: "wrap",
    gap: gap["2xl"],
    justifyContent: "space-between",
  },
  sectionHeadInset: {
    paddingBottom: verticalSpace["2xl"],
    paddingInline: horizontalSpace["2xl"],
  },
  sectionMachinesTable: {
    borderBottomColor: uiColor.border1,
    borderBottomStyle: "dashed",
    borderBottomWidth: 1,
    display: "flex",
    flexDirection: "column",
    gap: gap["2xl"],
    paddingBottom: 0,
    paddingInline: 0,
    paddingTop: verticalSpace["4xl"],
  },
  machineTableViewport: {
    borderTopColor: uiColor.border1,
    borderTopStyle: "solid",
    borderTopWidth: 1,
    maxHeight: "500px",
    overflowX: "auto",
    overflowY: "auto",
    width: "100%",
  },
  sectionMeta: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
  },
  dataTable: {
    borderCollapse: "collapse",
    borderSpacing: 0,
    borderStyle: "none",
    borderWidth: 0,
    fontVariantNumeric: "tabular-nums",
    minWidth: "100%",
    width: "100%",
  },
  th: {
    backgroundColor: uiColor.bgSubtle,
    borderBottomColor: uiColor.border1,
    borderBottomStyle: "solid",
    borderBottomWidth: 1,
    color: uiColor.text1,
    fontSize: fontSize.xs,
    fontWeight: fontWeight.medium,
    letterSpacing: "0.06em",
    paddingBlock: verticalSpace.sm,
    paddingInline: horizontalSpace["2xl"],
    position: "sticky",
    textAlign: "left",
    textTransform: "lowercase",
    top: 0,
    zIndex: 1,
  },
  thNum: {
    textAlign: "right",
  },
  td: {
    borderBottomColor: uiColor.border1,
    borderBottomStyle: "solid",
    borderBottomWidth: 1,
    color: uiColor.text2,
    fontSize: fontSize.xs,
    paddingBlock: verticalSpace.xl,
    paddingInline: horizontalSpace["3xl"],
    verticalAlign: "middle",
  },
  tdNum: {
    textAlign: "right",
  },
  tdLastRow: {
    borderBottomWidth: 0,
  },
  tableRow: {
    ":hover": {
      backgroundColor: uiColor.bgSubtle,
    },
  },
  hostCell: {
    alignItems: "center",
    display: "flex",
    flexWrap: "wrap",
    gap: gap.sm,
  },
  regionChip: {
    alignItems: "center",
    backgroundColor: uiColor.bgSubtle,
    borderColor: uiColor.border1,
    borderRadius: radius.sm,
    borderStyle: "solid",
    borderWidth: 1,
    color: uiColor.text1,
    display: "inline-flex",
    flexShrink: 0,
    fontSize: fontSize.xs,
    gap: gap.xs,
    letterSpacing: "0.03em",
    lineHeight: lineHeight.sm,
    paddingBlock: 2,
    paddingInline: horizontalSpace.sm,
  },
  snippetRow: {
    alignItems: "flex-start",
    display: "flex",
    flexDirection: "row",
    gap: gap.sm,
  },
  highlightedSnippet: {
    borderColor: uiColor.border1,
    borderRadius: radius.md,
    borderStyle: "solid",
    borderWidth: 1,
    flexGrow: 1,
    minWidth: 0,
    overflow: "hidden",
  },
  snippetPlain: {
    background: "rgba(0,0,0,0.05)",
    borderColor: uiColor.component3,
    borderRadius: radius.md,
    borderStyle: "solid",
    borderWidth: 1,
    flexGrow: 1,
    fontFamily: fontFamily.mono,
    fontSize: "0.8125rem",
    margin: 0,
    minWidth: 0,
    overflowX: "auto",
    padding: "1rem 1.25rem",
    whiteSpace: "pre",
  },
  unreachable: {
    backgroundColor: uiColor.bgSubtle,
    borderRadius: radius.sm,
    color: uiColor.text2,
    marginTop: verticalSpace["2xl"],
    padding: verticalSpace["2xl"],
  },
  liveDot: {
    backgroundColor: successColor.solid1,
    borderRadius: radius.full,
    boxShadow: `0 0 0 2px ${successColor.solid2}`,
    display: "inline-block",
    flexShrink: 0,
    height: 6,
    marginRight: horizontalSpace.xs,
    verticalAlign: "middle",
    width: 6,
  },
});

/** Brown `uiColor` scope for the selected catalog row (no inset bar). */
const catalogCardSelectedTheme = stylex.createTheme(uiColor, {
  bg: brown.bg,
  bgSubtle: brown.bgSubtle,
  component1: brown.component1,
  component2: brown.component2,
  component3: brown.component3,
  border1: brown.border1,
  border2: brown.border2,
  border3: brown.border3,
  solid1: brown.solid1,
  solid2: brown.solid2,
  text1: brown.text1,
  text2: brown.text2,
});

export const Route = createFileRoute("/_header-layout/models")({
  loader: async ({ context }) => {
    await context.queryClient.ensureQueryData(modelDirectoryRouteQueryOptions);
  },
  component: ModelsPage,
  head: () => ({
    meta: [
      { title: "Models · co/core" },
      {
        name: "description",
        content:
          "Live directory of inference models co/core providers are serving right now, aggregated from their signed provider records.",
      },
    ],
  }),
});

function inferModelKind(modelId: string): Exclude<ModelKind, "all"> {
  const m = modelId.toLowerCase();
  // The `stub` model is the network's hello-world health check, not
  // a real inference target. Bucket it as "test" so the catalog
  // labels it clearly and the detail pane can swap in the
  // network-heartbeat explanation.
  if (m === "stub") return "test";
  if (/(whisper|wav2lip|\btts\b|audio|speech)/.test(m)) return "audio";
  if (/(video|cogvideo|svd|animate|\bwan\b)/.test(m)) return "video";
  if (/(flux|sdxl|\bsd[\d.-]|stable|diffusion|dall|midjourney|imagen|\bimg\b)/.test(m))
    return "image";
  if (/(llama|mistral|gpt|qwen|gemma|phi|mixtral|chat|instruct|claude|\bo1\b|embed)/.test(m))
    return "text";
  return "other";
}

function kindBadgeStyle(kind: Exclude<ModelKind, "all">) {
  switch (kind) {
    case "text":
      return styles.kindText;
    case "image":
      return styles.kindImage;
    case "audio":
      return styles.kindAudio;
    case "video":
      return styles.kindVideo;
    case "test":
      return styles.kindTest;
    default:
      return styles.kindOther;
  }
}

/** Display label for a kind tab/badge. `test` reads as "test env" so the
 *  stub connectivity smoke test never looks like a production model
 *  category — it's an environment check, not something you'd serve from. */
function kindLabel(kind: ModelKind): string {
  return kind === "test" ? "test env" : kind;
}

function isStub(modelId: string): boolean {
  return modelId.toLowerCase() === "stub";
}

const CC_PER_MTOK_FMT = new Intl.NumberFormat("en-US", {
  notation: "compact",
  maximumFractionDigits: 1,
});

function fmtCcPerMtok(rate: number | null): string {
  if (rate === null) return "—";
  return CC_PER_MTOK_FMT.format(rate);
}

const SHORT_DATE_FMT = new Intl.DateTimeFormat("en-US", {
  month: "short",
  day: "numeric",
});

function fmtLastSeen(iso: string): string {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "";
  const sec = Math.round((Date.now() - t) / 1000);
  if (sec < 8) return "just now";
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 7) return `${day}d ago`;
  return SHORT_DATE_FMT.format(new Date(t));
}

const COMPACT_NUMBER_FMT = new Intl.NumberFormat("en-US", {
  notation: "compact",
  maximumFractionDigits: 1,
});

function fmtCompact(n: number): string {
  if (!Number.isFinite(n) || n === 0) return "0";
  return COMPACT_NUMBER_FMT.format(n);
}

/** ISO 3166-1 alpha-2 country code (e.g. "US") → regional-indicator flag
 *  emoji (e.g. "🇺🇸"). Returns null for anything that isn't two ASCII
 *  letters so a malformed self-claim renders as plain text, not garbage. */
function regionFlag(code: string): string | null {
  const cc = code.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) return null;
  const base = 0x1f1e6 - 0x41;
  return String.fromCodePoint(base + cc.charCodeAt(0), base + cc.charCodeAt(1));
}

function uniqueOperatorCount(models: ModelDirectoryEntry[]): number {
  const set = new Set<string>();
  for (const m of models) {
    for (const mach of m.machines) set.add(mach.did);
  }
  return set.size;
}

function ModelsPage() {
  const { data: directory } = useQuery(modelDirectoryRouteQueryOptions);
  const apiV1BaseUrl =
    typeof window !== "undefined" ? `${window.location.origin}/v1` : DEFAULT_API_V1_BASE;

  const [query, setQuery] = useState("");
  const [kind, setKind] = useState<ModelKind>("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [snippetLang, setSnippetLang] = useState<SnippetLang>("typescript");

  const models = directory?.models;

  const kindCounts = useMemo(() => {
    const counts: Record<ModelKind, number> = {
      all: models?.length ?? 0,
      text: 0,
      image: 0,
      audio: 0,
      video: 0,
      test: 0,
      other: 0,
    };
    if (!models) return counts;
    for (const m of models) {
      counts[inferModelKind(m.modelId)] += 1;
    }
    return counts;
  }, [models]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!models) return [];
    return models.filter((m) => {
      const k = inferModelKind(m.modelId);
      if (kind !== "all" && k !== kind) return false;
      if (!q) return true;
      return (
        m.modelId.toLowerCase().includes(q) ||
        m.machines.some(
          (mach) =>
            (mach.machineLabel?.toLowerCase().includes(q) ?? false) ||
            (mach.chip?.toLowerCase().includes(q) ?? false) ||
            mach.did.toLowerCase().includes(q) ||
            (mach.host?.handle?.toLowerCase().includes(q) ?? false) ||
            (mach.host?.displayName?.toLowerCase().includes(q) ?? false),
        )
      );
    });
  }, [models, kind, query]);

  useEffect(() => {
    if (filtered.length === 0) {
      setSelectedId(null);
      return;
    }
    if (selectedId == null || !filtered.some((m) => m.modelId === selectedId)) {
      setSelectedId(filtered[0]?.modelId ?? null);
    }
  }, [filtered, selectedId]);

  const selected = useMemo(
    () => filtered.find((m) => m.modelId === selectedId) ?? filtered[0] ?? null,
    [filtered, selectedId],
  );

  const uniqueHosts = useMemo(() => uniqueOperatorCount(models ?? []), [models]);

  const snippetsByLang = useMemo(() => {
    const out = {} as Record<SnippetLang, string>;
    for (const l of SNIPPET_LANGS) {
      out[l] = selected ? buildSnippet(l, apiV1BaseUrl, selected.modelId) : "";
    }
    return out;
  }, [apiV1BaseUrl, selected]);

  const highlights = useQueries({
    queries: SNIPPET_LANGS.map((l) => ({
      ...highlightCodeQueryOptions({
        code: snippetsByLang[l],
        lang: SNIPPET_LANG_TO_SHIKI[l] as
          | "bash"
          | "python"
          | "typescript"
          | "java"
          | "go"
          | "csharp",
      }),
      enabled: snippetsByLang[l].length > 0,
    })),
  });

  const snippet = snippetsByLang[snippetLang];
  const highlightedSnippetHtml = highlights[SNIPPET_LANGS.indexOf(snippetLang)]?.data;

  if (!directory) {
    return (
      <Page.Root variant="large" style={styles.root}>
        <Page.Header style={styles.header}>
          <Flex direction="column" gap="xl">
            <Heading1 style={styles.headingMono}>
              <span {...stylex.props(styles.titlePrompt)}>~/</span>models
            </Heading1>
            <SmallBody style={styles.metaRowDim}>Loading the live model directory…</SmallBody>
          </Flex>
          <Page.Actions>
            <ButtonLink to="/docs/inference" preload="intent" variant="outline" size="sm">
              API docs
            </ButtonLink>
          </Page.Actions>
        </Page.Header>
      </Page.Root>
    );
  }

  if (directory.appviewUnreachable) {
    return (
      <Page.Root variant="large" style={styles.root}>
        <Page.Header style={styles.header}>
          <Flex direction="column" gap="xl">
            <Heading1 style={styles.headingMono}>
              <span {...stylex.props(styles.titlePrompt)}>~/</span>models
            </Heading1>
          </Flex>
          <Page.Actions>
            <ButtonLink to="/docs/inference" preload="intent" variant="outline" size="sm">
              API docs
            </ButtonLink>
          </Page.Actions>
        </Page.Header>
        <Body style={styles.unreachable}>
          The AppView is unreachable right now, so the directory is empty. Try again in a moment;
          the page will repopulate as soon as provider records can be indexed again.
        </Body>
      </Page.Root>
    );
  }

  if (models?.length === 0) {
    return (
      <Page.Root variant="large" style={styles.root}>
        <Page.Header style={styles.header}>
          <Flex direction="column" gap="xl">
            <Heading1 style={styles.headingMono}>
              <span {...stylex.props(styles.titlePrompt)}>~/</span>models
            </Heading1>
          </Flex>
          <Page.Actions>
            <ButtonLink to="/docs/inference" preload="intent" variant="outline" size="sm">
              API docs
            </ButtonLink>
          </Page.Actions>
        </Page.Header>
        <Body style={ui.textDim}>
          No providers online. The directory rebuilds itself as machines come up.
        </Body>
      </Page.Root>
    );
  }

  return (
    <Page.Root variant="large" style={styles.root}>
      <Page.Header style={styles.header}>
        <Flex direction="column" gap="xl">
          <Heading1 style={styles.headingMono}>
            <span {...stylex.props(styles.titlePrompt)}>~/</span>models
          </Heading1>
          <div {...stylex.props(styles.metaRow)}>
            <span>
              <strong {...stylex.props(ui.text)}>{models?.length ?? 0}</strong> models
            </span>
            <span {...stylex.props(styles.metaSep)} aria-hidden="true">
              ·
            </span>
            <span>
              <strong {...stylex.props(ui.text)}>{uniqueHosts}</strong> operators online
            </span>
            <span {...stylex.props(styles.metaSep)} aria-hidden="true">
              ·
            </span>
            <span>pick a model · inspect machines · call via OpenAI SDK</span>
          </div>
        </Flex>
        <Page.Actions>
          <ButtonLink to="/docs/inference" preload="intent" variant="outline" size="sm">
            API docs
          </ButtonLink>
        </Page.Actions>
      </Page.Header>

      <div {...stylex.props(styles.explorer)}>
        <div {...stylex.props(styles.panel, styles.catalogSticky)}>
          <div {...stylex.props(styles.catalogHead)}>
            <div {...stylex.props(styles.catalogHeadRow)}>
              <Flex direction="row" gap="sm" style={styles.catalogTitleRow} wrap>
                <Heading4 style={styles.headingMono}>catalog</Heading4>
                <span {...stylex.props(styles.catalogCount)}>
                  {filtered.length} of {models?.length ?? 0}
                </span>
              </Flex>
              <TextField
                aria-label="Filter models"
                placeholder="filter models…"
                value={query}
                onChange={setQuery}
                size="sm"
                variant="secondary"
                style={styles.filterField}
              />
            </div>
            <div {...stylex.props(styles.tabRow)} role="tablist" aria-label="Model category">
              {KIND_TABS.map((tab) => (
                <button
                  key={tab}
                  type="button"
                  role="tab"
                  aria-selected={kind === tab}
                  {...stylex.props(styles.tab, kind === tab && styles.tabActive)}
                  onClick={() => setKind(tab)}
                >
                  {kindLabel(tab)}
                  <span {...stylex.props(styles.tabCount)}>{kindCounts[tab]}</span>
                </button>
              ))}
            </div>
          </div>
          <div {...stylex.props(styles.modelGrid)}>
            {filtered.length === 0 ? (
              <div {...stylex.props(styles.catalogEmpty)}>no models match · clear your filter</div>
            ) : (
              filtered.map((m) => {
                const active = selected?.modelId === m.modelId;
                const k = inferModelKind(m.modelId);
                return (
                  <button
                    key={m.modelId}
                    type="button"
                    {...stylex.props(styles.catalogCard, active && catalogCardSelectedTheme)}
                    onClick={() => setSelectedId(m.modelId)}
                  >
                    <div {...stylex.props(styles.catalogCardHead)}>
                      <div {...stylex.props(styles.catalogCardTitle)}>
                        <span {...stylex.props(styles.catalogModelId)}>{m.modelId}</span>
                        <span {...stylex.props(styles.kindBadge, kindBadgeStyle(k))}>
                          {kindLabel(k)}
                        </span>
                      </div>
                    </div>
                    <div {...stylex.props(styles.catalogMeta)}>
                      {m.machineCount} {m.machineCount === 1 ? "machine" : "machines"} ·{" "}
                      {fmtCompact(m.activity.day.requests)} req · 24h
                    </div>
                    <div {...stylex.props(styles.catalogStats)}>
                      <div {...stylex.props(styles.catalogStatCell)}>
                        <span {...stylex.props(styles.catalogStatLbl)}>in · tokens/Mtok</span>
                        <span {...stylex.props(styles.catalogStatVal)}>
                          {fmtCcPerMtok(m.inputPricePerMTok)}
                        </span>
                      </div>
                      <div {...stylex.props(styles.catalogStatCell)}>
                        <span {...stylex.props(styles.catalogStatLbl)}>out · tokens/Mtok</span>
                        <span {...stylex.props(styles.catalogStatVal)}>
                          {fmtCcPerMtok(m.outputPricePerMTok)}
                        </span>
                      </div>
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </div>

        {selected ? (
          <div {...stylex.props(styles.panel, styles.detailPane)}>
            <div {...stylex.props(styles.detailHead)}>
              <div {...stylex.props(styles.detailTitleRow)}>
                <span {...stylex.props(styles.detailName)}>{selected.modelId}</span>
                <span
                  {...stylex.props(
                    styles.kindBadge,
                    kindBadgeStyle(inferModelKind(selected.modelId)),
                  )}
                >
                  {kindLabel(inferModelKind(selected.modelId))}
                </span>
              </div>
              {isStub(selected.modelId) ? (
                <Body variant="secondary">
                  <strong>This is not a real model.</strong> <InlineCode>stub</InlineCode> is
                  co/core&apos;s hello-world end-to-end test — every paired machine advertises it,
                  every request routes through the exchange, every receipt gets signed, and you get
                  a canned response back. It exists so a new provider can pair, dispatch one
                  request, and confirm that their box is alive on the network without burning tokens
                  on a real inference. For actual completions, pick one of the other models in the
                  catalog.
                </Body>
              ) : (
                <Body variant="secondary">
                  Advertised on the network by{" "}
                  <strong>
                    {selected.machineCount} {selected.machineCount === 1 ? "machine" : "machines"}
                  </strong>
                  . Rates come from each provider&apos;s <InlineCode>priceList</InlineCode> entry
                  for this model id (typically tokens per MTok at the 1:1 uniform rate). Activity is
                  from indexed receipts.
                </Body>
              )}
              <div {...stylex.props(styles.tagRow)}>
                {selected.currency ? (
                  <span {...stylex.props(styles.tag)}>currency · {selected.currency}</span>
                ) : null}
                {selected.freshestAt ? (
                  <span {...stylex.props(styles.tag)}>
                    freshest record · {fmtLastSeen(selected.freshestAt)}
                  </span>
                ) : null}
                <span {...stylex.props(styles.tag)}>
                  <span {...stylex.props(styles.liveDot)} aria-hidden />
                  live directory
                </span>
              </div>
            </div>

            <div {...stylex.props(styles.statsRow)}>
              <div {...stylex.props(styles.statCell)}>
                <span {...stylex.props(styles.statLbl)}>machines</span>
                <span {...stylex.props(styles.statVal)}>{selected.machineCount}</span>
              </div>
              <div {...stylex.props(styles.statCell)}>
                <span {...stylex.props(styles.statLbl)}>input</span>
                <span {...stylex.props(styles.statVal)}>
                  {fmtCcPerMtok(selected.inputPricePerMTok)}
                  <span {...stylex.props(styles.statUnit)}>tokens/Mtok</span>
                </span>
              </div>
              <div {...stylex.props(styles.statCell)}>
                <span {...stylex.props(styles.statLbl)}>output</span>
                <span {...stylex.props(styles.statVal)}>
                  {fmtCcPerMtok(selected.outputPricePerMTok)}
                  <span {...stylex.props(styles.statUnit)}>tokens/Mtok</span>
                </span>
              </div>
              <div {...stylex.props(styles.statCell)}>
                <span {...stylex.props(styles.statLbl)}>runs · 7d</span>
                <span {...stylex.props(styles.statVal)}>
                  {fmtCompact(selected.activity.week.requests)}
                  <span {...stylex.props(styles.statUnit)}>req</span>
                </span>
              </div>
              <div {...stylex.props(styles.statCell)}>
                <span {...stylex.props(styles.statLbl)}>tokens · 7d</span>
                <span {...stylex.props(styles.statVal)}>
                  {fmtCompact(selected.activity.week.tokens)}
                </span>
              </div>
              <div {...stylex.props(styles.statCell)}>
                <span {...stylex.props(styles.statLbl)}>tokens · 24h</span>
                <span {...stylex.props(styles.statVal)}>
                  {fmtCompact(selected.activity.day.tokens)}
                </span>
              </div>
            </div>

            <div {...stylex.props(styles.sectionMachinesTable)}>
              <div {...stylex.props(styles.sectionHead, styles.sectionHeadInset)}>
                <Heading4 style={styles.headingMono}>machines on this model</Heading4>
                <SmallBody style={styles.sectionMeta}>
                  {selected.machineCount} {selected.machineCount === 1 ? "row" : "rows"}
                </SmallBody>
              </div>
              <div {...stylex.props(styles.machineTableViewport)}>
                <table {...stylex.props(styles.dataTable)}>
                  <thead>
                    <tr>
                      <th {...stylex.props(styles.th)}>rig</th>
                      <th {...stylex.props(styles.th)}>host</th>
                      <th {...stylex.props(styles.th)}>24h</th>
                      <th {...stylex.props(styles.th)}>last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selected.machines.map((mach, i) => {
                      const isLast = i === selected.machines.length - 1;
                      // Derive the flag emoji once (it's null for a non-2-letter
                      // self-claim); reused in the region chip below.
                      const regionFlagEmoji = mach.region ? regionFlag(mach.region) : null;
                      return (
                        <tr
                          key={`${selected.modelId}-${mach.attestationPubKey ?? mach.did}`}
                          {...stylex.props(styles.tableRow)}
                        >
                          <td {...stylex.props(styles.td, isLast && styles.tdLastRow)}>
                            <SmallBody>
                              {mach.machineLabel ? mach.machineLabel : <em>(unnamed)</em>}
                              {mach.chip ? ` · ${mach.chip}` : ""}
                              {mach.ramGB != null ? `, ${mach.ramGB} GB` : ""}
                            </SmallBody>
                            <TrustTierBadge tier={mach.verifiedTier} />
                          </td>
                          <td {...stylex.props(styles.td, isLast && styles.tdLastRow)}>
                            <div {...stylex.props(styles.hostCell)}>
                              <OperatorChip
                                did={mach.did}
                                handle={mach.host?.handle ?? null}
                                displayName={mach.host?.displayName ?? null}
                                avatarUrl={mach.host?.avatarUrl ?? null}
                              />
                              {mach.region ? (
                                <span
                                  {...stylex.props(styles.regionChip)}
                                  title={`Provider-claimed region · ${mach.region.toUpperCase()}`}
                                >
                                  {regionFlagEmoji ? (
                                    <span aria-hidden="true">{regionFlagEmoji}</span>
                                  ) : null}
                                  {mach.region.toUpperCase()}
                                </span>
                              ) : null}
                            </div>
                          </td>
                          <td {...stylex.props(styles.td, isLast && styles.tdLastRow)}>
                            <SmallBody variant="secondary">
                              {fmtCompact(mach.activity.day.requests)} req ·{" "}
                              {fmtCompact(mach.activity.day.tokens)} tk
                            </SmallBody>
                          </td>
                          <td
                            {...stylex.props(styles.td, styles.tdNum, isLast && styles.tdLastRow)}
                          >
                            <SmallBody variant="secondary">
                              {mach.lastSeen ? fmtLastSeen(mach.lastSeen) : "—"}
                            </SmallBody>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            <div {...stylex.props(styles.section, styles.sectionLast)}>
              <div {...stylex.props(styles.sectionHead)}>
                <Heading4 style={styles.headingMono}>example usage</Heading4>
                <SmallBody style={styles.sectionMeta}>
                  OpenAI SDK (and curl) — same snippets as{" "}
                  <Link to="/docs/inference" preload="intent">
                    API docs
                  </Link>
                  .
                </SmallBody>
              </div>
              <SegmentedControl
                aria-label="Snippet language"
                size="sm"
                selectedKeys={new Set([snippetLang])}
                onSelectionChange={(selection) => {
                  const id = selection.values().next().value;
                  if (typeof id !== "string") return;
                  if ((SNIPPET_LANGS as readonly string[]).includes(id)) {
                    setSnippetLang(id as SnippetLang);
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
                {highlightedSnippetHtml ? (
                  <div
                    {...stylex.props(styles.highlightedSnippet)}
                    dangerouslySetInnerHTML={{ __html: highlightedSnippetHtml }}
                  />
                ) : (
                  <pre {...stylex.props(styles.snippetPlain)}>{snippet}</pre>
                )}
                {snippet ? <CopyToClipboardButton text={snippet} /> : null}
              </Flex>
            </div>
          </div>
        ) : null}
      </div>
    </Page.Root>
  );
}
