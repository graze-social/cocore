"use client";

// /chat — run chat sessions on other people's machines.
//
// Transcripts live entirely in the browser (encrypted localStorage,
// per DID; see chat-store.ts) — the console server never stores user chats.
// Each turn goes through the existing cookie-authed dispatch SSE
// endpoint, which publishes the job to the user's PDS and streams
// the decrypted reply back (chat-dispatch.ts).

import * as stylex from "@stylexjs/stylex";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createLink } from "@tanstack/react-router";
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { Button as AriaButton } from "react-aria-components";
import { Square } from "lucide-react";
import type { ReactElement } from "react";

import { getMyBalanceQueryOptions } from "@/components/account/token-balance.functions.ts";
import {
  ChatDispatchError,
  dispatchChatTurn,
  flattenTranscript,
} from "@/components/chat/chat-dispatch.ts";
import {
  type ChatMessage,
  type ChatSession,
  createSession,
  loadActiveSessionId,
  loadSessions,
  MAX_TOKENS_CHOICES,
  newSessionId,
  saveActiveSessionId,
  saveSessions,
  titleFromText,
} from "@/components/chat/chat-store.ts";
import { ChatMarkdown } from "@/components/chat/chat-markdown.tsx";
import { ThinkingDisclosure } from "@/components/chat/chat-thinking.tsx";
import { modelDirectoryRouteQueryOptions } from "@/components/models/models.functions.ts";
import { formatTokensCompact } from "@/lib/token-display.ts";
import type { ModelDirectoryEntry } from "@/lib/model-directory.server.ts";
import { Button } from "@/design-system/button";
import { Drawer, DrawerBody, DrawerHeader } from "@/design-system/drawer";
import { Flex } from "@/design-system/flex";
import { Page } from "@/design-system/page";
import { Kbd } from "@/design-system/kbd";
import { breakpoints } from "@/design-system/theme/media-queries.stylex";
import { Popover } from "@/design-system/popover";
import { SearchField } from "@/design-system/search-field";
import { getSessionQueryOptions } from "@/integrations/auth/session.functions.ts";
import { successColor, uiColor } from "@/design-system/theme/color.stylex";
import { radius } from "@/design-system/theme/radius.stylex";
import {
  gap,
  horizontalSpace,
  size as sizeSpace,
  verticalSpace,
} from "@/design-system/theme/semantic-spacing.stylex";
import { fontFamily, fontSize, fontWeight } from "@/design-system/theme/typography.stylex";
import { Heading1 } from "@/design-system/typography";
import { Text } from "@/design-system/typography/text";

const ButtonLink = createLink(Button);

const CHAT_SUGGESTIONS = [
  "explain this rust lifetime error",
  "summarize my protocol notes",
  "draft release notes from a diff",
];

// Prototype meta text sits at ~10.5px; the smallest token is 12px,
// so fine print gets its own size between the two.
const MICRO = "0.71rem";

const styles = stylex.create({
  header: {
    marginBottom: 0,
  },
  root: {
    boxSizing: "border-box",
    display: "flex",
    flexDirection: "column",
    fontFamily: fontFamily.mono,
    gap: verticalSpace["2xl"],
    marginLeft: "auto",
    marginRight: "auto",
    maxWidth: "1600px",
    minWidth: 0,
    paddingBottom: verticalSpace["8xl"],
    width: "100%",
  },
  titlePrompt: {
    color: uiColor.text1,
    fontWeight: fontWeight.normal,
  },
  headingMono: {
    fontFamily: fontFamily.mono,
  },
  metaRow: {
    alignItems: "center",
    color: uiColor.text1,
    display: "flex",
    flexWrap: "wrap",
    fontSize: fontSize.sm,
    gap: horizontalSpace.lg,
    marginTop: verticalSpace.sm,
  },
  metaSep: {
    color: uiColor.border2,
  },
  shell: {
    backgroundColor: uiColor.bg,
    borderColor: uiColor.border1,
    borderRadius: radius.md,
    borderStyle: "solid",
    borderWidth: 1,
    boxSizing: "border-box",
    display: "flex",
    flexDirection: "row",
    height: "calc(100dvh - 250px)",
    maxWidth: "100%",
    minHeight: "520px",
    minWidth: 0,
    overflow: "hidden",
    width: "100%",
  },

  /* ── sidebar ── */
  side: {
    backgroundColor: uiColor.bgSubtle,
    borderRightColor: uiColor.border1,
    borderRightStyle: "solid",
    borderRightWidth: 1,
    // Mobile-first: the desktop sidebar is hidden on narrow screens
    // (history lives in the header drawer instead) and reappears at md.
    display: { default: "none", [breakpoints.md]: "flex" },
    flexDirection: "column",
    flexShrink: 0,
    minWidth: 0,
    width: "272px",
  },
  sideHead: {
    borderBottomColor: uiColor.border1,
    borderBottomStyle: "dashed",
    borderBottomWidth: 1,
    display: "flex",
    flexDirection: "column",
    gap: gap.md,
    padding: horizontalSpace.md,
  },
  convoList: {
    display: "flex",
    flexDirection: "column",
    flexGrow: 1,
    gap: gap.xs,
    minWidth: 0,
    overflowY: "auto",
    padding: horizontalSpace.sm,
  },
  convo: {
    backgroundColor: { default: "transparent", ":hover": uiColor.bg },
    borderColor: "transparent",
    borderRadius: radius.xs,
    borderStyle: "solid",
    borderWidth: 1,
    boxSizing: "border-box",
    cursor: "pointer",
    display: "flex",
    flexDirection: "column",
    gap: gap.sm,
    minWidth: 0,
    overflow: "hidden",
    paddingBottom: verticalSpace.md,
    paddingLeft: horizontalSpace.md,
    paddingRight: horizontalSpace.md,
    paddingTop: verticalSpace.md,
    textAlign: "left",
    width: "100%",
  },
  convoActive: {
    backgroundColor: uiColor.component2,
    borderColor: uiColor.border1,
  },
  convoRow: {
    alignItems: "baseline",
    display: "flex",
    gap: gap.md,
    justifyContent: "space-between",
    minWidth: 0,
    width: "100%",
  },
  convoTitle: {
    color: uiColor.text2,
    flexShrink: 1,
    fontSize: fontSize.xs,
    fontWeight: fontWeight.medium,
    minWidth: 0,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  convoModelId: {
    color: uiColor.text1,
    flexShrink: 1,
    fontSize: MICRO,
    fontVariantNumeric: "tabular-nums",
    minWidth: 0,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  convoMetaText: {
    color: uiColor.text1,
    flexShrink: 0,
    fontSize: MICRO,
    fontVariantNumeric: "tabular-nums",
    whiteSpace: "nowrap",
  },
  convoEmpty: {
    alignItems: "center",
    color: uiColor.text1,
    display: "flex",
    flexDirection: "column",
    gap: gap.md,
    paddingBottom: verticalSpace["2xl"],
    paddingTop: verticalSpace["2xl"],
    textAlign: "center",
  },
  convoEmptyHint: {
    color: uiColor.text1,
    fontSize: MICRO,
    maxWidth: "180px",
  },
  sideFoot: {
    borderTopColor: uiColor.border1,
    borderTopStyle: "dashed",
    borderTopWidth: 1,
    color: uiColor.text1,
    display: "flex",
    fontSize: MICRO,
    fontVariantNumeric: "tabular-nums",
    justifyContent: "space-between",
    paddingBottom: verticalSpace.md,
    paddingLeft: horizontalSpace.lg,
    paddingRight: horizontalSpace.lg,
    paddingTop: verticalSpace.md,
  },
  emphasis: {
    color: uiColor.text2,
    fontWeight: fontWeight.medium,
  },

  /* ── main pane head ── */
  main: {
    display: "flex",
    flexDirection: "column",
    flexGrow: 1,
    minWidth: 0,
  },
  chatHead: {
    alignItems: {
      default: "stretch",
      [breakpoints.md]: "center",
    },
    borderBottomColor: uiColor.border1,
    borderBottomStyle: "dashed",
    borderBottomWidth: 1,
    display: "flex",
    flexWrap: "wrap",
    gap: gap.xl,
    justifyContent: "space-between",
    paddingBottom: verticalSpace.md,
    paddingLeft: horizontalSpace.xl,
    paddingRight: horizontalSpace.xl,
    paddingTop: verticalSpace.md,
  },
  chatHeadTop: {
    alignItems: "center",
    display: "flex",
    flexDirection: "row",
    gap: gap.md,
    justifyContent: {
      default: "space-between",
      [breakpoints.md]: "flex-start",
    },
    minWidth: 0,
    width: {
      default: "100%",
      [breakpoints.md]: "auto",
    },
  },
  chatHeadMain: {
    flexGrow: 1,
    minWidth: 0,
  },
  mobileDrawerWrap: {
    // Mobile-first: the history-drawer trigger shows on narrow screens
    // and is hidden at md, where the desktop sidebar is visible instead.
    display: { default: "flex", [breakpoints.md]: "none" },
    flexShrink: 0,
    marginLeft: "auto",
  },
  mobileSessionsBtn: {
    flexShrink: 0,
  },
  drawerBody: {
    display: "flex",
    flexDirection: "column",
    flexGrow: 1,
    // The drawer dialog isn't a guaranteed flex container, so anchor the
    // body to the viewport height (minus the drawer header) instead of
    // relying on a percentage chain that can collapse to content height.
    height: `calc(100dvh - ${sizeSpace["3xl"]})`,
    minHeight: 0,
    overflow: "hidden",
    paddingBottom: 0,
    paddingLeft: 0,
    paddingRight: 0,
    paddingTop: 0,
  },
  sideInDrawer: {
    backgroundColor: uiColor.bgSubtle,
    boxSizing: "border-box",
    display: "flex",
    flexDirection: "column",
    flexGrow: 1,
    minHeight: 0,
    width: "100%",
  },
  chatHeadTitle: {
    color: uiColor.text2,
    fontSize: fontSize.sm,
    fontWeight: fontWeight.semibold,
    letterSpacing: "-0.01em",
    maxWidth: "38ch",
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  chatHeadSub: {
    color: uiColor.text1,
    fontSize: MICRO,
    fontVariantNumeric: "tabular-nums",
    marginTop: "2px",
  },
  sessionStrip: {
    alignItems: "center",
    color: uiColor.text1,
    display: "flex",
    flexWrap: "wrap",
    fontSize: fontSize.xs,
    fontVariantNumeric: "tabular-nums",
    gap: horizontalSpace["2xl"],
  },
  hostChip: {
    alignItems: "center",
    backgroundColor: uiColor.bgSubtle,
    borderColor: uiColor.border1,
    borderRadius: radius.xs,
    borderStyle: "solid",
    borderWidth: 1,
    color: uiColor.text2,
    display: "inline-flex",
    fontSize: fontSize.xs,
    gap: gap.md,
    paddingBottom: "3px",
    paddingLeft: horizontalSpace.md,
    paddingRight: horizontalSpace.md,
    paddingTop: "3px",
    whiteSpace: "nowrap",
  },
  stripItem: {
    whiteSpace: "nowrap",
  },
  stripLabel: {
    color: uiColor.text1,
    marginRight: "4px",
  },
  liveDot: {
    backgroundColor: successColor.solid1,
    borderRadius: radius.full,
    display: "inline-block",
    flexShrink: 0,
    height: "6px",
    width: "6px",
  },

  /* ── transcript ── */
  scroll: {
    boxSizing: "border-box",
    flexGrow: 1,
    minHeight: 0,
    minWidth: 0,
    overflowAnchor: "none",
    overflowX: "hidden",
    overflowY: "auto",
    paddingBottom: verticalSpace.lg,
    paddingTop: verticalSpace["2xl"],
  },
  msgCol: {
    boxSizing: "border-box",
    display: "flex",
    flexDirection: "column",
    gap: verticalSpace["2xl"],
    marginLeft: "auto",
    marginRight: "auto",
    maxWidth: "760px",
    minWidth: 0,
    paddingLeft: horizontalSpace["2xl"],
    paddingRight: horizontalSpace["2xl"],
    width: "100%",
  },
  msgUser: {
    alignSelf: "flex-end",
    backgroundColor: uiColor.bgSubtle,
    borderBottomLeftRadius: "8px",
    borderBottomRightRadius: "2px",
    borderColor: uiColor.border1,
    borderStyle: "solid",
    borderTopLeftRadius: "8px",
    borderTopRightRadius: "8px",
    borderWidth: 1,
    fontFamily: fontFamily.sans,
    fontSize: fontSize.sm,
    lineHeight: 1.55,
    maxWidth: "78%",
    overflowWrap: "break-word",
    paddingBottom: verticalSpace.md,
    paddingLeft: horizontalSpace.lg,
    paddingRight: horizontalSpace.lg,
    paddingTop: verticalSpace.md,
    whiteSpace: "pre-wrap",
  },
  msgAssistant: {
    alignSelf: "stretch",
    display: "flex",
    flexDirection: "column",
    gap: verticalSpace.sm,
    minWidth: 0,
  },
  msgGutter: {
    alignItems: "center",
    color: uiColor.text1,
    display: "flex",
    fontSize: MICRO,
    gap: horizontalSpace.md,
  },
  msgGutterModel: {
    color: uiColor.text1,
    fontWeight: fontWeight.medium,
  },
  msgBody: {
    maxWidth: "100%",
    minWidth: 0,
  },
  msgError: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
    fontStyle: "italic",
  },
  msgMeta: {
    color: uiColor.text1,
    display: "flex",
    flexWrap: "wrap",
    fontSize: MICRO,
    fontVariantNumeric: "tabular-nums",
    gap: horizontalSpace.lg,
    marginTop: "2px",
    opacity: 0.85,
  },

  /* ── empty session ── */
  empty: {
    alignItems: "center",
    display: "flex",
    flexDirection: "column",
    flexGrow: 1,
    gap: verticalSpace.md,
    justifyContent: "center",
    paddingLeft: horizontalSpace["2xl"],
    paddingRight: horizontalSpace["2xl"],
    textAlign: "center",
  },
  emptyGlyph: {
    color: uiColor.border3,
    fontSize: fontSize.xl,
    fontWeight: fontWeight.bold,
    marginBottom: verticalSpace.sm,
  },
  // A little hand-drawn "goober" hanging out in the empty chat — flair only.
  emptyGoober: {
    display: "block",
    width: "7rem",
    height: "7rem",
    objectFit: "contain",
    opacity: 0.95,
    marginBottom: verticalSpace.sm,
    pointerEvents: "none",
    userSelect: "none",
  },
  emptyTitle: {
    color: uiColor.text2,
    fontSize: fontSize.lg,
    fontWeight: fontWeight.semibold,
    letterSpacing: "-0.01em",
    margin: 0,
  },
  emptyTitleFaint: {
    color: uiColor.text1,
    fontWeight: fontWeight.normal,
  },
  emptyText: {
    color: uiColor.text1,
    fontFamily: fontFamily.sans,
    fontSize: fontSize.xs,
    lineHeight: 1.6,
    margin: 0,
    maxWidth: "52ch",
  },
  sugg: {
    display: "flex",
    flexWrap: "wrap",
    gap: gap.md,
    justifyContent: "center",
    marginTop: verticalSpace.lg,
  },
  suggBtn: {
    backgroundColor: { default: uiColor.bg, ":hover": uiColor.bgSubtle },
    borderColor: { default: uiColor.border2, ":hover": uiColor.text2 },
    borderRadius: radius.full,
    borderStyle: { default: "dashed", ":hover": "solid" },
    borderWidth: 1,
    color: { default: uiColor.text1, ":hover": uiColor.text2 },
    cursor: "pointer",
    fontFamily: fontFamily.mono,
    fontSize: fontSize.xs,
    paddingBottom: "6px",
    paddingLeft: horizontalSpace.lg,
    paddingRight: horizontalSpace.lg,
    paddingTop: "6px",
    transitionDuration: "0.12s",
    transitionProperty: "color, border-color, background-color",
  },
  emptyCtas: {
    display: "flex",
    flexWrap: "wrap",
    gap: gap.md,
    justifyContent: "center",
    marginTop: verticalSpace.lg,
  },

  /* ── composer ── */
  composer: {
    backgroundColor: uiColor.bgSubtle,
    borderTopColor: uiColor.border1,
    borderTopStyle: "solid",
    borderTopWidth: 1,
    boxSizing: "border-box",
    minWidth: 0,
    paddingBottom: verticalSpace.lg,
    paddingLeft: horizontalSpace.xl,
    paddingRight: horizontalSpace.xl,
    paddingTop: verticalSpace.lg,
  },
  composerBox: {
    backgroundColor: uiColor.bg,
    borderColor: { default: uiColor.border2, ":focus-within": uiColor.text2 },
    borderRadius: radius.sm,
    borderStyle: "solid",
    borderWidth: 1,
    boxSizing: "border-box",
    display: "flex",
    flexDirection: "column",
    marginLeft: "auto",
    marginRight: "auto",
    maxWidth: "760px",
    minWidth: 0,
    paddingBottom: verticalSpace.sm,
    paddingLeft: horizontalSpace.lg,
    paddingRight: horizontalSpace.lg,
    paddingTop: verticalSpace.md,
    position: "relative",
    transitionDuration: "0.12s",
    transitionProperty: "border-color",
    width: "100%",
  },
  textarea: {
    backgroundColor: "transparent",
    borderWidth: 0,
    boxSizing: "border-box",
    color: uiColor.text2,
    display: "block",
    fontFamily: fontFamily.sans,
    fontSize: fontSize.sm,
    lineHeight: 1.5,
    maxHeight: "160px",
    maxWidth: "100%",
    minHeight: "38px",
    outline: "none",
    padding: 0,
    resize: "none",
    width: "100%",
  },
  composerBar: {
    alignItems: "center",
    borderTopColor: uiColor.border1,
    borderTopStyle: "dashed",
    borderTopWidth: 1,
    display: "flex",
    flexWrap: "nowrap",
    gap: gap.md,
    marginTop: verticalSpace.sm,
    minWidth: 0,
    paddingTop: verticalSpace.sm,
  },
  modelPickerWrap: {
    flex: "1 1 0",
    minWidth: 0,
    overflow: "hidden",
  },
  modelPickerRoot: {
    minWidth: 0,
    overflow: "hidden",
    width: "100%",
  },
  chipBtn: {
    alignItems: "center",
    appearance: "none",
    backgroundColor: uiColor.bgSubtle,
    borderColor: uiColor.border1,
    borderRadius: radius.xs,
    borderStyle: "solid",
    borderWidth: 1,
    boxSizing: "border-box",
    color: uiColor.text2,
    cursor: "pointer",
    display: "flex",
    fontFamily: fontFamily.mono,
    fontSize: fontSize.xs,
    fontWeight: fontWeight.normal,
    height: "auto",
    justifyContent: "flex-start",
    maxWidth: "100%",
    minWidth: 0,
    overflow: "hidden",
    paddingBottom: "4px",
    paddingLeft: horizontalSpace.md,
    paddingRight: horizontalSpace.md,
    paddingTop: "4px",
    textAlign: "left",
    width: "100%",
  },
  chipBtnInner: {
    alignItems: "center",
    columnGap: gap.sm,
    display: "grid",
    gridTemplateColumns: "auto minmax(0, 1fr) auto",
    minWidth: 0,
    width: "100%",
  },
  chipModelId: {
    minWidth: 0,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  chipSuffix: {
    alignItems: "center",
    display: "flex",
    gap: gap.xs,
    minWidth: 0,
    whiteSpace: "nowrap",
  },
  chipKey: {
    color: uiColor.text1,
    flexShrink: 0,
  },
  chipTarget: {
    flexShrink: 1,
    minWidth: 0,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  chipCaret: {
    color: uiColor.text1,
    flexShrink: 0,
    fontSize: "9px",
  },
  rateNote: {
    color: uiColor.text1,
    flexShrink: 0,
    fontSize: MICRO,
    fontVariantNumeric: "tabular-nums",
    marginLeft: "auto",
    marginRight: horizontalSpace.md,
    whiteSpace: "nowrap",
  },
  composerSend: {
    flexShrink: 0,
  },
  privacyNote: {
    color: uiColor.text1,
    fontSize: MICRO,
    lineHeight: 1.5,
    marginLeft: "auto",
    marginRight: "auto",
    marginTop: verticalSpace.sm,
    maxWidth: "760px",
    textAlign: "center",
    width: "100%",
  },

  /* ── model / host popover ── */
  pop: {
    display: "flex",
    flexDirection: "column",
    gap: verticalSpace.md,
    maxHeight: "min(540px, calc(100vh - 240px))",
    overflowY: "auto",
    width: "min(420px, calc(100vw - 48px))",
  },
  popSectHead: {
    alignItems: "baseline",
    borderBottomColor: uiColor.border1,
    borderBottomStyle: "dashed",
    borderBottomWidth: 1,
    color: uiColor.text1,
    display: "flex",
    fontSize: MICRO,
    justifyContent: "space-between",
    letterSpacing: "0.07em",
    paddingBottom: verticalSpace.xs,
  },
  popSectHint: {
    color: uiColor.text1,
    letterSpacing: 0,
    opacity: 0.8,
  },
  popOpt: {
    backgroundColor: { default: "transparent", ":hover": uiColor.bg },
    borderColor: "transparent",
    borderRadius: radius.xs,
    borderStyle: "solid",
    borderWidth: 1,
    cursor: "pointer",
    display: "flex",
    flexDirection: "column",
    fontFamily: fontFamily.mono,
    gap: gap.xs,
    paddingBottom: verticalSpace.sm,
    paddingLeft: horizontalSpace.md,
    paddingRight: horizontalSpace.md,
    paddingTop: verticalSpace.sm,
    textAlign: "left",
    width: "100%",
  },
  popOptSelected: {
    backgroundColor: uiColor.component2,
    borderColor: uiColor.border1,
  },
  popOptRow: {
    alignItems: "baseline",
    display: "flex",
    gap: gap.lg,
    justifyContent: "space-between",
    width: "100%",
  },
  popOptName: {
    color: uiColor.text2,
    fontSize: fontSize.xs,
    fontWeight: fontWeight.semibold,
    minWidth: 0,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  popOptSub: {
    color: uiColor.text1,
    fontSize: MICRO,
    fontVariantNumeric: "tabular-nums",
  },
});

interface MachineOption {
  did: string;
  label: string;
  detail: string | null;
}

function shortDid(did: string): string {
  return did.length > 24 ? `${did.slice(0, 14)}…${did.slice(-6)}` : did;
}

function machineLabel(m: ModelDirectoryEntry["machines"][number]): string {
  const owner = m.host?.handle ? `@${m.host.handle.replace(/^@/, "")}` : null;
  const machine = m.machineLabel ?? m.chip ?? null;
  if (owner && machine) return `${owner}/${machine}`;
  return owner ?? machine ?? shortDid(m.did);
}

function fmtWhen(iso: string): string {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "";
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 60) return "now";
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

function fmtClock(iso: string): string {
  const t = new Date(iso);
  if (!Number.isFinite(t.getTime())) return "";
  return `${String(t.getHours()).padStart(2, "0")}:${String(t.getMinutes()).padStart(2, "0")}`;
}

function fmtTok(n: number): string {
  return n >= 1024 ? `${Math.round(n / 1024)}k` : `${n}`;
}

function ModelPicker({
  models,
  modelId,
  targetProviderDid,
  maxTokensOut,
  onModel,
  onTarget,
  onMaxTokens,
}: {
  models: ModelDirectoryEntry[];
  modelId: string | null;
  targetProviderDid: string | null;
  maxTokensOut: number;
  onModel: (id: string) => void;
  onTarget: (did: string | null) => void;
  onMaxTokens: (n: number) => void;
}): ReactElement {
  const [open, setOpen] = useState(false);
  const [modelQuery, setModelQuery] = useState("");
  const selected = models.find((m) => m.modelId === modelId) ?? null;
  const filteredModels = useMemo(() => {
    const q = modelQuery.trim().toLowerCase();
    if (!q) return models;
    return models.filter((m) => {
      if (m.modelId.toLowerCase().includes(q)) return true;
      return m.machines.some((mac) => machineLabel(mac).toLowerCase().includes(q));
    });
  }, [models, modelQuery]);
  const machines: MachineOption[] = (selected?.machines ?? []).map((m) => ({
    did: m.did,
    label: machineLabel(m),
    detail:
      [m.chip, m.ramGB != null ? `${m.ramGB}gb ram` : null].filter(Boolean).join(" · ") || null,
  }));
  const targetLabel = targetProviderDid
    ? (machines.find((m) => m.did === targetProviderDid)?.label ?? shortDid(targetProviderDid))
    : "auto";

  const pickModel = (id: string) => {
    onModel(id);
    setOpen(false);
  };
  const pickTarget = (did: string | null) => {
    onTarget(did);
    setOpen(false);
  };
  const pickMaxTokens = (n: number) => {
    onMaxTokens(n);
    setOpen(false);
  };

  return (
    <div {...stylex.props(styles.modelPickerRoot)}>
      <Popover
        isOpen={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) setModelQuery("");
        }}
        placement="top start"
        trigger={
          <AriaButton {...stylex.props(styles.chipBtn)}>
            <span {...stylex.props(styles.chipBtnInner)}>
              <span {...stylex.props(styles.chipKey)}>model</span>
              <span {...stylex.props(styles.chipModelId)}>{selected ? selected.modelId : "—"}</span>
              <span {...stylex.props(styles.chipSuffix)}>
                <span {...stylex.props(styles.chipKey)}> · on</span>
                <span {...stylex.props(styles.chipTarget)}>{targetLabel}</span>
                <span {...stylex.props(styles.chipCaret)}>▾</span>
              </span>
            </span>
          </AriaButton>
        }
        style={styles.pop}
      >
        <div {...stylex.props(styles.popSectHead)}>
          <span>model</span>
          <span {...stylex.props(styles.popSectHint)}>models live on the network</span>
        </div>
        {models.length > 4 ? (
          <SearchField
            size="sm"
            placeholder="search models"
            value={modelQuery}
            onChange={setModelQuery}
            aria-label="search models"
          />
        ) : null}
        <Flex direction="column" gap="xs">
          {models.length === 0 ? (
            <Text variant="secondary" size="sm">
              no models online right now
            </Text>
          ) : null}
          {models.length > 0 && filteredModels.length === 0 ? (
            <Text variant="secondary" size="sm">
              no models match “{modelQuery.trim()}”
            </Text>
          ) : null}
          {filteredModels.map((m) => (
            <button
              key={m.modelId}
              type="button"
              {...stylex.props(styles.popOpt, m.modelId === modelId && styles.popOptSelected)}
              onClick={() => pickModel(m.modelId)}
            >
              <span {...stylex.props(styles.popOptRow)}>
                <span {...stylex.props(styles.popOptName)}>{m.modelId}</span>
                <span {...stylex.props(styles.popOptSub)}>
                  <span {...stylex.props(styles.liveDot)} /> {m.machineCount} live
                </span>
              </span>
              <span {...stylex.props(styles.popOptRow)}>
                <span {...stylex.props(styles.popOptSub)}>
                  {m.activity.week.requests.toLocaleString("en-US")} runs · 7d
                </span>
                <span {...stylex.props(styles.popOptSub)}>
                  {m.outputPricePerMTok != null
                    ? `${formatTokensCompact(m.outputPricePerMTok)} CC/MTok out`
                    : ""}
                </span>
              </span>
            </button>
          ))}
        </Flex>

        <div {...stylex.props(styles.popSectHead)}>
          <span>run on</span>
          <span {...stylex.props(styles.popSectHint)}>uniform pricing — pick for trust</span>
        </div>
        <Flex direction="column" gap="xs">
          <button
            type="button"
            {...stylex.props(styles.popOpt, targetProviderDid === null && styles.popOptSelected)}
            onClick={() => pickTarget(null)}
          >
            <span {...stylex.props(styles.popOptRow)}>
              <span {...stylex.props(styles.popOptName)}>auto</span>
              <span {...stylex.props(styles.popOptSub)}>advisor picks</span>
            </span>
            <span {...stylex.props(styles.popOptSub)}>freshest attested machine for the model</span>
          </button>
          {machines.map((m) => (
            <button
              key={m.did}
              type="button"
              {...stylex.props(styles.popOpt, m.did === targetProviderDid && styles.popOptSelected)}
              onClick={() => pickTarget(m.did)}
            >
              <span {...stylex.props(styles.popOptRow)}>
                <span {...stylex.props(styles.popOptName)}>{m.label}</span>
                <span {...stylex.props(styles.popOptSub)}>
                  <span {...stylex.props(styles.liveDot)} /> live
                </span>
              </span>
              {m.detail ? <span {...stylex.props(styles.popOptSub)}>{m.detail}</span> : null}
            </button>
          ))}
        </Flex>

        <div {...stylex.props(styles.popSectHead)}>
          <span>max tokens</span>
          <span {...stylex.props(styles.popSectHint)}>per reply</span>
        </div>
        <Flex gap="sm">
          {MAX_TOKENS_CHOICES.map((n) => (
            <Button
              key={n}
              size="sm"
              variant={maxTokensOut === n ? "primary" : "outline"}
              onPress={() => pickMaxTokens(n)}
            >
              {fmtTok(n)}
            </Button>
          ))}
        </Flex>
      </Popover>
    </div>
  );
}

interface ChatSessionsPanelProps {
  visible: ChatSession[];
  activeId: string | null;
  query: string;
  hydrated: boolean;
  spentTotal: number;
  balance: number | undefined;
  onQueryChange: (query: string) => void;
  onSelectSession: (id: string) => void;
  onNewChat: () => void;
}

function ChatSessionsPanel({
  visible,
  activeId,
  query,
  hydrated,
  spentTotal,
  balance,
  onQueryChange,
  onSelectSession,
  onNewChat,
}: ChatSessionsPanelProps): ReactElement {
  return (
    <>
      <div {...stylex.props(styles.sideHead)}>
        <Button variant="primary" size="sm" onPress={onNewChat}>
          + new chat
        </Button>
        <SearchField
          size="sm"
          placeholder="filter sessions"
          value={query}
          onChange={onQueryChange}
          aria-label="filter sessions"
        />
      </div>
      <div {...stylex.props(styles.convoList)}>
        {visible.map((s) => (
          <button
            key={s.id}
            type="button"
            {...stylex.props(styles.convo, s.id === activeId && styles.convoActive)}
            onClick={() => onSelectSession(s.id)}
          >
            <span {...stylex.props(styles.convoRow)}>
              <span {...stylex.props(styles.convoTitle)}>{s.title}</span>
              <span {...stylex.props(styles.convoMetaText)}>{fmtWhen(s.updatedAt)}</span>
            </span>
            <span {...stylex.props(styles.convoRow)}>
              <span {...stylex.props(styles.convoModelId)}>{s.modelId}</span>
              <span {...stylex.props(styles.convoMetaText)}>
                {s.spentTokens > 0 ? `${formatTokensCompact(s.spentTokens)} tok` : ""}
              </span>
            </span>
          </button>
        ))}
        {hydrated && visible.length === 0 ? (
          <div {...stylex.props(styles.convoEmpty)}>
            <span>{query ? "no sessions match" : "no sessions yet"}</span>
            {!query ? (
              <span {...stylex.props(styles.convoEmptyHint)}>
                transcripts stay in this browser — nothing is stored on our servers
              </span>
            ) : null}
          </div>
        ) : null}
      </div>
      <div {...stylex.props(styles.sideFoot)}>
        <span>
          spent{" "}
          <span {...stylex.props(styles.emphasis)}>{formatTokensCompact(spentTotal)} tok</span>
        </span>
        {balance != null ? (
          <span>
            balance{" "}
            <span {...stylex.props(styles.emphasis)}>{formatTokensCompact(balance)} tok</span>
          </span>
        ) : null}
      </div>
    </>
  );
}

export function ChatPage(): ReactElement {
  const queryClient = useQueryClient();
  const { data: session } = useQuery(getSessionQueryOptions);
  // The route is auth-gated, so a missing DID only happens before the
  // session query resolves (or in dev previews); "anon" keeps storage
  // hydration working there and the real key takes over once known.
  const did = session?.user.did ?? "anon";
  const chatStorageKey = session?.chatStorageKey ?? null;

  const { data: directory } = useQuery(modelDirectoryRouteQueryOptions);
  // `stub` is a connectivity smoke test, not a production model — it just
  // echoes input. Keep it out of chat entirely (picker AND default); a
  // fleet serving only stub correctly shows "no models online" here. It
  // still appears on the /models catalog, labelled as a test entry.
  const models = useMemo(
    () => (directory?.models ?? []).filter((m) => m.modelId.toLowerCase() !== "stub"),
    [directory],
  );
  const defaultModelId = models[0]?.modelId ?? null;

  const { data: balance } = useQuery(getMyBalanceQueryOptions);

  // Transcripts hydrate after mount (SSR renders empty). The module-
  // level cache in chat-store.ts keeps history across route changes.
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [hydrated, setHydrated] = useState(false);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [draft, setDraft] = useState("");
  const [streamingId, setStreamingId] = useState<string | null>(null);

  // Settings for the not-yet-created session shown by "new chat".
  const [draftModelId, setDraftModelId] = useState<string | null>(null);
  const [draftTarget, setDraftTarget] = useState<string | null>(null);
  const [draftMaxTokens, setDraftMaxTokens] = useState<number>(MAX_TOKENS_CHOICES[1]);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEffect(() => {
    if (did === "anon" || !chatStorageKey) {
      setSessions([]);
      setActiveId(null);
      setHydrated(false);
      return;
    }

    let cancelled = false;
    void (async () => {
      const loaded = await loadSessions(did, chatStorageKey);
      const savedActive = loadActiveSessionId(did);
      if (cancelled) return;
      setSessions(loaded);
      setActiveId(
        savedActive && loaded.some((s) => s.id === savedActive)
          ? savedActive
          : (loaded[0]?.id ?? null),
      );
      setHydrated(true);
    })();

    return () => {
      cancelled = true;
    };
  }, [did, chatStorageKey]);

  useEffect(() => {
    if (did === "anon" || !hydrated) return;
    saveActiveSessionId(did, activeId);
  }, [did, hydrated, activeId]);

  // Throttled persistence: streaming updates state on every chunk;
  // write at most every 400ms (trailing) + on unmount. Sessions with
  // no messages are view-state only and never persisted.
  const persistTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const latest = useRef<{
    did: string;
    chatStorageKey: string | null;
    hydrated: boolean;
    sessions: ChatSession[];
  }>({
    did: "anon",
    chatStorageKey: null,
    hydrated: false,
    sessions: [],
  });
  latest.current = { did, chatStorageKey, hydrated, sessions };
  useEffect(() => {
    if (did === "anon" || !chatStorageKey || !hydrated) return;
    if (persistTimer.current) clearTimeout(persistTimer.current);
    persistTimer.current = setTimeout(() => {
      persistTimer.current = null;
      const cur = latest.current;
      if (cur.did !== "anon" && cur.chatStorageKey && cur.hydrated) {
        void saveSessions(
          cur.did,
          cur.sessions.filter((s) => s.messages.length > 0),
          cur.chatStorageKey,
        );
      }
    }, 400);
  }, [did, chatStorageKey, hydrated, sessions]);
  useEffect(
    () => () => {
      if (persistTimer.current) clearTimeout(persistTimer.current);
      const cur = latest.current;
      if (cur.did !== "anon" && cur.chatStorageKey && cur.hydrated) {
        void saveSessions(
          cur.did,
          cur.sessions.filter((s) => s.messages.length > 0),
          cur.chatStorageKey,
        );
      }
    },
    [],
  );

  const active = sessions.find((s) => s.id === activeId) ?? null;

  const modelId = active?.modelId ?? draftModelId ?? defaultModelId;
  const targetProviderDid = active ? active.targetProviderDid : draftTarget;
  const maxTokensOut = active?.maxTokensOut ?? draftMaxTokens;

  const updateSession = useCallback((id: string, fn: (s: ChatSession) => ChatSession) => {
    setSessions((prev) => prev.map((s) => (s.id === id ? fn(s) : s)));
  }, []);

  const patchMessage = useCallback(
    (sessionId: string, messageId: string, fn: (m: ChatMessage) => ChatMessage) => {
      updateSession(sessionId, (s) => ({
        ...s,
        messages: s.messages.map((m) => (m.id === messageId ? fn(m) : m)),
      }));
    },
    [updateSession],
  );

  // Auto-scroll after layout only when the user was already pinned to
  // the bottom before the latest chunk (or after send / convo switch).
  const scrollRef = useRef<HTMLDivElement>(null);
  const forceScrollRef = useRef(false);
  const pinnedToBottomRef = useRef(true);
  const scrollSnapshotRef = useRef({ top: 0, height: 0 });
  const lastMessage = active?.messages[active.messages.length - 1];

  const syncScrollSnapshot = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    scrollSnapshotRef.current = { top: el.scrollTop, height: el.scrollHeight };
    pinnedToBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 64;
  }, []);

  const onTranscriptScroll = useCallback(() => {
    syncScrollSnapshot();
  }, [syncScrollSnapshot]);

  const onTranscriptWheel = useCallback((e: React.WheelEvent<HTMLDivElement>) => {
    // Wheel fires before scrollTop updates; cancel pin immediately so an
    // in-flight stream chunk can't yank the viewport back down.
    if (e.deltaY < 0) pinnedToBottomRef.current = false;
  }, []);

  useEffect(() => {
    forceScrollRef.current = true;
    pinnedToBottomRef.current = true;
  }, [activeId]);

  useLayoutEffect(() => {
    const el = scrollRef.current;
    if (!el) return;

    const clientHeight = el.clientHeight;
    const { top: prevTop, height: prevHeight } = scrollSnapshotRef.current;
    const wasPinnedToBottom =
      prevHeight > 0 && prevHeight - prevTop - clientHeight < 64 && pinnedToBottomRef.current;

    if (forceScrollRef.current || wasPinnedToBottom) {
      el.scrollTop = el.scrollHeight;
      forceScrollRef.current = false;
    }

    syncScrollSnapshot();
  }, [activeId, active?.messages.length, lastMessage?.text, syncScrollSnapshot]);

  const taRef = useRef<HTMLTextAreaElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  const newChat = () => {
    setActiveId(null);
    setDraftModelId(modelId);
    setDraftTarget(null);
    setDraft("");
    setSidebarOpen(false);
    taRef.current?.focus();
  };

  const pickSession = (id: string) => {
    setActiveId(id);
    setSidebarOpen(false);
  };

  const setModel = (id: string) => {
    if (active) {
      // Pinned machine may not serve the new model; unpin if so.
      const entry = models.find((m) => m.modelId === id);
      updateSession(active.id, (s) => ({
        ...s,
        modelId: id,
        targetProviderDid:
          s.targetProviderDid && entry?.machines.some((m) => m.did === s.targetProviderDid)
            ? s.targetProviderDid
            : null,
      }));
    } else {
      setDraftModelId(id);
      setDraftTarget(null);
    }
  };

  const setTarget = (didOrNull: string | null) => {
    if (active) {
      updateSession(active.id, (s) => ({ ...s, targetProviderDid: didOrNull }));
    } else {
      setDraftTarget(didOrNull);
    }
  };

  const setMaxTokens = (n: number) => {
    if (active) updateSession(active.id, (s) => ({ ...s, maxTokensOut: n }));
    else setDraftMaxTokens(n);
  };

  const stopStreaming = useCallback(() => {
    abortRef.current?.abort();
  }, []);

  const send = async () => {
    const text = draft.trim();
    if (!text || streamingId || !modelId || !did) return;
    setDraft("");
    forceScrollRef.current = true;
    pinnedToBottomRef.current = true;

    // Materialize the session on first send.
    let target = active;
    if (!target) {
      target = { ...createSession(modelId), targetProviderDid, maxTokensOut };
      setSessions((prev) => [target!, ...prev]);
      setActiveId(target.id);
    }
    const sessionId = target.id;
    const now = new Date().toISOString();
    const userMsg: ChatMessage = { id: newSessionId(), role: "user", text, createdAt: now };
    const assistantMsg: ChatMessage = {
      id: newSessionId(),
      role: "assistant",
      text: "",
      reasoning: "",
      modelId,
      createdAt: now,
    };
    const transcript = [...target.messages, userMsg].map((m) => ({ role: m.role, text: m.text }));

    updateSession(sessionId, (s) => ({
      ...s,
      title: s.messages.length === 0 ? titleFromText(text) : s.title,
      updatedAt: now,
      messages: [...s.messages, userMsg, assistantMsg],
    }));
    setStreamingId(assistantMsg.id);
    const abort = new AbortController();
    abortRef.current = abort;

    try {
      const result = await dispatchChatTurn({
        model: modelId,
        prompt: flattenTranscript(transcript),
        maxTokensOut,
        targetProviderDid,
        signal: abort.signal,
        onMeta: (meta) => {
          const entry = models.find((m) => m.modelId === modelId);
          const machine = entry?.machines.find((m) => m.did === meta.providerDid);
          patchMessage(sessionId, assistantMsg.id, (m) => ({
            ...m,
            providerDid: meta.providerDid,
            ...(machine ? { providerLabel: machineLabel(machine) } : {}),
          }));
        },
        onChunk: (chunk) => {
          patchMessage(sessionId, assistantMsg.id, (m) => ({ ...m, text: m.text + chunk }));
        },
        onReasoning: (chunk) => {
          patchMessage(sessionId, assistantMsg.id, (m) => ({
            ...m,
            reasoning: (m.reasoning ?? "") + chunk,
          }));
        },
      });
      patchMessage(sessionId, assistantMsg.id, (m) => ({
        ...m,
        meta: {
          tokensIn: result.tokensIn,
          tokensOut: result.tokensOut,
          durationMs: result.durationMs,
          receiptUri: result.receiptUri,
        },
      }));
      updateSession(sessionId, (s) => ({
        ...s,
        spentTokens: s.spentTokens + result.tokensIn + result.tokensOut,
        updatedAt: new Date().toISOString(),
      }));
      void queryClient.invalidateQueries({ queryKey: getMyBalanceQueryOptions.queryKey });
    } catch (e) {
      if (e instanceof DOMException && e.name === "AbortError") return;
      const isDispatch = e instanceof ChatDispatchError;
      patchMessage(sessionId, assistantMsg.id, (m) => ({
        ...m,
        errorCode: isDispatch ? e.code : "unknown",
        errorReason: e instanceof Error ? e.message : String(e),
      }));
    } finally {
      abortRef.current = null;
      setStreamingId(null);
    }
  };

  const onComposerKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void send();
    }
  };

  const visible = sessions.filter(
    (s) => s.messages.length > 0 && (!query || s.title.toLowerCase().includes(query.toLowerCase())),
  );
  const spentTotal = sessions.reduce((sum, s) => sum + s.spentTokens, 0);

  const selectedModel = models.find((m) => m.modelId === modelId) ?? null;
  const targetMachine = targetProviderDid
    ? (selectedModel?.machines.find((m) => m.did === targetProviderDid) ?? null)
    : null;
  const messages = active?.messages ?? [];

  // Rough context estimate, mirroring the receipts where we have
  // them and ~4 chars/token where we don't.
  const ctxUsed = messages.reduce(
    (sum, m) => sum + (m.meta ? m.meta.tokensOut : Math.round(m.text.length / 4)),
    0,
  );

  const noModels = hydrated && models.length === 0;

  return (
    <Page.Root variant="large" style={styles.root}>
      <Page.Header style={styles.header}>
        <Flex direction="column" gap="xl">
          <Heading1 style={styles.headingMono}>
            <span {...stylex.props(styles.titlePrompt)}>~/</span>chat
          </Heading1>
          <div {...stylex.props(styles.metaRow)}>
            <span>run chats on other people&rsquo;s machines</span>
            <span {...stylex.props(styles.metaSep)}>·</span>
            <span>
              <span {...stylex.props(styles.emphasis)}>{models.length}</span> model
              {models.length === 1 ? "" : "s"} live
            </span>
            <span {...stylex.props(styles.metaSep)}>·</span>
            <span>uniform pricing · billed per token</span>
          </div>
        </Flex>
      </Page.Header>

      <div {...stylex.props(styles.shell)}>
        <aside {...stylex.props(styles.side)}>
          <ChatSessionsPanel
            visible={visible}
            activeId={activeId}
            query={query}
            hydrated={hydrated}
            spentTotal={spentTotal}
            balance={balance?.balance}
            onQueryChange={setQuery}
            onSelectSession={pickSession}
            onNewChat={newChat}
          />
        </aside>

        <section {...stylex.props(styles.main)}>
          <div {...stylex.props(styles.chatHead)}>
            <div {...stylex.props(styles.chatHeadTop)}>
              <div {...stylex.props(styles.chatHeadMain)}>
                <div {...stylex.props(styles.chatHeadTitle)}>{active?.title ?? "new session"}</div>
                <div {...stylex.props(styles.chatHeadSub)}>
                  {messages.length} message{messages.length === 1 ? "" : "s"}
                  {active ? ` · started ${fmtClock(active.createdAt)}` : ""}
                </div>
              </div>
              <div {...stylex.props(styles.mobileDrawerWrap)}>
                <Drawer
                  direction="left"
                  isOpen={sidebarOpen}
                  onOpenChange={setSidebarOpen}
                  size="sm"
                  trigger={
                    <Button variant="outline" size="sm" style={styles.mobileSessionsBtn}>
                      sessions
                      {visible.length > 0 ? ` · ${visible.length}` : ""}
                    </Button>
                  }
                >
                  <DrawerHeader>sessions</DrawerHeader>
                  <DrawerBody style={styles.drawerBody}>
                    <div {...stylex.props(styles.sideInDrawer)}>
                      <ChatSessionsPanel
                        visible={visible}
                        activeId={activeId}
                        query={query}
                        hydrated={hydrated}
                        spentTotal={spentTotal}
                        balance={balance?.balance}
                        onQueryChange={setQuery}
                        onSelectSession={pickSession}
                        onNewChat={newChat}
                      />
                    </div>
                  </DrawerBody>
                </Drawer>
              </div>
            </div>
            <div {...stylex.props(styles.sessionStrip)}>
              <span {...stylex.props(styles.hostChip)}>
                <span {...stylex.props(styles.liveDot)} />
                {targetMachine ? machineLabel(targetMachine) : "auto"}
                <span {...stylex.props(styles.stripLabel)}>
                  {targetMachine
                    ? "pinned"
                    : `${selectedModel?.machineCount ?? 0} machine${
                        (selectedModel?.machineCount ?? 0) === 1 ? "" : "s"
                      }`}
                </span>
              </span>
              <span {...stylex.props(styles.stripItem)}>
                <span {...stylex.props(styles.stripLabel)}>ctx</span>
                <span {...stylex.props(styles.emphasis)}>
                  {fmtTok(ctxUsed)} / {fmtTok(maxTokensOut)}
                </span>
              </span>
              <span {...stylex.props(styles.stripItem)}>
                <span {...stylex.props(styles.stripLabel)}>session</span>
                <span {...stylex.props(styles.emphasis)}>
                  {formatTokensCompact(active?.spentTokens ?? 0)} tok
                </span>
              </span>
            </div>
          </div>

          {messages.length === 0 ? (
            <div {...stylex.props(styles.empty)}>
              <img
                src="/goobies/sloth.png"
                alt=""
                aria-hidden
                {...stylex.props(styles.emptyGoober)}
              />
              <div {...stylex.props(styles.emptyGlyph)}>▸_</div>
              {noModels ? (
                <>
                  <h2 {...stylex.props(styles.emptyTitle)}>
                    {directory?.appviewUnreachable ? "directory unreachable" : "no models online"}
                  </h2>
                  <p {...stylex.props(styles.emptyText)}>
                    {directory?.appviewUnreachable
                      ? "the model directory didn't answer — the network may be mid-deploy. refresh in a minute."
                      : "no machine is serving a model right now. start one of your own machines, or browse the directory to see what usually runs here."}
                  </p>
                  <div {...stylex.props(styles.emptyCtas)}>
                    <ButtonLink to="/machines" variant="primary" size="sm">
                      start a machine
                    </ButtonLink>
                    <ButtonLink to="/models" variant="outline" size="sm">
                      browse models
                    </ButtonLink>
                  </div>
                </>
              ) : (
                <>
                  <h2 {...stylex.props(styles.emptyTitle)}>
                    {targetMachine ? (
                      machineLabel(targetMachine)
                    ) : (
                      <>
                        {modelId ?? "…"}
                        <span {...stylex.props(styles.emptyTitleFaint)}>
                          {" "}
                          · {selectedModel?.machineCount ?? 0} machine
                          {(selectedModel?.machineCount ?? 0) === 1 ? "" : "s"} live
                        </span>
                      </>
                    )}
                  </h2>
                  <p {...stylex.props(styles.emptyText)}>
                    billed per generated token from your balance — nothing is metered while you
                    type. your transcript stays in this browser; the network only sees sealed
                    prompts and signed receipts.
                  </p>
                  <div {...stylex.props(styles.sugg)}>
                    {CHAT_SUGGESTIONS.map((s) => (
                      <button
                        key={s}
                        type="button"
                        {...stylex.props(styles.suggBtn)}
                        onClick={() => {
                          setDraft(s);
                          taRef.current?.focus();
                        }}
                      >
                        {s}
                      </button>
                    ))}
                  </div>
                </>
              )}
            </div>
          ) : (
            <div
              {...stylex.props(styles.scroll)}
              ref={scrollRef}
              onScroll={onTranscriptScroll}
              onWheel={onTranscriptWheel}
            >
              <div {...stylex.props(styles.msgCol)}>
                {messages.map((m) =>
                  m.role === "user" ? (
                    <div key={m.id} {...stylex.props(styles.msgUser)}>
                      {m.text}
                    </div>
                  ) : (
                    (() => {
                      const streaming = m.id === streamingId;
                      // "Thinking" is active only while reasoning is arriving and
                      // the answer hasn't started; once content begins the caret
                      // (and the disclosure) move to the answer.
                      const thinkingActive = streaming && !!m.reasoning && !m.text;
                      const answerActive = streaming && !thinkingActive;
                      return (
                        <div key={m.id} {...stylex.props(styles.msgAssistant)}>
                          <div {...stylex.props(styles.msgGutter)}>
                            <span {...stylex.props(styles.msgGutterModel)}>
                              {m.modelId ?? modelId}
                            </span>
                            {m.providerLabel || m.providerDid ? (
                              <>
                                <span {...stylex.props(styles.metaSep)}>·</span>
                                <span>{m.providerLabel ?? shortDid(m.providerDid ?? "")}</span>
                              </>
                            ) : null}
                          </div>
                          <div {...stylex.props(styles.msgBody)}>
                            {m.reasoning ? (
                              <ThinkingDisclosure reasoning={m.reasoning} active={thinkingActive} />
                            ) : null}
                            <ChatMarkdown streaming={answerActive} text={m.text} />
                          </div>
                          {m.meta ? (
                            <div {...stylex.props(styles.msgMeta)}>
                              <span>
                                −
                                <span {...stylex.props(styles.emphasis)}>
                                  {m.meta.tokensIn + m.meta.tokensOut}
                                </span>{" "}
                                tok
                              </span>
                              {m.meta.durationMs > 0 ? (
                                <span>
                                  <span {...stylex.props(styles.emphasis)}>
                                    {Math.round((m.meta.tokensOut / m.meta.durationMs) * 1000)}
                                  </span>{" "}
                                  tok/s
                                </span>
                              ) : null}
                              <span>{(m.meta.durationMs / 1000).toFixed(1)}s</span>
                            </div>
                          ) : null}
                          {m.errorReason ? (
                            <div {...stylex.props(styles.msgError)}>
                              failed ({m.errorCode}): {m.errorReason}
                            </div>
                          ) : null}
                        </div>
                      );
                    })()
                  ),
                )}
              </div>
            </div>
          )}

          <div {...stylex.props(styles.composer)}>
            <div {...stylex.props(styles.composerBox)}>
              <textarea
                ref={taRef}
                rows={2}
                value={draft}
                placeholder={
                  modelId
                    ? `message ${modelId}${targetMachine ? ` on ${machineLabel(targetMachine)}` : ""}…`
                    : "no models online — nothing to message"
                }
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={onComposerKeyDown}
                {...stylex.props(styles.textarea)}
              />
              <div {...stylex.props(styles.composerBar)}>
                <div {...stylex.props(styles.modelPickerWrap)}>
                  <ModelPicker
                    models={models}
                    modelId={modelId}
                    targetProviderDid={targetProviderDid}
                    maxTokensOut={maxTokensOut}
                    onModel={setModel}
                    onTarget={setTarget}
                    onMaxTokens={setMaxTokens}
                  />
                </div>
                <span {...stylex.props(styles.rateNote)}>
                  {balance ? `${formatTokensCompact(balance.balance)} tok left · ` : ""}
                  billed per generated token
                </span>
                {streamingId ? (
                  <Button
                    variant="critical"
                    size="sm"
                    style={styles.composerSend}
                    onPress={stopStreaming}
                  >
                    <Square size={12} fill="currentColor" aria-hidden />
                    stop
                  </Button>
                ) : (
                  <Button
                    variant="primary"
                    size="sm"
                    style={styles.composerSend}
                    isDisabled={!draft.trim() || !modelId}
                    onPress={() => void send()}
                  >
                    send <Kbd>⏎</Kbd>
                  </Button>
                )}
              </div>
            </div>
          </div>
        </section>
      </div>
    </Page.Root>
  );
}
