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
import { ImagePlus, SlidersHorizontal, Square, X } from "lucide-react";
import type { ReactElement } from "react";

import { getMyBalanceQueryOptions } from "@/components/account/token-balance.functions.ts";
import {
  type ChatDispatchImage,
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
import { chatImageDataUrl, loadChatImages, saveChatImages } from "@/components/chat/chat-images.ts";
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
import { Switch } from "@/design-system/switch";
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

/** A staged image in the composer, before send. `data` is the base64 of the
 *  raw bytes (no data: prefix) — sent to the provider; `url` is the full data
 *  URI used only for the thumbnail preview. */
interface PendingImage {
  id: string;
  mime: string;
  data: string;
  url: string;
}

// Composer image limits. The provider/advisor cap inline image bytes at
// ~20-32 MiB total; keep the chat composer well under that and bounded.
const MAX_CHAT_IMAGES = 6;
const MAX_CHAT_IMAGE_BYTES = 10 * 1024 * 1024; // per image, decoded

/** Read an image File into a PendingImage (base64 + preview data URI), or
 *  null if it isn't an image or is too large. */
async function readImageFile(file: File): Promise<PendingImage | null> {
  if (!file.type.startsWith("image/")) return null;
  if (file.size > MAX_CHAT_IMAGE_BYTES) return null;
  const buf = new Uint8Array(await file.arrayBuffer());
  let bin = "";
  for (const b of buf) bin += String.fromCharCode(b);
  const data = btoa(bin);
  return {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    mime: file.type,
    data,
    url: `data:${file.type};base64,${data}`,
  };
}

const CHAT_SUGGESTIONS = [
  "explain this rust lifetime error",
  "summarize my protocol notes",
  "draft release notes from a diff",
];

// Coarse region routing. `null` means "Any" — don't pin a region; otherwise
// the ISO 3166-1 alpha-2 code is forwarded to the dispatch, which routes only
// to providers advertising that region. A short curated list keeps the picker
// scannable; the wire still accepts any valid code.
interface CountryOption {
  code: string | null;
  label: string;
}
const COUNTRY_CHOICES: CountryOption[] = [
  { code: null, label: "Any" },
  { code: "US", label: "United States" },
  { code: "CA", label: "Canada" },
  { code: "GB", label: "United Kingdom" },
  { code: "DE", label: "Germany" },
  { code: "FR", label: "France" },
  { code: "NL", label: "Netherlands" },
  { code: "JP", label: "Japan" },
  { code: "AU", label: "Australia" },
  { code: "IN", label: "India" },
  { code: "BR", label: "Brazil" },
  { code: "SG", label: "Singapore" },
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
    cornerShape: "squircle",
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
    cornerShape: "squircle",
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
    position: "relative",
  },
  dropOverlay: {
    alignItems: "center",
    backgroundColor: uiColor.bgSubtle,
    borderColor: uiColor.text2,
    borderRadius: radius.md,
    cornerShape: "squircle",
    borderStyle: "dashed",
    borderWidth: 2,
    bottom: verticalSpace.md,
    color: uiColor.text2,
    display: "flex",
    flexDirection: "column",
    fontSize: fontSize.sm,
    gap: gap.sm,
    justifyContent: "center",
    left: horizontalSpace.md,
    opacity: 0.96,
    pointerEvents: "none",
    position: "absolute",
    right: horizontalSpace.md,
    top: verticalSpace.md,
    zIndex: 20,
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
    cornerShape: "squircle",
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
  // One user turn: image attachments stacked ABOVE the text bubble, the
  // whole group right-aligned (iMessage style).
  userTurn: {
    alignItems: "flex-end",
    alignSelf: "flex-end",
    display: "flex",
    flexDirection: "column",
    gap: verticalSpace.sm,
    maxWidth: "78%",
    minWidth: 0,
  },
  msgUser: {
    alignSelf: "flex-end",
    backgroundColor: uiColor.bgSubtle,
    borderBottomLeftRadius: radius.md,
    borderBottomRightRadius: radius.xs,
    borderColor: uiColor.border1,
    borderStyle: "solid",
    borderTopLeftRadius: radius.md,
    borderTopRightRadius: radius.md,
    borderWidth: 1,
    cornerShape: "squircle",
    fontFamily: fontFamily.sans,
    fontSize: fontSize.sm,
    lineHeight: 1.55,
    maxWidth: "100%",
    overflowWrap: "break-word",
    paddingBottom: verticalSpace.md,
    paddingLeft: horizontalSpace.lg,
    paddingRight: horizontalSpace.lg,
    paddingTop: verticalSpace.md,
    whiteSpace: "pre-wrap",
  },
  bubbleImageRow: {
    display: "flex",
    flexWrap: "wrap",
    gap: gap.sm,
    justifyContent: "flex-end",
  },
  bubbleImage: {
    borderColor: uiColor.border2,
    borderRadius: radius.md,
    cornerShape: "squircle",
    borderStyle: "solid",
    borderWidth: 1,
    height: "160px",
    maxWidth: "100%",
    objectFit: "cover",
    width: "auto",
  },
  bubbleImageMissing: {
    alignItems: "center",
    color: uiColor.text1,
    display: "flex",
    fontSize: MICRO,
    gap: gap.xs,
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
    cornerShape: "squircle",
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
  imageRow: {
    display: "flex",
    flexWrap: "wrap",
    gap: gap.sm,
    marginBottom: verticalSpace.sm,
  },
  imageThumb: {
    borderColor: uiColor.border2,
    borderRadius: radius.sm,
    cornerShape: "squircle",
    borderStyle: "solid",
    borderWidth: 1,
    height: "48px",
    overflow: "visible",
    position: "relative",
    width: "48px",
  },
  imageThumbImg: {
    borderRadius: radius.sm,
    cornerShape: "squircle",
    display: "block",
    height: "100%",
    objectFit: "cover",
    width: "100%",
  },
  imageThumbRemove: {
    alignItems: "center",
    backgroundColor: uiColor.text2,
    borderRadius: "9999px",
    borderWidth: 0,
    color: uiColor.bg,
    cursor: "pointer",
    display: "flex",
    height: "16px",
    justifyContent: "center",
    padding: 0,
    position: "absolute",
    right: "-6px",
    top: "-6px",
    width: "16px",
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
    cornerShape: "squircle",
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
  advBtn: {
    alignItems: "center",
    appearance: "none",
    backgroundColor: { default: uiColor.bgSubtle, ":hover": uiColor.bg },
    borderColor: { default: uiColor.border1, ":hover": uiColor.border2 },
    borderRadius: radius.xs,
    cornerShape: "squircle",
    borderStyle: "solid",
    borderWidth: 1,
    boxSizing: "border-box",
    color: uiColor.text2,
    cursor: "pointer",
    display: "flex",
    flexShrink: 0,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.xs,
    gap: gap.sm,
    paddingBottom: "4px",
    paddingLeft: horizontalSpace.md,
    paddingRight: horizontalSpace.md,
    paddingTop: "4px",
    whiteSpace: "nowrap",
  },
  advBtnActive: {
    borderColor: uiColor.text2,
    color: uiColor.text2,
  },
  advCount: {
    color: uiColor.text1,
    fontVariantNumeric: "tabular-nums",
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
    cornerShape: "squircle",
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
  advPop: {
    display: "flex",
    flexDirection: "column",
    gap: verticalSpace.md,
    width: "min(360px, calc(100vw - 48px))",
  },
  countryGrid: {
    display: "flex",
    flexWrap: "wrap",
    gap: gap.sm,
  },
  proBonoRow: {
    alignItems: "flex-start",
    display: "flex",
    gap: gap.lg,
    justifyContent: "space-between",
  },
  proBonoText: {
    display: "flex",
    flexDirection: "column",
    gap: gap.xs,
    minWidth: 0,
  },
  proBonoTitle: {
    color: uiColor.text2,
    fontSize: fontSize.xs,
    fontWeight: fontWeight.semibold,
  },
  proBonoHint: {
    color: uiColor.text1,
    fontSize: MICRO,
    lineHeight: 1.5,
  },
});

interface MachineOption {
  did: string;
  /** Matches the advisor machineId (provider-record rkey). Null only for
   *  legacy agents that predate the field; always present in practice. */
  machineId: string | null;
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

/** Render the image part of a user turn: thumbnails when the bytes are
 *  available (just-sent or rehydrated from IndexedDB), otherwise a "had
 *  image" indicator — while loading (undefined) it reads as the same neutral
 *  chip, and once we know the bytes are gone ("lost") it says so. */
function renderUserImages(
  msgId: string,
  count: number,
  state: string[] | "lost" | undefined,
): ReactElement {
  if (Array.isArray(state)) {
    return (
      <div {...stylex.props(styles.bubbleImageRow)}>
        {state.map((url, i) => (
          <img key={`${msgId}-${i}`} src={url} alt="" {...stylex.props(styles.bubbleImage)} />
        ))}
      </div>
    );
  }
  const label = count === 1 ? "1 image" : `${count} images`;
  return (
    <div {...stylex.props(styles.bubbleImageMissing)}>
      <ImagePlus size={12} aria-hidden />
      <span>{state === "lost" ? `${label} · no longer cached` : label}</span>
    </div>
  );
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

/** Friendlier copy for the advanced-routing dispatch errors. Falls back to
 *  the server-supplied reason for everything else (including the country-miss
 *  codes, whose server message already reads well). */
function friendlyDispatchReason(code: string, reason: string): string {
  switch (code) {
    case "no-pro-bono-providers":
    case "no_pro_bono_providers":
      return "No machine is offering you free compute right now.";
    case "no-providers-for-country":
    case "no_providers_for_country":
      return reason || "No machine is serving that region right now.";
    default:
      return reason;
  }
}

function ModelPicker({
  models,
  modelId,
  targetProviderDid,
  targetMachineId,
  maxTokensOut,
  onModel,
  onTarget,
  onMaxTokens,
}: {
  models: ModelDirectoryEntry[];
  modelId: string | null;
  targetProviderDid: string | null;
  targetMachineId: string | null;
  maxTokensOut: number;
  onModel: (id: string) => void;
  onTarget: (did: string | null, machineId: string | null) => void;
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
    machineId: m.machineId ?? null,
    label: machineLabel(m),
    detail:
      [m.chip, m.ramGB != null ? `${m.ramGB}gb ram` : null].filter(Boolean).join(" · ") || null,
  }));
  // Match on both DID and machineId when available so two machines under the
  // same owner DID don't both light up as "selected".
  const isPinnedTo = (m: MachineOption) =>
    m.did === targetProviderDid &&
    (targetMachineId == null || m.machineId == null || m.machineId === targetMachineId);
  const targetLabel = targetProviderDid
    ? (machines.find(isPinnedTo)?.label ?? shortDid(targetProviderDid))
    : "auto";

  const pickModel = (id: string) => {
    onModel(id);
    setOpen(false);
  };
  const pickTarget = (did: string | null, machineId: string | null) => {
    onTarget(did, machineId);
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
            onClick={() => pickTarget(null, null)}
          >
            <span {...stylex.props(styles.popOptRow)}>
              <span {...stylex.props(styles.popOptName)}>auto</span>
              <span {...stylex.props(styles.popOptSub)}>advisor picks</span>
            </span>
            <span {...stylex.props(styles.popOptSub)}>freshest attested machine for the model</span>
          </button>
          {machines.map((m) => (
            <button
              key={m.machineId ?? m.did}
              type="button"
              {...stylex.props(styles.popOpt, isPinnedTo(m) && styles.popOptSelected)}
              onClick={() => pickTarget(m.did, m.machineId)}
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

/** Advanced routing options tucked behind a "advanced" chip in the composer
 *  toolbar: coarse region routing (ISO 3166-1 alpha-2, "Any" = unpinned) and
 *  a pro-bono toggle that routes only to providers serving this user for
 *  free. Both are advisory hints forwarded to the dispatch. */
function AdvancedOptions({
  country,
  proBono,
  onCountry,
  onProBono,
}: {
  country: string | null;
  proBono: boolean;
  onCountry: (code: string | null) => void;
  onProBono: (on: boolean) => void;
}): ReactElement {
  const [open, setOpen] = useState(false);
  const activeCount = (country ? 1 : 0) + (proBono ? 1 : 0);
  return (
    <Popover
      isOpen={open}
      onOpenChange={setOpen}
      placement="top end"
      trigger={
        <AriaButton {...stylex.props(styles.advBtn, activeCount > 0 && styles.advBtnActive)}>
          <SlidersHorizontal size={12} aria-hidden />
          advanced
          {activeCount > 0 ? <span {...stylex.props(styles.advCount)}>· {activeCount}</span> : null}
        </AriaButton>
      }
      style={styles.advPop}
    >
      <div {...stylex.props(styles.popSectHead)}>
        <span>route to</span>
        <span {...stylex.props(styles.popSectHint)}>coarse region — advisory</span>
      </div>
      <div {...stylex.props(styles.countryGrid)}>
        {COUNTRY_CHOICES.map((c) => (
          <Button
            key={c.code ?? "any"}
            size="sm"
            variant={country === c.code ? "primary" : "outline"}
            onPress={() => onCountry(c.code)}
            // Compact 2-letter code is shown; the full country name is the
            // accessible label (screen readers + hover) so "US" isn't opaque.
            aria-label={c.label}
          >
            {c.code ?? "Any"}
          </Button>
        ))}
      </div>

      <div {...stylex.props(styles.popSectHead)}>
        <span>pro bono</span>
        <span {...stylex.props(styles.popSectHint)}>free compute only</span>
      </div>
      <div {...stylex.props(styles.proBonoRow)}>
        <span {...stylex.props(styles.proBonoText)}>
          <span {...stylex.props(styles.proBonoTitle)}>request pro-bono (free) compute</span>
          <span {...stylex.props(styles.proBonoHint)}>
            routes only to machines whose pro-bono policy serves you for free.
          </span>
        </span>
        <Switch
          aria-label="request pro-bono (free) compute"
          isSelected={proBono}
          onChange={onProBono}
        />
      </div>
    </Popover>
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
  // Images staged in the composer (drag-drop or paste), sent with the next
  // turn then cleared. Kept out of the persisted session store (base64 would
  // blow the localStorage quota).
  const [pendingImages, setPendingImages] = useState<PendingImage[]>([]);
  // True while a file is dragged over the chat area (drives the drop overlay).
  const [dragActive, setDragActive] = useState(false);
  // Rendered thumbnails for sent user turns, keyed by message id. An array of
  // data URLs when the bytes are available (just-sent or rehydrated from
  // IndexedDB), or "lost" when a turn had images (`imageCount`) but the cache
  // no longer holds them — then we show a "had image" indicator.
  const [msgImages, setMsgImages] = useState<Record<string, string[] | "lost">>({});
  const [streamingId, setStreamingId] = useState<string | null>(null);

  // Advanced routing options, kept at page scope: a coarse region (ISO
  // 3166-1 alpha-2, null = "Any") and a pro-bono toggle. They apply to every
  // turn in this page session and reset on reload (intentionally not
  // persisted — they're per-sitting routing hints, not session content).
  const [country, setCountry] = useState<string | null>(null);
  const [proBono, setProBono] = useState(false);

  // Settings for the not-yet-created session shown by "new chat".
  const [draftModelId, setDraftModelId] = useState<string | null>(null);
  const [draftTarget, setDraftTarget] = useState<string | null>(null);
  const [draftTargetMachineId, setDraftTargetMachineId] = useState<string | null>(null);
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
  const targetMachineId = active ? (active.targetMachineId ?? null) : draftTargetMachineId;
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
    setDraftTargetMachineId(null);
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
      // Match on both DID and machineId — two machines under the same owner
      // DID each serve distinct model sets, so clearing the pin must be
      // per-machine, not per-owner.
      const entry = models.find((m) => m.modelId === id);
      const stillValid =
        !!active.targetProviderDid &&
        entry?.machines.some(
          (m) =>
            m.did === active.targetProviderDid &&
            (active.targetMachineId == null ||
              m.machineId == null ||
              m.machineId === active.targetMachineId),
        );
      updateSession(active.id, (s) => ({
        ...s,
        modelId: id,
        targetProviderDid: stillValid ? s.targetProviderDid : null,
        targetMachineId: stillValid ? s.targetMachineId : null,
      }));
    } else {
      setDraftModelId(id);
      setDraftTarget(null);
      setDraftTargetMachineId(null);
    }
  };

  const setTarget = (didOrNull: string | null, machineIdOrNull: string | null) => {
    if (active) {
      updateSession(active.id, (s) => ({
        ...s,
        targetProviderDid: didOrNull,
        targetMachineId: machineIdOrNull,
      }));
    } else {
      setDraftTarget(didOrNull);
      setDraftTargetMachineId(machineIdOrNull);
    }
  };

  const setMaxTokens = (n: number) => {
    if (active) updateSession(active.id, (s) => ({ ...s, maxTokensOut: n }));
    else setDraftMaxTokens(n);
  };

  const stopStreaming = useCallback(() => {
    abortRef.current?.abort();
  }, []);

  /** Stage image files in the composer, capping the total count. Silently
   *  skips non-images and oversized files. */
  const addImageFiles = useCallback(async (files: Iterable<File>) => {
    const read = await Promise.all([...files].map(readImageFile));
    const ok = read.filter((r): r is PendingImage => r !== null);
    if (ok.length === 0) return;
    setPendingImages((prev) => [...prev, ...ok].slice(0, MAX_CHAT_IMAGES));
  }, []);

  const removePendingImage = useCallback((id: string) => {
    setPendingImages((prev) => prev.filter((p) => p.id !== id));
  }, []);

  const onChatDragOver = useCallback((e: React.DragEvent) => {
    if (!Array.from(e.dataTransfer.types).includes("Files")) return;
    e.preventDefault();
    setDragActive(true);
  }, []);

  const onChatDragLeave = useCallback((e: React.DragEvent) => {
    // Only clear when the cursor actually leaves the drop region, not when it
    // crosses into a child element.
    if (e.currentTarget === e.target) setDragActive(false);
  }, []);

  const onChatDrop = useCallback(
    (e: React.DragEvent) => {
      const files = e.dataTransfer.files;
      if (!files || files.length === 0) return;
      e.preventDefault();
      setDragActive(false);
      void addImageFiles(files);
    },
    [addImageFiles],
  );

  const onComposerPaste = useCallback(
    (e: React.ClipboardEvent) => {
      const files = [...e.clipboardData.items]
        .filter((it) => it.kind === "file")
        .map((it) => it.getAsFile())
        .filter((f): f is File => f !== null && f.type.startsWith("image/"));
      if (files.length > 0) {
        e.preventDefault();
        void addImageFiles(files);
      }
    },
    [addImageFiles],
  );

  const send = async () => {
    const text = draft.trim();
    // A turn is sendable with text OR images (an image-only "what is this?"
    // is valid). Snapshot + clear the staged images up front.
    const turnImages: ChatDispatchImage[] = pendingImages.map((p) => ({
      mime: p.mime,
      data: p.data,
    }));
    if ((!text && turnImages.length === 0) || streamingId || !modelId || !did) return;
    setDraft("");
    setPendingImages([]);
    forceScrollRef.current = true;
    pinnedToBottomRef.current = true;

    // Materialize the session on first send.
    let target = active;
    if (!target) {
      target = { ...createSession(modelId), targetProviderDid, targetMachineId, maxTokensOut };
      setSessions((prev) => [target!, ...prev]);
      setActiveId(target.id);
    }
    const sessionId = target.id;
    const now = new Date().toISOString();
    const userMsg: ChatMessage = {
      id: newSessionId(),
      role: "user",
      // For an image-only turn keep a short marker so the bubble + title
      // aren't blank when no thumbnail is available.
      text: text || (turnImages.length === 1 ? "(image)" : `(${turnImages.length} images)`),
      ...(turnImages.length > 0 ? { imageCount: turnImages.length } : {}),
      createdAt: now,
    };
    if (turnImages.length > 0) {
      // Show the just-sent thumbnails immediately (reuse the composer's data
      // URLs), and cache the bytes in IndexedDB so they survive a reload.
      setMsgImages((prev) => ({ ...prev, [userMsg.id]: pendingImages.map((p) => p.url) }));
      if (chatStorageKey) {
        void saveChatImages(did, userMsg.id, turnImages, chatStorageKey);
      }
    }
    const assistantMsg: ChatMessage = {
      id: newSessionId(),
      role: "assistant",
      text: "",
      reasoning: "",
      modelId,
      createdAt: now,
    };
    // Transcript carries the REAL input text (empty for an image-only turn),
    // not the display marker, so the sealed envelope/prompt is faithful.
    const transcript = [
      ...target.messages.map((m) => ({ role: m.role, text: m.text })),
      { role: "user", text },
    ];

    updateSession(sessionId, (s) => ({
      ...s,
      title: s.messages.length === 0 ? titleFromText(userMsg.text) : s.title,
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
        ...(turnImages.length > 0 ? { transcript, images: turnImages } : {}),
        maxTokensOut,
        targetProviderDid,
        targetMachineId,
        // null country = "Any" (the dispatch treats null/absent as unpinned);
        // proBono only forwarded when on.
        country,
        ...(proBono ? { proBono: true } : {}),
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
      const rawReason = e instanceof Error ? e.message : String(e);
      patchMessage(sessionId, assistantMsg.id, (m) => ({
        ...m,
        errorCode: isDispatch ? e.code : "unknown",
        errorReason: isDispatch ? friendlyDispatchReason(e.code, rawReason) : rawReason,
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
    ? (selectedModel?.machines.find(
        (m) =>
          m.did === targetProviderDid &&
          (targetMachineId == null || m.machineId == null || m.machineId === targetMachineId),
      ) ?? null)
    : null;
  const messages = active?.messages ?? [];

  // Stable signature of the user turns that carry images, so the rehydrate
  // effect re-runs only when that set changes (not on every render).
  const imageTurnIds = messages
    .filter((m) => m.role === "user" && m.imageCount)
    .map((m) => m.id)
    .join(",");

  // Rehydrate thumbnails for the visible session's image turns from
  // IndexedDB. Skips turns already resolved (just-sent, or a prior load). A
  // turn whose bytes are gone is marked "lost" so the bubble shows a "had
  // image" indicator. The setMsgImages updater double-guards against races.
  useEffect(() => {
    if (did === "anon" || !chatStorageKey || !imageTurnIds) return;
    let cancelled = false;
    for (const id of imageTurnIds.split(",")) {
      void loadChatImages(did, id, chatStorageKey).then((imgs) => {
        if (cancelled) return;
        setMsgImages((prev) =>
          prev[id] !== undefined
            ? prev
            : { ...prev, [id]: imgs && imgs.length > 0 ? imgs.map(chatImageDataUrl) : "lost" },
        );
      });
    }
    return () => {
      cancelled = true;
    };
  }, [imageTurnIds, did, chatStorageKey]);

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

        <section
          {...stylex.props(styles.main)}
          onDragOver={onChatDragOver}
          onDragLeave={onChatDragLeave}
          onDrop={onChatDrop}
        >
          {dragActive ? (
            <div {...stylex.props(styles.dropOverlay)}>
              <ImagePlus size={28} aria-hidden />
              <span>drop images to attach</span>
            </div>
          ) : null}
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
              {country ? (
                <span {...stylex.props(styles.hostChip)}>
                  <span {...stylex.props(styles.stripLabel)}>region</span>
                  {country}
                </span>
              ) : null}
              {proBono ? <span {...stylex.props(styles.hostChip)}>pro bono</span> : null}
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
                    <div key={m.id} {...stylex.props(styles.userTurn)}>
                      {m.imageCount ? renderUserImages(m.id, m.imageCount, msgImages[m.id]) : null}
                      <div {...stylex.props(styles.msgUser)}>{m.text}</div>
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
              {pendingImages.length > 0 ? (
                <div {...stylex.props(styles.imageRow)}>
                  {pendingImages.map((img) => (
                    <div key={img.id} {...stylex.props(styles.imageThumb)}>
                      <img src={img.url} alt="" {...stylex.props(styles.imageThumbImg)} />
                      <AriaButton
                        aria-label="remove image"
                        onPress={() => removePendingImage(img.id)}
                        {...stylex.props(styles.imageThumbRemove)}
                      >
                        <X size={11} aria-hidden />
                      </AriaButton>
                    </div>
                  ))}
                </div>
              ) : null}
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
                onPaste={onComposerPaste}
                {...stylex.props(styles.textarea)}
              />
              <div {...stylex.props(styles.composerBar)}>
                <div {...stylex.props(styles.modelPickerWrap)}>
                  <ModelPicker
                    models={models}
                    modelId={modelId}
                    targetProviderDid={targetProviderDid}
                    targetMachineId={targetMachineId}
                    maxTokensOut={maxTokensOut}
                    onModel={setModel}
                    onTarget={setTarget}
                    onMaxTokens={setMaxTokens}
                  />
                </div>
                <AdvancedOptions
                  country={country}
                  proBono={proBono}
                  onCountry={setCountry}
                  onProBono={setProBono}
                />
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
                    isDisabled={(!draft.trim() && pendingImages.length === 0) || !modelId}
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
