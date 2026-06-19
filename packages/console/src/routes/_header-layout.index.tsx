// Marketing page for "/". Public, layout-wrapped so visitors get the
// same nav and footer as the rest of the site. Logged-in users still land
// here; the navbar links them straight back into /machines.

import * as stylex from "@stylexjs/stylex";
import { createFileRoute, createLink, Link } from "@tanstack/react-router";

import { HeroGooberFloat } from "@/components/marketing/HeroGooberFloat.tsx";
import { Goober } from "@/components/Goober.tsx";
import {
  loadMarketingSnapshotServerFn,
  type MarketingSnapshot,
} from "@/lib/marketing-snapshot.functions.ts";
import { formatLatencyMs } from "@/lib/latency-display.ts";
import { SITE_MARKETING_DESCRIPTION, SITE_MARKETING_TITLE } from "@/lib/site-marketing.shared.ts";
import { Button } from "@/design-system/button";
import { Flex } from "@/design-system/flex";
import { Page } from "@/design-system/page";
import { primaryColor, successColor, uiColor } from "@/design-system/theme/color.stylex";
import { breakpoints } from "@/design-system/theme/media-queries.stylex";
import { radius } from "@/design-system/theme/radius.stylex";
import { ui } from "@/design-system/theme/semantic-color.stylex";
import {
  gap,
  horizontalSpace,
  size as sizeSpace,
  verticalSpace,
} from "@/design-system/theme/semantic-spacing.stylex";
import {
  fontFamily,
  fontSize,
  fontWeight,
  tracking,
} from "@/design-system/theme/typography.stylex";
import { Body, Heading2, Heading3, InlineCode } from "@/design-system/typography";

const ButtonLink = createLink(Button);

const styles = stylex.create({
  // ── Root ───────────────────────────────────────────────────
  root: {
    maxWidth: 1200,
    marginLeft: "auto",
    marginRight: "auto",
    paddingBottom: {
      default: verticalSpace["8xl"],
      [breakpoints.md]: verticalSpace["12xl"],
    },
    paddingTop: {
      default: verticalSpace["4xl"],
      [breakpoints.md]: verticalSpace["6xl"],
    },
    width: "100%",
  },
  // ── Hero ───────────────────────────────────────────────────
  hero: {
    alignItems: "center",
    display: "grid",
    // Two columns from md so the illustration stays beside the copy; text
    // column grows on lg while the goober lane keeps a stable width.
    gridTemplateColumns: {
      default: "1fr",
      [breakpoints.md]: "minmax(0, 1fr) minmax(180px, 340px)",
      [breakpoints.lg]: "minmax(0, 820px) minmax(240px, 380px)",
    },
    paddingBottom: {
      default: verticalSpace["10xl"],
      [breakpoints.md]: verticalSpace["12xl"],
    },
    paddingTop: {
      default: verticalSpace.none,
      [breakpoints.md]: verticalSpace["6xl"],
    },
  },
  heroTextCol: {
    containerType: "inline-size",
    maxWidth: 820,
    minWidth: 0,
  },
  eyebrow: {
    alignItems: "center",
    backgroundColor: uiColor.bgSubtle,
    borderColor: uiColor.border1,
    borderRadius: radius.full,
    borderStyle: "solid",
    borderWidth: 1,
    color: uiColor.text1,
    cornerShape: "squircle",
    display: "inline-flex",
    fontFamily: fontFamily.mono,
    fontSize: fontSize.xs,
    gap: gap["md"],
    marginBottom: verticalSpace["6xl"],
    paddingBottom: verticalSpace["xs"],
    paddingLeft: horizontalSpace["xl"],
    paddingRight: horizontalSpace["xl"],
    paddingTop: verticalSpace["xs"],
  },
  pulseDot: {
    animationDuration: "1.6s",
    animationIterationCount: "infinite",
    animationName: stylex.keyframes({
      "0%, 100%": { opacity: 1, transform: "scale(1)" },
      "50%": { opacity: 0.55, transform: "scale(0.9)" },
    }),
    animationTimingFunction: "ease-in-out",
    backgroundColor: successColor.solid1,
    borderRadius: radius.full,
    boxShadow: `0 0 0 3px ${successColor.component1}`,
    height: 6,
    width: 6,
  },
  heroTitle: {
    color: uiColor.text2,
    fontFamily: fontFamily.sans,
    // Fluid scaling against the hero column itself (cqi = % of nearest
    // container's inline-size). Clamp keeps it readable at narrow widths
    // and prevents it from blowing out past the design ceiling on wide
    // screens.
    fontSize: "clamp(2rem, 11cqi, 3.625rem)",
    fontWeight: fontWeight.semibold,
    letterSpacing: tracking.tight,
    lineHeight: 1.04,
    marginBottom: {
      default: verticalSpace["5xl"],
      [breakpoints.md]: verticalSpace["6xl"],
    },
    marginTop: 0,
    textWrap: "balance",
  },
  heroAccent: {
    color: primaryColor.solid1,
    fontStyle: "italic",
    fontWeight: fontWeight.medium,
  },
  heroSub: {
    color: uiColor.text1,
    fontSize: fontSize.lg,
    lineHeight: 1.55,
    marginBottom: {
      default: verticalSpace["5xl"],
      [breakpoints.md]: verticalSpace["7xl"],
    },
    maxWidth: "52ch",
  },
  ctaRow: {
    flexWrap: "wrap",
    gap: gap["2xl"],
    marginBottom: {
      default: verticalSpace["5xl"],
      [breakpoints.md]: verticalSpace["6xl"],
    },
  },
  installBar: {
    alignItems: "center",
    backgroundColor: uiColor.component1,
    borderColor: uiColor.border1,
    borderRadius: radius.md,
    borderStyle: "solid",
    borderWidth: 1,
    color: uiColor.text2,
    cornerShape: "squircle",
    display: "inline-flex",
    fontFamily: fontFamily.mono,
    fontSize: fontSize.sm,
    gap: gap["xl"],
    paddingBottom: verticalSpace["md"],
    paddingLeft: horizontalSpace["2xl"],
    paddingRight: horizontalSpace["2xl"],
    paddingTop: verticalSpace["md"],
    textDecoration: "none",
  },
  installPrompt: {
    color: uiColor.text1,
    userSelect: "none",
  },
  installCmd: {
    color: successColor.solid1,
  },

  // ── Receipt chain visual ───────────────────────────────────
  chain: {
    backgroundColor: uiColor.bg,
    borderColor: uiColor.border1,
    borderRadius: radius.lg,
    borderStyle: "solid",
    borderWidth: 1,
    color: uiColor.text2,
    // Becomes the container for the per-row layout decisions below.
    containerType: "inline-size",
    cornerShape: "squircle",
    fontFamily: fontFamily.mono,
    fontSize: fontSize.xs,
    lineHeight: 1.5,
    // Let this grid track actually shrink so it can fit half the hero
    // and so the inner content can wrap instead of clipping.
    minWidth: 0,
    overflow: "hidden",
    paddingBottom: {
      default: verticalSpace["4xl"],
      [breakpoints.md]: verticalSpace["5xl"],
      [breakpoints.lg]: verticalSpace["6xl"],
    },
    paddingLeft: {
      default: horizontalSpace["4xl"],
      [breakpoints.md]: horizontalSpace["5xl"],
      [breakpoints.lg]: horizontalSpace["6xl"],
    },
    paddingRight: {
      default: horizontalSpace["4xl"],
      [breakpoints.md]: horizontalSpace["5xl"],
      [breakpoints.lg]: horizontalSpace["6xl"],
    },
    paddingTop: {
      default: verticalSpace["4xl"],
      [breakpoints.md]: verticalSpace["5xl"],
      [breakpoints.lg]: verticalSpace["6xl"],
    },
    position: "relative",
  },
  chainHead: {
    alignItems: "center",
    borderBottomColor: uiColor.border1,
    borderBottomStyle: "dashed",
    borderBottomWidth: 1,
    color: uiColor.text1,
    display: "flex",
    flexWrap: "wrap",
    gap: gap["xl"],
    justifyContent: "space-between",
    marginBottom: verticalSpace["4xl"],
    overflowWrap: "anywhere",
    paddingBottom: verticalSpace["3xl"],
  },
  chainLights: {
    display: "flex",
    gap: gap["sm"],
  },
  chainLight: {
    backgroundColor: uiColor.component3,
    borderRadius: radius.full,
    height: 9,
    width: 9,
  },
  chainLightRed: {
    backgroundColor: "color(display-p3 0.85 0.35 0.3)",
  },
  chainLightYellow: {
    backgroundColor: "color(display-p3 0.95 0.75 0.3)",
  },
  chainLightGreen: {
    backgroundColor: successColor.solid1,
  },
  chainRecord: {
    backgroundColor: uiColor.component1,
    borderColor: uiColor.border1,
    borderRadius: radius.sm,
    borderStyle: "solid",
    borderWidth: 1,
    cornerShape: "squircle",
    display: "flex",
    flexDirection: "column",
    gap: gap["md"],
    minWidth: 0,
    paddingBottom: verticalSpace["md"],
    paddingLeft: horizontalSpace["2xl"],
    paddingRight: horizontalSpace["2xl"],
    paddingTop: verticalSpace["md"],
  },
  chainFieldsRow: {
    alignItems: "baseline",
    columnGap: gap["6xl"],
    display: "flex",
    flexDirection: "row",
    flexWrap: "wrap",
    minWidth: 0,
    rowGap: gap["md"],
  },
  chainRecordSigned: {
    borderColor: successColor.border1,
  },
  chainNsid: {
    alignItems: "baseline",
    color: "color(display-p3 0.95 0.75 0.3)",
    columnGap: gap["lg"],
    display: "flex",
    flexWrap: "wrap",
    fontWeight: fontWeight.medium,
    justifyContent: "space-between",
    overflowWrap: "anywhere",
    rowGap: gap["xs"],
  },
  chainNsidSigned: {
    color: successColor.solid1,
  },
  chainBy: {
    color: uiColor.text1,
    fontSize: "10.5px",
    fontWeight: fontWeight.normal,
  },
  chainField: {
    alignItems: "baseline",
    columnGap: gap["lg"],
    display: "inline-flex",
    flexDirection: "row",
    fontSize: "10.5px",
    maxWidth: "100%",
    minWidth: 0,
  },
  chainKey: {
    color: uiColor.text1,
    flexShrink: 0,
  },
  chainValue: {
    color: uiColor.text2,
    fontVariantNumeric: "tabular-nums",
    minWidth: 0,
    // Allow long monospace tokens (hashes, URIs) to break at word
    // boundaries when they would otherwise overflow, but don't aggressively
    // split inside short tokens like "stub-7b@v0.4".
    overflowWrap: "break-word",
  },
  chainValueOk: {
    color: successColor.solid1,
  },
  chainLink: {
    alignItems: "center",
    color: uiColor.text1,
    display: "flex",
    fontSize: "10px",
    gap: gap["md"],
    paddingBottom: verticalSpace["sm"],
    paddingLeft: horizontalSpace["lg"],
    paddingTop: verticalSpace["sm"],
  },
  chainArrow: {
    color: "color(display-p3 0.5 0.75 0.95)",
  },
  chainFoot: {
    alignItems: "center",
    borderTopColor: uiColor.border1,
    borderTopStyle: "dashed",
    borderTopWidth: 1,
    color: uiColor.text1,
    columnGap: gap["xl"],
    display: "flex",
    flexWrap: "wrap",
    fontSize: "10.5px",
    justifyContent: "space-between",
    marginTop: verticalSpace["4xl"],
    paddingTop: verticalSpace["3xl"],
    rowGap: gap["xs"],
  },
  chainVerify: {
    alignItems: "center",
    color: successColor.solid1,
    display: "inline-flex",
    gap: gap["sm"],
  },
  proofCaption: {
    color: uiColor.text1,
    fontSize: fontSize.sm,
    lineHeight: 1.6,
    marginBottom: verticalSpace.none,
    marginLeft: {
      default: verticalSpace.none,
      [breakpoints.md]: "auto",
    },
    marginRight: {
      default: verticalSpace.none,
      [breakpoints.md]: "auto",
    },
    marginTop: {
      default: gap["5xl"],
      [breakpoints.md]: gap["8xl"],
    },
    maxWidth: "640px",
    textAlign: {
      default: "start",
      [breakpoints.md]: "center",
    },
  },
  proofChain: {
    marginLeft: "auto",
    marginRight: "auto",
    marginTop: {
      default: gap["5xl"],
      [breakpoints.md]: gap["8xl"],
    },
    maxWidth: 760,
  },

  // ── Stats strip ────────────────────────────────────────────
  statsStrip: {
    borderBottomColor: uiColor.border1,
    borderBottomStyle: "solid",
    borderBottomWidth: 1,
    borderTopColor: uiColor.border1,
    borderTopStyle: "solid",
    borderTopWidth: 1,
    columnGap: gap["6xl"],
    display: "grid",
    gridTemplateColumns: {
      default: "repeat(2, 1fr)",
      [breakpoints.sm]: "repeat(3, 1fr)",
      [breakpoints.lg]: "repeat(6, 1fr)",
    },
    marginBottom: verticalSpace["12xl"],
    paddingBottom: verticalSpace["5xl"],
    paddingTop: verticalSpace["5xl"],
    rowGap: gap["5xl"],
  },
  statItem: {
    fontFamily: fontFamily.mono,
  },
  statLabel: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
    letterSpacing: "0.06em",
    marginBottom: verticalSpace["sm"],
    textTransform: "lowercase",
  },
  statValue: {
    alignItems: "baseline",
    color: uiColor.text2,
    display: "flex",
    fontSize: "28px",
    fontVariantNumeric: "tabular-nums",
    fontWeight: fontWeight.medium,
    gap: gap["sm"],
    letterSpacing: tracking.tight,
    lineHeight: 1,
  },
  statUnit: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
    fontWeight: fontWeight.normal,
  },

  // ── Live-on-the-network glimpse ────────────────────────────
  liveGrid: {
    display: "grid",
    gap: { default: gap["5xl"], [breakpoints.md]: gap["6xl"] },
    gridTemplateColumns: { default: "1fr", [breakpoints.md]: "repeat(3, minmax(0, 1fr))" },
    marginTop: { default: gap["5xl"], [breakpoints.md]: gap["7xl"] },
  },
  liveCol: {
    backgroundColor: uiColor.bg,
    borderColor: uiColor.border1,
    borderRadius: radius.lg,
    borderStyle: "solid",
    borderWidth: 1,
    cornerShape: "squircle",
    display: "flex",
    flexDirection: "column",
    gap: gap["3xl"],
    minWidth: 0,
    paddingBottom: verticalSpace["5xl"],
    paddingLeft: horizontalSpace["5xl"],
    paddingRight: horizontalSpace["5xl"],
    paddingTop: verticalSpace["5xl"],
  },
  liveColTitle: {
    color: primaryColor.solid1,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.xs,
    letterSpacing: "0.06em",
    textTransform: "lowercase",
  },
  liveList: {
    display: "flex",
    flexDirection: "column",
    gap: gap["2xl"],
    margin: 0,
    minWidth: 0,
    padding: 0,
  },
  liveItem: {
    alignItems: "center",
    columnGap: gap["xl"],
    display: "flex",
    minWidth: 0,
  },
  liveItemLink: {
    color: "inherit",
    textDecoration: "none",
  },
  liveAvatar: {
    alignItems: "center",
    backgroundColor: uiColor.component2,
    borderRadius: radius.full,
    color: uiColor.text1,
    cornerShape: "squircle",
    display: "grid",
    flexShrink: 0,
    fontFamily: fontFamily.mono,
    fontSize: "11px",
    height: 28,
    overflow: "hidden",
    placeItems: "center",
    width: 28,
  },
  liveAvatarImg: {
    height: "100%",
    objectFit: "cover",
    width: "100%",
  },
  liveItemText: {
    display: "flex",
    flexDirection: "column",
    minWidth: 0,
  },
  livePrimary: {
    color: uiColor.text2,
    fontSize: fontSize.sm,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  liveSecondary: {
    color: uiColor.text1,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.xs,
    overflow: "hidden",
    textDecoration: "none",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  liveBadge: {
    backgroundColor: successColor.component2,
    borderRadius: radius.full,
    color: successColor.solid1,
    cornerShape: "squircle",
    fontFamily: fontFamily.mono,
    fontSize: "10px",
    marginLeft: "auto",
    paddingBottom: 1,
    paddingLeft: horizontalSpace["lg"],
    paddingRight: horizontalSpace["lg"],
    paddingTop: 1,
  },
  liveReceiptRow: {
    borderBottomColor: uiColor.border1,
    borderBottomStyle: "dashed",
    borderBottomWidth: { default: 1, ":last-child": 0 },
    display: "flex",
    flexDirection: "column",
    gap: gap["xs"],
    minWidth: 0,
    paddingBottom: verticalSpace["2xl"],
  },
  liveReceiptModel: {
    color: "color(display-p3 0.95 0.75 0.3)",
    fontFamily: fontFamily.mono,
    fontSize: "11px",
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  liveReceiptMeta: {
    color: uiColor.text1,
    fontFamily: fontFamily.mono,
    fontSize: "10.5px",
  },
  liveLatency: {
    color: successColor.solid1,
  },
  liveEmpty: {
    color: uiColor.text1,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.xs,
  },

  // ── Section ────────────────────────────────────────────────
  section: {
    paddingBottom: {
      default: verticalSpace["8xl"],
      [breakpoints.md]: verticalSpace["12xl"],
      [breakpoints.lg]: verticalSpace["12xl"],
    },
    position: "relative",
  },
  // Cloud goobie floated into a section's open right margin (desktop only).
  sectionCloud: {
    display: { default: "none", [breakpoints.md]: "block" },
    right: 0,
    top: verticalSpace["4xl"],
  },
  // Heron goobie floated beside the live-section header, filling the open
  // right margin next to the heading + copy (desktop only).
  liveArt: {
    display: { default: "none", [breakpoints.md]: "block" },
    right: 0,
    top: verticalSpace["6xl"],
  },

  // ── §01 provider compatibility row ─────────────────────────
  // §01 right column: a fan-in diagram — the SDKs you already use, their
  // lines converging into the co/core mark. SVG strokes/text inherit the
  // wrapper's (muted) `color` via currentColor; the co/core node is its own
  // bronze element so the two colors stay clean + theme-aware.
  compatDiagram: {
    alignSelf: {
      [breakpoints.md]: "stretch",
    },
    color: uiColor.text1,
    display: "grid",
    fontFamily: fontFamily.mono,
    justifySelf: {
      [breakpoints.md]: "stretch",
    },
    placeItems: "center",
    // On mobile the diagram stacks under the §01 copy; sectionSub's
    // marginBottom plus the grid row gap double up above (~48px) while
    // only swapGrid's marginTop sits below (~24px). Pull up one step and
    // pad both sides so the SVG reads centered in its lane.
    marginTop: {
      default: `calc(-1 * ${verticalSpace["5xl"]})`,
      [breakpoints.md]: verticalSpace.none,
    },
    paddingBottom: {
      default: verticalSpace["5xl"],
      [breakpoints.md]: verticalSpace.none,
    },
    paddingTop: {
      default: verticalSpace["5xl"],
      [breakpoints.md]: verticalSpace.none,
    },
  },
  compatDiagramInner: {
    alignItems: "center",
    display: "flex",
    gap: {
      default: gap["lg"],
      [breakpoints.md]: gap.none,
    },
    height: {
      [breakpoints.md]: "176px",
    },
    marginLeft: {
      [breakpoints.md]: "auto",
    },
    marginRight: {
      [breakpoints.md]: "auto",
    },
    paddingRight: {
      [breakpoints.md]: "88px",
    },
    position: {
      default: "static",
      [breakpoints.md]: "relative",
    },
    width: {
      [breakpoints.md]: "fit-content",
    },
  },
  compatFan: {
    flexShrink: 0,
    height: "auto",
    width: 170,
  },
  compatBrand: {
    alignItems: "center",
    backgroundColor: uiColor.bgSubtle,
    borderColor: primaryColor.solid1,
    borderRadius: radius.full,
    borderStyle: "solid",
    borderWidth: 1,
    color: primaryColor.solid1,
    cornerShape: "squircle",
    display: "inline-flex",
    fontFamily: fontFamily.mono,
    fontSize: fontSize.sm,
    fontWeight: fontWeight.medium,
    gap: gap["md"],
    left: {
      [breakpoints.md]: 163,
    },
    paddingBottom: verticalSpace["sm"],
    paddingLeft: horizontalSpace["2xl"],
    paddingRight: horizontalSpace["2xl"],
    paddingTop: verticalSpace["sm"],
    position: {
      default: "static",
      [breakpoints.md]: "absolute",
    },
    top: {
      [breakpoints.md]: "50%",
    },
    transform: {
      [breakpoints.md]: "translateY(-50%)",
    },
    whiteSpace: "nowrap",
  },
  compatMark: {
    height: 15,
    width: 15,
  },

  // ── §04 open-standard diagram ──────────────────────────────
  standardGrid: {
    alignItems: "center",
    display: "grid",
    gap: {
      default: gap["5xl"],
      [breakpoints.md]: gap["8xl"],
    },
    gridTemplateColumns: { default: "1fr", [breakpoints.md]: "1fr minmax(0, 340px)" },
  },
  diagram: {
    backgroundColor: uiColor.bg,
    borderColor: uiColor.border1,
    borderRadius: radius.lg,
    borderStyle: "solid",
    borderWidth: 1,
    cornerShape: "squircle",
    display: "flex",
    flexDirection: "column",
    fontFamily: fontFamily.mono,
    paddingBottom: {
      default: verticalSpace["5xl"],
      [breakpoints.md]: verticalSpace["6xl"],
    },
    paddingLeft: {
      default: horizontalSpace["5xl"],
      [breakpoints.md]: horizontalSpace["6xl"],
    },
    paddingRight: {
      default: horizontalSpace["5xl"],
      [breakpoints.md]: horizontalSpace["6xl"],
    },
    paddingTop: {
      default: verticalSpace["5xl"],
      [breakpoints.md]: verticalSpace["6xl"],
    },
  },
  diagramCap: {
    color: primaryColor.solid1,
    fontSize: fontSize.xs,
    letterSpacing: "0.06em",
    marginBottom: verticalSpace["xl"],
    textTransform: "lowercase",
  },
  diagramNode: {
    alignItems: "center",
    backgroundColor: uiColor.component1,
    borderColor: uiColor.border1,
    borderRadius: radius.sm,
    borderStyle: "solid",
    borderWidth: 1,
    color: uiColor.text2,
    cornerShape: "squircle",
    display: "flex",
    fontSize: fontSize.sm,
    gap: gap["md"],
    justifyContent: "space-between",
    paddingBottom: verticalSpace["sm"],
    paddingLeft: horizontalSpace["2xl"],
    paddingRight: horizontalSpace["2xl"],
    paddingTop: verticalSpace["sm"],
  },
  diagramNodeSigned: {
    borderColor: successColor.border1,
    color: successColor.solid1,
  },
  diagramTag: {
    color: uiColor.text1,
    fontSize: "10.5px",
  },
  diagramArrow: {
    color: uiColor.text1,
    fontSize: fontSize.sm,
    paddingBottom: verticalSpace["xs"],
    paddingTop: verticalSpace["xs"],
    textAlign: "center",
  },
  diagramRule: {
    borderTopColor: uiColor.border1,
    borderTopStyle: "dashed",
    borderTopWidth: 1,
    marginBottom: verticalSpace["lg"],
    marginTop: verticalSpace["lg"],
  },
  diagramFootLabel: {
    color: uiColor.text1,
    fontSize: "10.5px",
    marginBottom: verticalSpace["md"],
  },
  diagramExchanges: {
    columnGap: gap["md"],
    display: "flex",
    flexWrap: "wrap",
    rowGap: gap["md"],
  },
  diagramExchange: {
    backgroundColor: uiColor.bgSubtle,
    borderColor: uiColor.border1,
    borderRadius: radius.full,
    borderStyle: "solid",
    borderWidth: 1,
    color: uiColor.text1,
    cornerShape: "squircle",
    fontSize: "11px",
    paddingBottom: 2,
    paddingLeft: horizontalSpace["lg"],
    paddingRight: horizontalSpace["lg"],
    paddingTop: 2,
  },
  diagramExchangeUs: {
    borderColor: primaryColor.solid1,
    color: primaryColor.solid1,
  },
  sectionEyebrow: {
    alignItems: "center",
    color: primaryColor.solid1,
    display: "flex",
    fontFamily: fontFamily.mono,
    fontSize: fontSize.xs,
    fontWeight: fontWeight.medium,
    gap: gap["md"],
    letterSpacing: "0.08em",
    marginBottom: {
      default: verticalSpace["xl"],
      [breakpoints.md]: verticalSpace["6xl"],
    },
    textTransform: "lowercase",
  },
  sectionEyebrowNum: {
    color: uiColor.text1,
    fontVariantNumeric: "tabular-nums",
  },
  sectionH2: {
    color: uiColor.text2,
    fontFamily: fontFamily.sans,
    fontSize: { default: "32px", [breakpoints.sm]: "40px" },
    fontWeight: fontWeight.semibold,
    letterSpacing: tracking.tight,
    lineHeight: 1.1,
    marginBottom: {
      default: verticalSpace["5xl"],
      [breakpoints.md]: verticalSpace["8xl"],
    },
    marginTop: 0,
    maxWidth: "720px",
    textWrap: "balance",
  },
  sectionH2Mono: {
    backgroundColor: uiColor.bgSubtle,
    borderColor: uiColor.border1,
    borderRadius: radius.sm,
    borderStyle: "solid",
    borderWidth: 1,
    cornerShape: "squircle",
    display: "inline-block",
    fontFamily: fontFamily.mono,
    fontSize: "0.78em",
    fontWeight: fontWeight.medium,
    letterSpacing: "-0.015em",
    paddingLeft: horizontalSpace["lg"],
    paddingRight: horizontalSpace["lg"],
    transform: "translateY(-4px)",
  },
  sectionSub: {
    color: uiColor.text1,
    fontSize: fontSize.lg,
    lineHeight: 1.7,
    marginBottom: {
      default: verticalSpace["5xl"],
      [breakpoints.md]: verticalSpace["8xl"],
      [breakpoints.lg]: verticalSpace["10xl"],
    },
    marginTop: 0,
    maxWidth: "640px",
  },
  inlineLink: {
    color: primaryColor.solid1,
    textDecorationLine: "underline",
    textUnderlineOffset: "2px",
  },
  /** §01 copy sits directly above the before/after cards — keep the handoff tight. */
  dropInSub: {
    marginBottom: {
      default: verticalSpace["4xl"],
      [breakpoints.md]: verticalSpace["5xl"],
    },
  },

  // ── Two-strings swap (before / after) ─────────────────────
  swapGrid: {
    display: "grid",
    gap: {
      default: gap["5xl"],
      [breakpoints.md]: gap["6xl"],
    },
    gridTemplateColumns: { default: "1fr", [breakpoints.md]: "1fr 1fr" },
    marginTop: {
      default: gap["4xl"],
      [breakpoints.md]: gap["5xl"],
    },
  },
  swapCard: {
    backgroundColor: uiColor.bg,
    borderColor: uiColor.border1,
    borderRadius: radius.md,
    borderStyle: "solid",
    borderWidth: 1,
    cornerShape: "squircle",
    overflow: "hidden",
  },
  swapHead: {
    alignItems: "center",
    backgroundColor: uiColor.component2,
    borderBottomColor: uiColor.border1,
    borderBottomStyle: "solid",
    borderBottomWidth: 1,
    color: uiColor.text1,
    display: "flex",
    fontFamily: fontFamily.mono,
    fontSize: fontSize.xs,
    justifyContent: "space-between",
    paddingBottom: verticalSpace["lg"],
    paddingLeft: horizontalSpace["3xl"],
    paddingRight: horizontalSpace["3xl"],
    paddingTop: verticalSpace["lg"],
  },
  swapBadge: {
    alignItems: "center",
    backgroundColor: uiColor.component3,
    borderRadius: radius.full,
    color: uiColor.text1,
    cornerShape: "squircle",
    display: "inline-flex",
    fontSize: "10px",
    letterSpacing: "0.04em",
    paddingBottom: 2,
    paddingLeft: horizontalSpace["lg"],
    paddingRight: horizontalSpace["lg"],
    paddingTop: 2,
    textTransform: "lowercase",
  },
  swapBadgeAfter: {
    backgroundColor: successColor.component2,
    color: successColor.solid1,
  },
  swapPre: {
    color: uiColor.text2,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.sm,
    lineHeight: 1.7,
    marginBottom: 0,
    marginTop: 0,
    overflowX: "auto",
    paddingBottom: verticalSpace["4xl"],
    paddingLeft: horizontalSpace["4xl"],
    paddingRight: horizontalSpace["4xl"],
    paddingTop: verticalSpace["4xl"],
    whiteSpace: "pre",
  },
  swapKw: { color: "color(display-p3 0.85 0.45 0.35)" },
  swapFn: { color: "color(display-p3 0.95 0.75 0.3)" },
  swapStr: { color: uiColor.text1 },
  /** After-card strings that changed (endpoint, key, model) — same treatment as api_key. */
  swapHighlight: {
    backgroundColor: successColor.component2,
    borderRadius: 2,
    color: successColor.solid1,
    paddingLeft: 2,
    paddingRight: 2,
  },

  // ── Steps ──────────────────────────────────────────────────
  steps: {
    backgroundColor: uiColor.bg,
    borderColor: uiColor.border1,
    borderRadius: radius.md,
    borderStyle: "solid",
    borderWidth: 1,
    cornerShape: "squircle",
    columnGap: 0,
    display: "grid",
    gridTemplateColumns: {
      default: "1fr",
      [breakpoints.md]: "minmax(0, 1fr) 1px minmax(0, 1fr) 1px minmax(0, 1fr)",
    },
    gridTemplateRows: {
      [breakpoints.md]: "auto auto auto repeat(4, minmax(min-content, max-content))",
    },
    overflow: "hidden",
    rowGap: { default: gap["5xl"], [breakpoints.md]: 0 },
  },
  /** Full-height rules between step columns (dedicated 1px tracks; avoids broken nested subgrid). */
  stepRule: {
    alignSelf: { [breakpoints.md]: "stretch" },
    backgroundColor: uiColor.border1,
    display: { default: "none", [breakpoints.md]: "block" },
    gridRow: { [breakpoints.md]: "1 / -1" },
    minHeight: { [breakpoints.md]: 0 },
    minWidth: { [breakpoints.md]: 1 },
    width: { [breakpoints.md]: "100%" },
  },
  stepRuleCol2: {
    gridColumn: { [breakpoints.md]: 2 },
  },
  stepRuleCol4: {
    gridColumn: { [breakpoints.md]: 4 },
  },
  /**
   * One wrapper per step column: spans all rows on md+; shares parent row tracks with stepCode
   * subgrid for aligned code lines.
   */
  stepColumn: {
    backgroundColor: uiColor.bg,
    borderBottomColor: uiColor.border1,
    borderBottomStyle: "solid",
    borderBottomWidth: {
      default: 1,
      ":last-child": 0,
      [breakpoints.md]: 0,
    },
    display: { default: "flex", [breakpoints.md]: "grid" },
    flexDirection: { default: "column" },
    gap: { default: gap["5xl"], [breakpoints.md]: 0 },
    gridRow: { [breakpoints.md]: "1 / -1" },
    gridTemplateRows: { [breakpoints.md]: "subgrid" },
    minWidth: { default: 0, [breakpoints.md]: 0 },
    // Former .steps horizontal inset + inner column pad, on stacked mobile cards.
    paddingInline: {
      default: horizontalSpace["5xl"],
      [breakpoints.md]: 0,
    },
    paddingBottom: {
      default: verticalSpace["5xl"],
      [breakpoints.md]: verticalSpace["8xl"],
    },
    paddingTop: {
      default: verticalSpace["5xl"],
      [breakpoints.md]: verticalSpace["5xl"],
    },
  },
  stepColumn1: {
    gridColumn: { [breakpoints.md]: 1 },
    paddingLeft: {
      [breakpoints.md]: `calc(${horizontalSpace["5xl"]} + ${horizontalSpace["4xl"]})`,
    },
    paddingRight: { [breakpoints.md]: gap["7xl"] },
  },
  stepColumn2: {
    gridColumn: { [breakpoints.md]: 3 },
    paddingLeft: { [breakpoints.md]: horizontalSpace["4xl"] },
    paddingRight: { [breakpoints.md]: gap["7xl"] },
  },
  stepColumn3: {
    gridColumn: { [breakpoints.md]: 5 },
    paddingLeft: { [breakpoints.md]: horizontalSpace["4xl"] },
    paddingRight: {
      [breakpoints.md]: `calc(${horizontalSpace["5xl"]} + ${horizontalSpace["4xl"]})`,
    },
  },
  stepGridPadTop: {
    paddingTop: { [breakpoints.md]: verticalSpace["8xl"] },
  },
  /** Replaces flex gap between head / title / body on the md+ grid. */
  stepGridSep: {
    marginBottom: { [breakpoints.md]: gap["5xl"] },
  },
  stepHead: {
    alignItems: "center",
    display: "flex",
    fontFamily: fontFamily.mono,
    gap: gap["xl"],
  },
  stepNum: {
    alignItems: "center",
    backgroundColor: uiColor.solid1,
    borderRadius: radius.xs,
    color: uiColor.bg,
    cornerShape: "squircle",
    display: "grid",
    fontSize: fontSize.xs,
    fontWeight: fontWeight.semibold,
    height: sizeSpace["xl"],
    justifyContent: "center",
    placeItems: "center",
    width: sizeSpace["xl"],
  },
  stepName: {
    color: uiColor.text1,
    fontSize: fontSize.sm,
    letterSpacing: "0.04em",
    textTransform: "lowercase",
  },
  stepCode: {
    alignSelf: { [breakpoints.md]: "stretch" },
    backgroundColor: uiColor.component1,
    borderColor: uiColor.border1,
    borderRadius: radius.sm,
    borderStyle: "solid",
    borderWidth: 1,
    color: uiColor.text2,
    cornerShape: "squircle",
    display: { default: "flex", [breakpoints.md]: "grid" },
    flexDirection: { default: "column" },
    gridRow: { [breakpoints.md]: "4 / span 4" },
    gridTemplateRows: { [breakpoints.md]: "subgrid" },
    minWidth: 0,
    paddingBlock: verticalSpace["3xl"],
    paddingInline: horizontalSpace["3xl"],
  },
  stepCodeLine: {
    fontFamily: fontFamily.mono,
    fontSize: fontSize.xs,
    lineHeight: 1.65,
    marginBottom: {
      default: gap["xs"],
      ":last-child": 0,
    },
    minWidth: 0,
    overflowWrap: "break-word",
  },
  stepCodePrompt: { color: uiColor.text1, marginRight: horizontalSpace["sm"] },
  stepCodeCmd: { color: successColor.solid1 },
  stepCodeAccent: { color: "color(display-p3 0.95 0.75 0.3)" },

  // ── atproto callout ────────────────────────────────────────
  atpCallout: {
    alignItems: "center",
    backgroundColor: uiColor.bg,
    borderColor: uiColor.border1,
    borderRadius: radius.lg,
    borderStyle: "solid",
    borderWidth: 1,
    cornerShape: "squircle",
    display: "grid",
    gap: {
      default: gap["5xl"],
      [breakpoints.md]: gap["7xl"],
      [breakpoints.lg]: gap["8xl"],
    },
    gridTemplateColumns: { default: "1fr", [breakpoints.md]: "1fr 1fr" },
    paddingBottom: {
      default: verticalSpace["5xl"],
      [breakpoints.md]: verticalSpace["8xl"],
    },
    paddingLeft: {
      default: horizontalSpace["5xl"],
      [breakpoints.md]: horizontalSpace["8xl"],
    },
    paddingRight: {
      default: horizontalSpace["5xl"],
      [breakpoints.md]: horizontalSpace["8xl"],
    },
    paddingTop: {
      default: verticalSpace["5xl"],
      [breakpoints.md]: verticalSpace["8xl"],
    },
  },
  atpFeatures: {
    display: "flex",
    flexDirection: "column",
    gap: {
      default: gap["4xl"],
      [breakpoints.md]: gap["5xl"],
    },
    marginTop: {
      default: verticalSpace["4xl"],
      [breakpoints.md]: verticalSpace["5xl"],
    },
  },
  atpFeature: {
    columnGap: gap["xl"],
    display: "grid",
    gridTemplateColumns: "28px 1fr",
  },
  atpMark: {
    color: primaryColor.solid1,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.sm,
    paddingTop: 2,
  },
  atpFeatureTitle: {
    color: uiColor.text2,
    fontSize: fontSize.sm,
    fontWeight: fontWeight.semibold,
    marginBottom: 2,
  },
  atpFeatureBody: {
    color: uiColor.text1,
    fontSize: fontSize.sm,
    lineHeight: 1.5,
  },
  lexTable: {
    backgroundColor: uiColor.component1,
    borderColor: uiColor.border1,
    borderRadius: radius.md,
    borderStyle: "solid",
    borderWidth: 1,
    color: uiColor.text2,
    // Size rows against the table width (half-width in the 2-col callout
    // on tablet, full width on mobile) so we stack NSID / owner sooner.
    containerType: "inline-size",
    cornerShape: "squircle",
    fontFamily: fontFamily.mono,
    fontSize: fontSize.xs,
    lineHeight: 1.5,
    minWidth: 0,
    paddingBottom: verticalSpace["3xl"],
    paddingLeft: horizontalSpace["4xl"],
    paddingRight: horizontalSpace["4xl"],
    paddingTop: verticalSpace["3xl"],
  },
  lexRow: {
    borderBottomColor: uiColor.border1,
    borderBottomStyle: "dashed",
    borderBottomWidth: { default: 1, ":last-child": 0 },
    columnGap: gap["4xl"],
    display: "grid",
    gridTemplateColumns: {
      default: "1fr",
      "@container (min-width: 32rem)": "1fr auto",
    },
    minWidth: 0,
    paddingBottom: verticalSpace["md"],
    paddingTop: verticalSpace["md"],
    rowGap: gap["xs"],
  },
  lexNsid: {
    color: "color(display-p3 0.95 0.75 0.3)",
    minWidth: 0,
    overflowWrap: "break-word",
  },
  lexNs: {
    color: uiColor.text1,
  },
  lexOwner: {
    alignSelf: {
      default: "start",
      "@container (min-width: 32rem)": "center",
    },
    color: uiColor.text1,
    fontSize: "10.5px",
    justifySelf: {
      default: "start",
      "@container (min-width: 32rem)": "end",
    },
    minWidth: 0,
    overflowWrap: "break-word",
    textAlign: {
      default: "start",
      "@container (min-width: 32rem)": "end",
    },
  },
  lexOwnerAccent: {
    color: successColor.solid1,
  },

  // ── Provider CTA ───────────────────────────────────────────
  provider: {
    alignItems: "center",
    display: "grid",
    gap: {
      default: gap["5xl"],
      [breakpoints.md]: gap["7xl"],
      [breakpoints.lg]: gap["8xl"],
    },
    gridTemplateColumns: { default: "1fr", [breakpoints.md]: "1fr 1fr" },
  },
  providerCard: {
    backgroundColor: uiColor.bg,
    borderColor: uiColor.border1,
    borderRadius: radius.lg,
    borderStyle: "solid",
    borderWidth: 1,
    color: uiColor.text2,
    cornerShape: "squircle",
    overflow: "hidden",
    paddingBottom: {
      default: verticalSpace["5xl"],
      [breakpoints.md]: verticalSpace["7xl"],
    },
    paddingLeft: {
      default: horizontalSpace["5xl"],
      [breakpoints.md]: horizontalSpace["7xl"],
    },
    paddingRight: {
      default: horizontalSpace["5xl"],
      [breakpoints.md]: horizontalSpace["7xl"],
    },
    paddingTop: {
      default: verticalSpace["5xl"],
      [breakpoints.md]: verticalSpace["7xl"],
    },
    position: "relative",
  },
  providerEyebrow: {
    color: successColor.solid1,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.xs,
    letterSpacing: "0.06em",
    marginBottom: verticalSpace["xl"],
    textTransform: "lowercase",
  },
  providerTitle: {
    color: uiColor.text2,
    fontFamily: fontFamily.sans,
    fontSize: "28px",
    fontWeight: fontWeight.semibold,
    letterSpacing: tracking.tight,
    lineHeight: 1.15,
    marginBottom: verticalSpace["xl"],
    marginTop: 0,
    textWrap: "balance",
  },
  providerBody: {
    color: uiColor.text1,
    fontSize: fontSize.sm,
    lineHeight: 1.7,
    marginBottom: verticalSpace["5xl"],
    marginTop: 0,
  },
  providerInstall: {
    alignItems: "center",
    backgroundColor: uiColor.component1,
    borderRadius: radius.sm,
    color: uiColor.text2,
    cornerShape: "squircle",
    display: "flex",
    fontFamily: fontFamily.mono,
    fontSize: fontSize.xs,
    gap: gap["md"],
    marginBottom: verticalSpace["5xl"],
    paddingBottom: verticalSpace["lg"],
    paddingLeft: horizontalSpace["2xl"],
    paddingRight: horizontalSpace["2xl"],
    paddingTop: verticalSpace["lg"],
  },
  providerInstallPrompt: { color: uiColor.text1 },
  providerInstallCmd: { color: successColor.solid1 },
  providerInstallNote: { color: uiColor.text1, marginLeft: horizontalSpace["sm"] },
  providerChecklist: {
    display: "flex",
    flexDirection: "column",
    gap: gap["4xl"],
  },
  providerCheck: {
    alignItems: "start",
    columnGap: gap["xl"],
    display: "grid",
    gridTemplateColumns: "24px 1fr",
  },
  providerTick: {
    color: successColor.solid1,
    fontFamily: fontFamily.mono,
    fontWeight: fontWeight.semibold,
    paddingTop: 2,
  },
  providerCheckTitle: {
    color: uiColor.text2,
    fontSize: fontSize.base,
    fontWeight: fontWeight.semibold,
    marginBottom: verticalSpace["xs"],
  },
  providerCheckBody: {
    color: uiColor.text1,
    fontSize: fontSize.sm,
    lineHeight: 1.5,
  },
});

export const Route = createFileRoute("/_header-layout/")({
  component: MarketingPage,
  loader: async () => ({ marketing: await loadMarketingSnapshotServerFn() }),
  head: () => ({
    meta: [
      { title: SITE_MARKETING_TITLE },
      {
        name: "description",
        content: SITE_MARKETING_DESCRIPTION,
      },
    ],
  }),
});

// The notarized macOS app (served at /agent/app) is the install path:
// download, open, and the in-app wizard handles sign-in → model → runtime
// → serve. The old `curl … | sh` one-liner is sunset for new users (still
// available for headless fleets via the /start guide).
const APP_DOWNLOAD_HREF = "/agent/app";

const LEXICONS: Array<{ name: string; owner: string; accent?: string }> = [
  { name: "provider", owner: "provider" },
  { name: "attestation", owner: "provider", accent: "· SE-signed" },
  { name: "job", owner: "requester" },
  { name: "paymentAuthorization", owner: "requester" },
  { name: "receipt", owner: "provider", accent: "· SE-signed" },
  { name: "settlement", owner: "exchange" },
  { name: "exchangePolicy", owner: "exchange" },
  { name: "dispute", owner: "exchange" },
];

// Plain integer formatter for the stats strip counts.
const compactInt = new Intl.NumberFormat("en-US", { maximumFractionDigits: 0 });

// Compact-notation formatter (1,000,000 → "1M", 2,500 → "2.5K") for
// the big "free to start" grant — keeps it punchy without a row of
// zeros.
const compactBig = new Intl.NumberFormat("en-US", {
  notation: "compact",
  maximumFractionDigits: 1,
});

/** A person's display label for the live glimpse: prefer display name,
 *  then handle, then a short DID. */
function personLabel(p: MarketingSnapshot["live"]["people"][number]): string {
  if (p.displayName) return p.displayName;
  if (p.handle) return p.handle;
  return p.did.length <= 22 ? p.did : `${p.did.slice(0, 12)}…${p.did.slice(-6)}`;
}

/** Two-letter initials for the avatar fallback chip. */
function personInitials(label: string): string {
  const trimmed = label.replace(/^@/, "").trim();
  const parts = trimmed.split(/[\s.]+/).filter(Boolean);
  const first = parts[0]?.[0] ?? trimmed[0] ?? "?";
  const second = parts[1]?.[0] ?? "";
  return (first + second).toUpperCase();
}

function MarketingPage() {
  const { marketing } = Route.useLoaderData();

  return (
    <Page.Root variant="large" style={styles.root}>
      {/* ── Hero ─────────────────────────────────────────────── */}
      <section {...stylex.props(styles.hero)}>
        <div {...stylex.props(styles.heroTextCol)}>
          <div {...stylex.props(styles.eyebrow)}>
            <span {...stylex.props(styles.pulseDot)} />
            <span>an experiment in member-owned AI</span>
          </div>
          <h1 {...stylex.props(styles.heroTitle)}>
            An AI <span {...stylex.props(styles.heroAccent)}>cooperative.</span>
          </h1>
          <p {...stylex.props(styles.heroSub, ui.textDim)}>
            co/core is a place where people share the compute they already own to run AI for each
            other, instead of renting from a handful of giant providers. It's an experiment in
            inference we build, share, and own together — and your existing code works as-is,
            because we speak the same standard API everything else does. The models are open ones
            that run on the hardware people already have.
          </p>
          <Flex style={styles.ctaRow}>
            <ButtonLink to="/login" search={{ redirect: "/start" }} variant="primary" size="lg">
              Get started — it's free →
            </ButtonLink>
            <ButtonLink to="/docs/inference" variant="secondary" size="lg">
              See how it works
            </ButtonLink>
          </Flex>
          <a href={APP_DOWNLOAD_HREF} {...stylex.props(styles.installBar)}>
            <span {...stylex.props(styles.installPrompt)}>↓</span>
            <span>
              Have compute to share? Get the{" "}
              <span {...stylex.props(styles.installCmd)}>cocore app</span> — macOS, Apple Silicon
            </span>
          </a>
        </div>
        <HeroGooberFloat />
      </section>

      {/* ── Stats strip ───────────────────────────────────────── */}
      <div {...stylex.props(styles.statsStrip)}>
        <div {...stylex.props(styles.statItem)}>
          <div {...stylex.props(styles.statLabel)}>machines online</div>
          <div {...stylex.props(styles.statValue)}>
            {compactInt.format(marketing.stats.machinesOnline)}
          </div>
        </div>
        <div {...stylex.props(styles.statItem)}>
          <div {...stylex.props(styles.statLabel)}>models available</div>
          <div {...stylex.props(styles.statValue)}>
            {compactInt.format(marketing.stats.modelsAvailable)}
            {marketing.stats.modelsActiveWeek > 0 ? (
              <span {...stylex.props(styles.statUnit)}>
                {" "}
                / {compactInt.format(marketing.stats.modelsActiveWeek)} active (7d)
              </span>
            ) : null}
          </div>
        </div>
        <div {...stylex.props(styles.statItem)}>
          <div {...stylex.props(styles.statLabel)}>time to first token</div>
          <div {...stylex.props(styles.statValue)}>
            {marketing.stats.firstTokenP50Ms !== null ? (
              <>
                {formatLatencyMs(marketing.stats.firstTokenP50Ms)}
                <span {...stylex.props(styles.statUnit)}>p50</span>
              </>
            ) : (
              <>
                1<span {...stylex.props(styles.statUnit)}>token in/out</span>
              </>
            )}
          </div>
        </div>
        <div {...stylex.props(styles.statItem)}>
          <div {...stylex.props(styles.statLabel)}>combined memory</div>
          <div {...stylex.props(styles.statValue)}>
            {compactInt.format(marketing.stats.totalRamGB)}{" "}
            <span {...stylex.props(styles.statUnit)}>GB RAM</span>
          </div>
        </div>
        <div {...stylex.props(styles.statItem)}>
          <div {...stylex.props(styles.statLabel)}>combined cores</div>
          <div {...stylex.props(styles.statValue)}>
            {compactInt.format(marketing.stats.totalCpuCores)}{" "}
            <span {...stylex.props(styles.statUnit)}>cpu cores</span>
          </div>
        </div>
        <div {...stylex.props(styles.statItem)}>
          <div {...stylex.props(styles.statLabel)}>free to start</div>
          <div {...stylex.props(styles.statValue)}>
            {compactBig.format(marketing.stats.tokenGrant)}{" "}
            <span {...stylex.props(styles.statUnit)}>tokens</span>
          </div>
        </div>
      </div>

      {/* ── Live on the network ───────────────────────────────── */}
      <section {...stylex.props(styles.section)}>
        <Goober name="heron" size={220} style={styles.liveArt} />
        <div {...stylex.props(styles.sectionEyebrow)}>
          <span {...stylex.props(styles.pulseDot)} /> live on the network
        </div>
        <Heading2 style={styles.sectionH2}>Real members. Real machines. Real receipts.</Heading2>
        <Body style={styles.sectionSub}>
          A glimpse of the co-op right now — some of the people who've signed up, some of the
          machines sharing compute, and the latest jobs they've signed off on. Every one of these is
          a real, public record.
        </Body>

        <div {...stylex.props(styles.liveGrid)}>
          {/* People */}
          <div {...stylex.props(styles.liveCol)}>
            <div {...stylex.props(styles.liveColTitle)}>some cocore members</div>
            {marketing.live.people.length > 0 ? (
              <div {...stylex.props(styles.liveList)}>
                {marketing.live.people.map((p) => {
                  const label = personLabel(p);
                  return (
                    <Link
                      key={p.did}
                      to="/u/$identifier"
                      params={{ identifier: p.handle ?? p.did }}
                      {...stylex.props(styles.liveItem, styles.liveItemLink)}
                    >
                      <span {...stylex.props(styles.liveAvatar)}>
                        {p.avatarUrl ? (
                          <img
                            src={p.avatarUrl}
                            alt=""
                            loading="lazy"
                            {...stylex.props(styles.liveAvatarImg)}
                          />
                        ) : (
                          personInitials(label)
                        )}
                      </span>
                      <span {...stylex.props(styles.liveItemText)}>
                        <span {...stylex.props(styles.livePrimary)}>{label}</span>
                        {p.handle && p.displayName ? (
                          <span {...stylex.props(styles.liveSecondary)}>@{p.handle}</span>
                        ) : null}
                      </span>
                      {p.isProvider ? (
                        <span {...stylex.props(styles.liveBadge)}>provider</span>
                      ) : null}
                    </Link>
                  );
                })}
              </div>
            ) : (
              <div {...stylex.props(styles.liveEmpty)}>no members indexed yet</div>
            )}
          </div>

          {/* Machines */}
          <div {...stylex.props(styles.liveCol)}>
            <div {...stylex.props(styles.liveColTitle)}>machines sharing compute</div>
            {marketing.live.machines.length > 0 ? (
              <div {...stylex.props(styles.liveList)}>
                {marketing.live.machines.map((m, i) => {
                  const host = m.hostDisplayName ?? m.hostHandle;
                  return (
                    <div key={`${m.did}-${i}`} {...stylex.props(styles.liveItem)}>
                      <span {...stylex.props(styles.liveAvatar)}>▢</span>
                      <span {...stylex.props(styles.liveItemText)}>
                        <span {...stylex.props(styles.livePrimary)}>
                          {m.machineLabel ?? "a member's machine"}
                        </span>
                        <span {...stylex.props(styles.liveSecondary)}>
                          {[m.chip, host ? `· ${host}` : null].filter(Boolean).join(" ")}
                        </span>
                      </span>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div {...stylex.props(styles.liveEmpty)}>no machines indexed yet</div>
            )}
          </div>

          {/* Receipts */}
          <div {...stylex.props(styles.liveCol)}>
            <div {...stylex.props(styles.liveColTitle)}>recent job receipts</div>
            {marketing.live.receipts.length > 0 ? (
              <div {...stylex.props(styles.liveList)}>
                {marketing.live.receipts.map((r, i) => (
                  <div key={i} {...stylex.props(styles.liveReceiptRow)}>
                    <span {...stylex.props(styles.liveReceiptModel)}>{r.model}</span>
                    <span {...stylex.props(styles.liveReceiptMeta)}>
                      {r.tokens} · {r.providerShort}
                      {r.latencyMs !== null ? (
                        <span {...stylex.props(styles.liveLatency)}>
                          {" "}
                          · {formatLatencyMs(r.latencyMs)}
                        </span>
                      ) : null}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div {...stylex.props(styles.liveEmpty)}>no receipts indexed yet</div>
            )}
          </div>
        </div>
      </section>

      {/* ── Drop-in ───────────────────────────────────────────── */}
      <section {...stylex.props(styles.section)}>
        <div {...stylex.props(styles.standardGrid)}>
          <div>
            <div {...stylex.props(styles.sectionEyebrow)}>
              <span {...stylex.props(styles.sectionEyebrowNum)}>01</span> drop-in
            </div>
            <Heading2 style={styles.sectionH2}>Just change three lines.</Heading2>
            <Body style={[styles.sectionSub, styles.dropInSub]}>
              Cocore speaks the same API language as everybody else. Point your existing SDK at{" "}
              <InlineCode>console.cocore.dev/v1</InlineCode>, drop in a{" "}
              <InlineCode>cocore-…</InlineCode> key, and keep going — streaming, tool calls, and the
              usual <InlineCode>chat/completions</InlineCode> shape all work, no code changes. Host
              from our presets or any{" "}
              <a
                href="https://huggingface.co/models?library=mlx"
                target="_blank"
                rel="noreferrer"
                {...stylex.props(styles.inlineLink)}
              >
                MLX model
              </a>
              .
            </Body>
          </div>

          <div {...stylex.props(styles.compatDiagram)}>
            <div {...stylex.props(styles.compatDiagramInner)}>
              <svg viewBox="0 0 170 176" aria-hidden {...stylex.props(styles.compatFan)}>
                {["OpenAI", "Anthropic", "Together", "Groq", "Ollama"].map((name, i) => {
                  const y = 16 + i * 36;
                  return (
                    <g key={name}>
                      <text x="0" y={y + 4} fontSize="12.5" fill="currentColor">
                        {name}
                      </text>
                      <path
                        d={`M84 ${y} C124 ${y} 134 88 160 88`}
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1"
                        strokeOpacity="0.45"
                      />
                    </g>
                  );
                })}
                <circle cx="160" cy="88" r="2.5" fill="currentColor" />
              </svg>
              <span {...stylex.props(styles.compatBrand)}>
                <svg
                  viewBox="0 0 100 100"
                  fill="currentColor"
                  fillRule="evenodd"
                  aria-hidden
                  {...stylex.props(styles.compatMark)}
                >
                  <path d="M0 0 H100 V70 L70 100 H0 Z M22 22 V78 H55.6 L78 55.6 V22 Z" />
                </svg>
                co/core
              </span>
            </div>
          </div>
        </div>

        <div {...stylex.props(styles.swapGrid)}>
          <div {...stylex.props(styles.swapCard)}>
            <div {...stylex.props(styles.swapHead)}>
              <span>client.py</span>
              <span {...stylex.props(styles.swapBadge)}>before</span>
            </div>
            <pre {...stylex.props(styles.swapPre)}>
              <span {...stylex.props(styles.swapKw)}>from</span> openai{" "}
              <span {...stylex.props(styles.swapKw)}>import</span> OpenAI{"\n\n"}
              client = OpenAI({"\n"}
              {"    "}base_url=
              <span {...stylex.props(styles.swapStr)}>"https://api.openai.com/v1"</span>,{"\n"}
              {"    "}api_key=<span {...stylex.props(styles.swapStr)}>"sk-proj-…"</span>,{"\n"})
              {"\n\n"}
              resp = client.chat.completions.<span {...stylex.props(styles.swapFn)}>create</span>(
              {"\n"}
              {"    "}model=<span {...stylex.props(styles.swapStr)}>"gpt-4o-mini"</span>,{"\n"}
              {"    "}messages=[{"{"}
              <span {...stylex.props(styles.swapStr)}>"role"</span>:{" "}
              <span {...stylex.props(styles.swapStr)}>"user"</span>,{"\n"}
              {"               "}
              <span {...stylex.props(styles.swapStr)}>"content"</span>:{" "}
              <span {...stylex.props(styles.swapStr)}>"hello"</span>
              {"}"}],{"\n"}
              {"    "}stream=<span {...stylex.props(styles.swapKw)}>True</span>,{"\n"})
            </pre>
          </div>

          <div {...stylex.props(styles.swapCard)}>
            <div {...stylex.props(styles.swapHead)}>
              <span>client.py</span>
              <span {...stylex.props(styles.swapBadge, styles.swapBadgeAfter)}>after</span>
            </div>
            <pre {...stylex.props(styles.swapPre)}>
              <span {...stylex.props(styles.swapKw)}>from</span> openai{" "}
              <span {...stylex.props(styles.swapKw)}>import</span> OpenAI{"\n\n"}
              client = OpenAI({"\n"}
              {"    "}base_url=
              <span {...stylex.props(styles.swapHighlight)}>"https://console.cocore.dev/v1"</span>,
              {"\n"}
              {"    "}api_key=
              <span {...stylex.props(styles.swapHighlight)}>"cocore-7f3a2c…"</span>,{"\n"}){"\n\n"}
              resp = client.chat.completions.<span {...stylex.props(styles.swapFn)}>create</span>(
              {"\n"}
              {"    "}model=
              <span {...stylex.props(styles.swapHighlight)}>"mlx-community/Qwen2.5-0.5B"</span>,
              {"\n"}
              {"    "}messages=[{"{"}
              <span {...stylex.props(styles.swapStr)}>"role"</span>:{" "}
              <span {...stylex.props(styles.swapStr)}>"user"</span>,{"\n"}
              {"               "}
              <span {...stylex.props(styles.swapStr)}>"content"</span>:{" "}
              <span {...stylex.props(styles.swapStr)}>"hello"</span>
              {"}"}],{"\n"}
              {"    "}stream=<span {...stylex.props(styles.swapKw)}>True</span>,{"\n"})
            </pre>
          </div>
        </div>
      </section>

      {/* ── How it works ──────────────────────────────────────── */}
      <section {...stylex.props(styles.section)}>
        <div {...stylex.props(styles.sectionEyebrow)}>
          <span {...stylex.props(styles.sectionEyebrowNum)}>02</span> how it works
        </div>
        <Goober name="cloud" size={140} style={styles.sectionCloud} />
        <Heading2 style={styles.sectionH2}>You send a request. The co-op runs it.</Heading2>
        <Body style={styles.sectionSub}>
          Your request finds a member's available compute, runs the job, and comes back to you. The
          whole thing is an open spec — every job leaves a signed, public record anyone can verify
          for themselves, ours included.
        </Body>

        <div {...stylex.props(styles.steps)}>
          <div {...stylex.props(styles.stepColumn, styles.stepColumn1)}>
            <div {...stylex.props(styles.stepHead, styles.stepGridPadTop, styles.stepGridSep)}>
              <span {...stylex.props(styles.stepNum)}>1</span>
              <span {...stylex.props(styles.stepName)}>job</span>
            </div>
            <div {...stylex.props(styles.stepGridSep)}>
              <Heading3>You send a job</Heading3>
            </div>
            <div {...stylex.props(styles.stepGridSep)}>
              <Body variant="secondary">
                Your encrypted prompt heads out into the co-op. Run your prompt for a given model
                anywhere in the open network, or choose to keep your jobs private to only a trusted
                circle of co-op friends and their machines.
              </Body>
            </div>
            <div {...stylex.props(styles.stepCode)}>
              <div {...stylex.props(styles.stepCodeLine)}>
                <span {...stylex.props(styles.stepCodePrompt)}>→</span>
                <span {...stylex.props(styles.stepCodeAccent)}>dev.cocore.compute.job</span>
              </div>
              <div {...stylex.props(styles.stepCodeLine)}>
                <span {...stylex.props(styles.stepCodePrompt)}> </span>
                inputCommitment: sha256
              </div>
              <div {...stylex.props(styles.stepCodeLine)}>
                <span {...stylex.props(styles.stepCodePrompt)}> </span>priceCeiling:{" "}
                <span {...stylex.props(styles.stepCodeCmd)}>2,500 tokens</span>
              </div>
              <div {...stylex.props(styles.stepCodeLine)}>
                <span {...stylex.props(styles.stepCodePrompt)}> </span>acceptedTrustLevel: hw
              </div>
            </div>
          </div>

          <div {...stylex.props(styles.stepRule, styles.stepRuleCol2)} aria-hidden />

          <div {...stylex.props(styles.stepColumn, styles.stepColumn2)}>
            <div {...stylex.props(styles.stepHead, styles.stepGridPadTop, styles.stepGridSep)}>
              <span {...stylex.props(styles.stepNum)}>2</span>
              <span {...stylex.props(styles.stepName)}>attest + run</span>
            </div>
            <div {...stylex.props(styles.stepGridSep)}>
              <Heading3>A member runs it</Heading3>
            </div>
            <div {...stylex.props(styles.stepGridSep)}>
              <Body variant="secondary">
                Someone picks up your job, runs it, then returns the result after signing with a key
                locked in the Secure Enclave that never leaves their hardware — proof of exactly who
                did the work, and that nobody touched it after.
              </Body>
            </div>
            <div {...stylex.props(styles.stepCode)}>
              <div {...stylex.props(styles.stepCodeLine)}>
                <span {...stylex.props(styles.stepCodePrompt)}>→</span>
                <span {...stylex.props(styles.stepCodeAccent)}>dev.cocore.compute.receipt</span>
              </div>
              <div {...stylex.props(styles.stepCodeLine)}>
                <span {...stylex.props(styles.stepCodePrompt)}> </span>tokens:{" "}
                <span {...stylex.props(styles.stepCodeCmd)}>{marketing.steps.receiptTokens}</span>
              </div>
              <div {...stylex.props(styles.stepCodeLine)}>
                <span {...stylex.props(styles.stepCodePrompt)}> </span>price:{" "}
                <span {...stylex.props(styles.stepCodeCmd)}>{marketing.steps.receiptPrice}</span>
              </div>
              <div {...stylex.props(styles.stepCodeLine)}>
                <span {...stylex.props(styles.stepCodePrompt)}> </span>enclaveSig:{" "}
                <span {...stylex.props(styles.stepCodeCmd)}>✓ SE-bound</span>
              </div>
            </div>
          </div>

          <div {...stylex.props(styles.stepRule, styles.stepRuleCol4)} aria-hidden />

          <div {...stylex.props(styles.stepColumn, styles.stepColumn3)}>
            <div {...stylex.props(styles.stepHead, styles.stepGridPadTop, styles.stepGridSep)}>
              <span {...stylex.props(styles.stepNum)}>3</span>
              <span {...stylex.props(styles.stepName)}>settle</span>
            </div>
            <div {...stylex.props(styles.stepGridSep)}>
              <Heading3>Receipts, in the open</Heading3>
            </div>
            <div {...stylex.props(styles.stepGridSep)}>
              <Body variant="secondary">
                A receipt closes out the job — credits go to whomever who ran it, minus a small cut
                to a shared pot. Each month that pot splits back to members by how much they pitched
                in, so the cut cycles right back to the people running the network.
              </Body>
            </div>
            <div {...stylex.props(styles.stepCode)}>
              <div {...stylex.props(styles.stepCodeLine)}>
                <span {...stylex.props(styles.stepCodePrompt)}>→</span>
                <span {...stylex.props(styles.stepCodeAccent)}>dev.cocore.compute.settlement</span>
              </div>
              <div {...stylex.props(styles.stepCodeLine)}>
                <span {...stylex.props(styles.stepCodePrompt)}> </span>debit:{" "}
                <span {...stylex.props(styles.stepCodeCmd)}>
                  {marketing.steps.settlementCharged}
                </span>
              </div>
              <div {...stylex.props(styles.stepCodeLine)}>
                <span {...stylex.props(styles.stepCodePrompt)}> </span>credit:{" "}
                <span {...stylex.props(styles.stepCodeCmd)}>
                  {marketing.steps.settlementPayout}
                </span>
              </div>
              <div {...stylex.props(styles.stepCodeLine)}>
                <span {...stylex.props(styles.stepCodePrompt)}> </span>fee:{" "}
                <span {...stylex.props(styles.stepCodeCmd)}>{marketing.steps.settlementFee}</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── atproto callout ───────────────────────────────────── */}
      <section {...stylex.props(styles.section)}>
        <div {...stylex.props(styles.atpCallout)}>
          <div>
            <div {...stylex.props(styles.sectionEyebrow)}>
              <span {...stylex.props(styles.sectionEyebrowNum)}>03</span> open by default
            </div>
            <Heading2 style={styles.sectionH2}>You don't have to take our word for it.</Heading2>
            <Body style={styles.sectionSub}>
              Every job writes a receipt anyone can verify on their own, without ever calling us. We
              can't inflate a balance, fake a payout, or quietly change the rules. And if you don't
              like how we run things, you can run the whole thing yourself — point your own copy at
              the same data and it lands on exactly the same numbers.
            </Body>
            <div {...stylex.props(styles.atpFeatures)}>
              <div {...stylex.props(styles.atpFeature)}>
                <span {...stylex.props(styles.atpMark)}>◆</span>
                <div>
                  <div {...stylex.props(styles.atpFeatureTitle)}>
                    The record lives with the person who made it
                  </div>
                  <div {...stylex.props(styles.atpFeatureBody)}>
                    We keep a fast index, but the real, signed record of every job lives on the
                    provider's own account — not locked inside our database.
                  </div>
                </div>
              </div>
              <div {...stylex.props(styles.atpFeature)}>
                <span {...stylex.props(styles.atpMark)}>◆</span>
                <div>
                  <div {...stylex.props(styles.atpFeatureTitle)}>
                    Receipts check out on their own
                  </div>
                  <div {...stylex.props(styles.atpFeatureBody)}>
                    A receipt plus our public spec plus the signer's identity is all you need to
                    confirm a job happened — offline, with no cocore API in the loop.
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div {...stylex.props(styles.lexTable)}>
            {LEXICONS.map((lex) => (
              <div key={lex.name} {...stylex.props(styles.lexRow)}>
                <div {...stylex.props(styles.lexNsid)}>
                  <span {...stylex.props(styles.lexNs)}>dev.cocore.compute.</span>
                  {lex.name}
                </div>
                <div {...stylex.props(styles.lexOwner)}>
                  {lex.owner}
                  {lex.accent ? (
                    <span {...stylex.props(styles.lexOwnerAccent)}> {lex.accent}</span>
                  ) : null}
                </div>
              </div>
            ))}
          </div>
        </div>

        <p {...stylex.props(styles.proofCaption)}>
          Here's a real receipt and the records it points back to — the job you sent, the machine's
          attestation, and the public settlement. Follow the chain and check it yourself.
        </p>
        <div {...stylex.props(styles.chain, styles.proofChain)}>
          <div {...stylex.props(styles.chainHead)}>
            <div {...stylex.props(styles.chainLights)}>
              <span {...stylex.props(styles.chainLight, styles.chainLightRed)} />
              <span {...stylex.props(styles.chainLight, styles.chainLightYellow)} />
              <span {...stylex.props(styles.chainLight, styles.chainLightGreen)} />
            </div>
            <span>{marketing.hero.receiptUriDisplay}</span>
          </div>

          <div {...stylex.props(styles.chainRecord, styles.chainRecordSigned)}>
            <div {...stylex.props(styles.chainNsid, styles.chainNsidSigned)}>
              <span>dev.cocore.compute.receipt</span>
              <span {...stylex.props(styles.chainBy)}>{marketing.hero.signedByLine}</span>
            </div>
            <div {...stylex.props(styles.chainFieldsRow)}>
              <div {...stylex.props(styles.chainField)}>
                <span {...stylex.props(styles.chainKey)}>model</span>
                <span {...stylex.props(styles.chainValue)}>{marketing.hero.model}</span>
              </div>
              <div {...stylex.props(styles.chainField)}>
                <span {...stylex.props(styles.chainKey)}>tokens</span>
                <span {...stylex.props(styles.chainValue)}>{marketing.hero.tokens}</span>
              </div>
              <div {...stylex.props(styles.chainField)}>
                <span {...stylex.props(styles.chainKey)}>price</span>
                <span {...stylex.props(styles.chainValue)}>{marketing.hero.price}</span>
              </div>
              <div {...stylex.props(styles.chainField)}>
                <span {...stylex.props(styles.chainKey)}>enclaveSig</span>
                <span
                  {...stylex.props(
                    styles.chainValue,
                    marketing.hero.enclaveSigLabel.startsWith("✓") ? styles.chainValueOk : null,
                  )}
                >
                  {marketing.hero.enclaveSigLabel}
                </span>
              </div>
            </div>
          </div>

          <div {...stylex.props(styles.chainLink)}>
            <span {...stylex.props(styles.chainArrow)}>└─ strongRef →</span>
            <span>job</span>
          </div>
          <div {...stylex.props(styles.chainRecord)}>
            <div {...stylex.props(styles.chainNsid)}>
              <span>dev.cocore.compute.job</span>
              <span {...stylex.props(styles.chainBy)}>@you.bsky.social</span>
            </div>
            <div {...stylex.props(styles.chainFieldsRow)}>
              <div {...stylex.props(styles.chainField)}>
                <span {...stylex.props(styles.chainKey)}>inputHash</span>
                <span {...stylex.props(styles.chainValue)}>
                  sha256 7a3f…b9c1 <span {...stylex.props(styles.chainValueOk)}>✓</span>
                </span>
              </div>
              <div {...stylex.props(styles.chainField)}>
                <span {...stylex.props(styles.chainKey)}>priceCeiling</span>
                <span {...stylex.props(styles.chainValue)}>
                  2,500 tokens <span {...stylex.props(styles.chainValueOk)}>✓ within</span>
                </span>
              </div>
            </div>
          </div>

          <div {...stylex.props(styles.chainLink)}>
            <span {...stylex.props(styles.chainArrow)}>└─ strongRef →</span>
            <span>attestation</span>
          </div>
          <div {...stylex.props(styles.chainRecord)}>
            <div {...stylex.props(styles.chainNsid)}>
              <span>dev.cocore.compute.attestation</span>
              <span {...stylex.props(styles.chainBy)}>@kira.bsky</span>
            </div>
            <div {...stylex.props(styles.chainFieldsRow)}>
              <div {...stylex.props(styles.chainField)}>
                <span {...stylex.props(styles.chainKey)}>chip</span>
                <span {...stylex.props(styles.chainValue)}>Apple M3 Max · SIP on</span>
              </div>
              <div {...stylex.props(styles.chainField)}>
                <span {...stylex.props(styles.chainKey)}>MDA chain</span>
                <span {...stylex.props(styles.chainValue, styles.chainValueOk)}>
                  ✓ → Apple Root
                </span>
              </div>
            </div>
          </div>

          <div {...stylex.props(styles.chainLink)}>
            <span {...stylex.props(styles.chainArrow)}>└─ settled by →</span>
            <span>exchange</span>
          </div>
          <div {...stylex.props(styles.chainRecord)}>
            <div {...stylex.props(styles.chainNsid)}>
              <span>dev.cocore.compute.settlement</span>
              <span {...stylex.props(styles.chainBy)}>@cocore.dev</span>
            </div>
            <div {...stylex.props(styles.chainFieldsRow)}>
              <div {...stylex.props(styles.chainField)}>
                <span {...stylex.props(styles.chainKey)}>charged</span>
                <span {...stylex.props(styles.chainValue)}>{marketing.hero.charged}</span>
              </div>
              <div {...stylex.props(styles.chainField)}>
                <span {...stylex.props(styles.chainKey)}>payout</span>
                <span {...stylex.props(styles.chainValue)}>{marketing.hero.payout}</span>
              </div>
            </div>
          </div>

          <div {...stylex.props(styles.chainFoot)}>
            <span>verifier · plain HTTPS to 3 PDSes</span>
            <span {...stylex.props(styles.chainVerify)}>
              <span {...stylex.props(styles.pulseDot)} />
              verifyReceipt → ok
            </span>
          </div>
        </div>
      </section>

      {/* ── Open standard ─────────────────────────────────────── */}
      <section {...stylex.props(styles.section)}>
        <div {...stylex.props(styles.standardGrid)}>
          <div>
            <div {...stylex.props(styles.sectionEyebrow)}>
              <span {...stylex.props(styles.sectionEyebrowNum)}>04</span> an open standard
            </div>
            <Heading2 style={styles.sectionH2}>An open standard. Run your own exchange.</Heading2>
            <Body style={styles.sectionSub}>
              Underneath the co-op is an open standard for two plain things: making an inference
              request, and recording what happened afterward — a signed, public account of every
              job. We run one exchange on top of it, with our rules: one unit in, one unit out, a
              shared pot that goes back to members. But the standard is the real work here. Anyone
              can stand up a different exchange — their own pricing, their own membership, their own
              idea of what's fair — reading and writing the very same records. Ours is just the
              first one. If co/core ever stops being the version you want, you don't have to ask us
              to change it; you can go build yours.
            </Body>
          </div>

          <div {...stylex.props(styles.diagram)}>
            <div {...stylex.props(styles.diagramCap)}>the records · signed + public</div>
            <div {...stylex.props(styles.diagramNode)}>
              <span>job</span>
              <span {...stylex.props(styles.diagramTag)}>from requester</span>
            </div>
            <div {...stylex.props(styles.diagramArrow)}>↓</div>
            <div {...stylex.props(styles.diagramNode, styles.diagramNodeSigned)}>
              <span>receipt</span>
              <span {...stylex.props(styles.diagramTag)}>signed by who ran it</span>
            </div>
            <div {...stylex.props(styles.diagramArrow)}>↓</div>
            <div {...stylex.props(styles.diagramNode)}>
              <span>settlement</span>
              <span {...stylex.props(styles.diagramTag)}>from an exchange</span>
            </div>
            <div {...stylex.props(styles.diagramRule)} />
            <div {...stylex.props(styles.diagramFootLabel)}>any exchange reads + writes them</div>
            <div {...stylex.props(styles.diagramExchanges)}>
              <span {...stylex.props(styles.diagramExchange, styles.diagramExchangeUs)}>
                ◆ co/core
              </span>
              <span {...stylex.props(styles.diagramExchange)}>your exchange</span>
              <span {...stylex.props(styles.diagramExchange)}>another</span>
            </div>
          </div>
        </div>
      </section>

      {/* ── Provider CTA ──────────────────────────────────────── */}
      <section {...stylex.props(styles.section)}>
        <div {...stylex.props(styles.provider)}>
          <div {...stylex.props(styles.providerCard)}>
            <div {...stylex.props(styles.providerEyebrow)}>share your compute</div>
            <h2 {...stylex.props(styles.providerTitle)}>Share your compute. Help run the co-op.</h2>
            <p {...stylex.props(styles.providerBody)}>
              Download the cocore app, sign in, pick a model or two, and your computer joins the
              network — running jobs for other members while you're not using it. No Terminal,
              nothing to babysit; it updates itself. Every job it runs adds to your balance, and a
              share of everything the co-op does comes back to members each month.
            </p>
            <div {...stylex.props(styles.providerInstall)}>
              <span {...stylex.props(styles.providerInstallPrompt)}>↓</span>
              <span {...stylex.props(styles.providerInstallCmd)}>download the cocore app</span>
              <span {...stylex.props(styles.providerInstallNote)}>→ open · sign in · serve</span>
            </div>
            <Flex gap="md" wrap>
              <ButtonLink to="/login" search={{ redirect: "/start" }} variant="primary" size="md">
                Pair a machine →
              </ButtonLink>
              <ButtonLink to="/docs/inference" variant="secondary" size="md">
                Read the docs
              </ButtonLink>
            </Flex>
          </div>

          <div {...stylex.props(styles.providerChecklist)}>
            <div {...stylex.props(styles.providerCheck)}>
              <span {...stylex.props(styles.providerTick)}>✓</span>
              <div>
                <div {...stylex.props(styles.providerCheckTitle)}>Your machine, your key</div>
                <div {...stylex.props(styles.providerCheckBody)}>
                  A key born inside the Secure Enclave is your machine's identity — it can't be
                  copied off the machine, and it signs everything your machine does.
                </div>
              </div>
            </div>
            <div {...stylex.props(styles.providerCheck)}>
              <span {...stylex.props(styles.providerTick)}>✓</span>
              <div>
                <div {...stylex.props(styles.providerCheckTitle)}>One token in, one token out</div>
                <div {...stylex.props(styles.providerCheckBody)}>
                  The same price for everyone, set in the open. Every job moves tokens three ways:
                  the requester spends, your machine keeps 95%, and 5% goes to a shared pot that
                  goes back to members every month.
                </div>
              </div>
            </div>
            <div {...stylex.props(styles.providerCheck)}>
              <span {...stylex.props(styles.providerTick)}>✓</span>
              <div>
                <div {...stylex.props(styles.providerCheckTitle)}>Run your own jobs free</div>
                <div {...stylex.props(styles.providerCheckBody)}>
                  Serving a job to yourself costs no fee — but it still writes a receipt, so the
                  trail stays complete.
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
    </Page.Root>
  );
}
