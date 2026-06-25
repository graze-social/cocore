"use client";

import * as stylex from "@stylexjs/stylex";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { MoreHorizontal } from "lucide-react";
import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";

import { Link as RouterLink, useNavigate } from "@tanstack/react-router";

import { Avatar } from "@/design-system/avatar";
import { Button } from "@/design-system/button";
import {
  Card,
  CardBody,
  CardDescription,
  CardHeader,
  CardHeaderAction,
  CardTitle,
} from "@/design-system/card";
import { Checkbox } from "@/design-system/checkbox";
import { CopyToClipboardButton } from "@/design-system/copy-to-clipboard-button";
import { TrustTierBadge } from "@/components/TrustTierBadge.tsx";
import {
  Dialog,
  DialogBody,
  DialogDescription,
  DialogFooter,
  DialogHeader,
} from "@/design-system/dialog";
import { Flex } from "@/design-system/flex";
import { IconButton } from "@/design-system/icon-button";
import { Kbd } from "@/design-system/kbd";
import { ListBoxSeparator } from "@/design-system/listbox";
import { Menu, MenuItem } from "@/design-system/menu";
import { SegmentedControl, SegmentedControlItem } from "@/design-system/segmented-control";
import { Switch } from "@/design-system/switch";
import { Tag, TagGroup } from "@/design-system/tag-group";
import { TextField } from "@/design-system/text-field";
import {
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
} from "@/design-system/table";
import { Alert } from "@/design-system/alert";
import { Link } from "@/design-system/link";
import {
  criticalColor,
  primaryColor,
  successColor,
  uiColor,
  warningColor,
} from "@/design-system/theme/color.stylex";
import { breakpoints } from "@/design-system/theme/media-queries.stylex";
import { radius } from "@/design-system/theme/radius.stylex";
import { ui } from "@/design-system/theme/semantic-color.stylex";
import { gap, horizontalSpace, verticalSpace } from "@/design-system/theme/semantic-spacing.stylex";
import {
  fontFamily,
  fontSize,
  fontWeight,
  lineHeight,
} from "@/design-system/theme/typography.stylex";
import { toasts } from "@/design-system/toast";
import {
  Body,
  Heading1,
  Heading4,
  InlineCode,
  LabelText,
  SmallBody,
} from "@/design-system/typography";

import {
  CLI_LINES_INSTALL as CLI_LINES,
  CLI_ONE_LINER_INSTALL as CLI_ONE_LINER,
} from "@/components/machines/cli-snippets.ts";
import {
  listMyFriendsQueryOptions,
  type ListedFriend,
} from "@/components/friends/friends.functions.ts";
import { ProBonoBadge, RegionFlag } from "@/components/machines/MachineBadges.tsx";
import {
  dedupMyProviderRecordsMutationOptions,
  deleteMyProviderRecordMutationOptions,
  listMyMachinesQueryOptions,
  recoverMachineMutationOptions,
  setMyProviderActiveMutationOptions,
  setMyProviderDesiredModelsMutationOptions,
  setMyProviderMachineLabelMutationOptions,
  type MyMachinesPayload,
} from "@/components/machines/machines.functions.ts";
import { formatTokens, formatTokensCompact } from "@/lib/token-display.ts";

import { type Machine, type MachineState } from "./machines-data.ts";
import { Page } from "@/design-system/page/index.tsx";
import { Text } from "@/design-system/typography/text.tsx";
import { ResizableTableContainer, Collection } from "react-aria-components";

const FLEET_TABLE_COLUMNS: {
  id: string;
  name: string;
  width?: number;
  minWidth?: number;
  maxWidth?: number;
}[] = [
  { id: "alias", name: "Alias", width: 320 },
  { id: "state", name: "State", width: 80 },
  { id: "gpu", name: "GPU", width: 120 },
  { id: "job", name: "Status", minWidth: 140 },
  { id: "earned", name: "Earned · 24h (tokens)", width: 200 },
  { id: "actions", name: "\u00a0", width: 40 },
];

/** Per-model RAM floor, mirrored from the provider agent's price
 *  catalog (`provider/src/pricing.rs` \u2014 `RATES[].min_ram_gb` +
 *  `description`). This is a UX hint only: it lets the picker warn an
 *  operator before they pin a model their machine can't plausibly load.
 *  It is NOT an allow-list and never blocks a save \u2014 the agent's own
 *  catalog remains the source of truth, and an unlisted model simply
 *  gets no warning. Keep in sync with pricing.rs when floors change. */
interface ModelFloor {
  /** Floor RAM in GB below which the model is unlikely to load. */
  minRamGB: number;
  /** Short human label for the warning copy (e.g. "Qwen2.5-3B"). */
  label: string;
}

const MODEL_RAM_FLOORS: Readonly<Record<string, ModelFloor>> = {
  "mlx-community/Qwen2.5-0.5B-Instruct-4bit": { minRamGB: 4, label: "Qwen2.5-0.5B" },
  "mlx-community/Qwen2.5-3B-Instruct-4bit": { minRamGB: 8, label: "Qwen2.5-3B" },
  "mlx-community/Qwen2.5-7B-Instruct-4bit": { minRamGB: 16, label: "Qwen2.5-7B" },
  "mlx-community/gemma-3-4b-it-qat-4bit": { minRamGB: 8, label: "Gemma 3 4B" },
  "mlx-community/Qwen2.5-32B-Instruct-4bit": { minRamGB: 32, label: "Qwen2.5-32B" },
  "mlx-community/Llama-3.3-70B-Instruct-4bit": { minRamGB: 64, label: "Llama 3.3 70B" },
};

interface RamWarning {
  modelId: string;
  label: string;
  minRamGB: number;
}

/** Non-blocking RAM check for the picker: returns one entry per
 *  selected model whose floor exceeds the machine's RAM. A model with
 *  no known floor (free-text / unlisted) is never flagged. `machineRam`
 *  of 0 / unknown is treated as "can't assess" \u2014 no warnings, since a
 *  false alarm is worse than a missing hint. */
function ramWarningsFor(selected: readonly string[], machineRam: number): RamWarning[] {
  if (!machineRam || machineRam <= 0) return [];
  const out: RamWarning[] = [];
  for (const modelId of selected) {
    const floor = MODEL_RAM_FLOORS[modelId];
    if (floor && floor.minRamGB > machineRam) {
      out.push({ modelId, label: floor.label, minRamGB: floor.minRamGB });
    }
  }
  return out;
}

/** Curated MLX models offered as one-click suggestions in the "Manage
 *  models" picker. Mirrors the agent's built-in catalog. Any MLX model
 *  NSID works via the free-text input \u2014 this is just a convenience list,
 *  not an allow-list. */
const SUGGESTED_MODELS: readonly string[] = Object.keys(MODEL_RAM_FLOORS);

const FLEET_FULL_COLUMN: { id: string; name: string }[] = [{ id: "full", name: "" }];

type FleetBodyRow = Machine | { id: string; kind: "empty" };

function isFleetEmptyRow(row: FleetBodyRow): row is { id: string; kind: "empty" } {
  return "kind" in row && row.kind === "empty";
}

const styles = stylex.create({
  chartTitle: {
    fontSize: fontSize.base,
    fontWeight: fontWeight.medium,
    color: uiColor.text2,
    textTransform: "lowercase",
  },
  chartDescription: {
    fontSize: fontSize.xs,
    color: uiColor.text1,
    fontWeight: fontWeight.normal,
  },
  aliasColumn: {
    paddingLeft: horizontalSpace["xs"],
  },
  aliasCellContent: {
    paddingLeft: horizontalSpace["md"],
  },
  aliasLink: {
    color: uiColor.text2,
    cursor: "pointer",
    fontFamily: fontFamily.mono,
    textDecorationLine: {
      default: "none",
      ":hover": "underline",
    },
  },
  header: {
    marginBottom: 0,
  },
  headerActions: {
    flexWrap: "wrap",
    rowGap: gap.sm,
  },
  root: {
    display: "flex",
    flexDirection: "column",
    gap: verticalSpace["2xl"],
    fontFamily: fontFamily.mono,
    maxWidth: "1600px",
    marginLeft: "auto",
    marginRight: "auto",
  },
  pageHead: {
    alignItems: "flex-end",
    justifyContent: "space-between",
    gap: horizontalSpace["4xl"],
    display: "flex",
    flexWrap: "wrap",
  },
  titlePrompt: {
    color: uiColor.text1,
    fontWeight: fontWeight.normal,
  },
  headingMono: {
    fontFamily: fontFamily.mono,
  },
  pairSuccessCard: {
    backgroundColor: uiColor.bgSubtle,
    borderColor: uiColor.border1,
    borderRadius: radius.md,
    borderStyle: "solid",
    borderWidth: 1,
    padding: horizontalSpace["3xl"],
  },
  rigIdMuted: {
    color: uiColor.text1,
    fontWeight: fontWeight.normal,
    marginLeft: horizontalSpace.sm,
  },
  helpCenter: {
    marginTop: verticalSpace.sm,
    textAlign: "center",
  },
  modelAddRow: {
    alignItems: "flex-end",
  },
  modelAddField: {
    flex: 1,
  },
  modelSuggestList: {
    display: "flex",
    flexWrap: "wrap",
    gap: gap.sm,
  },
  errText: {
    color: criticalColor.text1,
  },
  tableId: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
  },
  gpuMeta: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
  },
  earnZero: {
    color: uiColor.border2,
  },
  earnCents: {
    color: uiColor.text1,
  },
  kvGrid: {
    columnGap: horizontalSpace.lg,
    display: "grid",
    fontSize: fontSize.sm,
    gridTemplateColumns: "90px 1fr",
    rowGap: verticalSpace.xs,
  },
  kvDt: {
    color: uiColor.text1,
  },
  kvDd: {
    color: uiColor.text2,
    margin: 0,
    // Long model identifiers must wrap inside the value column rather
    // than widen the drawer and trigger horizontal scroll.
    overflowWrap: "anywhere",
    minWidth: 0,
  },
  metricVal: {
    fontSize: fontSize.lg,
    marginTop: verticalSpace.xs,
  },
  chartPct: {
    color: uiColor.text1,
    fontSize: fontSize.sm,
  },
  metaRow: {
    color: uiColor.text1,
    fontSize: fontSize.sm,
    gap: horizontalSpace.lg,
    alignItems: "center",
    display: "flex",
    flexWrap: "wrap",
    marginTop: verticalSpace.sm,
    lineHeight: lineHeight["lg"],
  },
  metaSep: {
    color: uiColor.border2,
  },
  statsGrid: {
    display: "grid",
    gap: gap["2xl"],
    gridTemplateColumns: {
      default: "1fr",
      [breakpoints.sm]: "repeat(2, 1fr)",
      [breakpoints.lg]: "repeat(4, 1fr)",
    },
  },
  statSpark: {
    bottom: verticalSpace.sm,
    opacity: 0.55,
    position: "absolute",
    right: horizontalSpace.sm,
  },
  statCard: {
    position: "relative",
  },
  statLabel: {
    fontSize: fontSize.xs,
    letterSpacing: "0.04em",
    textTransform: "lowercase",
  },
  statValue: {
    fontSize: fontSize["3xl"],
    fontVariantNumeric: "tabular-nums",
    fontWeight: fontWeight.medium,
    letterSpacing: "-0.02em",
    marginTop: verticalSpace.sm,
  },
  statFrac: {
    color: uiColor.text1,
    fontWeight: fontWeight.normal,
  },
  statDelta: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
    fontVariantNumeric: "tabular-nums",
    marginTop: verticalSpace.xs,
  },
  statDeltaUp: {
    color: successColor.solid1,
  },
  chartsRow: {
    display: "grid",
    gap: gap["2xl"],
    gridTemplateColumns: {
      default: "1fr",
      [breakpoints.lg]: "1fr 1fr",
    },
  },
  chartReadout: {
    alignItems: "baseline",
    display: "flex",
    gap: horizontalSpace["3xl"],
    marginBottom: verticalSpace.sm,
  },
  chartBig: {
    fontSize: fontSize.xl,
    fontVariantNumeric: "tabular-nums",
    fontWeight: fontWeight.medium,
  },
  chartSmall: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
    fontVariantNumeric: "tabular-nums",
  },
  fleetHeader: {
    marginBottom: 0,
  },
  fleetHead: {
    alignItems: "center",
    justifyContent: "space-between",
    gap: horizontalSpace.lg,
    display: "flex",
    flexWrap: "wrap",
  },
  fleetTitleCount: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
    fontWeight: fontWeight.normal,
    marginLeft: horizontalSpace.sm,
  },
  tableWrap: {
    overflowX: "auto",
    width: "100%",
  },
  /** Desktop (>=48rem): the wide multi-column table. Hidden on narrow
   *  screens where it would force horizontal scroll. */
  fleetTableDesktop: {
    display: {
      default: "none",
      [breakpoints.md]: "block",
    },
  },
  /** Mobile (<48rem): a stacked card-per-machine list that fits the
   *  viewport width. Hidden at >=48rem where the table takes over. */
  fleetCardList: {
    display: {
      default: "flex",
      [breakpoints.md]: "none",
    },
    flexDirection: "column",
    gap: gap.lg,
    padding: horizontalSpace.lg,
  },
  fleetCardEmpty: {
    color: uiColor.text1,
    fontSize: fontSize.sm,
    paddingBottom: verticalSpace["4xl"],
    paddingTop: verticalSpace["4xl"],
    textAlign: "center",
  },
  fleetCard: {
    backgroundColor: uiColor.bg,
    borderColor: uiColor.border1,
    borderRadius: radius.md,
    borderStyle: "solid",
    borderWidth: 1,
    display: "flex",
    flexDirection: "column",
    gap: gap.md,
    minWidth: 0,
    overflow: "hidden",
    padding: horizontalSpace.xl,
  },
  fleetCardHead: {
    alignItems: "flex-start",
    display: "flex",
    gap: horizontalSpace.md,
    justifyContent: "space-between",
  },
  fleetCardIdentity: {
    display: "flex",
    flexDirection: "column",
    gap: gap.xs,
    minWidth: 0,
  },
  fleetCardAlias: {
    color: uiColor.text2,
    cursor: "pointer",
    fontFamily: fontFamily.mono,
    overflowWrap: "anywhere",
    textDecorationLine: {
      default: "none",
      ":hover": "underline",
    },
  },
  fleetCardRkey: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
    overflowWrap: "anywhere",
  },
  fleetCardState: {
    alignItems: "center",
    color: uiColor.text2,
    display: "flex",
    flexShrink: 0,
    fontSize: fontSize.sm,
    gap: horizontalSpace.sm,
  },
  fleetCardMetaRow: {
    alignItems: "baseline",
    color: uiColor.text1,
    display: "flex",
    flexWrap: "wrap",
    fontSize: fontSize.xs,
    gap: horizontalSpace.lg,
  },
  fleetCardEarn: {
    color: uiColor.text2,
  },
  fleetCardStatus: {
    overflowWrap: "anywhere",
  },
  fleetCardFooter: {
    alignItems: "center",
    display: "flex",
    gap: horizontalSpace.md,
    justifyContent: "space-between",
  },
  fleetCardDrawerWrap: {
    borderTopColor: uiColor.border1,
    borderTopStyle: "solid",
    borderTopWidth: 1,
    marginLeft: `calc(-1 * ${horizontalSpace.xl})`,
    marginRight: `calc(-1 * ${horizontalSpace.xl})`,
  },
  fleetCellEndContent: {
    textAlign: "right",
    width: "100%",
  },
  fleetEmptyCell: {
    paddingBottom: verticalSpace["6xl"],
    paddingTop: verticalSpace["6xl"],
    textAlign: "center",
  },
  row: {
    cursor: "pointer",
    transitionDuration: "0.12s",
    transitionProperty: "background-color",
    transitionTimingFunction: "ease",
    ":hover": {
      backgroundColor: uiColor.bgSubtle,
    },
  },
  rowExpanded: {
    backgroundColor: uiColor.bgSubtle,
  },
  rowActions: {
    gap: gap.xs,
    justifyContent: "flex-end",
    display: "flex",
  },
  statusDot: {
    borderRadius: radius.full,
    flexShrink: 0,
    height: 7,
    width: 7,
  },
  statusRunning: {
    animationDuration: "1.6s",
    animationIterationCount: "infinite",
    animationName: stylex.keyframes({
      "0%, 100%": { opacity: 1 },
      "50%": { opacity: 0.5 },
    }),
    animationTimingFunction: "ease-in-out",
    backgroundColor: successColor.solid1,
    boxShadow: `0 0 0 3px ${successColor.bgSubtle}`,
  },
  statusProvisioning: {
    animationDuration: "1.2s",
    animationIterationCount: "infinite",
    animationName: stylex.keyframes({
      "0%, 100%": { opacity: 1 },
      "50%": { opacity: 0.4 },
    }),
    animationTimingFunction: "ease-in-out",
    backgroundColor: warningColor.solid1,
    boxShadow: `0 0 0 3px ${warningColor.bgSubtle}`,
  },
  statusIdle: {
    backgroundColor: primaryColor.solid2,
  },
  statusPaused: {
    backgroundColor: uiColor.solid2,
  },
  statusOffline: {
    backgroundColor: criticalColor.solid1,
    opacity: 0.75,
  },
  statusFault: {
    backgroundColor: criticalColor.solid1,
  },
  faultText: {
    color: criticalColor.text1,
  },
  drawer: {
    display: "grid",
    gridTemplateColumns: {
      default: "1fr",
      [breakpoints.md]: "1.4fr 1fr 1fr",
    },
    paddingBottom: verticalSpace["2xl"],
    paddingLeft: horizontalSpace["3xl"],
    paddingRight: horizontalSpace["3xl"],
    paddingTop: verticalSpace.md,
  },
  drawerSection: {
    borderRightColor: uiColor.border1,
    borderRightStyle: "solid",
    borderRightWidth: {
      default: 0,
      [breakpoints.md]: 1,
    },
    padding: horizontalSpace["4xl"],
  },
  /** Third column: must win over `drawerSection` md border (pseudo + media merge order). */
  drawerSectionLast: {
    borderRightStyle: "none",
    borderRightWidth: 0,
  },
  metricGrid: {
    display: "grid",
    gap: gap.sm,
    gridTemplateColumns: "1fr 1fr",
    marginBottom: verticalSpace.lg,
  },
  metricCell: {
    backgroundColor: uiColor.bgSubtle,
    borderColor: uiColor.border1,
    borderRadius: radius.md,
    borderStyle: "solid",
    borderWidth: 1,
    padding: horizontalSpace.lg,
  },
  /** Right column of the 2×2 metrics grid — avoids a double line with the drawer edge. */
  metricCellGridEnd: {
    borderRightWidth: 0,
  },
  cliBox: {
    backgroundColor: uiColor.component1,
    borderRadius: radius.md,
    color: uiColor.text2,
    fontSize: fontSize.xs,
    lineHeight: lineHeight.base,
    paddingBottom: verticalSpace["3xl"],
    paddingLeft: horizontalSpace["2xl"],
    paddingRight: horizontalSpace["2xl"],
    paddingTop: verticalSpace["3xl"],
    position: "relative",
  },
  cliCopy: {
    position: "absolute",
    right: horizontalSpace.sm,
    top: verticalSpace.sm,
  },
  cliPrompt: {
    color: successColor.solid1,
    marginRight: horizontalSpace.md,
    userSelect: "none",
  },
  codeInputRow: {
    alignItems: "center",
    display: "flex",
    gap: horizontalSpace.sm,
    justifyContent: "center",
    marginTop: verticalSpace["4xl"],
  },
  codeDigit: {
    backgroundColor: uiColor.bgSubtle,
    borderColor: uiColor.border2,
    borderRadius: radius.md,
    borderStyle: "solid",
    borderWidth: 1,
    color: uiColor.text2,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.lg,
    fontWeight: fontWeight.medium,
    height: 44,
    textAlign: "center",
    textTransform: "uppercase",
    width: 32,
  },
  codeDigitFilled: {
    backgroundColor: uiColor.bg,
  },
  codeError: {
    borderColor: criticalColor.border2,
  },
  successIcon: {
    alignItems: "center",
    backgroundColor: successColor.bgSubtle,
    borderRadius: radius.full,
    color: successColor.solid1,
    display: "grid",
    fontSize: fontSize.xl,
    height: 48,
    marginBottom: verticalSpace.lg,
    marginLeft: "auto",
    marginRight: "auto",
    placeItems: "center",
    width: 48,
  },
  footerRow: {
    borderTopColor: uiColor.border1,
    borderTopStyle: "dashed",
    borderTopWidth: 1,
    color: uiColor.text1,
    fontSize: fontSize.xs,
    justifyContent: "space-between",
    marginTop: verticalSpace.lg,
    paddingTop: verticalSpace.lg,
    display: "flex",
    flexWrap: "wrap",
    gap: horizontalSpace.lg,
  },
  chartTooltip: {
    borderRadius: radius.sm,
    color: uiColor.textContrast,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.xs,
    paddingBottom: verticalSpace.xs,
    paddingLeft: horizontalSpace.sm,
    paddingRight: horizontalSpace.sm,
    paddingTop: verticalSpace.xs,
    pointerEvents: "none",
    position: "absolute",
    transform: "translate(-50%, -100%)",
    whiteSpace: "nowrap",
    zIndex: 10,
  },
  detailCell: {
    backgroundColor: uiColor.bgSubtle,
    borderBottomColor: uiColor.border1,
    borderBottomStyle: "solid",
    borderBottomWidth: 1,
    borderLeftWidth: 0,
    borderRightWidth: 0,
    borderTopWidth: 0,
    padding: 0,
  },
  detailRow: {
    cursor: "default",
  },
});

function formatFetchedAgo(iso: string): string {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "";
  const sec = Math.round((Date.now() - t) / 1000);
  if (sec < 8) return "just now";
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 120) return `${min}m ago`;
  return new Date(iso).toLocaleString();
}

function showToast(title: string) {
  toasts.add({ title }, { timeout: 2400 });
}

function csvEscape(cell: string): string {
  return `"${cell.replace(/"/g, '""')}"`;
}

function downloadFleetCsv(payload: MyMachinesPayload | undefined) {
  if (!payload?.did) {
    showToast("Sign in to export");
    return;
  }
  const lines: string[] = [];
  const { receiptStats: rs } = payload;
  lines.push(csvEscape("section"), csvEscape("field"), csvEscape("value"));
  lines.push(csvEscape("account"), csvEscape("did"), csvEscape(payload.did));
  lines.push(csvEscape("summary"), csvEscape("exportedAt"), csvEscape(payload.fetchedAt));
  if (rs) {
    lines.push(
      csvEscape("summary"),
      csvEscape("earn24hTokens"),
      csvEscape(String(rs.earn24hTokens)),
    );
    lines.push(csvEscape("summary"), csvEscape("earn7dTokens"), csvEscape(String(rs.earn7dTokens)));
    lines.push(
      csvEscape("summary"),
      csvEscape("earn30dTokens"),
      csvEscape(String(rs.earn30dTokens)),
    );
    lines.push(csvEscape("summary"), csvEscape("jobs24h"), csvEscape(String(rs.jobs24h)));
    lines.push(csvEscape("summary"), csvEscape("jobs7d"), csvEscape(String(rs.jobs7d)));
    lines.push(csvEscape("summary"), csvEscape("jobs30d"), csvEscape(String(rs.jobs30d)));
  }
  lines.push(csvEscape("machines"), csvEscape("header"), csvEscape(""));
  lines.push(
    [
      "alias",
      "record_key",
      "state",
      "chip_label",
      "ram_gb",
      "trust_level",
      "earnings_24h_tokens",
      "earnings_7d_tokens",
      "earnings_lifetime_tokens",
      "jobs_completed_index",
      "paired_at",
    ]
      .map(csvEscape)
      .join(","),
  );
  for (const m of payload.machines) {
    lines.push(
      [
        m.alias,
        m.id,
        m.state,
        m.gpu,
        String(m.ram),
        m.trustLevel ?? "",
        String(m.earnings24h),
        String(m.earnings7d),
        String(m.earningsLifetime),
        String(m.jobsCompleted),
        m.pairedAt,
      ]
        .map((c) => csvEscape(c))
        .join(","),
    );
  }
  const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const slug = payload.did.replace(/[^\w.:+-]/g, "_").slice(0, 48);
  a.download = `cocore-fleet-${slug}-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
  showToast("Fleet export downloaded");
}

function smoothPath(points: [number, number][]) {
  if (points.length < 2) return "";
  const p0 = points[0];
  if (!p0) return "";
  const d = [`M ${p0[0]},${p0[1]}`];
  for (let i = 1; i < points.length; i++) {
    const [x0, y0] = points[i - 1]!;
    const [x1, y1] = points[i]!;
    const cx = (x0 + x1) / 2;
    d.push(`C ${cx},${y0} ${cx},${y1} ${x1},${y1}`);
  }
  return d.join(" ");
}

function UtilChart({
  data,
  xTickIndices,
  xLabel,
}: {
  data: number[];
  xTickIndices: number[];
  xLabel: (i: number) => string;
}) {
  const gid = useId().replace(/:/g, "");
  const W = 540;
  const H = 160;
  const P = { t: 14, r: 12, b: 22, l: 28 };
  const innerW = W - P.l - P.r;
  const innerH = H - P.t - P.b;
  const max = 100;
  const [hover, setHover] = useState<number | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);

  const count = Math.max(1, data.length);
  const denom = Math.max(1, count - 1);
  const xAt = (i: number) => P.l + (i / denom) * innerW;
  const yAt = (v: number) => P.t + innerH - (v / max) * innerH;
  const points = data.map((v, i) => [xAt(i), yAt(v)] as [number, number]);
  const linePath =
    data.length < 2
      ? `M ${P.l},${yAt(data[0] ?? 0)} L ${W - P.r},${yAt(data[0] ?? 0)}`
      : smoothPath(points);
  const areaPath = `${linePath} L ${xAt(count - 1)},${P.t + innerH} L ${xAt(0)},${P.t + innerH} Z`;

  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const r = svgRef.current?.getBoundingClientRect();
    if (!r) return;
    const x = ((e.clientX - r.left) / r.width) * W;
    const i = Math.round(((x - P.l) / innerW) * (count - 1));
    if (i >= 0 && i < data.length) setHover(i);
  };

  const gridY = [0, 25, 50, 75, 100];

  return (
    <div style={{ position: "relative" }}>
      <svg
        ref={svgRef}
        viewBox={`0 0 ${W} ${H}`}
        width="100%"
        preserveAspectRatio="xMidYMid meet"
        style={{ height: "auto", display: "block" }}
        onMouseMove={onMove}
        onMouseLeave={() => setHover(null)}
      >
        <defs>
          <linearGradient id={`util-grad-${gid}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={successColor.solid1} stopOpacity="0.22" />
            <stop offset="100%" stopColor={successColor.solid1} stopOpacity="0.02" />
          </linearGradient>
        </defs>
        {gridY.map((v) => (
          <g key={v}>
            <line
              x1={P.l}
              x2={W - P.r}
              y1={yAt(v)}
              y2={yAt(v)}
              stroke={uiColor.border1}
              strokeWidth="0.5"
              strokeDasharray={v === 0 ? "0" : "2 3"}
            />
            <text
              x={P.l - 6}
              y={yAt(v) + 3}
              fontSize="9.5"
              textAnchor="end"
              fill={uiColor.text1}
              fontFamily={fontFamily.mono}
            >
              {v}
            </text>
          </g>
        ))}
        {xTickIndices.map((i) => (
          <text
            key={i}
            x={xAt(i)}
            y={H - 6}
            fontSize="9.5"
            textAnchor="middle"
            fill={uiColor.text1}
            fontFamily={fontFamily.mono}
          >
            {xLabel(i)}
          </text>
        ))}
        <path d={areaPath} fill={`url(#util-grad-${gid})`} />
        <path d={linePath} fill="none" stroke={successColor.solid1} strokeWidth="1.5" />
        {points.map(([x, y], i) => (
          <circle
            key={i}
            cx={x}
            cy={y}
            r={hover === i ? 3.5 : 0}
            fill={successColor.solid1}
            stroke={uiColor.bg}
            strokeWidth="1.5"
          />
        ))}
        {hover != null && (
          <line
            x1={xAt(hover)}
            x2={xAt(hover)}
            y1={P.t}
            y2={P.t + innerH}
            stroke={uiColor.solid2}
            strokeWidth="0.5"
            strokeDasharray="2 2"
          />
        )}
      </svg>
      {hover != null && (
        <div
          {...stylex.props(ui.bgSolidDark, styles.chartTooltip)}
          style={{
            top: `${(yAt(data[hover]!) / H) * 100}%`,
            left: `${(xAt(hover) / W) * 100}%`,
          }}
        >
          <span style={{ color: uiColor.border2 }}>{xLabel(hover)}</span>
          <span style={{ color: successColor.solid1 }}> {data[hover] ?? 0}%</span>
        </div>
      )}
    </div>
  );
}

function EarnChart({
  data,
  xTickIndices,
  xLabel,
}: {
  data: number[];
  xTickIndices: number[];
  xLabel: (i: number) => string;
}) {
  const W = 540;
  const H = 160;
  const P = { t: 14, r: 12, b: 22, l: 32 };
  const innerW = W - P.l - P.r;
  const innerH = H - P.t - P.b;
  const rawMax = Math.max(0, ...data);
  const max = Math.max(0.01, Math.ceil(rawMax * 1.1));
  const [hover, setHover] = useState<number | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);

  const n = Math.max(1, data.length);
  const barW = (innerW / n) * 0.72;
  const xAt = (i: number) => P.l + (i + 0.5) * (innerW / n);
  const yAt = (v: number) => P.t + innerH - (v / max) * innerH;

  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const r = svgRef.current?.getBoundingClientRect();
    if (!r) return;
    const x = ((e.clientX - r.left) / r.width) * W;
    const i = Math.floor(((x - P.l) / innerW) * n);
    if (i >= 0 && i < data.length) setHover(i);
  };

  const gridY = [0, max / 2, max].map((v) => Math.round(v * 100) / 100);

  return (
    <div style={{ position: "relative" }}>
      <svg
        ref={svgRef}
        viewBox={`0 0 ${W} ${H}`}
        width="100%"
        preserveAspectRatio="xMidYMid meet"
        style={{ height: "auto", display: "block" }}
        onMouseMove={onMove}
        onMouseLeave={() => setHover(null)}
      >
        {gridY.map((v, i) => (
          <g key={i}>
            <line
              x1={P.l}
              x2={W - P.r}
              y1={yAt(v)}
              y2={yAt(v)}
              stroke={uiColor.border1}
              strokeWidth="0.5"
              strokeDasharray={v === 0 ? "0" : "2 3"}
            />
            <text
              x={P.l - 6}
              y={yAt(v) + 3}
              fontSize="9.5"
              textAnchor="end"
              fill={uiColor.text1}
              fontFamily={fontFamily.mono}
            >
              {formatTokensCompact(v)}
            </text>
          </g>
        ))}
        {xTickIndices.map((i) => (
          <text
            key={i}
            x={xAt(i)}
            y={H - 6}
            fontSize="9.5"
            textAnchor="middle"
            fill={uiColor.text1}
            fontFamily={fontFamily.mono}
          >
            {xLabel(i)}
          </text>
        ))}
        {data.map((v, i) => {
          const isHover = hover === i;
          return (
            <rect
              key={i}
              x={xAt(i) - barW / 2}
              y={yAt(v)}
              width={barW}
              height={(v / max) * innerH}
              fill={isHover ? uiColor.solid2 : uiColor.solid1}
              rx="1"
            />
          );
        })}
      </svg>
      {hover != null && (
        <div
          {...stylex.props(ui.bgSolidDark, styles.chartTooltip)}
          style={{
            top: `${(yAt(data[hover]!) / H) * 100}%`,
            left: `${(xAt(hover) / W) * 100}%`,
          }}
        >
          <span style={{ color: uiColor.border2 }}>{xLabel(hover)}</span>
          <span> {formatTokens(data[hover] ?? 0)} tk</span>
        </div>
      )}
    </div>
  );
}

function Sparkline({
  data,
  height = 32,
  width = 80,
  tone = "default",
}: {
  data: number[];
  height?: number;
  width?: number;
  tone?: "default" | "success";
}) {
  const series = data.length > 0 ? data : [0];
  const hi = Math.max(...series, 1);
  const lo = Math.min(...series, 0);
  const range = hi - lo || 1;
  const denom = Math.max(1, series.length - 1);
  const pts = series.map((v, i) => [
    (i / denom) * width,
    height - ((v - lo) / range) * height * 0.8 - 2,
  ]);
  const path = pts.map((p, i) => `${i === 0 ? "M" : "L"} ${p[0]},${p[1]}`).join(" ");
  const stroke = tone === "success" ? successColor.solid1 : primaryColor.solid1;
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`}>
      <path d={path} fill="none" stroke={stroke} strokeWidth="1" />
    </svg>
  );
}

function PairMachineDialogContent({
  onClose,
  onPair,
}: {
  isOpen: boolean;
  onClose: () => void;
  onPair: () => void;
}) {
  // The pair flow runs entirely on the Mac the user wants to add:
  // `cocore agent pair` prints a URL in its terminal, the user
  // opens that URL in any signed-in browser, approves, and the
  // agent receives its session. This dialog is informational —
  // copy the two-line snippet, then come back here and click
  // "Done" to refetch the machines list (the new machine will show
  // up once it's registered with the advisor).
  return (
    <>
      <DialogHeader>Add a machine</DialogHeader>
      <DialogDescription>
        Download the co/core app, drag it to Applications, and open it — it walks you through
        sign-in, picking a model, and serving. No terminal needed.
      </DialogDescription>
      <DialogBody>
        <Flex direction="column" gap="md">
          <Button
            variant="primary"
            onPress={() => {
              window.location.href = "/agent/app";
            }}
          >
            Download for macOS (Apple Silicon)
          </Button>
          <LabelText variant="secondary" style={styles.helpCenter}>
            Notarized — opens with no Gatekeeper warning. Apple Silicon only.
          </LabelText>

          <LabelText variant="secondary">Prefer the terminal? (headless / fleets)</LabelText>
          <div {...stylex.props(styles.cliBox)}>
            <CopyToClipboardButton text={CLI_ONE_LINER} style={styles.cliCopy} />
            <div>
              <span {...stylex.props(styles.cliPrompt)}>$</span>
              <span style={{ color: uiColor.text1 }}># on the machine you want to pair</span>
            </div>
            {CLI_LINES.split("\n").map((line) => (
              <div key={line}>
                <span {...stylex.props(styles.cliPrompt)}>$</span>
                {line}
              </div>
            ))}
          </div>
          <LabelText variant="secondary" style={styles.helpCenter}>
            The new machine appears here once it registers with the advisor.
          </LabelText>
        </Flex>
      </DialogBody>
      <DialogFooter>
        <Flex direction="row" gap="md">
          <Button variant="secondary" size="sm" onPress={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            size="sm"
            onPress={() => {
              onPair();
              onClose();
            }}
          >
            Done
          </Button>
        </Flex>
      </DialogFooter>
    </>
  );
}

export function ManageModelsDialogContent({
  machine,
  isPending,
  onCancel,
  onSave,
}: {
  machine: Machine;
  isPending: boolean;
  onCancel: () => void;
  onSave: (models: string[]) => void;
}) {
  // The machine's CURRENT effective selection: the owner-pinned
  // `desiredModels` if set, otherwise whatever the agent is actually
  // serving (`supportedModels`). When we seed from supportedModels the
  // set isn't pinned yet — surface that subtly below.
  const pinned = machine.desiredModels && machine.desiredModels.length > 0;
  const initial = pinned ? (machine.desiredModels ?? []) : (machine.supportedModels ?? []);
  const [selected, setSelected] = useState<string[]>(initial);
  const [draft, setDraft] = useState("");

  const addModel = (raw: string) => {
    const trimmed = raw.trim();
    if (trimmed.length === 0) return;
    setSelected((prev) => (prev.includes(trimmed) ? prev : [...prev, trimmed]));
    setDraft("");
  };

  const removeModel = (id: string) => {
    setSelected((prev) => prev.filter((m) => m !== id));
  };

  const suggestions = SUGGESTED_MODELS.filter((m) => !selected.includes(m));

  // Non-blocking: flag any selected model whose RAM floor exceeds this
  // machine's RAM. Save is never prevented — the agent's own catalog is
  // the source of truth; this is a heads-up so the operator isn't
  // surprised when a too-big model fails to load.
  const ramWarnings = ramWarningsFor(selected, machine.ram);

  return (
    <>
      <DialogHeader>Manage models — {machine.alias}</DialogHeader>
      <DialogDescription>
        Choose which models <InlineCode>{machine.alias}</InlineCode> serves. The change is written
        to the machine's provider record; the agent reloads its engines to match.
      </DialogDescription>
      <DialogBody>
        <Flex direction="column" gap="xl">
          <Flex direction="column" gap="md">
            <LabelText variant="secondary">
              {pinned ? "Pinned models" : "Currently loaded; not yet pinned"}
            </LabelText>
            <TagGroup
              aria-label="Selected models"
              items={selected.map((id) => ({ id }))}
              onRemove={(keys) => {
                for (const k of keys) removeModel(String(k));
              }}
              renderEmptyState={() => (
                <SmallBody variant="secondary">
                  No models selected — saving reverts this machine to its local default config.
                </SmallBody>
              )}
            >
              {(item: { id: string }) => (
                <Tag key={item.id} id={item.id} textValue={item.id}>
                  {item.id}
                </Tag>
              )}
            </TagGroup>
          </Flex>

          {ramWarnings.length > 0 ? (
            <Alert variant="warning" title="May not fit this machine's RAM">
              <Flex direction="column" gap="sm">
                {ramWarnings.map((w) => (
                  <SmallBody key={w.modelId}>
                    {w.label} needs ~{w.minRamGB} GB; this machine has {machine.ram} GB — may be
                    unstable or fail to load.
                  </SmallBody>
                ))}
              </Flex>
            </Alert>
          ) : null}

          <Flex direction="row" gap="md" style={styles.modelAddRow}>
            <TextField
              label="Add a model"
              value={draft}
              onChange={setDraft}
              placeholder="mlx-community/Qwen2.5-3B-Instruct-4bit"
              style={styles.modelAddField}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  addModel(draft);
                }
              }}
            />
            <Button
              variant="secondary"
              size="sm"
              isDisabled={draft.trim().length === 0}
              onPress={() => addModel(draft)}
            >
              Add
            </Button>
          </Flex>

          {suggestions.length > 0 ? (
            <Flex direction="column" gap="md">
              <LabelText variant="secondary">Suggested models</LabelText>
              <div {...stylex.props(styles.modelSuggestList)}>
                {suggestions.map((m) => (
                  <Button key={m} variant="outline" size="sm" onPress={() => addModel(m)}>
                    + {m}
                  </Button>
                ))}
              </div>
              <SmallBody variant="secondary">
                Larger models need more RAM; ones that don't fit won't load.
              </SmallBody>
            </Flex>
          ) : null}
        </Flex>
      </DialogBody>
      <DialogFooter>
        <Flex direction="row" gap="md">
          <Button variant="secondary" size="sm" isDisabled={isPending} onPress={() => onSave([])}>
            Reset to default
          </Button>
          <Button variant="secondary" size="sm" isDisabled={isPending} onPress={onCancel}>
            Cancel
          </Button>
          <Button
            variant="primary"
            size="sm"
            isDisabled={isPending}
            onPress={() => onSave(selected)}
          >
            {isPending ? "Saving…" : "Save"}
          </Button>
        </Flex>
      </DialogFooter>
    </>
  );
}

export function RenameMachineDialogContent({
  machine,
  isPending,
  onCancel,
  onSave,
}: {
  machine: Machine;
  isPending: boolean;
  onCancel: () => void;
  onSave: (label: string) => void;
}) {
  // Seed with the current alias. When a machine has never been named the
  // alias falls back to the bare rkey — clear that so the operator types a
  // real name rather than editing the record key.
  const seed = machine.alias === machine.id ? "" : machine.alias;
  const [draft, setDraft] = useState(seed);
  const trimmed = draft.trim();
  const canSave = trimmed.length > 0 && trimmed !== machine.alias;

  return (
    <>
      <DialogHeader>Rename machine</DialogHeader>
      <DialogDescription>
        Sets <InlineCode>machineLabel</InlineCode> on this machine's provider record. This is the
        name shown across the console; the agent picks it up on its next poll.
      </DialogDescription>
      <DialogBody>
        <TextField
          label="Machine name"
          value={draft}
          onChange={setDraft}
          placeholder={machine.id}
          autoFocus
          onKeyDown={(e) => {
            if (e.key === "Enter" && canSave) {
              e.preventDefault();
              onSave(trimmed);
            }
          }}
        />
      </DialogBody>
      <DialogFooter>
        <Flex direction="row" gap="md">
          <Button variant="secondary" size="sm" isDisabled={isPending} onPress={onCancel}>
            Cancel
          </Button>
          <Button
            variant="primary"
            size="sm"
            isDisabled={isPending || !canSave}
            onPress={() => onSave(trimmed)}
          >
            {isPending ? "Saving…" : "Save"}
          </Button>
        </Flex>
      </DialogFooter>
    </>
  );
}

/** Pro-bono policy as the proBono mutation expects it (`null` ≡ off). */
type ProBonoPolicy = { mode: "any" | "direct"; dids?: string[] } | null;

export function AdvancedSettingsDialogContent({
  machine,
  isSharePending,
  isProBonoPending,
  onShareLocation,
  onSaveProBono,
  onClose,
}: {
  machine: Machine;
  isSharePending: boolean;
  isProBonoPending: boolean;
  onShareLocation: (share: boolean) => void;
  /** Persists the policy and resolves/rejects with the write so the dialog can
   *  roll back its optimistic local state on failure. */
  onSaveProBono: (policy: ProBonoPolicy) => Promise<unknown>;
  onClose: () => void;
}) {
  // Three-way pro-bono state seeded from the record. Off = no policy; `any`
  // serves everyone free; `direct` serves only the friends checked below free.
  type ProBonoMode = "off" | "any" | "direct";
  const initialMode: ProBonoMode = machine.proBonoMode ?? "off";
  const [mode, setMode] = useState<ProBonoMode>(initialMode);
  // Friend DIDs served free under `direct`, seeded from the record. Any DID
  // already on the record that is no longer a friend is preserved silently so
  // editing the picker never drops it.
  const [selected, setSelected] = useState<Set<string>>(() => new Set(machine.proBonoDids ?? []));

  // The owner's friends are the allowlist source — pick from them instead of
  // pasting raw DIDs.
  const friendsQ = useQuery(listMyFriendsQueryOptions);
  const friends = friendsQ.data ?? [];

  // Every interaction here autosaves — sliding the control or ticking a friend
  // writes the provider record immediately, no separate submit step. The write
  // is optimistic: the handlers below update local state first, then roll it
  // back if `onSaveProBono`'s promise rejects so the dialog never shows a value
  // the server didn't accept.
  const persist = (next: ProBonoMode, dids: Set<string>): Promise<unknown> => {
    if (next === "off") return onSaveProBono(null);
    if (next === "any") return onSaveProBono({ mode: "any" });
    return onSaveProBono({ mode: "direct", dids: [...dids] });
  };

  const handleModeChange = (next: ProBonoMode) => {
    const prevMode = mode;
    setMode(next);
    void persist(next, selected).catch(() => setMode(prevMode));
  };

  const toggleFriend = (did: string, on: boolean) => {
    const prev = selected;
    const next = new Set(selected);
    if (on) next.add(did);
    else next.delete(did);
    setSelected(next);
    void persist("direct", next).catch(() => setSelected(prev));
  };

  return (
    <>
      <DialogHeader>Advanced settings — {machine.alias}</DialogHeader>
      <DialogDescription>
        Optional per-machine controls. Both are written to this machine's provider record; the agent
        picks them up the next time it serves.
      </DialogDescription>
      <DialogBody>
        <Flex direction="column" gap="2xl">
          <Flex direction="column" gap="md">
            <Switch
              isSelected={machine.shareLocation === true}
              isDisabled={isSharePending}
              onChange={onShareLocation}
            >
              Share country
            </Switch>
            <SmallBody variant="secondary">
              Publishes only a coarse, advisory country derived from this machine's IP — a VPN moves
              it and it isn't verified. It's refreshed each time the machine serves; turning it off
              removes the country on the next serve.
            </SmallBody>
            {machine.shareLocation && machine.region ? (
              <LabelText variant="secondary">
                Currently sharing: <InlineCode>{machine.region}</InlineCode>
              </LabelText>
            ) : null}
          </Flex>

          <Flex direction="column" gap="md">
            <Flex direction="row" gap="sm" align="center">
              <LabelText variant="secondary">Pro bono</LabelText>
              {isProBonoPending ? <SmallBody variant="secondary">Saving…</SmallBody> : null}
            </Flex>
            <SegmentedControl
              size="sm"
              isDisabled={isProBonoPending}
              selectedKeys={new Set([mode])}
              onSelectionChange={(keys) => {
                const k = [...keys][0] as ProBonoMode | undefined;
                if (k && k !== mode) handleModeChange(k);
              }}
            >
              <SegmentedControlItem id="off">Off</SegmentedControlItem>
              <SegmentedControlItem id="any">Anyone</SegmentedControlItem>
              <SegmentedControlItem id="direct">Friends</SegmentedControlItem>
            </SegmentedControl>
            <SmallBody variant="secondary">
              Pro-bono jobs are served free and unmetered, with no exchange cut. “Anyone” serves
              every requester free; “Friends” serves only the friends you check below — everyone
              else is still a normal paid job. “Off” bills every job. Changes save as you make them.
            </SmallBody>
            {mode === "direct" ? (
              <ProBonoFriendPicker
                friends={friends}
                isLoading={friendsQ.isLoading}
                isError={friendsQ.isError}
                onRetry={() => void friendsQ.refetch()}
                selected={selected}
                isDisabled={isProBonoPending}
                onToggle={toggleFriend}
              />
            ) : null}
          </Flex>
        </Flex>
      </DialogBody>
      <DialogFooter>
        <Flex direction="row" gap="md">
          <Button variant="secondary" size="sm" onPress={onClose}>
            Close
          </Button>
        </Flex>
      </DialogFooter>
    </>
  );
}

/** Friend allowlist for `direct` pro-bono: one checkbox row per friend, with a
 *  hint to the /friends page when the set is empty. */
function ProBonoFriendPicker({
  friends,
  isLoading,
  isError,
  onRetry,
  selected,
  isDisabled,
  onToggle,
}: {
  friends: ListedFriend[];
  isLoading: boolean;
  isError: boolean;
  onRetry: () => void;
  selected: Set<string>;
  isDisabled: boolean;
  onToggle: (did: string, on: boolean) => void;
}) {
  if (isLoading) {
    return <SmallBody variant="secondary">Loading friends…</SmallBody>;
  }
  // A failed load leaves `friends` empty too — distinguish it from a genuinely
  // empty friend set so we don't send someone with friends to /friends.
  if (isError) {
    return (
      <Flex direction="row" gap="md" align="center">
        <SmallBody variant="secondary">Couldn't load your friends.</SmallBody>
        <Button variant="tertiary" size="sm" onPress={onRetry}>
          Retry
        </Button>
      </Flex>
    );
  }
  if (friends.length === 0) {
    return (
      <SmallBody variant="secondary">
        You haven't friended anyone yet. Add friends on the{" "}
        <RouterLink to="/friends">friends page</RouterLink> to serve them pro bono.
      </SmallBody>
    );
  }
  return (
    <Flex direction="column" gap="sm">
      {friends.map((f) => {
        const name = f.displayName?.trim() || f.displayHandle || f.subjectHandle || f.subject;
        const fallback = (
          f.displayHandle?.trim()?.[0] ??
          f.subjectHandle?.[0] ??
          f.subject[0] ??
          "?"
        ).toUpperCase();
        return (
          <Checkbox
            key={f.subject}
            isSelected={selected.has(f.subject)}
            isDisabled={isDisabled}
            onChange={(on) => onToggle(f.subject, on)}
          >
            <Flex direction="row" gap="md" align="center">
              <Avatar src={f.avatarUrl ?? undefined} size="sm" alt={name} fallback={fallback} />
              <Flex direction="column" gap="none">
                <LabelText>{name}</LabelText>
                {f.displayHandle ? (
                  <SmallBody variant="secondary">@{f.displayHandle}</SmallBody>
                ) : null}
              </Flex>
            </Flex>
          </Checkbox>
        );
      })}
    </Flex>
  );
}

export function MachinesDashboard() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const fleetQ = useQuery(listMyMachinesQueryOptions);

  const machines = fleetQ.data?.machines ?? [];
  const receiptStats = fleetQ.data?.receiptStats;
  const fetchedAt = fleetQ.data?.fetchedAt ?? new Date().toISOString();
  const appviewError = fleetQ.data?.appviewError ?? null;

  const currentHour = new Date().getHours();
  const statSparkUtil = receiptStats?.hourlyActivityPct ?? Array.from({ length: 24 }, () => 0);
  const statSparkEarn = receiptStats?.hourlyEarnTokens ?? Array.from({ length: 24 }, () => 0);
  const activityAvg24h =
    statSparkUtil.length > 0
      ? Math.round(statSparkUtil.reduce((s, v) => s + v, 0) / statSparkUtil.length)
      : 0;

  const [filter, setFilter] = useState<MachineState | "all">("all");
  const [expandedKeys, setExpandedKeys] = useState(() => new Set<string>());
  const toggleFleetRowExpanded = useCallback((machineId: string) => {
    setExpandedKeys((prev) => {
      const next = new Set(prev);
      if (next.has(machineId)) next.delete(machineId);
      else next.add(machineId);
      return next;
    });
  }, []);
  const [pairOpen, setPairOpen] = useState(false);
  const [unpairTarget, setUnpairTarget] = useState<Machine | null>(null);
  const [manageModelsTarget, setManageModelsTarget] = useState<Machine | null>(null);
  const [renameTarget, setRenameTarget] = useState<Machine | null>(null);
  const [chartRange, setChartRange] = useState<"24h" | "7d" | "30d">("24h");

  const MS_DAY = 86_400_000;

  const chartData = useMemo(() => {
    const label24 = (i: number, len: number) => {
      const h = (((currentHour - (len - 1 - i)) % 24) + 24) % 24;
      return `${String(h).padStart(2, "0")}:00`;
    };
    const startOf7d = Date.now() - 7 * MS_DAY;
    const label7 = (i: number) =>
      new Date(startOf7d + i * MS_DAY + MS_DAY / 2).toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
      });
    const startOf30d = Date.now() - 30 * MS_DAY;
    const label30 = (i: number) =>
      new Date(startOf30d + i * MS_DAY + MS_DAY / 2).toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
      });

    if (!receiptStats) {
      if (chartRange === "7d") {
        const util = Array.from({ length: 7 }, () => 0);
        return {
          util,
          earn: Array.from({ length: 7 }, () => 0),
          xTicks: [0, 2, 4, 6],
          xLabel: label7,
          chartTotalEarn: 0,
          chartActivityAvg: 0,
          chartEarnPeak: 0,
          rangeLabel: "last 7d",
        };
      }
      if (chartRange === "30d") {
        return {
          util: Array.from({ length: 30 }, () => 0),
          earn: Array.from({ length: 30 }, () => 0),
          xTicks: [0, 7, 14, 21, 29],
          xLabel: label30,
          chartTotalEarn: 0,
          chartActivityAvg: 0,
          chartEarnPeak: 0,
          rangeLabel: "last 30d",
        };
      }
      const util = Array.from({ length: 24 }, () => 0);
      return {
        util,
        earn: Array.from({ length: 24 }, () => 0),
        xTicks: [0, 6, 12, 18, 23],
        xLabel: (i: number) => label24(i, 24),
        chartTotalEarn: 0,
        chartActivityAvg: 0,
        chartEarnPeak: 0,
        rangeLabel: "last 24h",
      };
    }

    const s = receiptStats;
    if (chartRange === "7d") {
      const util = s.dailyActivityPct7d;
      const earn = s.dailyEarnTokens7d;
      const chartActivityAvg =
        util.length > 0 ? Math.round(util.reduce((a, b) => a + b, 0) / util.length) : 0;
      return {
        util,
        earn,
        xTicks: [0, 2, 4, 6],
        xLabel: label7,
        chartTotalEarn: s.earn7dTokens,
        chartActivityAvg,
        chartEarnPeak: earn.length ? Math.max(0, ...earn) : 0,
        rangeLabel: "last 7d",
      };
    }
    if (chartRange === "30d") {
      const util = s.dailyActivityPct30d;
      const earn = s.dailyEarnTokens30d;
      const chartActivityAvg =
        util.length > 0 ? Math.round(util.reduce((a, b) => a + b, 0) / util.length) : 0;
      return {
        util,
        earn,
        xTicks: [0, 7, 14, 21, 29],
        xLabel: label30,
        chartTotalEarn: s.earn30dTokens,
        chartActivityAvg,
        chartEarnPeak: earn.length ? Math.max(0, ...earn) : 0,
        rangeLabel: "last 30d",
      };
    }
    const util = s.hourlyActivityPct;
    const earn = s.hourlyEarnTokens;
    const chartActivityAvg =
      util.length > 0 ? Math.round(util.reduce((a, b) => a + b, 0) / util.length) : 0;
    return {
      util,
      earn,
      xTicks: [0, 6, 12, 18, 23],
      xLabel: (i: number) => label24(i, 24),
      chartTotalEarn: s.earn24hTokens,
      chartActivityAvg,
      chartEarnPeak: earn.length ? Math.max(0, ...earn) : 0,
      rangeLabel: "last 24h",
    };
  }, [receiptStats, chartRange, currentHour]);

  const setProviderActiveM = useMutation({
    ...setMyProviderActiveMutationOptions,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: listMyMachinesQueryOptions.queryKey });
    },
  });

  const setDesiredModelsM = useMutation({
    ...setMyProviderDesiredModelsMutationOptions,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: listMyMachinesQueryOptions.queryKey });
      setManageModelsTarget(null);
    },
  });

  const renameM = useMutation({
    ...setMyProviderMachineLabelMutationOptions,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: listMyMachinesQueryOptions.queryKey });
      setRenameTarget(null);
    },
  });

  const deleteProviderM = useMutation({
    ...deleteMyProviderRecordMutationOptions,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: listMyMachinesQueryOptions.queryKey });
      setUnpairTarget(null);
    },
  });

  const recoverM = useMutation({
    ...recoverMachineMutationOptions,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: listMyMachinesQueryOptions.queryKey });
    },
  });

  const dedupM = useMutation({
    ...dedupMyProviderRecordsMutationOptions,
    onSuccess: (r) => {
      void queryClient.invalidateQueries({ queryKey: listMyMachinesQueryOptions.queryKey });
      const errMsg = r.errors.length > 0 ? ` (${r.errors.length} errors)` : "";
      const summary =
        r.deleted.length === 0
          ? `No duplicates found across ${r.totalBefore} provider record${r.totalBefore === 1 ? "" : "s"}`
          : `Removed ${r.deleted.length} duplicate${r.deleted.length === 1 ? "" : "s"}, kept ${r.kept.length}${errMsg}`;
      toasts.add({ title: summary }, { timeout: 4000 });
    },
    onError: (e) =>
      toasts.add(
        { title: e instanceof Error ? `Cleanup failed: ${e.message}` : "Cleanup failed" },
        { timeout: 5000 },
      ),
  });

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (
        e.target instanceof HTMLInputElement ||
        e.target instanceof HTMLTextAreaElement ||
        (e.target as HTMLElement).isContentEditable
      ) {
        return;
      }
      if (e.key.toLowerCase() === "p" && !e.metaKey && !e.ctrlKey) {
        e.preventDefault();
        setPairOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const counts = {
    all: machines.length,
    running: machines.filter((m) => m.state === "running").length,
    idle: machines.filter((m) => m.state === "idle").length,
    paused: machines.filter((m) => m.state === "paused").length,
    offline: machines.filter((m) => m.state === "offline").length,
  };

  const visible = filter === "all" ? machines : machines.filter((m) => m.state === filter);

  const fleetBodyItems: FleetBodyRow[] =
    visible.length === 0 ? [{ id: "fleet-empty", kind: "empty" }] : visible;

  const totalEarn24h = receiptStats?.earn24hTokens ?? 0;
  const onlineCount = counts.running + counts.idle;
  const jobsLast24h = receiptStats?.jobs24h ?? 0;
  const jobsLast30d = receiptStats?.jobs30d ?? 0;
  const fleetRowsSplitHint = counts.all > 1;

  const handleAction = useCallback(
    (action: string, m: Machine) => {
      const errToast = (e: unknown) => showToast(e instanceof Error ? e.message : "Request failed");

      switch (action) {
        case "pause":
          setProviderActiveM.mutate(
            { rkey: m.id, active: false },
            {
              onSuccess: () =>
                showToast(`${m.alias}: paused · provider record is not matched while inactive`),
              onError: errToast,
            },
          );
          return;
        case "resume":
          setProviderActiveM.mutate(
            { rkey: m.id, active: true },
            {
              onSuccess: () => showToast(`${m.alias}: resumed · eligible for matching again`),
              onError: errToast,
            },
          );
          return;
        case "models":
          setManageModelsTarget(m);
          return;
        case "rename":
          setRenameTarget(m);
          return;
        case "unpair":
          setUnpairTarget(m);
          return;
        case "recover":
          recoverM.mutate(
            { rkey: m.id },
            {
              onSuccess: (r) =>
                showToast(
                  r.delivered
                    ? `${m.alias}: recovery signal sent · the machine is trying to self-right`
                    : `${m.alias}: not reachable right now · it'll recover on reconnect`,
                ),
              onError: errToast,
            },
          );
          return;
        default:
          break;
      }
    },
    [setProviderActiveM, recoverM],
  );

  const handlePaired = () => {
    void queryClient.invalidateQueries({ queryKey: listMyMachinesQueryOptions.queryKey });
    window.setTimeout(() => {
      setPairOpen(false);
      showToast("pairing approved · refresh when the agent publishes provider + receipts");
    }, 500);
  };

  const chartRangeControl = (
    <SegmentedControl
      size="sm"
      selectedKeys={new Set([chartRange])}
      onSelectionChange={(keys) => {
        const k = [...keys][0] as "24h" | "7d" | "30d" | undefined;
        if (k) setChartRange(k);
      }}
    >
      <SegmentedControlItem id="24h">24h</SegmentedControlItem>
      <SegmentedControlItem id="7d">7d</SegmentedControlItem>
      <SegmentedControlItem id="30d">30d</SegmentedControlItem>
    </SegmentedControl>
  );

  return (
    <Page.Root style={styles.root}>
      {appviewError ? (
        <Alert variant="critical" title="AppView partial error">
          <Body>{appviewError}</Body>
        </Alert>
      ) : null}
      {/* Show the payouts-not-set-up nudge only when the user has at
          least one provider record. A user who has never paired a
          machine doesn't need this prompt. */}
      {/* EligibilityBanner removed with Stripe in the 2026-05-11 closed-loop pivot. */}
      <Page.Header style={styles.header}>
        <Flex direction="column" gap="xl">
          <Heading1 style={styles.headingMono}>
            <span {...stylex.props(styles.titlePrompt)}>~/</span>
            machines
          </Heading1>
          <div {...stylex.props(styles.metaRow)}>
            <span>
              <strong {...stylex.props(ui.text)}>{onlineCount}</strong> of {counts.all} online
            </span>
            <span {...stylex.props(styles.metaSep)}>·</span>
            <span>
              receipt activity avg {activityAvg24h}% · {jobsLast24h} indexed completions / 24h
            </span>
            <span {...stylex.props(styles.metaSep)}>·</span>
            <span>last sync {formatFetchedAgo(fetchedAt)}</span>
          </div>
        </Flex>
        <Flex direction="row" gap="md" align="center" style={styles.headerActions}>
          <Button variant="secondary" size="sm" onPress={() => downloadFleetCsv(fleetQ.data)}>
            Export
          </Button>
          <Button
            variant="secondary"
            size="sm"
            isDisabled={dedupM.isPending}
            onPress={() => dedupM.mutate()}
          >
            {dedupM.isPending ? "Cleaning…" : "Clean up duplicates"}
          </Button>
          <Dialog
            isOpen={pairOpen}
            onOpenChange={setPairOpen}
            trigger={
              <Button variant="primary" size="sm">
                + Pair machine <Kbd>P</Kbd>
              </Button>
            }
          >
            <PairMachineDialogContent
              isOpen={pairOpen}
              onClose={() => setPairOpen(false)}
              onPair={handlePaired}
            />
          </Dialog>
          <Dialog
            isOpen={unpairTarget != null}
            onOpenChange={(open) => {
              if (!open) setUnpairTarget(null);
            }}
            trigger={
              <button
                type="button"
                style={{
                  position: "absolute",
                  width: 0,
                  height: 0,
                  opacity: 0,
                  pointerEvents: "none",
                }}
                tabIndex={-1}
                aria-hidden
              />
            }
          >
            <DialogHeader>Unpair machine?</DialogHeader>
            <DialogBody>
              <DialogDescription>
                This deletes the <InlineCode>dev.cocore.compute.provider</InlineCode> record{" "}
                <InlineCode>{unpairTarget?.id ?? "—"}</InlineCode>
                {unpairTarget ? ` (${unpairTarget.alias})` : ""} from your PDS. Stop the agent on
                the host if you no longer want it to publish.
              </DialogDescription>
            </DialogBody>
            <DialogFooter>
              <Flex direction="row" gap="md">
                <Button variant="secondary" size="sm" onPress={() => setUnpairTarget(null)}>
                  Cancel
                </Button>
                <Button
                  variant="critical"
                  size="sm"
                  isDisabled={deleteProviderM.isPending || !unpairTarget}
                  onPress={() => {
                    if (!unpairTarget) return;
                    const alias = unpairTarget.alias;
                    const rkey = unpairTarget.id;
                    deleteProviderM.mutate(
                      { rkey },
                      {
                        onSuccess: () => showToast(`${alias}: provider record deleted`),
                        onError: (e) =>
                          showToast(e instanceof Error ? e.message : "Could not remove record"),
                      },
                    );
                  }}
                >
                  {deleteProviderM.isPending ? "Removing…" : "Remove record"}
                </Button>
              </Flex>
            </DialogFooter>
          </Dialog>
          <Dialog
            isOpen={manageModelsTarget != null}
            onOpenChange={(open) => {
              if (!open) setManageModelsTarget(null);
            }}
            trigger={
              <button
                type="button"
                style={{
                  position: "absolute",
                  width: 0,
                  height: 0,
                  opacity: 0,
                  pointerEvents: "none",
                }}
                tabIndex={-1}
                aria-hidden
              />
            }
          >
            {manageModelsTarget ? (
              <ManageModelsDialogContent
                key={manageModelsTarget.id}
                machine={manageModelsTarget}
                isPending={setDesiredModelsM.isPending}
                onCancel={() => setManageModelsTarget(null)}
                onSave={(models) => {
                  const m = manageModelsTarget;
                  setDesiredModelsM.mutate(
                    { rkey: m.id, models },
                    {
                      onSuccess: () =>
                        showToast(`${m.alias}: models updated · the machine will reload them`),
                      onError: (e) =>
                        showToast(e instanceof Error ? e.message : "Could not update models"),
                    },
                  );
                }}
              />
            ) : null}
          </Dialog>
          <Dialog
            isOpen={renameTarget != null}
            onOpenChange={(open) => {
              if (!open) setRenameTarget(null);
            }}
            trigger={
              <button
                type="button"
                style={{
                  position: "absolute",
                  width: 0,
                  height: 0,
                  opacity: 0,
                  pointerEvents: "none",
                }}
                tabIndex={-1}
                aria-hidden
              />
            }
          >
            {renameTarget ? (
              <RenameMachineDialogContent
                key={renameTarget.id}
                machine={renameTarget}
                isPending={renameM.isPending}
                onCancel={() => setRenameTarget(null)}
                onSave={(label) => {
                  const m = renameTarget;
                  renameM.mutate(
                    { rkey: m.id, label },
                    {
                      onSuccess: () => showToast(`${m.alias}: renamed to “${label}”`),
                      onError: (e) =>
                        showToast(e instanceof Error ? e.message : "Could not rename machine"),
                    },
                  );
                }}
              />
            ) : null}
          </Dialog>
        </Flex>
      </Page.Header>

      <Flex direction="column" gap="4xl">
        <div {...stylex.props(styles.statsGrid)}>
          <Card size="md" style={styles.statCard}>
            <CardBody>
              <Text weight="light" variant="secondary" style={styles.statLabel}>
                Machines online
              </Text>
              <div {...stylex.props(styles.statValue)}>
                {onlineCount}
                <span {...stylex.props(styles.statFrac)}>/{counts.all}</span>
              </div>
              <div {...stylex.props(styles.statDelta)}>
                {counts.running > 0 ? (
                  <span {...stylex.props(styles.statDeltaUp)}>▲ {counts.running} running</span>
                ) : null}
                <span>
                  {" "}
                  ·{" "}
                  {counts.offline
                    ? `${counts.offline} offline`
                    : "telemetry not available from the index"}
                </span>
              </div>
            </CardBody>
          </Card>
          <Card size="md" style={styles.statCard}>
            <CardBody>
              <Text weight="light" variant="secondary" style={styles.statLabel}>
                Receipt activity (24h)
              </Text>
              <div {...stylex.props(styles.statValue)}>
                {activityAvg24h}
                <span {...stylex.props(styles.statFrac)}>%</span>
              </div>
              <div {...stylex.props(styles.statDelta)}>
                <span>receipt density in the AppView index · not live GPU load</span>
              </div>
              <div {...stylex.props(styles.statSpark)}>
                <Sparkline data={statSparkUtil} tone="success" />
              </div>
            </CardBody>
          </Card>
          <Card size="md" style={styles.statCard}>
            <CardBody>
              <Text weight="light" variant="secondary" style={styles.statLabel}>
                Earned · today
              </Text>
              <div {...stylex.props(styles.statValue)}>
                {formatTokens(totalEarn24h)}
                <span {...stylex.props(styles.statFrac)}> tokens</span>
              </div>
              <div {...stylex.props(styles.statDelta)}>
                <span>
                  last 7d: {formatTokens(receiptStats?.earn7dTokens ?? 0)} tk · 30d:{" "}
                  {formatTokens(receiptStats?.earn30dTokens ?? 0)} tk · indexed receipts only
                </span>
              </div>
              <div {...stylex.props(styles.statSpark)}>
                <Sparkline data={statSparkEarn} />
              </div>
            </CardBody>
          </Card>
          <Card size="md" style={styles.statCard}>
            <CardBody>
              <Text weight="light" variant="secondary" style={styles.statLabel}>
                Jobs · 24h
              </Text>
              <div {...stylex.props(styles.statValue)}>{jobsLast24h}</div>
              <div {...stylex.props(styles.statDelta)}>
                <span>
                  {jobsLast24h} / 24h · {jobsLast30d} / 30d · in-progress work not indexed here
                </span>
              </div>
            </CardBody>
          </Card>
        </div>

        <div {...stylex.props(styles.chartsRow)}>
          <Card size="md">
            <CardHeader hasBorder>
              <Flex direction="column" gap="xs">
                <CardTitle style={styles.chartTitle}>Gpu utilization</CardTitle>
                <CardDescription style={styles.chartDescription}>
                  relative completion density in the index · {chartData.rangeLabel}
                </CardDescription>
              </Flex>
              <CardHeaderAction>{chartRangeControl}</CardHeaderAction>
            </CardHeader>
            <CardBody>
              <div {...stylex.props(styles.chartReadout)}>
                <div {...stylex.props(styles.chartBig)}>
                  {chartData.chartActivityAvg}
                  <span {...stylex.props(styles.chartPct)}>%</span>
                </div>
                <div {...stylex.props(styles.chartSmall)}>
                  peak <strong {...stylex.props(ui.text)}>{Math.max(0, ...chartData.util)}%</strong>{" "}
                  · low {chartData.util.length ? Math.min(...chartData.util) : 0}% ·{" "}
                  {chartData.rangeLabel}
                </div>
              </div>
              <UtilChart
                data={chartData.util}
                xTickIndices={chartData.xTicks}
                xLabel={chartData.xLabel}
              />
            </CardBody>
          </Card>
          <Card size="md">
            <CardHeader hasBorder>
              <Flex direction="column" gap="xs">
                <CardTitle style={styles.chartTitle}>earnings</CardTitle>
                <CardDescription style={styles.chartDescription}>
                  {chartRange === "24h" ? "hourly · " : "daily · "}
                  {chartData.rangeLabel} · token-priced receipts in index
                </CardDescription>
              </Flex>
              <CardHeaderAction>{chartRangeControl}</CardHeaderAction>
            </CardHeader>
            <CardBody>
              <div {...stylex.props(styles.chartReadout)}>
                <div {...stylex.props(styles.chartBig)}>
                  {formatTokens(chartData.chartTotalEarn)}
                  <span {...stylex.props(styles.statFrac)}> tokens</span>
                </div>
                <div {...stylex.props(styles.chartSmall)}>
                  peak {chartRange === "24h" ? "hour" : "day"} ≈{" "}
                  <strong {...stylex.props(ui.text)}>
                    {formatTokens(chartData.chartEarnPeak)} tk
                  </strong>
                </div>
              </div>
              <EarnChart
                data={chartData.earn}
                xTickIndices={chartData.xTicks}
                xLabel={chartData.xLabel}
              />
            </CardBody>
          </Card>
        </div>

        <Card size="md">
          <CardHeader hasBorder style={styles.fleetHeader}>
            <CardTitle style={styles.chartTitle}>
              Fleet
              <span {...stylex.props(styles.fleetTitleCount)}>{counts.all} machines</span>
            </CardTitle>
            <CardHeaderAction>
              <SegmentedControl
                size="sm"
                selectedKeys={new Set([filter])}
                onSelectionChange={(keys) => {
                  const k = [...keys][0] as MachineState | "all" | undefined;
                  if (k) {
                    setFilter(k);
                    setExpandedKeys(new Set());
                  }
                }}
              >
                <SegmentedControlItem id="all">all {counts.all}</SegmentedControlItem>
                <SegmentedControlItem id="running">run {counts.running}</SegmentedControlItem>
                <SegmentedControlItem id="idle">idle {counts.idle}</SegmentedControlItem>
                <SegmentedControlItem id="paused">paused {counts.paused}</SegmentedControlItem>
                <SegmentedControlItem id="offline">off {counts.offline}</SegmentedControlItem>
              </SegmentedControl>
            </CardHeaderAction>
            {fleetRowsSplitHint ? (
              <CardDescription style={styles.chartDescription}>
                Per-row earnings and job counts are attributed to the machine that served them (via
                each receipt's attestation).
              </CardDescription>
            ) : null}
          </CardHeader>
          <ResizableTableContainer {...stylex.props(styles.tableWrap, styles.fleetTableDesktop)}>
            <Table
              aria-label="Provider machines"
              size="sm"
              treeColumn="alias"
              expandedKeys={expandedKeys}
              onExpandedChange={(keys) => setExpandedKeys(new Set([...keys].map((k) => String(k))))}
            >
              <TableHeader columns={FLEET_TABLE_COLUMNS}>
                {(column) => (
                  <TableColumn
                    isRowHeader={column.id === "alias"}
                    width={column.width}
                    minWidth={column.minWidth}
                    maxWidth={column.maxWidth}
                    style={column.id === "alias" ? styles.aliasColumn : undefined}
                  >
                    {column.name}
                  </TableColumn>
                )}
              </TableHeader>
              <TableBody items={fleetBodyItems}>
                {(item) => {
                  if (isFleetEmptyRow(item)) {
                    return (
                      <TableRow columns={FLEET_FULL_COLUMN} id={item.id}>
                        {() => (
                          <TableCell colSpan={6} style={styles.fleetEmptyCell}>
                            <LabelText variant="secondary">No machines in this state</LabelText>
                          </TableCell>
                        )}
                      </TableRow>
                    );
                  }
                  const m = item;
                  const isOpen = expandedKeys.has(m.id);
                  const tokensEarned24h = formatTokens(m.earnings24h);
                  const detailItem = { id: `${m.id}__detail`, machine: m };
                  return (
                    <TableRow
                      columns={FLEET_TABLE_COLUMNS}
                      id={m.id}
                      textValue={m.alias}
                      style={[styles.row, isOpen && styles.rowExpanded]}
                      onAction={() => toggleFleetRowExpanded(m.id)}
                      tree={
                        <Collection items={[detailItem]}>
                          {(row) => (
                            <TableRow
                              columns={FLEET_FULL_COLUMN}
                              id={row.id}
                              style={styles.detailRow}
                            >
                              {() => (
                                <TableCell colSpan={6} style={styles.detailCell}>
                                  <MachineDrawer m={row.machine} onAction={handleAction} />
                                </TableCell>
                              )}
                            </TableRow>
                          )}
                        </Collection>
                      }
                    >
                      {(column) => {
                        if (column.id === "alias") {
                          return (
                            <TableCell contentStyle={styles.aliasCellContent}>
                              <Flex direction="row" gap="md" align="center">
                                <RouterLink
                                  to="/machines/$rkey"
                                  params={{ rkey: m.id }}
                                  {...stylex.props(styles.aliasLink)}
                                  onClick={(e) => e.stopPropagation()}
                                  onPointerDown={(e) => e.stopPropagation()}
                                >
                                  {m.alias}
                                </RouterLink>
                                <Text size="xs" style={ui.textDim}>
                                  {m.id}
                                </Text>
                                {m.verifiedTier ? <TrustTierBadge tier={m.verifiedTier} /> : null}
                                <RegionFlag region={m.region} />
                                <ProBonoBadge mode={m.proBonoMode} />
                              </Flex>
                            </TableCell>
                          );
                        }
                        if (column.id === "state") {
                          return (
                            <TableCell>
                              <Flex direction="row" gap="sm" align="center">
                                <span
                                  {...stylex.props(
                                    styles.statusDot,
                                    m.state === "running" && styles.statusRunning,
                                    m.state === "provisioning" && styles.statusProvisioning,
                                    m.state === "idle" && styles.statusIdle,
                                    m.state === "paused" && styles.statusPaused,
                                    m.state === "offline" && styles.statusOffline,
                                    // An engine fault overrides the state dot color — the
                                    // machine is up but can't serve its real model.
                                    Boolean(m.faultReason) && styles.statusFault,
                                  )}
                                />

                                {m.faultReason ? "fault" : m.state}
                              </Flex>
                            </TableCell>
                          );
                        }
                        if (column.id === "gpu") {
                          return (
                            <TableCell>
                              <span {...stylex.props(styles.gpuMeta)}>
                                {m.chipMeta ?? `${m.vram}gb`}
                              </span>
                            </TableCell>
                          );
                        }
                        if (column.id === "job") {
                          return (
                            <TableCell>
                              {m.faultReason ? (
                                <LabelText variant="secondary" style={styles.faultText}>
                                  Engine not loaded — only serving stub
                                </LabelText>
                              ) : (
                                <LabelText variant="secondary">
                                  {m.state === "provisioning" &&
                                    "Starting up — loading the engine…"}
                                  {m.state === "idle" && "Eligible for matching when active"}
                                  {m.state === "paused" && (m.pausedReason ?? "Paused")}
                                  {m.state === "running" && "Served a job in the last 5 min"}
                                  {m.state === "offline" && (m.offlineReason ?? "Offline")}
                                </LabelText>
                              )}
                            </TableCell>
                          );
                        }
                        if (column.id === "earned") {
                          return (
                            <TableCell contentStyle={styles.fleetCellEndContent}>
                              {m.earnings24h === 0 ? (
                                <span {...stylex.props(styles.earnZero)}>—</span>
                              ) : (
                                <span {...stylex.props(ui.text)}>
                                  {tokensEarned24h}
                                  <span {...stylex.props(styles.earnCents)}> tk</span>
                                </span>
                              )}
                            </TableCell>
                          );
                        }
                        return (
                          <TableCell contentStyle={styles.fleetCellEndContent}>
                            <div
                              {...stylex.props(styles.rowActions)}
                              onPointerDown={(e) => e.stopPropagation()}
                            >
                              <Menu
                                size="sm"
                                placement="bottom end"
                                trigger={
                                  <IconButton
                                    variant="tertiary"
                                    size="sm"
                                    aria-label={`Actions for ${m.alias}`}
                                  >
                                    <MoreHorizontal aria-hidden size={18} />
                                  </IconButton>
                                }
                                onAction={(key) => {
                                  if (key === "open") {
                                    void navigate({
                                      to: "/machines/$rkey",
                                      params: { rkey: m.id },
                                    });
                                  } else if (key === "pause") {
                                    handleAction(m.state === "paused" ? "resume" : "pause", m);
                                  } else if (key === "models") {
                                    handleAction("models", m);
                                  } else if (key === "rename") {
                                    handleAction("rename", m);
                                  } else if (key === "unpair") {
                                    handleAction("unpair", m);
                                  }
                                }}
                              >
                                <MenuItem id="open" textValue="View details">
                                  View details
                                </MenuItem>
                                <MenuItem
                                  id="pause"
                                  isDisabled={m.state === "offline"}
                                  textValue={
                                    m.state === "paused" ? "Resume serving" : "Pause serving"
                                  }
                                >
                                  {m.state === "paused" ? "Resume serving" : "Pause serving"}
                                </MenuItem>
                                <MenuItem id="models" textValue="Manage models…">
                                  Manage models…
                                </MenuItem>
                                <MenuItem id="rename" textValue="Rename…">
                                  Rename…
                                </MenuItem>
                                <ListBoxSeparator />
                                <MenuItem id="unpair" variant="destructive" textValue="Unpair">
                                  Unpair
                                </MenuItem>
                              </Menu>
                            </div>
                          </TableCell>
                        );
                      }}
                    </TableRow>
                  );
                }}
              </TableBody>
            </Table>
          </ResizableTableContainer>
          {/* Narrow screens (<48rem): the table above is hidden and the
              same fleet renders as a stacked card-per-machine list so it
              fits the viewport with no horizontal scroll. */}
          <div {...stylex.props(styles.fleetCardList)}>
            {visible.length === 0 ? (
              <div {...stylex.props(styles.fleetCardEmpty)}>
                <LabelText variant="secondary">No machines in this state</LabelText>
              </div>
            ) : (
              visible.map((m) => (
                <FleetMachineCard
                  key={m.id}
                  m={m}
                  isOpen={expandedKeys.has(m.id)}
                  onToggle={() => toggleFleetRowExpanded(m.id)}
                  onAction={handleAction}
                  onOpenDetail={() => {
                    void navigate({ to: "/machines/$rkey", params: { rkey: m.id } });
                  }}
                />
              ))
            )}
          </div>
        </Card>
      </Flex>
    </Page.Root>
  );
}

function FleetMachineCard({
  m,
  isOpen,
  onToggle,
  onAction,
  onOpenDetail,
}: {
  m: Machine;
  isOpen: boolean;
  onToggle: () => void;
  onAction: (action: string, m: Machine) => void;
  onOpenDetail: () => void;
}) {
  const tokensEarned24h = formatTokens(m.earnings24h);
  const statusText = m.faultReason
    ? "Engine not loaded — only serving stub"
    : m.state === "provisioning"
      ? "Starting up — loading the engine…"
      : m.state === "idle"
        ? "Eligible for matching when active"
        : m.state === "paused"
          ? (m.pausedReason ?? "Paused")
          : m.state === "running"
            ? "Served a job in the last 5 min"
            : (m.offlineReason ?? "Offline");
  return (
    <div {...stylex.props(styles.fleetCard)}>
      <div {...stylex.props(styles.fleetCardHead)}>
        <div {...stylex.props(styles.fleetCardIdentity)}>
          <RouterLink
            to="/machines/$rkey"
            params={{ rkey: m.id }}
            {...stylex.props(styles.fleetCardAlias)}
          >
            {m.alias}
          </RouterLink>
          <span {...stylex.props(styles.fleetCardRkey)}>{m.id}</span>
        </div>
        <span {...stylex.props(styles.fleetCardState)}>
          <span
            {...stylex.props(
              styles.statusDot,
              m.state === "running" && styles.statusRunning,
              m.state === "provisioning" && styles.statusProvisioning,
              m.state === "idle" && styles.statusIdle,
              m.state === "paused" && styles.statusPaused,
              m.state === "offline" && styles.statusOffline,
              Boolean(m.faultReason) && styles.statusFault,
            )}
          />
          {m.faultReason ? "fault" : m.state}
        </span>
      </div>

      <div {...stylex.props(styles.fleetCardMetaRow)}>
        <span {...stylex.props(styles.gpuMeta)}>{m.chipMeta ?? `${m.vram}gb`}</span>
        <span {...stylex.props(styles.fleetCardEarn)}>
          {m.earnings24h === 0 ? (
            <span {...stylex.props(styles.earnZero)}>— tk · 24h</span>
          ) : (
            <>
              <span {...stylex.props(ui.text)}>{tokensEarned24h}</span> tk · 24h
            </>
          )}
        </span>
      </div>

      <LabelText
        variant="secondary"
        style={[styles.fleetCardStatus, m.faultReason ? styles.faultText : undefined]}
      >
        {statusText}
      </LabelText>

      <div {...stylex.props(styles.fleetCardFooter)}>
        <Button variant="outline" size="sm" onPress={onToggle}>
          {isOpen ? "Hide details" : "Details"}
        </Button>
        <Menu
          size="sm"
          placement="bottom end"
          trigger={
            <IconButton variant="tertiary" size="sm" aria-label={`Actions for ${m.alias}`}>
              <MoreHorizontal aria-hidden size={18} />
            </IconButton>
          }
          onAction={(key) => {
            if (key === "open") {
              onOpenDetail();
            } else if (key === "pause") {
              onAction(m.state === "paused" ? "resume" : "pause", m);
            } else if (key === "models") {
              onAction("models", m);
            } else if (key === "rename") {
              onAction("rename", m);
            } else if (key === "unpair") {
              onAction("unpair", m);
            }
          }}
        >
          <MenuItem id="open" textValue="View details">
            View details
          </MenuItem>
          <MenuItem
            id="pause"
            isDisabled={m.state === "offline"}
            textValue={m.state === "paused" ? "Resume serving" : "Pause serving"}
          >
            {m.state === "paused" ? "Resume serving" : "Pause serving"}
          </MenuItem>
          <MenuItem id="models" textValue="Manage models…">
            Manage models…
          </MenuItem>
          <MenuItem id="rename" textValue="Rename…">
            Rename…
          </MenuItem>
          <ListBoxSeparator />
          <MenuItem id="unpair" variant="destructive" textValue="Unpair">
            Unpair
          </MenuItem>
        </Menu>
      </div>

      {isOpen ? (
        <div {...stylex.props(styles.fleetCardDrawerWrap)}>
          <MachineDrawer m={m} onAction={onAction} />
        </div>
      ) : null}
    </div>
  );
}

function MachineDrawer({
  m,
  onAction,
}: {
  m: Machine;
  onAction: (action: string, m: Machine) => void;
}) {
  const tk = (tokens: number) => `${formatTokens(tokens)} tk`;
  return (
    <div {...stylex.props(styles.drawer)}>
      <Flex gap="2xl" direction="column" style={styles.drawerSection}>
        <Heading4>Provider status</Heading4>
        {m.faultReason ? (
          <Alert variant="critical" title="Inference engine didn't start">
            <Flex gap="md" direction="column">
              <SmallBody>{m.faultReason}</SmallBody>
              {m.faultModels && m.faultModels.length > 0 ? (
                <SmallBody variant="secondary">
                  Affected model{m.faultModels.length > 1 ? "s" : ""}:{" "}
                  <InlineCode>{m.faultModels.join(", ")}</InlineCode>
                </SmallBody>
              ) : null}
              <SmallBody variant="secondary">
                Still stuck after trying the steps above? DM{" "}
                <Link
                  href="https://bsky.app/profile/cocore.dev"
                  target="_blank"
                  rel="noreferrer noopener"
                >
                  @cocore.dev on Bluesky
                </Link>{" "}
                with this machine's label ({m.alias}) and the fault code{" "}
                <InlineCode>{m.faultCode ?? "unknown"}</InlineCode>, and we'll help you get it
                online.
              </SmallBody>
            </Flex>
          </Alert>
        ) : null}
        {m.unhealthy ? (
          <Alert variant="warning" title="Not receiving jobs — recovering">
            <Flex gap="md" direction="column">
              <SmallBody>
                The advisor stopped routing jobs to this machine because it{" "}
                {m.unhealthyReason === "preflight-no-response"
                  ? "stopped answering readiness checks"
                  : m.unhealthyReason === "job-idle-timeout"
                    ? "accepted a job and then went silent"
                    : "stopped responding"}
                . It's being asked to self-right automatically, and jobs are going to your other
                machines in the meantime. It rejoins on its own the moment it answers again.
              </SmallBody>
              <Flex gap="sm" align="center">
                <Button variant="outline" size="sm" onPress={() => onAction("recover", m)}>
                  Try to recover
                </Button>
                <SmallBody variant="secondary">
                  Still stuck? Open this machine's menu bar app and click “Restart serving”.
                </SmallBody>
              </Flex>
            </Flex>
          </Alert>
        ) : null}
        {m.standingKnown === false ? (
          <SmallBody variant="secondary">
            Live status from the grid is temporarily unavailable — showing the last published record
            state only.
          </SmallBody>
        ) : null}
        <SmallBody variant="secondary">
          {m.state === "idle" && !m.faultReason && (
            <>
              Record is active (eligible for matchmaking). Live workload is not visible in this
              console.
            </>
          )}
          {m.state === "idle" && m.faultReason && (
            <>
              The machine is connected but won't be matched to real inference jobs until the engine
              loads — it's only advertising the no-op <InlineCode>stub</InlineCode> model.
            </>
          )}
          {m.state === "paused" && <>{m.pausedReason}</>}
          {m.state === "running" && <>Served a job in the last 5 minutes.</>}
          {m.state === "offline" && <>{m.offlineReason ?? "Offline in this view."}</>}
        </SmallBody>
      </Flex>
      <Flex gap="sm" direction="column" style={styles.drawerSection}>
        <Heading4>Hardware</Heading4>
        <dl {...stylex.props(styles.kvGrid)}>
          <dt {...stylex.props(styles.kvDt)}>Chip</dt>
          <dd {...stylex.props(styles.kvDd)}>
            {m.gpu}
            {m.chipMeta ? ` · ${m.chipMeta}` : ` · ${m.vram}GB`}
          </dd>
          <dt {...stylex.props(styles.kvDt)}>RAM</dt>
          <dd {...stylex.props(styles.kvDd)}>{m.ram}GB</dd>
          <dt {...stylex.props(styles.kvDt)}>Paired</dt>
          <dd {...stylex.props(styles.kvDd)}>{m.pairedAt}</dd>
          {m.trustLevel ? (
            <>
              <dt {...stylex.props(styles.kvDt)}>Trust</dt>
              <dd {...stylex.props(styles.kvDd)}>{m.trustLevel}</dd>
            </>
          ) : null}
          <dt {...stylex.props(styles.kvDt)}>Models</dt>
          <dd {...stylex.props(styles.kvDd)}>
            <Flex direction="column" gap="sm" align="start">
              <span>
                {m.desiredModels && m.desiredModels.length > 0
                  ? m.desiredModels.join(", ")
                  : m.supportedModels && m.supportedModels.length > 0
                    ? m.supportedModels.join(", ")
                    : "—"}
              </span>
              <Flex direction="row" gap="sm" wrap>
                <Button variant="outline" size="sm" onPress={() => onAction("models", m)}>
                  Manage models…
                </Button>
                <Button variant="outline" size="sm" onPress={() => onAction("rename", m)}>
                  Rename…
                </Button>
              </Flex>
            </Flex>
          </dd>
        </dl>
      </Flex>
      <Flex gap="2xl" direction="column" style={[styles.drawerSection, styles.drawerSectionLast]}>
        <Heading4>Earnings (index)</Heading4>
        <div {...stylex.props(styles.metricGrid)}>
          <div {...stylex.props(styles.metricCell)}>
            <LabelText variant="secondary">7d earnings</LabelText>
            <div {...stylex.props(ui.text, styles.metricVal)}>{tk(m.earnings7d)}</div>
          </div>
          <div {...stylex.props(styles.metricCell, styles.metricCellGridEnd)}>
            <LabelText variant="secondary">Lifetime</LabelText>
            <div {...stylex.props(ui.text, styles.metricVal)}>{tk(m.earningsLifetime)}</div>
          </div>
          <div {...stylex.props(styles.metricCell)}>
            <LabelText variant="secondary">Jobs (index est.)</LabelText>
            <div {...stylex.props(ui.text, styles.metricVal)}>
              {m.jobsCompleted.toLocaleString()}
            </div>
          </div>
          <div {...stylex.props(styles.metricCell, styles.metricCellGridEnd)}>
            <LabelText variant="secondary">24h earnings</LabelText>
            <div {...stylex.props(ui.text, styles.metricVal)}>{tk(m.earnings24h)}</div>
          </div>
        </div>
        <Flex direction="row" gap="sm" wrap>
          {(m.state === "idle" || m.state === "running") && (
            <Button variant="outline" size="sm" onPress={() => onAction("pause", m)}>
              Pause serving
            </Button>
          )}
          {m.state === "paused" && (
            <Button variant="outline" size="sm" onPress={() => onAction("resume", m)}>
              Resume serving
            </Button>
          )}
          <Button variant="critical-outline" size="sm" onPress={() => onAction("unpair", m)}>
            Unpair
          </Button>
        </Flex>
      </Flex>
    </div>
  );
}
