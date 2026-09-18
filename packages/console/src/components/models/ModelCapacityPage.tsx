"use client";

// /models/capacity — live model supply vs. demand, one row per model.
//
// Two readers, one table:
//
//   an operator deciding what to host reads the supply columns and the state
//   badge — "needs capacity" is worth a multi-GB download, "no demand" is not;
//
//   a requester reads the pressure column — how much traffic each healthy
//   machine is already carrying is the best available proxy for where a job
//   will wait.
//
// Everything is derived and read-only (see model-supply-demand.server.ts):
// supply from the advisor's live registry, demand from the AppView's index of
// provider-signed receipts. Neither is authoritative state this page owns.

import * as stylex from "@stylexjs/stylex";
import { useQuery } from "@tanstack/react-query";
import { Link as RouterLink } from "@tanstack/react-router";
import type { ReactElement } from "react";

import { modelCapacityQueryOptions } from "@/components/models/model-capacity.functions.ts";
import { Alert } from "@/design-system/alert";
import { Badge } from "@/design-system/badge";
import { Card, CardBody, CardDescription, CardHeader, CardTitle } from "@/design-system/card";
import { Flex } from "@/design-system/flex";
import { Page } from "@/design-system/page";
import { SegmentedControl, SegmentedControlItem } from "@/design-system/segmented-control";
import {
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
} from "@/design-system/table";
import { uiColor } from "@/design-system/theme/color.stylex";
import { breakpoints } from "@/design-system/theme/media-queries.stylex";
import { horizontalSpace, verticalSpace } from "@/design-system/theme/semantic-spacing.stylex";
import {
  fontFamily,
  fontSize,
  fontWeight,
  lineHeight,
} from "@/design-system/theme/typography.stylex";
import { Heading1, SmallBody } from "@/design-system/typography";
import {
  SUPPLY_BLOCKERS,
  SUPPLY_DEMAND_WINDOWS,
  type ModelSupplyDemandRow,
  type SupplyBlocker,
  type SupplyDemandState,
  type SupplyDemandWindow,
} from "@/lib/model-supply-demand.ts";
import { formatTokensCompact } from "@/lib/token-display.ts";

const WINDOW_LABELS: Record<SupplyDemandWindow, string> = { day: "24h", week: "7d" };

const STATE_LABELS: Record<SupplyDemandState, string> = {
  unserved: "needs capacity",
  hot: "under pressure",
  steady: "steady",
  idle: "no demand",
  dark: "nothing serving",
};

const STATE_VARIANTS: Record<SupplyDemandState, "critical" | "warning" | "success" | "default"> = {
  unserved: "critical",
  hot: "warning",
  steady: "success",
  idle: "default",
  dark: "default",
};

const BLOCKER_LABELS: Record<SupplyBlocker, string> = {
  engineFault: "engine fault",
  paused: "paused",
  unhealthy: "unhealthy",
  coolingDown: "cooling down",
};

const COLUMNS = [
  { id: "model", name: "model" },
  { id: "supply", name: "healthy / advertising" },
  { id: "operators", name: "operators" },
  { id: "requests", name: "requests" },
  { id: "tokens", name: "tokens" },
  { id: "pressure", name: "requests / machine" },
] as const;

type ColumnId = (typeof COLUMNS)[number]["id"];

const NUMBER = new Intl.NumberFormat("en-US");

function formatCount(n: number): string {
  return NUMBER.format(Math.round(n));
}

/** Pressure carries a decimal below 10 (the difference between 0.4 and 4
 *  requests per machine matters) and rounds above it (the difference between
 *  110 and 110.4 does not). */
function formatPressure(v: number | null): string {
  if (v === null) return "—";
  if (v === 0) return "0";
  if (v < 10) return v.toFixed(1);
  return formatCount(v);
}

/** "2 unhealthy · 1 engine fault" — only the blockers actually present. */
function blockerSummary(row: ModelSupplyDemandRow): string | null {
  const parts = SUPPLY_BLOCKERS.filter((b) => row.blocked[b] > 0).map(
    (b) => `${row.blocked[b]} ${BLOCKER_LABELS[b]}`,
  );
  return parts.length > 0 ? parts.join(" · ") : null;
}

const styles = stylex.create({
  header: { marginBottom: 0 },
  root: {
    display: "flex",
    flexDirection: "column",
    fontFamily: fontFamily.mono,
    gap: verticalSpace["2xl"],
    marginLeft: "auto",
    marginRight: "auto",
    maxWidth: "1600px",
    paddingBottom: verticalSpace["12xl"],
    width: "100%",
  },
  headingMono: { fontFamily: fontFamily.mono },
  titlePrompt: { color: uiColor.text1, fontWeight: fontWeight.normal },
  intro: {
    color: uiColor.text1,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.sm,
    lineHeight: lineHeight.lg,
    marginTop: verticalSpace.sm,
    maxWidth: "62rem",
  },
  controls: {
    alignItems: "center",
    display: "flex",
    flexWrap: "wrap",
    gap: horizontalSpace.lg,
    justifyContent: "space-between",
  },
  meta: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
    lineHeight: lineHeight.lg,
  },
  statGrid: {
    display: "grid",
    gap: "1rem",
    gridTemplateColumns: {
      default: "repeat(2, minmax(0, 1fr))",
      [breakpoints.lg]: "repeat(4, minmax(0, 1fr))",
    },
  },
  statCard: { minWidth: 0 },
  statValue: {
    fontSize: fontSize["2xl"],
    fontVariantNumeric: "tabular-nums",
    fontWeight: fontWeight.medium,
    color: uiColor.text2,
  },
  statLabel: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
    textTransform: "lowercase",
  },
  card: { minWidth: 0, width: "100%" },
  cardTitle: {
    color: uiColor.text2,
    fontSize: fontSize.base,
    fontWeight: fontWeight.medium,
    textTransform: "lowercase",
  },
  cardDescription: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
    fontWeight: fontWeight.normal,
  },
  cardHeaderFlush: { marginBottom: 0 },
  tableWrap: { overflowX: "auto", width: "100%" },
  table: { width: "100%" },
  modelCell: { display: "flex", flexDirection: "column", gap: "0.25rem", minWidth: 0 },
  modelId: {
    color: uiColor.text2,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  modelIdDim: { color: uiColor.text1 },
  num: { fontVariantNumeric: "tabular-nums" },
  numStrong: { fontVariantNumeric: "tabular-nums", fontWeight: fontWeight.medium },
  sub: { color: uiColor.text1, fontSize: fontSize.xs },
  stack: { display: "flex", flexDirection: "column", gap: "0.125rem" },
  badgeRow: { display: "flex", flexWrap: "wrap", gap: "0.375rem" },
  emptyCell: {
    color: uiColor.text1,
    paddingBottom: "2rem",
    paddingTop: "2rem",
    textAlign: "center",
  },
  legend: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
    lineHeight: lineHeight.lg,
  },
  modelsLink: {
    color: uiColor.text2,
    textDecorationLine: { default: "underline", ":hover": "underline" },
  },
});

/** `value: null` renders an em dash — used when the source that would answer
 *  this number was unreachable. An unknown count must never render as 0. */
function Stat({ value, label }: { value: string | null; label: string }): ReactElement {
  return (
    <Card size="md" style={styles.statCard}>
      {/* Card itself only declares the --card-* custom properties; the padding
          lives on CardHeader/CardBody/CardFooter. A bare child gets none. */}
      <CardBody>
        <Flex direction="column" gap="xs">
          <span {...stylex.props(styles.statValue)}>{value ?? "—"}</span>
          <span {...stylex.props(styles.statLabel)}>{label}</span>
        </Flex>
      </CardBody>
    </Card>
  );
}

export function ModelCapacityPage({
  window,
  onWindowChange,
}: {
  window: SupplyDemandWindow;
  onWindowChange: (next: SupplyDemandWindow) => void;
}): ReactElement {
  const query = useQuery(modelCapacityQueryOptions(window));
  const data = query.data;
  const rows = data?.rows ?? [];
  const windowLabel = WINDOW_LABELS[window];
  // A source that didn't answer leaves its half of every row UNKNOWN. Both
  // halves are zero-valued in the payload (the fold has nothing to add up), so
  // the page — not the fold — is responsible for not reading those zeroes out
  // as facts: an unreachable AppView must not make every model read
  // "no demand", and an unreachable advisor must not make every model read
  // "needs capacity".
  const supplyKnown = data ? !data.advisorUnreachable : false;
  const demandKnown = data ? !data.appviewUnreachable : false;

  // React Aria's TableBody needs at least one item to render a row, so an
  // empty result is carried by a sentinel the row renderer special-cases.
  const bodyItems: ModelSupplyDemandRow[] =
    rows.length > 0 ? rows : [{ modelId: "__empty__" } as unknown as ModelSupplyDemandRow];

  return (
    <Page.Root variant="large" style={styles.root}>
      <Page.Header style={styles.header}>
        <Flex direction="column" gap="xl">
          <Heading1 style={styles.headingMono}>
            <span {...stylex.props(styles.titlePrompt)}>~/</span>
            models/capacity
          </Heading1>
          <div {...stylex.props(styles.intro)}>
            Which models need more machines, and which already have more than the traffic justifies.
            Supply is the advisor&rsquo;s live registry of connected machines; demand is completed
            work counted from provider-signed receipts the AppView has indexed. Both are derived
            views — nothing here is a ledger. Running a machine? Sort order puts &ldquo;needs
            capacity&rdquo; first. Submitting jobs? The last column is where they queue.
          </div>
        </Flex>
      </Page.Header>

      <div {...stylex.props(styles.controls)}>
        <SegmentedControl
          aria-label="Trailing window"
          size="sm"
          selectedKeys={new Set([window])}
          onSelectionChange={(selection) => {
            const id = selection.values().next().value;
            if (typeof id !== "string") return;
            if ((SUPPLY_DEMAND_WINDOWS as readonly string[]).includes(id)) {
              onWindowChange(id as SupplyDemandWindow);
            }
          }}
        >
          {SUPPLY_DEMAND_WINDOWS.map((w) => (
            <SegmentedControlItem key={w} id={w}>
              {`last ${WINDOW_LABELS[w]}`}
            </SegmentedControlItem>
          ))}
        </SegmentedControl>
        {data ? (
          <div {...stylex.props(styles.meta)}>
            as of {new Date(data.generatedAt).toLocaleString()} ·{" "}
            <RouterLink to="/models" preload="intent" {...stylex.props(styles.modelsLink)}>
              model directory
            </RouterLink>
          </div>
        ) : null}
      </div>

      {query.isError ? (
        <Alert variant="critical" title="Couldn't load model capacity">
          <SmallBody>
            {query.error instanceof Error ? query.error.message : "Unknown error"}
          </SmallBody>
        </Alert>
      ) : null}

      {data?.advisorUnreachable ? (
        <Alert variant="warning" title="Supply is unknown right now">
          <SmallBody>
            The advisor didn&rsquo;t answer, so we can&rsquo;t say what&rsquo;s connected. The
            machine counts below are <strong>not</strong> a claim that capacity is zero — only the
            demand columns are trustworthy on this load.
          </SmallBody>
        </Alert>
      ) : null}

      {data?.appviewUnreachable ? (
        <Alert variant="warning" title="Demand is unknown right now">
          <SmallBody>
            The AppView index didn&rsquo;t answer, so request and token counts are missing rather
            than zero. Supply columns are still live.
          </SmallBody>
        </Alert>
      ) : null}

      {data ? (
        <div {...stylex.props(styles.statGrid)}>
          <Stat
            value={supplyKnown && demandKnown ? formatCount(data.totals.unservedModels) : null}
            label="models needing capacity"
          />
          <Stat
            value={supplyKnown && demandKnown ? formatCount(data.totals.idleModels) : null}
            label={`models with no demand in ${windowLabel}`}
          />
          <Stat
            value={
              supplyKnown
                ? `${formatCount(data.totals.healthyMachines)} / ${formatCount(data.totals.machines)}`
                : null
            }
            label="healthy / connected machines"
          />
          <Stat
            value={demandKnown ? formatCount(data.totals.requests) : null}
            label={`requests in ${windowLabel}`}
          />
        </div>
      ) : null}

      <Card size="md" style={styles.card}>
        <CardHeader hasBorder style={styles.cardHeaderFlush}>
          <CardTitle style={styles.cardTitle}>supply and demand by model</CardTitle>
          <CardDescription style={styles.cardDescription}>
            Trailing {windowLabel}. Stranded demand first, then the models whose healthy machines
            are carrying the most work each.
          </CardDescription>
        </CardHeader>
        <div {...stylex.props(styles.tableWrap)}>
          <Table aria-label="Model supply and demand" size="sm" style={styles.table}>
            <TableHeader columns={COLUMNS}>
              {(column) => (
                <TableColumn
                  isRowHeader={column.id === "model"}
                  hasEllipsis={column.id === "model"}
                  width={column.id === "model" ? "40%" : undefined}
                >
                  {column.name}
                </TableColumn>
              )}
            </TableHeader>
            <TableBody items={bodyItems}>
              {(row) => {
                if (row.modelId === "__empty__") {
                  return (
                    <TableRow columns={[{ id: "empty" }]} id="__empty__">
                      {() => (
                        <TableCell colSpan={COLUMNS.length} style={styles.emptyCell}>
                          {query.isPending
                            ? "Loading…"
                            : "No models are online and nothing has been served yet."}
                        </TableCell>
                      )}
                    </TableRow>
                  );
                }
                const blockers = blockerSummary(row);
                return (
                  <TableRow columns={COLUMNS} id={row.modelId} textValue={row.modelId}>
                    {(column) =>
                      renderCell(column.id, row, {
                        blockers,
                        windowLabel,
                        supplyKnown,
                        demandKnown,
                      })
                    }
                  </TableRow>
                );
              }}
            </TableBody>
          </Table>
        </div>
      </Card>

      {data && supplyKnown && demandKnown ? (
        <div {...stylex.props(styles.legend)}>
          <strong>needs capacity</strong> — work was served in the window but no connected machine
          can serve it now. <strong>under pressure</strong> — healthy machines are each carrying
          sustained traffic; another machine would help. <strong>no demand</strong> — capacity is
          online and nothing is routing to it; not worth a download.{" "}
          <strong>nothing serving</strong> — every machine advertising it is blocked, and nobody is
          asking either. A machine with an engine fault advertises only the <code>stub</code> smoke
          test and counts as zero supply everywhere, which is why <code>stub</code> sits last.
          {data.demandCoverage.coversWindow === false ? (
            <>
              {" "}
              Demand counts come from the most-recent{" "}
              {formatCount(data.demandCoverage.scanned ?? 0)} indexed receipts
              {data.demandCoverage.oldestScannedAt
                ? ` (back to ${new Date(data.demandCoverage.oldestScannedAt).toLocaleString()})`
                : ""}
              , so the {windowLabel} figures are lower bounds.
            </>
          ) : null}
        </div>
      ) : null}
    </Page.Root>
  );
}

interface CellContext {
  blockers: string | null;
  windowLabel: string;
  /** False when the advisor was unreachable: the supply half of this row is
   *  unknown, not zero. */
  supplyKnown: boolean;
  /** False when the AppView was unreachable: the demand half is unknown. */
  demandKnown: boolean;
}

const DASH = "—";

function renderCell(columnId: ColumnId, row: ModelSupplyDemandRow, ctx: CellContext): ReactElement {
  const { blockers, windowLabel, supplyKnown, demandKnown } = ctx;
  switch (columnId) {
    case "model":
      return (
        <TableCell hasEllipsis>
          <span {...stylex.props(styles.modelCell)}>
            <span {...stylex.props(styles.modelId, row.smokeTest && styles.modelIdDim)}>
              {row.modelId}
            </span>
            <span {...stylex.props(styles.badgeRow)}>
              {/* The state is a verdict about supply AND demand together, so it
                  is only honest when both halves actually arrived. */}
              {!demandKnown ? (
                <Badge size="sm" variant="default">
                  demand unknown
                </Badge>
              ) : !supplyKnown ? (
                <Badge size="sm" variant="default">
                  supply unknown
                </Badge>
              ) : (
                <Badge size="sm" variant={STATE_VARIANTS[row.state]}>
                  {STATE_LABELS[row.state]}
                </Badge>
              )}
              {supplyKnown && row.silent > 0 ? (
                <Badge size="sm" variant="warning">
                  {`${row.silent} failing silently`}
                </Badge>
              ) : null}
            </span>
          </span>
        </TableCell>
      );
    case "supply":
      return (
        <TableCell>
          <span {...stylex.props(styles.stack)}>
            <span {...stylex.props(styles.numStrong)}>
              {supplyKnown ? `${formatCount(row.healthy)} / ${formatCount(row.advertising)}` : DASH}
            </span>
            {supplyKnown && blockers ? <span {...stylex.props(styles.sub)}>{blockers}</span> : null}
          </span>
        </TableCell>
      );
    case "operators":
      return (
        <TableCell>
          <span {...stylex.props(styles.num)}>
            {supplyKnown ? formatCount(row.operators) : DASH}
          </span>
        </TableCell>
      );
    case "requests":
      return (
        <TableCell>
          <span {...stylex.props(styles.num)}>
            {demandKnown ? formatCount(row.requests) : DASH}
          </span>
        </TableCell>
      );
    case "tokens":
      return (
        <TableCell>
          <span
            {...stylex.props(styles.num)}
            title={demandKnown ? `${formatCount(row.tokens)} tokens` : undefined}
          >
            {demandKnown ? formatTokensCompact(row.tokens) : DASH}
          </span>
        </TableCell>
      );
    case "pressure":
      // Pressure divides demand by supply, so either side being unknown makes
      // the ratio unknown too.
      if (!supplyKnown || !demandKnown) {
        return (
          <TableCell>
            <span {...stylex.props(styles.numStrong)}>{DASH}</span>
          </TableCell>
        );
      }
      return (
        <TableCell>
          <span {...stylex.props(styles.stack)}>
            <span {...stylex.props(styles.numStrong)}>
              {formatPressure(row.requestsPerHealthyMachine)}
            </span>
            <span {...stylex.props(styles.sub)}>
              {row.requestsPerHealthyMachine === null
                ? row.unserved
                  ? "no machine to queue on"
                  : "no healthy supply"
                : `per machine / ${windowLabel}`}
            </span>
          </span>
        </TableCell>
      );
  }
}
