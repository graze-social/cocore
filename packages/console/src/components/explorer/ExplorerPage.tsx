"use client";

import * as stylex from "@stylexjs/stylex";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useMemo, useState } from "react";

import {
  type ExplorerNode,
  explorerGraphQueryOptions,
} from "@/components/explorer/explorer.functions.ts";
import { NetworkGraph } from "@/components/explorer/NetworkGraph.tsx";
import { explorerLayout, explorerSectionStyles } from "@/components/explorer/explorer.stylex.ts";
import { AppviewExplorer } from "@/components/AppviewExplorer.tsx";
import { Avatar } from "@/design-system/avatar";
import { Badge } from "@/design-system/badge";
import { Card, CardBody, CardHeader, CardTitle } from "@/design-system/card";
import { Flex } from "@/design-system/flex";
import { Page } from "@/design-system/page";
import { SearchField } from "@/design-system/search-field";
import { SegmentedControl, SegmentedControlItem } from "@/design-system/segmented-control";
import { Select, SelectItem } from "@/design-system/select";
import { uiColor } from "@/design-system/theme/color.stylex";
import { radius } from "@/design-system/theme/radius.stylex";
import { gap, verticalSpace } from "@/design-system/theme/semantic-spacing.stylex";
import {
  fontFamily,
  fontSize,
  fontWeight,
  lineHeight,
} from "@/design-system/theme/typography.stylex";
import { Heading1 } from "@/design-system/typography";
import { green } from "@/design-system/theme/colors/green.stylex";
import { purple } from "@/design-system/theme/colors/purple.stylex";

const intFmt = new Intl.NumberFormat("en-US");

const styles = stylex.create({
  header: {
    marginBottom: 0,
  },
  root: {
    display: "flex",
    flexDirection: "column",
    fontFamily: fontFamily.mono,
    gap: verticalSpace["6xl"],
    marginLeft: "auto",
    marginRight: "auto",
    maxWidth: "1600px",
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
  metaRow: {
    color: uiColor.text1,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.sm,
    lineHeight: lineHeight.lg,
    marginTop: verticalSpace.sm,
  },
  sectionMeta: {
    color: uiColor.text1,
    fontFamily: fontFamily.mono,
    fontSize: fontSize.sm,
    lineHeight: lineHeight.lg,
  },
  cardTitleMono: {
    fontSize: fontSize.base,
    fontWeight: fontWeight.medium,
    color: uiColor.text2,
    textTransform: "lowercase",
  },
  summary: {
    display: "grid",
    gridTemplateColumns: "repeat(2, 1fr)",
    gap: gap["2xl"],
  },
  summaryWide: { gridTemplateColumns: "repeat(6, 1fr)" },
  stat: { fontFamily: fontFamily.mono },
  statLabel: {
    color: uiColor.text1,
    fontSize: fontSize.xs,
    textTransform: "lowercase",
    letterSpacing: "0.05em",
    marginBottom: verticalSpace.xs,
  },
  statValue: {
    color: uiColor.text2,
    fontSize: "22px",
    fontWeight: fontWeight.medium,
    fontVariantNumeric: "tabular-nums",
  },
  controls: {
    display: "flex",
    flexWrap: "wrap",
    alignItems: "center",
    justifyContent: "space-between",
    gap: gap.lg,
  },
  searchWrap: { minWidth: 220, flexGrow: 1, maxWidth: 360 },
  legend: { display: "flex", gap: gap.xl, alignItems: "center" },
  legendItem: { display: "flex", gap: gap.sm, alignItems: "center" },
  dot: { width: 12, height: 12, borderRadius: radius.full, display: "inline-block" },
  dotProvider: { backgroundColor: green.solid1 },
  dotPerson: {
    backgroundColor: purple.component3,
    borderColor: purple.border2,
    borderWidth: 1,
    borderStyle: "solid",
  },
  legendText: { color: uiColor.text1, fontSize: fontSize.xs },
  networkSection: {
    display: "flex",
    flexDirection: "column",
    gap: verticalSpace["4xl"],
  },
  stage: {
    display: "grid",
    gridTemplateColumns: "minmax(0, 1fr)",
    gap: gap["2xl"],
    alignItems: "start",
    "@media (min-width: 900px)": { gridTemplateColumns: "minmax(0, 1fr) 300px" },
  },
  detailCard: {
    alignSelf: "start",
    display: "flex",
    flexDirection: "column",
    maxHeight: explorerLayout.graphHeight,
    minHeight: 0,
    minWidth: 0,
    width: "100%",
  },
  detailCardHeader: {
    flexShrink: 0,
  },
  detailCardBody: {
    flex: 1,
    minHeight: 0,
    overflowY: "auto",
  },
  detailEmpty: { color: uiColor.text1, fontSize: fontSize.sm, lineHeight: 1.5 },
  detailHead: { display: "flex", gap: gap.lg, alignItems: "center" },
  detailName: { display: "flex", flexDirection: "column", minWidth: 0 },
  nameText: {
    color: uiColor.text2,
    fontWeight: fontWeight.medium,
    overflow: "hidden",
    textOverflow: "ellipsis",
  },
  handleText: { color: uiColor.text1, fontSize: fontSize.xs, fontFamily: fontFamily.mono },
  specGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(2, 1fr)",
    gap: gap.md,
    marginTop: verticalSpace.lg,
  },
  specLabel: { color: uiColor.text1, fontSize: fontSize.xs },
  specValue: { color: uiColor.text2, fontSize: fontSize.sm, fontVariantNumeric: "tabular-nums" },
  chips: { display: "flex", flexWrap: "wrap", gap: gap.sm, marginTop: verticalSpace.md },
  chip: {
    fontFamily: fontFamily.mono,
    fontSize: "11px",
    color: uiColor.text1,
    backgroundColor: uiColor.component1,
    borderRadius: radius.sm,
    paddingTop: 2,
    paddingBottom: 2,
    paddingLeft: 6,
    paddingRight: 6,
  },
  profileLink: {
    color: uiColor.solid1,
    fontSize: fontSize.sm,
    fontFamily: fontFamily.mono,
    marginTop: verticalSpace.lg,
    display: "inline-block",
    textDecoration: "none",
  },
  rawSection: {
    display: "flex",
    flexDirection: "column",
    gap: verticalSpace["4xl"],
    minWidth: 0,
    paddingTop: verticalSpace["2xl"],
    width: "100%",
  },
  rawSectionIntro: {
    display: "flex",
    flexDirection: "column",
    gap: verticalSpace.md,
  },
});

function StatTile({ label, value }: { label: string; value: string }) {
  return (
    <div {...stylex.props(styles.stat)}>
      <div {...stylex.props(styles.statLabel)}>{label}</div>
      <div {...stylex.props(styles.statValue)}>{value}</div>
    </div>
  );
}

function shortDid(did: string): string {
  return did.length > 22 ? `${did.slice(0, 14)}…${did.slice(-4)}` : did;
}

function NodeDetail({ node }: { node: ExplorerNode }) {
  const displayName = node.displayName?.trim() || null;
  const handle = node.handle?.trim() || null;
  const title = displayName || (handle ? `@${handle}` : shortDid(node.did));
  const handleLine = displayName && handle ? `@${handle}` : null;
  const fallback = (displayName?.[0] ?? handle?.[0] ?? node.did[0] ?? "?").toUpperCase();

  return (
    <Flex direction="column" gap="md">
      <div {...stylex.props(styles.detailHead)}>
        <Avatar src={node.avatarUrl ?? undefined} alt={title} size="lg" fallback={fallback} />
        <div {...stylex.props(styles.detailName)}>
          <span {...stylex.props(styles.nameText)}>{title}</span>
          {handleLine ? <span {...stylex.props(styles.handleText)}>{handleLine}</span> : null}
          {!displayName && !handle ? (
            <span {...stylex.props(styles.handleText)}>{node.did}</span>
          ) : null}
        </div>
      </div>

      <Flex gap="sm" wrap>
        {node.isProvider ? <Badge variant="primary">provider</Badge> : <Badge>member</Badge>}
        {node.machines > 0 ? (
          <Badge>
            {node.machines} machine{node.machines === 1 ? "" : "s"}
          </Badge>
        ) : null}
      </Flex>

      <div {...stylex.props(styles.specGrid)}>
        <div>
          <div {...stylex.props(styles.specLabel)}>memory</div>
          <div {...stylex.props(styles.specValue)}>
            {node.ramGB > 0 ? `${intFmt.format(node.ramGB)} GB` : "—"}
          </div>
        </div>
        <div>
          <div {...stylex.props(styles.specLabel)}>cores</div>
          <div {...stylex.props(styles.specValue)}>
            {node.cpuCores > 0 ? intFmt.format(node.cpuCores) : "—"}
          </div>
        </div>
        <div>
          <div {...stylex.props(styles.specLabel)}>trusts</div>
          <div {...stylex.props(styles.specValue)}>{node.trustsOut}</div>
        </div>
        <div>
          <div {...stylex.props(styles.specLabel)}>trusted by</div>
          <div {...stylex.props(styles.specValue)}>{node.trustedByIn}</div>
        </div>
      </div>

      {node.chips.length > 0 ? (
        <div>
          <div {...stylex.props(styles.specLabel)}>hardware</div>
          <div {...stylex.props(styles.chips)}>
            {node.chips.map((c) => (
              <span key={c} {...stylex.props(styles.chip)}>
                {c}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {node.models.length > 0 ? (
        <div>
          <div {...stylex.props(styles.specLabel)}>models</div>
          <div {...stylex.props(styles.chips)}>
            {node.models.slice(0, 8).map((m) => (
              <span key={m} {...stylex.props(styles.chip)}>
                {m.split("/").pop()}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {node.versions.length > 0 ? (
        <div>
          <div {...stylex.props(styles.specLabel)}>agent version</div>
          <div {...stylex.props(styles.chips)}>
            {node.versions.map((v) => (
              <span key={v} {...stylex.props(styles.chip)}>
                v{v}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      <Link
        to="/u/$identifier"
        params={{ identifier: node.handle ?? node.did }}
        preload="intent"
        {...stylex.props(styles.profileLink)}
      >
        view profile →
      </Link>
    </Flex>
  );
}

/** Newest-first ordering for agent version strings — numeric dot-part
 *  compare with lexicographic fallback (mirrors the server's ordering
 *  inside a node's own `versions`, which we can't import client-side). */
function compareVersionsDesc(a: string, b: string): number {
  const pa = a.split(".").map((p) => Number.parseInt(p, 10));
  const pb = b.split(".").map((p) => Number.parseInt(p, 10));
  if (pa.every(Number.isFinite) && pb.every(Number.isFinite)) {
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const d = (pb[i] ?? 0) - (pa[i] ?? 0);
      if (d !== 0) return d;
    }
    return 0;
  }
  return b.localeCompare(a);
}

/** Sentinel ids for the version filter's non-version choices. Real agent
 *  versions are dotted numerics, so these can't collide. */
const VERSION_ANY = "any";
const VERSION_NONE = "unversioned";

export function ExplorerPage() {
  const graphQuery = useQuery(explorerGraphQueryOptions);
  const [selectedDid, setSelectedDid] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<"all" | "providers">("all");
  const [versionFilter, setVersionFilter] = useState<string>(VERSION_ANY);

  const graph = graphQuery.data;
  const nodesByDid = useMemo(() => {
    const m = new Map<string, ExplorerNode>();
    for (const n of graph?.nodes ?? []) m.set(n.did, n);
    return m;
  }, [graph]);
  const selected = selectedDid ? (nodesByDid.get(selectedDid) ?? null) : null;

  // Distinct agent versions on the network, newest first, with provider
  // counts for the dropdown labels. "unversioned" appears only when some
  // provider's records predate the binaryVersion field.
  const versionOptions = useMemo(() => {
    const counts = new Map<string, number>();
    let unversioned = 0;
    for (const n of graph?.nodes ?? []) {
      if (!n.isProvider) continue;
      if (n.versions.length === 0) unversioned += 1;
      for (const v of n.versions) counts.set(v, (counts.get(v) ?? 0) + 1);
    }
    const versions = [...counts.keys()].sort(compareVersionsDesc);
    return { versions, counts, unversioned };
  }, [graph]);

  // The DID set the graph should keep for the active version filter; null
  // when the filter is off. Keeping the sentinel logic here means the
  // graph component only ever sees a plain allow-set.
  const versionDids = useMemo(() => {
    if (versionFilter === VERSION_ANY) return null;
    const keep = new Set<string>();
    for (const n of graph?.nodes ?? []) {
      if (!n.isProvider) continue;
      if (
        versionFilter === VERSION_NONE
          ? n.versions.length === 0
          : n.versions.includes(versionFilter)
      ) {
        keep.add(n.did);
      }
    }
    return keep;
  }, [graph, versionFilter]);

  return (
    <Page.Root variant="large" style={styles.root}>
      <Page.Header style={styles.header}>
        <Flex direction="column" gap="xl">
          <Heading1 style={styles.headingMono}>
            <span {...stylex.props(styles.titlePrompt)}>~/</span>explore
          </Heading1>
          <div {...stylex.props(styles.metaRow)}>
            Every machine and person on cocore, and the trust graph between them. Each dot is a DID
            — bronze ones run machines. Lines are trust: who routes their private jobs to whom. Drag
            to pan, scroll to zoom, click a node to inspect it.
          </div>
        </Flex>
      </Page.Header>

      <Flex direction="column" gap="6xl">
        <div {...stylex.props(styles.networkSection)}>
          {graph ? (
            <div {...stylex.props(styles.summary, styles.summaryWide)}>
              <StatTile label="people" value={intFmt.format(graph.summary.people)} />
              <StatTile label="providers" value={intFmt.format(graph.summary.providers)} />
              <StatTile label="machines" value={intFmt.format(graph.summary.machines)} />
              <StatTile
                label="combined RAM"
                value={`${intFmt.format(graph.summary.totalRamGB)} GB`}
              />
              <StatTile label="combined cores" value={intFmt.format(graph.summary.totalCpuCores)} />
              <StatTile label="trust edges" value={intFmt.format(graph.summary.trustEdges)} />
            </div>
          ) : null}

          {graph?.summary.rendered.truncated ? (
            <div {...stylex.props(styles.metaRow)}>
              Graphing the {intFmt.format(graph.summary.rendered.nodes)} most-connected of{" "}
              {intFmt.format(graph.summary.people)} — search to find anyone not drawn.
            </div>
          ) : null}

          <div {...stylex.props(styles.controls)}>
            <div {...stylex.props(styles.searchWrap)}>
              <SearchField
                size="lg"
                placeholder="find a handle or DID"
                value={query}
                onChange={setQuery}
                aria-label="search the network"
              />
            </div>
            <Flex gap="xl" align="center" wrap>
              <SegmentedControl
                aria-label="filter nodes"
                size="lg"
                selectedKeys={new Set([filter])}
                onSelectionChange={(sel) => {
                  const id = sel.values().next().value;
                  if (id === "all" || id === "providers") setFilter(id);
                }}
              >
                <SegmentedControlItem id="all">everyone</SegmentedControlItem>
                <SegmentedControlItem id="providers">providers</SegmentedControlItem>
              </SegmentedControl>
              <Select
                aria-label="filter by agent version"
                label="version"
                labelVariant="horizontal"
                selectedKey={versionFilter}
                onSelectionChange={(key) => {
                  if (key != null) setVersionFilter(String(key));
                }}
              >
                <SelectItem id={VERSION_ANY} textValue="any">
                  any
                </SelectItem>
                {versionOptions.versions.map((v) => (
                  <SelectItem key={v} id={v} textValue={`v${v}`}>
                    v{v} · {versionOptions.counts.get(v)}
                  </SelectItem>
                ))}
                {versionOptions.unversioned > 0 ? (
                  <SelectItem id={VERSION_NONE} textValue="unversioned">
                    unversioned · {versionOptions.unversioned}
                  </SelectItem>
                ) : null}
              </Select>
              <div {...stylex.props(styles.legend)}>
                <span {...stylex.props(styles.legendItem)}>
                  <span {...stylex.props(styles.dot, styles.dotProvider)} />
                  <span {...stylex.props(styles.legendText)}>provider</span>
                </span>
                <span {...stylex.props(styles.legendItem)}>
                  <span {...stylex.props(styles.dot, styles.dotPerson)} />
                  <span {...stylex.props(styles.legendText)}>member</span>
                </span>
              </div>
            </Flex>
          </div>

          <div {...stylex.props(styles.stage)}>
            <NetworkGraph
              nodes={graph?.nodes ?? []}
              edges={graph?.edges ?? []}
              selectedDid={selectedDid}
              onSelect={setSelectedDid}
              query={query}
              providersOnly={filter === "providers"}
              versionDids={versionDids}
            />
            <Card size="md" style={styles.detailCard}>
              <CardHeader hasBorder style={styles.detailCardHeader}>
                <CardTitle style={styles.cardTitleMono}>
                  {selected ? "node" : "no selection"}
                </CardTitle>
              </CardHeader>
              <CardBody style={styles.detailCardBody}>
                {selected ? (
                  <NodeDetail node={selected} />
                ) : (
                  <div {...stylex.props(styles.detailEmpty)}>
                    {graphQuery.isLoading
                      ? "Loading the network…"
                      : "Click any node to see its machines, hardware, and trust relationships."}
                  </div>
                )}
              </CardBody>
            </Card>
          </div>
        </div>

        <section {...stylex.props(styles.rawSection)}>
          <div {...stylex.props(styles.rawSectionIntro)}>
            <h2 {...stylex.props(explorerSectionStyles.heading)}>raw appview index</h2>
            <div {...stylex.props(styles.sectionMeta)}>
              The underlying read-only views: registered providers, indexed receipts and
              settlements, and verification tools.
            </div>
          </div>
          <AppviewExplorer />
        </section>
      </Flex>
    </Page.Root>
  );
}
