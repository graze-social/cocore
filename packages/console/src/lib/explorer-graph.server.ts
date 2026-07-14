// Assembles the network-explorer graph: people (accounts) + the
// machines they run + the directed trust (friend) edges between them.
//
// Pure read over the AppView. Every source is fetched with
// `Effect.either` so a single slow/missing endpoint degrades
// gracefully — e.g. before the AppView is redeployed with
// `listFriendEdges`, the graph still renders all the nodes, just
// without edges. Cached for a few minutes like the marketing
// snapshot; the explorer is a read-only browse surface, not a
// live dashboard.

import { Effect } from "effect";

import {
  type AppviewAccountSummary,
  type AppviewFriendEdge,
  type AppviewIndexedRecord,
  type JsonValue,
  appviewListAccountsEffect,
  appviewListFriendEdgesEffect,
  appviewListProfilesEffect,
  appviewListProvidersEffect,
} from "@/integrations/appview/appview.server.ts";
import { runTraced } from "@/lib/o11y.server.ts";

/** One person/account in the network graph, enriched with the
 *  hardware they run and their trust degree. */
export interface ExplorerNode {
  did: string;
  handle: string | null;
  displayName: string | null;
  avatarUrl: string | null;
  /** Runs at least one machine. */
  isProvider: boolean;
  /** Provider-record count (machines) for this DID. */
  machines: number;
  /** Summed RAM (GB) across this DID's machines. */
  ramGB: number;
  /** Summed CPU cores across machines that report them. */
  cpuCores: number;
  /** Distinct chip strings across machines (e.g. "Apple M3 Max"). */
  chips: string[];
  /** Distinct supported models across machines. */
  models: string[];
  /** Distinct agent versions across machines (provider record
   *  `binaryVersion`, stamped on every serve), newest first. Empty for
   *  members and for providers whose records predate the field. */
  versions: string[];
  /** Outgoing trust: machines this DID is willing to route jobs to. */
  trustsOut: number;
  /** Incoming trust: how many DIDs route their jobs to this DID. */
  trustedByIn: number;
  lastActivityAt: string | null;
}

/** A directed trust edge: `source` trusts `target` to run its jobs. */
export interface ExplorerEdge {
  source: string;
  target: string;
}

export interface ExplorerGraph {
  generatedAt: string;
  nodes: ExplorerNode[];
  edges: ExplorerEdge[];
  /** Counts over the WHOLE network, independent of the render cap
   *  below. These are the headline stats; they must match the friends
   *  directory's `total` and never get clamped by `MAX_NODES`. */
  summary: {
    people: number;
    providers: number;
    machines: number;
    totalRamGB: number;
    totalCpuCores: number;
    trustEdges: number;
    /** What actually made it into `nodes`/`edges` after the render cap.
     *  `truncated` is true when the network outgrew `MAX_NODES` and the
     *  graph shows only the most-connected subset. */
    rendered: { nodes: number; edges: number; truncated: boolean };
  };
}

// Hard cap on rendered nodes so the client force-sim stays smooth. Kept
// well above the current network so nothing is trimmed today; if it is
// ever exceeded we keep the most-connected + most-active nodes (see the
// trim in buildExplorerGraph). NOTE: this caps only what is DRAWN — the
// `summary` counts above are always computed over the full network, so
// the headline stats track the real network size even past the cap.
const MAX_NODES = 10_000;
const CACHE_TTL_MS = 2 * 60_000;
// The AppView clamps `listAccounts` to 100 rows/page, so we page through
// `offset` to seed every signed-up DID (not just the recent 100).
const ACCOUNTS_PAGE = 100;
// Safety bound on pagination so a runaway `total` can't loop forever.
const MAX_ACCOUNTS = 5000;
let cache: { expiresAt: number; graph: ExplorerGraph } | null = null;

function asObject(body: JsonValue): Record<string, JsonValue> | null {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  return body as Record<string, JsonValue>;
}

function safeString(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

interface ProfileFields {
  handle: string | null;
  displayName: string | null;
  avatarUrl: string | null;
}

function profilesByDidFromRows(rows: AppviewIndexedRecord[]): Map<string, ProfileFields> {
  const map = new Map<string, ProfileFields>();
  for (const row of rows) {
    const o = asObject(row.body);
    if (!o) continue;
    map.set(row.repo, {
      handle: safeString(o["handle"]),
      displayName: safeString(o["displayName"]),
      avatarUrl: safeString(o["avatarUrl"]),
    });
  }
  return map;
}

function mergeProfile(node: ExplorerNode, profile: ProfileFields | undefined): void {
  if (!profile) return;
  if (!node.handle && profile.handle) node.handle = profile.handle;
  if (!node.displayName && profile.displayName) node.displayName = profile.displayName;
  if (!node.avatarUrl && profile.avatarUrl) node.avatarUrl = profile.avatarUrl;
}

interface ProviderAgg {
  machines: number;
  ramGB: number;
  cpuCores: number;
  chips: Set<string>;
  models: Set<string>;
  versions: Set<string>;
}

/** Sort version strings newest-first: numeric dot-part comparison for
 *  well-formed versions ("0.9.40" > "0.9.9"), lexicographic fallback for
 *  anything else. Good enough for display + filter ordering; no semver
 *  pre-release semantics needed for agent versions. */
function sortVersionsDesc(versions: string[]): string[] {
  const parts = (v: string) => v.split(".").map((p) => Number.parseInt(p, 10));
  return [...versions].sort((a, b) => {
    const pa = parts(a);
    const pb = parts(b);
    if (pa.every(Number.isFinite) && pb.every(Number.isFinite)) {
      for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
        const d = (pb[i] ?? 0) - (pa[i] ?? 0);
        if (d !== 0) return d;
      }
      return 0;
    }
    return b.localeCompare(a);
  });
}

/** Group raw provider records by owning DID, summing hardware. */
function aggregateProviders(rows: AppviewIndexedRecord[]): Map<string, ProviderAgg> {
  const byDid = new Map<string, ProviderAgg>();
  for (const row of rows) {
    const o = asObject(row.body);
    if (!o) continue;
    let agg = byDid.get(row.repo);
    if (!agg) {
      agg = {
        machines: 0,
        ramGB: 0,
        cpuCores: 0,
        chips: new Set(),
        models: new Set(),
        versions: new Set(),
      };
      byDid.set(row.repo, agg);
    }
    agg.machines += 1;
    if (typeof o["ramGB"] === "number" && Number.isFinite(o["ramGB"]) && o["ramGB"] > 0) {
      agg.ramGB += o["ramGB"];
    }
    if (typeof o["cpuCores"] === "number" && Number.isFinite(o["cpuCores"]) && o["cpuCores"] > 0) {
      agg.cpuCores += o["cpuCores"];
    }
    if (typeof o["chip"] === "string" && o["chip"].length > 0) agg.chips.add(o["chip"]);
    if (typeof o["binaryVersion"] === "string" && o["binaryVersion"].length > 0) {
      agg.versions.add(o["binaryVersion"]);
    }
    const sm = o["supportedModels"];
    if (Array.isArray(sm)) {
      for (const m of sm) if (typeof m === "string" && m.length > 0) agg.models.add(m);
    }
  }
  return byDid;
}

function blankNode(did: string): ExplorerNode {
  return {
    did,
    handle: null,
    displayName: null,
    avatarUrl: null,
    isProvider: false,
    machines: 0,
    ramGB: 0,
    cpuCores: 0,
    chips: [],
    models: [],
    versions: [],
    trustsOut: 0,
    trustedByIn: 0,
    lastActivityAt: null,
  };
}

/** A node's importance for the cap trim: connected + provider-heavy
 *  + recently active nodes are kept first. */
function nodeWeight(n: ExplorerNode): number {
  return n.trustsOut + n.trustedByIn + (n.isProvider ? 3 : 0) + n.machines;
}

/** Page through the whole accounts directory so the graph seeds EVERY
 *  signed-up DID, not just the most-recent 100. The AppView clamps
 *  `limit` to 100 and returns `total`, so we walk `offset` until we've
 *  collected `total` (or hit the safety cap). A failed follow-up page
 *  degrades to "what we have so far" rather than losing everything; a
 *  failed first page propagates so the outer `Effect.either` can fall
 *  back to the other sources. */
const listAllAccountsEffect = Effect.gen(function* () {
  const first = yield* appviewListAccountsEffect({
    limit: ACCOUNTS_PAGE,
    offset: 0,
    sortBy: "recent",
  });
  const accounts: AppviewAccountSummary[] = [...first.accounts];
  const total = Math.min(first.total ?? accounts.length, MAX_ACCOUNTS);
  for (let offset = ACCOUNTS_PAGE; offset < total; offset += ACCOUNTS_PAGE) {
    const pageR = yield* Effect.either(
      appviewListAccountsEffect({ limit: ACCOUNTS_PAGE, offset, sortBy: "recent" }),
    );
    if (pageR._tag !== "Right" || pageR.right.accounts.length === 0) break;
    accounts.push(...pageR.right.accounts);
  }
  return accounts;
});

async function buildExplorerGraph(): Promise<ExplorerGraph> {
  const generatedAt = new Date().toISOString();

  const [accountsR, providersR, edgesR, profilesR] = await runTraced(
    "explorer.graph.appview",
    Effect.all(
      [
        Effect.either(listAllAccountsEffect),
        Effect.either(appviewListProvidersEffect),
        Effect.either(appviewListFriendEdgesEffect({ limit: 5000 })),
        Effect.either(appviewListProfilesEffect),
      ],
      { concurrency: "unbounded" },
    ),
  );

  const accounts: AppviewAccountSummary[] = accountsR._tag === "Right" ? accountsR.right : [];
  const providers: AppviewIndexedRecord[] =
    providersR._tag === "Right" ? providersR.right.providers : [];
  const rawEdges: AppviewFriendEdge[] = edgesR._tag === "Right" ? edgesR.right.edges : [];
  const profilesByDid = profilesByDidFromRows(
    profilesR._tag === "Right" ? profilesR.right.profiles : [],
  );

  const providerAgg = aggregateProviders(providers);

  // Seed nodes from the accounts directory (carries handle + avatar).
  const nodes = new Map<string, ExplorerNode>();
  for (const a of accounts) {
    const node = blankNode(a.did);
    node.handle = a.handle;
    node.displayName = a.displayName;
    node.avatarUrl = a.avatarUrl;
    node.isProvider = a.isProvider;
    node.lastActivityAt = a.lastActivityAt ?? null;
    mergeProfile(node, profilesByDid.get(a.did));
    nodes.set(a.did, node);
  }
  // Ensure every provider DID + every edge endpoint exists as a node,
  // even if the accounts directory didn't surface it.
  const ensure = (did: string): ExplorerNode => {
    let n = nodes.get(did);
    if (!n) {
      n = blankNode(did);
      mergeProfile(n, profilesByDid.get(did));
      nodes.set(did, n);
    }
    return n;
  };
  for (const did of providerAgg.keys()) ensure(did);

  // Fold in hardware aggregates.
  for (const [did, agg] of providerAgg) {
    const n = ensure(did);
    n.machines = agg.machines;
    n.ramGB = agg.ramGB;
    n.cpuCores = agg.cpuCores;
    n.chips = [...agg.chips];
    n.models = [...agg.models];
    n.versions = sortVersionsDesc([...agg.versions]);
    if (agg.machines > 0) n.isProvider = true;
  }

  // Edges (both endpoints become nodes) + trust degree.
  const edges: ExplorerEdge[] = [];
  for (const e of rawEdges) {
    const from = ensure(e.friender);
    const to = ensure(e.subject);
    from.trustsOut += 1;
    to.trustedByIn += 1;
    edges.push({ source: e.friender, target: e.subject });
  }

  // Headline stats reflect the WHOLE network — computed over every node
  // and edge, before any render cap. This is what must match the friends
  // directory's `total`; clamping it to MAX_NODES is the bug that pinned
  // "people" at 220.
  const allNodes = [...nodes.values()];
  const fullSummary = {
    people: allNodes.length,
    providers: allNodes.filter((n) => n.isProvider).length,
    machines: allNodes.reduce((s, n) => s + n.machines, 0),
    totalRamGB: allNodes.reduce((s, n) => s + n.ramGB, 0),
    totalCpuCores: allNodes.reduce((s, n) => s + n.cpuCores, 0),
    trustEdges: edges.length,
  };

  // Cap only what we DRAW, for client-side sim performance: keep the
  // most-connected/active nodes and drop now-dangling edges. The summary
  // above is unaffected.
  let nodeList = allNodes;
  let keptEdges = edges;
  const truncated = allNodes.length > MAX_NODES;
  if (truncated) {
    nodeList = [...allNodes].sort((a, b) => nodeWeight(b) - nodeWeight(a)).slice(0, MAX_NODES);
    const kept = new Set(nodeList.map((n) => n.did));
    keptEdges = edges.filter((e) => kept.has(e.source) && kept.has(e.target));
  }

  for (const node of nodeList) {
    mergeProfile(node, profilesByDid.get(node.did));
  }

  const summary = {
    ...fullSummary,
    rendered: { nodes: nodeList.length, edges: keptEdges.length, truncated },
  };

  return { generatedAt, nodes: nodeList, edges: keptEdges, summary };
}

export async function getExplorerGraphCached(): Promise<ExplorerGraph> {
  const now = Date.now();
  if (cache && cache.expiresAt > now) return cache.graph;
  const graph = await buildExplorerGraph();
  cache = { expiresAt: now + CACHE_TTL_MS, graph };
  return graph;
}
