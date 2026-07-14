// Client-safe data layer for the network Explorer. The route + page
// import this (never the `.server.ts` directly — TanStack Start's
// import-protection plugin forbids a component importing a server
// module). The graph is public read-only network data, so no auth
// middleware: the explorer works signed-out too.

import { queryOptions } from "@tanstack/react-query";
import { createServerFn } from "@tanstack/react-start";

import { type ExplorerGraph, getExplorerGraphCached } from "@/lib/explorer-graph.server.ts";

export type { ExplorerGraph, ExplorerNode, ExplorerEdge } from "@/lib/explorer-graph.server.ts";

// Not exported: the route + page consume `explorerGraphQueryOptions`,
// which wraps this server fn (same pattern as friends.functions.ts).
const loadExplorerGraphServerFn = createServerFn({ method: "GET" }).handler(
  (): Promise<ExplorerGraph> => getExplorerGraphCached(),
);

export const explorerGraphQueryOptions = queryOptions({
  queryKey: ["explorer", "graph"] as const,
  queryFn: (): Promise<ExplorerGraph> => loadExplorerGraphServerFn(),
  // Refetch readily on mount/focus; the server fn is itself cached
  // (see CACHE_TTL_MS in explorer-graph.server.ts), so a fresh fetch is
  // cheap and just picks up the newest server snapshot as the network grows.
  staleTime: 60_000,
  gcTime: 600_000,
});
