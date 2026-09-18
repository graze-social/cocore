// /models/capacity — the model supply/demand table.
//
// Filed as `models_.capacity` (trailing underscore) so `/models` stays a leaf
// route and doesn't have to become a layout with an <Outlet />.
//
// The trailing window lives in the URL (`?window=week`) so the view is
// shareable and the loader can prefetch the right one. The loader AWAITS the
// query: under streaming SSR an un-awaited loader promise still gates the
// whole dehydrated body, so deferring here would hide the cost rather than
// remove it. Both upstream fetches run concurrently inside
// buildModelSupplyDemand, and the advisor leg carries a 5s timeout, so the
// wait is bounded and measurable.

import { createFileRoute } from "@tanstack/react-router";
import type { ReactElement } from "react";

import { ModelCapacityPage } from "@/components/models/ModelCapacityPage.tsx";
import {
  DEFAULT_CAPACITY_WINDOW,
  modelCapacityQueryOptions,
} from "@/components/models/model-capacity.functions.ts";
import { SUPPLY_DEMAND_WINDOWS, type SupplyDemandWindow } from "@/lib/model-supply-demand.ts";

/** `window` stays OPTIONAL so every `<Link to="/models/capacity">` in the app
 *  can omit it — an all-optional search schema is what lets TanStack treat the
 *  `search` prop as unnecessary. An unrecognized value falls back to the
 *  default rather than erroring the route. */
interface CapacitySearch {
  window?: SupplyDemandWindow;
}

export const Route = createFileRoute("/_header-layout/models_/capacity")({
  // Public, read-only view — no auth middleware, same as /models.
  validateSearch: (search: Record<string, unknown>): CapacitySearch => {
    const raw = search["window"];
    return typeof raw === "string" && (SUPPLY_DEMAND_WINDOWS as readonly string[]).includes(raw)
      ? { window: raw as SupplyDemandWindow }
      : {};
  },
  loaderDeps: ({ search }) => ({ window: search.window ?? DEFAULT_CAPACITY_WINDOW }),
  loader: async ({ context, deps }) => {
    await context.queryClient.ensureQueryData(modelCapacityQueryOptions(deps.window));
  },
  component: ModelCapacityRoute,
  head: () => ({
    meta: [
      { title: "Model capacity · co/core" },
      {
        name: "description",
        content:
          "Live supply and demand per inference model on co/core: how many healthy machines serve each model, how much work it took recently, and which models need more capacity.",
      },
    ],
  }),
});

function ModelCapacityRoute(): ReactElement {
  const { window } = Route.useSearch();
  const navigate = Route.useNavigate();
  return (
    <ModelCapacityPage
      window={window ?? DEFAULT_CAPACITY_WINDOW}
      onWindowChange={(next) => {
        void navigate({ search: { window: next }, replace: true });
      }}
    />
  );
}
