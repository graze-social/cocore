// Server fn + query options for the /models/capacity page loader.
//
// Same shape as models.functions.ts and for the same reason: TanStack Start's
// import-protection plugin refuses to pull a `.server.ts` module into the
// client bundle, so createServerFn wraps the call and the client only ever
// sees the fetch-shaped wrapper.

import { queryOptions } from "@tanstack/react-query";
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

import {
  buildModelSupplyDemand,
  type ModelSupplyDemandPayload,
} from "@/lib/model-supply-demand.server.ts";
import { SUPPLY_DEMAND_WINDOWS, type SupplyDemandWindow } from "@/lib/model-supply-demand.ts";

export const DEFAULT_CAPACITY_WINDOW: SupplyDemandWindow = "day";

const capacitySchema = z.object({
  window: z.enum(SUPPLY_DEMAND_WINDOWS).optional(),
});

const loadModelCapacityServerFn = createServerFn({ method: "GET" })
  .inputValidator(capacitySchema)
  .handler(
    ({ data }): Promise<ModelSupplyDemandPayload> =>
      buildModelSupplyDemand(data.window ?? DEFAULT_CAPACITY_WINDOW),
  );

export function modelCapacityQueryOptions(window: SupplyDemandWindow = DEFAULT_CAPACITY_WINDOW) {
  return queryOptions({
    queryKey: ["models", "capacity", window] as const,
    queryFn: (): Promise<ModelSupplyDemandPayload> =>
      loadModelCapacityServerFn({ data: { window } }),
    // Supply turns over on the advisor's heartbeat cadence and demand on the
    // AppView's 5s memo; half a minute of staleness is invisible here and
    // keeps a window flip from re-paying both round trips.
    staleTime: 30_000,
    gcTime: 300_000,
  });
}
