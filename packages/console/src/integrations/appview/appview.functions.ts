import { mutationOptions, queryOptions } from "@tanstack/react-query";
import { createServerFn } from "@tanstack/react-start";
import { Effect } from "effect";
import { z } from "zod";

import {
  appviewGetReceiptsEffect,
  appviewGetSettlementsEffect,
  appviewListProvidersEffect,
  appviewVerifyReceiptEffect,
  appviewVerifySettlementEffect,
  type AppviewIndexedRecord,
} from "@/integrations/appview/appview.server.ts";
import { resolveActorsForDids, type ResolvedActor } from "@/lib/friends.server.ts";

const receiptsFiltersSchema = z.object({
  provider: z.string().optional(),
  requester: z.string().optional(),
  job: z.string().optional(),
});

const settlementsFiltersSchema = z.object({
  receipt: z.string().optional(),
  requester: z.string().optional(),
});

const uriSchema = z.object({
  uri: z.string().min(1, "URI is required"),
});

function runAppview<R, E>(effect: Effect.Effect<R, E>): Promise<R> {
  return Effect.runPromise(effect);
}

export type AppviewIndexedRecordEnriched = AppviewIndexedRecord & {
  repoHandle: string | null;
  repoDisplayName: string | null;
  repoAvatarUrl: string | null;
  // The requester (the DID a receipt/settlement was computed *for*),
  // resolved the same way as the repo so the UI can show who the work
  // was done for — not just a bare DID. Null for record kinds without a
  // requester (e.g. provider rows).
  requesterDid: string | null;
  requesterHandle: string | null;
  requesterDisplayName: string | null;
  requesterAvatarUrl: string | null;
};

const EMPTY_ACTOR: ResolvedActor = { handle: null, displayName: null, avatarUrl: null };

/** The `requester` DID carried in a receipt/settlement body, if present. */
function requesterDidOf(row: AppviewIndexedRecord): string | null {
  const body = row.body;
  if (body && typeof body === "object" && !Array.isArray(body)) {
    const r = (body as Record<string, unknown>).requester;
    if (typeof r === "string" && r.startsWith("did:")) return r;
  }
  return null;
}

async function enrichIndexedRecords(
  rows: AppviewIndexedRecord[],
  opts?: { withRequester?: boolean },
): Promise<AppviewIndexedRecordEnriched[]> {
  const requesterDids = opts?.withRequester ? rows.map(requesterDidOf) : rows.map(() => null);
  // One batched resolution for both sides; resolveActorsForDids dedups.
  const resolved = await resolveActorsForDids([
    ...rows.map((r) => r.repo),
    ...requesterDids.filter((d): d is string => d != null),
  ]);
  return rows.map((row, i) => {
    const repo = resolved.get(row.repo) ?? EMPTY_ACTOR;
    const reqDid = requesterDids[i] ?? null;
    const req = reqDid ? (resolved.get(reqDid) ?? EMPTY_ACTOR) : EMPTY_ACTOR;
    return {
      ...row,
      repoHandle: repo.handle,
      repoDisplayName: repo.displayName,
      repoAvatarUrl: repo.avatarUrl,
      requesterDid: reqDid,
      requesterHandle: req.handle,
      requesterDisplayName: req.displayName,
      requesterAvatarUrl: req.avatarUrl,
    };
  });
}

const listProvidersAppviewServerFn = createServerFn({ method: "GET" }).handler(async () => {
  const data = await runAppview(appviewListProvidersEffect);
  return { providers: await enrichIndexedRecords(data.providers) };
});

export const listProvidersAppviewQueryOptions = queryOptions({
  queryKey: ["appview", "providers"] as const,
  queryFn: listProvidersAppviewServerFn,
  staleTime: 30_000,
});

const getReceiptsAppviewServerFn = createServerFn({ method: "GET" })
  .inputValidator(receiptsFiltersSchema)
  .handler(async ({ data }) => {
    const result = await runAppview(appviewGetReceiptsEffect(data));
    return { receipts: await enrichIndexedRecords(result.receipts, { withRequester: true }) };
  });

export function getReceiptsAppviewQueryOptions(filters: z.infer<typeof receiptsFiltersSchema>) {
  return queryOptions({
    queryKey: ["appview", "receipts", filters] as const,
    queryFn: () => getReceiptsAppviewServerFn({ data: filters }),
    staleTime: 30_000,
  });
}

const getSettlementsAppviewServerFn = createServerFn({ method: "GET" })
  .inputValidator(settlementsFiltersSchema)
  .handler(async ({ data }) => {
    const result = await runAppview(appviewGetSettlementsEffect(data));
    return { settlements: await enrichIndexedRecords(result.settlements) };
  });

export function getSettlementsAppviewQueryOptions(
  filters: z.infer<typeof settlementsFiltersSchema>,
) {
  return queryOptions({
    queryKey: ["appview", "settlements", filters] as const,
    queryFn: () => getSettlementsAppviewServerFn({ data: filters }),
    staleTime: 30_000,
  });
}

const verifyReceiptAppviewServerFn = createServerFn({ method: "POST" })
  .inputValidator(uriSchema)
  .handler(({ data }) => runAppview(appviewVerifyReceiptEffect(data.uri)));

const verifySettlementAppviewServerFn = createServerFn({ method: "POST" })
  .inputValidator(uriSchema)
  .handler(({ data }) => runAppview(appviewVerifySettlementEffect(data.uri)));

export type VerifyReceiptVariables = z.infer<typeof uriSchema>;
export type VerifySettlementVariables = z.infer<typeof uriSchema>;

export const verifyReceiptAppviewMutationOptions = mutationOptions({
  mutationFn: (variables: VerifyReceiptVariables) =>
    verifyReceiptAppviewServerFn({ data: variables }),
});

export const verifySettlementAppviewMutationOptions = mutationOptions({
  mutationFn: (variables: VerifySettlementVariables) =>
    verifySettlementAppviewServerFn({ data: variables }),
});
