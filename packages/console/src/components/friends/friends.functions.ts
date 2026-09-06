// Server functions that bridge the /friends page UI to the
// PDS-side CRUD in `friends.server.ts`. Mirrors the api-keys
// pattern: one server fn per operation, exposed via TanStack
// Query options so the UI gets caching + invalidation for free.

import { mutationOptions, queryOptions } from "@tanstack/react-query";
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

import {
  type AppviewAccountSummary,
  appviewListAccountsEffect,
} from "@/integrations/appview/appview.server.ts";
import { runTraced } from "@/lib/o11y.server.ts";
import {
  addFriend,
  appviewProfileFieldsForDid,
  type CocoreFriend,
  listMyFriends,
  lookupActor,
  removeFriend,
} from "@/lib/friends.server.ts";
import { authMiddleware } from "@/middleware/auth.ts";

const addFriendSchema = z.object({
  subject: z.string().min(1).max(512),
  subjectHandle: z.string().max(256).optional().nullable(),
  note: z.string().max(1024).optional().nullable(),
});

const removeFriendSchema = z.object({
  rkey: z.string().min(1).max(256),
});

const lookupActorSchema = z.object({
  /** Handle or DID. The server-side `lookupActor` cleans up
   *  whitespace and a leading `@`. */
  query: z.string().min(1).max(256),
});

const discoverSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).optional(),
  offset: z.coerce.number().int().min(0).optional(),
  sortBy: z.enum(["recent", "newest"]).optional(),
  /** GET server-fn inputs may arrive as strings; coerce so flags reach AppView. */
  providersOnly: z.coerce.boolean().optional(),
  excludeViewerFriends: z.coerce.boolean().optional(),
});

/** PDS friend row plus display fields from the public bsky appview (best-effort). */
export type ListedFriend = CocoreFriend & {
  avatarUrl: string | null;
  displayName: string | null;
  displayHandle: string | null;
};

const listMyFriendsServerFn = createServerFn({ method: "GET" })
  .middleware([authMiddleware])
  .handler(async ({ context }): Promise<ListedFriend[]> => {
    const friends = await listMyFriends(context.oauthSession);
    return await Promise.all(
      friends.map(async (f): Promise<ListedFriend> => {
        const lookup = await lookupActor(f.subjectHandle ?? f.subject);
        const { avatarUrl, displayName, displayHandle } = appviewProfileFieldsForDid(
          lookup,
          f.subject,
          f.subjectHandle,
        );
        return { ...f, avatarUrl, displayName, displayHandle };
      }),
    );
  });

export const listMyFriendsQueryOptions = queryOptions({
  queryKey: ["friends", "list"] as const,
  // Wrap so TanStack Query sees `ListedFriend[]` — `createServerFn` types
  // widen the callable's return type for the client bundle.
  queryFn: async (): Promise<ListedFriend[]> => await listMyFriendsServerFn(),
  // The friends list resolves a live profile per friend (bsky.app) plus a
  // PDS read — the slow part. Cache it for a few minutes so navigating back
  // doesn't re-pay that, and keep it in memory across tab switches.
  staleTime: 180_000,
  gcTime: 600_000,
});

const addFriendServerFn = createServerFn({ method: "POST" })
  .inputValidator(addFriendSchema)
  .middleware([authMiddleware])
  .handler(async ({ context, data }) => {
    return await addFriend(context.oauthSession, {
      subject: data.subject,
      subjectHandle: data.subjectHandle ?? null,
      note: data.note ?? null,
    });
  });

const removeFriendServerFn = createServerFn({ method: "POST" })
  .inputValidator(removeFriendSchema)
  .middleware([authMiddleware])
  .handler(async ({ context, data }) => {
    return await removeFriend(context.oauthSession, data.rkey);
  });

const lookupActorServerFn = createServerFn({ method: "POST" })
  .inputValidator(lookupActorSchema)
  .handler(async ({ data }) => {
    // No auth middleware — this is a thin wrapper around the public
    // bsky appview's getProfile and doesn't touch any user state.
    return await lookupActor(data.query);
  });

interface DiscoverPayload {
  accounts: AppviewAccountSummary[];
  total: number;
  limit: number;
  offset: number;
  sortBy: "recent" | "newest";
  providersOnly: boolean;
}

const discoverAccountsServerFn = createServerFn({ method: "GET" })
  .inputValidator(discoverSchema)
  .middleware([authMiddleware])
  .handler(async ({ context, data }): Promise<DiscoverPayload> => {
    // viewerDid excludes the caller's own DID from the directory.
    // The auth middleware guarantees we have a session here.
    const res = await runTraced(
      "appview.listAccounts",
      appviewListAccountsEffect({
        limit: data.limit,
        offset: data.offset,
        sortBy: data.sortBy,
        providersOnly: data.providersOnly,
        viewerDid: context.did,
        excludeViewerFriends: data.excludeViewerFriends,
      }),
    );
    return res;
  });

export type DiscoverAccountsInput = z.infer<typeof discoverSchema>;

export function discoverAccountsQueryOptions(input: DiscoverAccountsInput) {
  return queryOptions({
    queryKey: ["friends", "discover", input] as const,
    queryFn: () => discoverAccountsServerFn({ data: input }),
    // Discovery is read-only and the AppView turns over slowly; cache it
    // (and keep it in memory) so flipping filters or revisiting doesn't
    // re-pay the AppView + bsky hydration round-trip each time.
    staleTime: 180_000,
    gcTime: 600_000,
  });
}

/** Discovery grid page size; `/friends` loader and `DiscoverFriendsCard` share this. */
export const FRIENDS_DISCOVER_PAGE_SIZE = 24;

/** First page, “recent activity” (default UI) — the only variant the
 *  `/friends` loader awaits. Every other filter combination is built
 *  on demand by `DiscoverFriendsCard` via `discoverAccountsQueryOptions`. */
export const friendsDiscoverRecentFirstPageQueryOptions = discoverAccountsQueryOptions({
  sortBy: "recent",
  providersOnly: false,
  excludeViewerFriends: true,
  limit: FRIENDS_DISCOVER_PAGE_SIZE,
  offset: 0,
});

export type AddFriendInput = z.infer<typeof addFriendSchema>;
export type RemoveFriendInput = z.infer<typeof removeFriendSchema>;
export type LookupActorInput = z.infer<typeof lookupActorSchema>;

export const addFriendMutationOptions = mutationOptions({
  mutationFn: (vars: AddFriendInput) => addFriendServerFn({ data: vars }),
});

export const removeFriendMutationOptions = mutationOptions({
  mutationFn: (vars: RemoveFriendInput) => removeFriendServerFn({ data: vars }),
});

export const lookupActorMutationOptions = mutationOptions({
  mutationFn: (vars: LookupActorInput) => lookupActorServerFn({ data: vars }),
});
