import { createFileRoute } from "@tanstack/react-router";

import { FriendsPage } from "@/components/friends/FriendsPage.tsx";
import {
  friendsDiscoverRecentFirstPageQueryOptions,
  listMyFriendsQueryOptions,
} from "@/components/friends/friends.functions.ts";
import { authMiddleware } from "@/middleware/auth.ts";

export const Route = createFileRoute("/_header-layout/friends")({
  server: {
    middleware: [authMiddleware],
  },
  loader: async ({ context }) => {
    const qc = context.queryClient;
    // Load ONLY the two lists the page shows on arrival.
    //
    // The other three were `void prefetchQuery` for the sort/filter tabs the
    // user hasn't clicked yet. Unawaited is not free: the SSR query
    // integration streams in-flight queries as part of the dehydrated cache,
    // so the response stays open until they settle — the same trap that made
    // every signed-in page slow before it was removed from `_header-layout`.
    //
    // Worse here, because all five are `listAccounts` against the AppView,
    // which serves them with synchronous SQLite. Firing four at once does not
    // overlap; they serialize on its event loop, measured at 0.36 / 0.60 /
    // 0.79 / 0.99s for the same query that takes 0.35s alone. So the tabs the
    // user may never open were making the tab they DID open three times
    // slower, and holding the document until all of them finished.
    //
    // The tab queries stay declared in the components, which fetch them on
    // click through react-query — a beat of loading state on a tab switch, in
    // exchange for a page that arrives.
    await Promise.all([
      qc.ensureQueryData(listMyFriendsQueryOptions),
      qc.ensureQueryData(friendsDiscoverRecentFirstPageQueryOptions),
    ]);
  },
  component: FriendsPage,
  head: () => ({
    meta: [
      { title: "Friends · co/core console" },
      {
        name: "description",
        content:
          "Manage the trusted DIDs that the friends-only chat-completions endpoint will route to.",
      },
    ],
  }),
});
