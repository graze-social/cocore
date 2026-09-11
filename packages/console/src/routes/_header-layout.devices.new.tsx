// /devices/new — the approve screen for a pairing code.
//
//   /devices/new                 — the user types a code from the agent
//   /devices/new?code=XXXXXXXX   — code prefilled (the agent opened this URL
//                                  via `xdg-open`, or an application sent the
//                                  user here to connect its account)
//
// Auth-gated: only an OAuth-signed-in user can approve a pair. The approval
// mints a scoped API key for the signed-in DID and hands it to the pair-store
// via dev.cocore.devicePair.confirm. The requester polls
// dev.cocore.devicePair.poll and picks up the session. The page copy comes
// from PairConfirm, which asks dev.cocore.devicePair.describe who is behind
// the code: a bare provider machine, or an application by name.

import * as stylex from "@stylexjs/stylex";
import { createFileRoute } from "@tanstack/react-router";

import { PairConfirm } from "@/components/PairConfirm.tsx";
import { Page } from "@/design-system/page/index.tsx";
import { verticalSpace } from "@/design-system/theme/semantic-spacing.stylex";
import { authMiddleware } from "@/middleware/auth.ts";

const styles = stylex.create({
  main: {
    display: "flex",
    flexDirection: "column",
    gap: verticalSpace["6xl"],
    paddingTop: "2rem",
    paddingBottom: "4rem",
  },
});

export const Route = createFileRoute("/_header-layout/devices/new")({
  validateSearch: (search: Record<string, unknown>): { code: string } => ({
    code: typeof search.code === "string" ? search.code.trim().toUpperCase() : "",
  }),
  server: {
    middleware: [authMiddleware],
  },
  component: NewDevicePage,
  head: () => ({
    meta: [{ title: "Approve a connection · co/core console" }],
  }),
});

function NewDevicePage() {
  const { code } = Route.useSearch();
  return (
    <Page.Root>
      <main {...stylex.props(styles.main)}>
        <PairConfirm initialCode={code} />
      </main>
    </Page.Root>
  );
}
