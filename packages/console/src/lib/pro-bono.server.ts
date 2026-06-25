// Requester-side pro-bono routing.
//
// A provider elects to serve some requesters pro bono (free, unmetered, no
// exchange cut) by writing a `proBono` policy onto its provider record (see
// the lexicon `dev.cocore.compute.provider#proBonoPolicy`). The PROVIDER
// decides this per-job locally, so a normal dispatch already lands on a free
// receipt when it happens to pick a provider whose policy matches. This module
// powers the OPT-IN "route me only to a provider that serves me free" path: it
// reads the AppView's mirror of provider records, parses each `proBono` policy,
// and returns the set of provider DIDs whose policy applies to a given
// requester. That set feeds the existing `allowedProviderDids` routing gate
// (the same mechanism behind the friends-only + verified paths), so a balance-
// less requester can be guaranteed a free machine.
//
// Provider records are public on the PDS (and already surfaced via the AppView
// listProviders mirror), so the DID allowlist a provider publishes under
// `mode: direct` is not newly exposed here.

import { appviewListProvidersEffect } from "@/integrations/appview/appview.server.ts";
import { runTraced } from "@/lib/o11y.server.ts";

interface ProBonoPolicyView {
  mode?: unknown;
  dids?: unknown;
}

/** Whether a provider's pro-bono policy serves `requesterDid` for free.
 *  `any` ⇒ everyone; `direct` ⇒ only the listed DIDs; anything else (absent /
 *  unknown mode) ⇒ no (fail closed to paid, matching the provider agent's
 *  `ProBonoPolicy::applies_to`). Pure + exported for testing. */
export function proBonoApplies(
  policy: ProBonoPolicyView | undefined,
  requesterDid: string,
): boolean {
  if (!policy) return false;
  if (policy.mode === "any") return true;
  if (policy.mode === "direct") {
    return Array.isArray(policy.dids) && policy.dids.some((d) => d === requesterDid);
  }
  return false;
}

interface ProviderRecordView {
  proBono?: ProBonoPolicyView;
}

/** The set of provider DIDs that currently offer `requesterDid` pro-bono work,
 *  resolved from the AppView's provider-record mirror. Deduped by DID (a single
 *  owner may run several machines; routing is DID-scoped here, then the live
 *  advisor intersect in pickProvider narrows to connected machines). Throws on
 *  an AppView failure so the caller can distinguish "nobody offers you pro
 *  bono" (empty set) from "the lookup failed". */
export async function resolveProBonoProviderDids(requesterDid: string): Promise<Set<string>> {
  const res = await runTraced("proBono.listProviders", appviewListProvidersEffect);
  const out = new Set<string>();
  for (const row of res.providers) {
    const body = row.body as ProviderRecordView;
    if (proBonoApplies(body.proBono, requesterDid)) out.add(row.repo);
  }
  return out;
}
