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

/** The set of MACHINE keys (`${did}:${machineId}`, where machineId is the
 *  provider-record rkey) that currently offer `requesterDid` pro-bono work,
 *  resolved from the AppView's provider-record mirror. Keyed per MACHINE, not
 *  per owner DID, because `proBono` is a per-record election: an owner can run
 *  one machine pro bono and another billed, so a DID-scoped allow-set could
 *  route a balance-less requester to the owner's *billing* machine and bust the
 *  pro-bono guarantee. The composite key is matched by {@link filterByAllowedDids}
 *  against the advisor row's `(did, machineId)`. Throws on an AppView failure so
 *  the caller can distinguish "nobody offers you pro bono" (empty set) from "the
 *  lookup failed". */
export async function resolveProBonoProviderKeys(requesterDid: string): Promise<Set<string>> {
  const res = await runTraced("proBono.listProviders", appviewListProvidersEffect);
  const out = new Set<string>();
  for (const row of res.providers) {
    const body = row.body as ProviderRecordView;
    // Need the rkey to address the specific machine; a record without one
    // can't be matched to an advisor row, so it can't be offered pro bono.
    if (row.rkey && proBonoApplies(body.proBono, requesterDid)) {
      out.add(`${row.repo}:${row.rkey}`);
    }
  }
  return out;
}
