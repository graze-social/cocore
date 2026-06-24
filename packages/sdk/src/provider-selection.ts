// Pure provider-selection helper shared by the console and AppView dispatch
// cores.

/** The requester's own machines that serve `model` and haven't been burned by a
 *  prior failover attempt, freshest-heartbeat first. */
export function ownMachineCandidates<
  T extends { did: string; supportedModels: string[]; lastSeen: string },
>(attested: T[], requesterDid: string, model: string, excludeDids: Set<string>): T[] {
  return attested
    .filter(
      (c) =>
        c.did === requesterDid &&
        !excludeDids.has(c.did) &&
        (c.supportedModels.length === 0 || c.supportedModels.includes(model)),
    )
    .sort((a, b) => Date.parse(b.lastSeen) - Date.parse(a.lastSeen));
}
