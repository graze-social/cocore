// Pure provider-selection helper shared by the console and AppView dispatch
// cores.

/** The requester's own machines that serve `model` and haven't been burned by a
 *  prior failover attempt, freshest-heartbeat first.
 *
 *  Self-preference requires an EXPLICIT model match — `supportedModels` must
 *  list `model`. We deliberately do NOT honor the "empty list ⇒ serves
 *  everything" wildcard the open-pool filter uses, because preferring your own
 *  machine is only a win when it can actually run the model:
 *
 *    * An agent advertises its health-gated `live_models()` set, so an empty
 *      list means it has NO serveable engine right now — preferring it would
 *      route the job to a box that can't serve it.
 *    * The provider then hits its `for_model` miss path: it seals a
 *      human-readable "no engine loaded for model X" string as the answer and
 *      completes WITHOUT publishing a receipt. The OpenAI client sees a 200,
 *      but the job never gets a receipt, so the dashboard shows it stuck in
 *      `pending` until it `expires` (graze-social/cocore#103).
 *
 *  Falling through (returning []) sends the job to the open pool, where a
 *  provider that genuinely serves the model writes a receipt as normal. This
 *  matches #98's stated intent: prefer self "when providing a requested
 *  model" — not for models self can't provide. */
export function ownMachineCandidates<
  T extends { did: string; supportedModels: string[]; lastSeen: string },
>(attested: T[], requesterDid: string, model: string, excludeDids: Set<string>): T[] {
  return attested
    .filter(
      (c) => c.did === requesterDid && !excludeDids.has(c.did) && c.supportedModels.includes(model),
    )
    .sort((a, b) => Date.parse(b.lastSeen) - Date.parse(a.lastSeen));
}
