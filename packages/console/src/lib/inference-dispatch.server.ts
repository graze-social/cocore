// The end-to-end inference dispatch core, decoupled from any wire
// format. Both the legacy SSE endpoint
// (`/api/xrpc/dev.cocore.inference.dispatch`) and the OpenAI-compat
// endpoint (`/api/v1/chat/completions`) consume this — each renders
// the typed events into its own response shape.
//
// The full pipeline:
//   1. submitJob → publish paymentAuthorization + job to the
//      requester's PDS via the user's OAuth session (DPoP-aware,
//      auto-refreshing). The local AppView is also notified so the
//      in-app dashboard sees it without waiting for firehose
//      subscription.
//   2. pickProvider → GET advisor /providers, freshest-attested-first
//   3. ephemeral X25519 keypair, seal prompt with NaCl crypto_box
//   4. POST advisor /jobs, read SSE
//   5. Decrypt each `chunk` event back to plaintext
//
// Output is an AsyncIterable of typed events so callers can choose
// SSE format, OpenAI streaming JSONL, buffered JSON, or anything else.

import type { OAuthSession } from "@atcute/oauth-node-client";
import { submitJob } from "@cocore/sdk/publish";
import { ownMachineCandidates } from "@cocore/sdk/provider-selection";
import { Effect } from "effect";
import nacl from "tweetnacl";

import {
  AppviewForwardTransport,
  isAppviewForwardConfigured,
} from "@/lib/appview-pds-forward.server.ts";
import { cocoreConfig } from "@/lib/cocore-config.ts";
import { runTraced } from "@/lib/o11y.server.ts";
import { PdsPublishTransport } from "@/lib/pds-publish.server.ts";
import { appviewGetProfileEffect } from "@/integrations/appview/appview.server.ts";

export interface DispatchInputs {
  did: string;
  model: string;
  /** Legacy text path: the flattened prompt string. Used to derive the
   *  sealed bytes when `payloadBytes` is absent. */
  prompt: string;
  /** Multimodal path: the exact bytes to seal + commit over (the
   *  canonical messages-v1 envelope). When present, these are sealed and
   *  hashed verbatim and `prompt` is ignored. */
  payloadBytes?: Uint8Array;
  /** Set to "messages-v1" when `payloadBytes` is the multimodal envelope,
   *  so the job record and the provider both interpret the bytes
   *  correctly. */
  inputFormat?: "messages-v1";
  maxTokensOut: number;
  priceCeiling: { amount: number; currency: string };
  targetProviderDid?: string;
  /** Specific machine under targetProviderDid to pin. When set, pickProvider
   *  selects that exact machine row and the advisor /jobs call includes
   *  targetMachineId so the advisor routes to that machine only. */
  targetMachineId?: string;
  /** OAuth session to publish records under. Required — every
   *  authoritative record must hit the user's PDS. */
  oauthSession: OAuthSession;
  /** Restrict provider selection to this allow-set. Each entry is either a
   *  bare DID — owner-granular, used by the friends-only + verified endpoints —
   *  or a `${did}:${machineId}` composite — machine-granular, used by the
   *  pro-bono path (the election is per provider record, so it must not widen
   *  to an owner's other billed machines). {@link filterByAllowedDids} matches
   *  either form. Used by the friends-only chat-completions endpoint, which
   *  fetches the user's friend records from their PDS and passes the DID set
   *  through to constrain pickProvider.
   *
   *  Empty set is meaningful and DIFFERENT from `undefined`:
   *  empty → "user has no friends with at least one connected
   *  provider; reject with NoFriendsAvailableError". `undefined` →
   *  "no constraint; consider the whole open network."
   *
   *  Ignored when `targetProviderDid` is set — explicit pinning by
   *  the user wins. (Today the only caller that pins is the
   *  per-machine inference dashboard, which is friends-aware
   *  already since the user chose their own machine.) */
  allowedProviderDids?: Set<string>;
  /** Optional ISO 3166-1 alpha-2 country filter (uppercased). When set,
   *  pickProvider keeps only candidates whose advertised `region` matches,
   *  AFTER the model (and friends) filters so the diagnostic is precise.
   *  Advisory routing: `region` is a provider self-claim, and a provider
   *  that doesn't publish a region is never matched by a country filter. */
  country?: string;
}

/** Distinct error types so the route layer can translate them into
 *  precise OpenAI-shaped error responses rather than collapsing
 *  every "advisor said no" into a generic 502.
 *
 *  Pattern: each class carries the operational context (model,
 *  friend count, connected count) the user actually needs to
 *  decide what to do next. */
export class NoProvidersConnectedError extends Error {
  constructor() {
    super("no providers are currently connected to the advisor");
    this.name = "NoProvidersConnectedError";
  }
}

export class NoProvidersForModelError extends Error {
  readonly model: string;
  readonly connectedCount: number;
  constructor(model: string, connectedCount: number) {
    super(
      `no connected provider serves model '${model}' (${connectedCount} provider${
        connectedCount === 1 ? "" : "s"
      } online overall)`,
    );
    this.name = "NoProvidersForModelError";
    this.model = model;
    this.connectedCount = connectedCount;
  }
}

export class NoFriendsAvailableError extends Error {
  readonly friendCount: number;
  constructor(friendCount: number) {
    super(
      friendCount === 0
        ? "you have no friends; add some at /friends or use the open /api/v1/chat/completions endpoint"
        : `none of your ${friendCount} friend${friendCount === 1 ? "" : "s"} are currently connected to the advisor`,
    );
    this.name = "NoFriendsAvailableError";
    this.friendCount = friendCount;
  }
}

export class NoFriendsForModelError extends Error {
  readonly model: string;
  readonly friendCount: number;
  readonly friendsConnectedCount: number;
  constructor(model: string, friendCount: number, friendsConnectedCount: number) {
    super(
      `none of your ${friendsConnectedCount} connected friend${
        friendsConnectedCount === 1 ? "" : "s"
      } serve model '${model}' (you have ${friendCount} friend${
        friendCount === 1 ? "" : "s"
      } total)`,
    );
    this.name = "NoFriendsForModelError";
    this.model = model;
    this.friendCount = friendCount;
    this.friendsConnectedCount = friendsConnectedCount;
  }
}

export class TargetProviderNotConnectedError extends Error {
  readonly providerDid: string;
  constructor(providerDid: string) {
    super(`provider ${providerDid} is not currently connected/attested`);
    this.name = "TargetProviderNotConnectedError";
    this.providerDid = providerDid;
  }
}

export class NoProvidersForCountryError extends Error {
  readonly model: string;
  readonly country: string;
  /** How many providers served the model (in any country) — so the caller
   *  can tell "model X exists but not in country Y" from "no model X". */
  readonly modelFitCount: number;
  constructor(model: string, country: string, modelFitCount: number) {
    super(
      `no connected provider serving model '${model}' advertises country '${country}' (${modelFitCount} serve the model in other / unknown regions)`,
    );
    this.name = "NoProvidersForCountryError";
    this.model = model;
    this.country = country;
    this.modelFitCount = modelFitCount;
  }
}

/** Stable codes for the error event. Route layers translate these
 *  to OpenAI-shaped error envelopes with appropriate HTTP statuses
 *  (404 for unknown-model situations, 503 for advisor-side absence
 *  of capacity, 502 for everything else).
 *
 *  Adding a code: add the string here, update the route's switch
 *  arms, document the new shape in the API docs. Removing one is
 *  a breaking change for any client that grew a special case
 *  around it — prefer to deprecate via comment first. */
export type DispatchErrorCode =
  | "no-providers-connected"
  | "no-providers-for-model"
  | "no-providers-for-country"
  | "no-friends-available"
  | "no-friends-for-model"
  | "target-provider-not-connected"
  | "provider-payouts-not-eligible"
  | "pds-publish-failed"
  | "provider-encryption-key-malformed"
  | "chunk-decrypt-failed"
  | "advisor-rejected"
  | "advisor-transport"
  | "no-capacity"
  | "unknown";

/** Who ran a job, resolved from the provider's AppView footprint, so a
 *  response can credit the human + machine behind a completion —
 *  e.g. "this completion lovingly created for you by devingaffney.com
 *  via their Mac-mini.local server". Best-effort: any field may be
 *  null when the provider hasn't published a profile / machine label,
 *  but `line` is always a sensible sentence (falls back to a short
 *  DID). */
export interface ProviderCredit {
  did: string;
  handle: string | null;
  displayName: string | null;
  machineLabel: string | null;
  line: string;
}

export type DispatchEvent =
  | {
      kind: "meta";
      jobUri: string;
      jobCid: string;
      authUri: string;
      inputCommitment: string;
      providerDid: string;
      sessionId: string;
    }
  | { kind: "chunk"; seq: number; channel: "content" | "reasoning"; text: string }
  | {
      kind: "complete";
      tokensIn: number;
      tokensOut: number;
      receiptUri: string;
      /** Who ran it — surfaced to API clients as a non-standard
       *  `x_cocore` field. Absent when resolution failed. */
      providerCredit?: ProviderCredit;
    }
  | { kind: "error"; reason: string; code: DispatchErrorCode };

/** Shorten a DID for display when no handle/display name is known. */
function shortDid(did: string): string {
  if (did.length <= 22) return did;
  return `${did.slice(0, 12)}…${did.slice(-6)}`;
}

/** Resolve the human + machine behind a served job so a completion can
 *  credit them. The machine is NOT guessed: `machineLabel` comes from
 *  the exact advisor row we selected and sealed the prompt to, so it's
 *  the machine that actually ran the job (a successful completion is
 *  proof of that — only that machine's key could decrypt the prompt).
 *  The DID's handle / display name come from the AppView profile.
 *  Best-effort and self-contained: a failed lookup still yields a
 *  sensible credit line rather than failing the dispatch. Started
 *  concurrently with inference and awaited at completion. */
async function resolveProviderCredit(
  did: string,
  machine: { machineId?: string; machineLabel?: string },
): Promise<ProviderCredit> {
  let handle: string | null = null;
  let displayName: string | null = null;
  // Authoritative: the label of the machine we routed to.
  let machineLabel = machine.machineLabel?.trim() || null;
  try {
    const result = await runTraced(
      "appview.getProfile",
      Effect.either(appviewGetProfileEffect(did)),
    );
    if (result._tag === "Right" && result.right) {
      handle = result.right.handle;
      displayName = result.right.displayName;
      // Legacy fallback only: pre-machineLabel advisors don't carry the
      // label on the /providers row. Recover it from the exact provider
      // record by rkey (= machineId), then from any labeled machine.
      if (!machineLabel) {
        const machines = result.right.machines;
        const exact = machine.machineId
          ? machines.find((m) => m.rkey === machine.machineId)
          : undefined;
        machineLabel = (exact ?? machines.find((m) => m.machineLabel))?.machineLabel ?? null;
      }
    }
  } catch {
    // best-effort — fall through with whatever we resolved
  }
  const who = displayName ?? handle ?? shortDid(did);
  const line = machineLabel
    ? `this completion lovingly created for you by ${who} via their ${machineLabel} server`
    : `this completion lovingly created for you by ${who}`;
  return { did, handle, displayName, machineLabel, line };
}

interface AdvisorProviderRow {
  did: string;
  encryptionPubKey: string;
  supportedModels: string[];
  attestedAt: string | null;
  lastSeen: string;
  /** Per-machine identity for the row (the agent's provider-record
   *  rkey). The advisor returns one row per connected machine, so this
   *  distinguishes machines under the same DID. Optional: legacy
   *  agents that predate machine_id omit it. */
  machineId?: string;
  /** Human-readable label for this machine (e.g. "Mac-mini.local").
   *  Optional for legacy-agent compatibility. */
  machineLabel?: string;
  /** Coarse, opt-in ISO 3166-1 alpha-2 country the provider advertises
   *  (echoed from its provider record via the advisor Register frame).
   *  Advisory self-claim; absent when the provider hasn't opted into
   *  location sharing. Used for `country` routing. */
  region?: string;
}

export interface PickProviderOptions {
  /** When set, exclude any candidate whose DID is not in this set
   *  AND is not equal to {@link selfLoopExempt}. Closed-loop dispatch
   *  passes null (the ledger's tokenFloor enforces admission). The
   *  field is kept for a possible phase-two fiat-redeemable exchange
   *  that re-introduces a payouts gate. */
  payoutsEligibleDids: Set<string> | null;
  /** When non-null, this DID is exempt from the payouts filter.
   *  Used for self-loop jobs (requester == provider) under phase-two
   *  fiat semantics; ignored under closed-loop. */
  selfLoopExempt: string | null;
}

/** Pure filter — extracted so it's testable without standing up
 *  an advisor + AppView. Returns the list of advisor candidates
 *  that pass the eligibility check (or the input list verbatim
 *  when filtering is disabled). */
export function filterByPayoutsEligibility<T extends { did: string }>(
  candidates: T[],
  options: PickProviderOptions,
): T[] {
  if (!options.payoutsEligibleDids) return candidates;
  return candidates.filter((c) => {
    if (options.selfLoopExempt && c.did === options.selfLoopExempt) return true;
    return options.payoutsEligibleDids!.has(c.did);
  });
}

/** Pure filter for friends-only routing. Returns the candidates
 *  whose DID is in `allowedDids`. `undefined` means "no friends
 *  constraint, pass through verbatim." `Set()` (empty) is a
 *  meaningful "filter everything out" signal that the caller
 *  should distinguish — the route layer turns that into
 *  NoFriendsAvailableError. */
export function filterByAllowedDids<T extends { did: string; machineId?: string }>(
  candidates: T[],
  allowedDids: Set<string> | undefined,
): T[] {
  if (!allowedDids) return candidates;
  // An entry is either a bare DID — owner-granular (friends / verified) — or a
  // `${did}:${machineId}` composite — machine-granular (pro-bono, where the
  // election is per provider record). Match either, so a pro-bono allow-set
  // never widens to an owner's other, billed machines.
  return candidates.filter(
    (c) =>
      allowedDids.has(c.did) || (c.machineId != null && allowedDids.has(`${c.did}:${c.machineId}`)),
  );
}

/** Pure filter for country routing. `undefined`/empty country passes the
 *  list through verbatim ("no country constraint"). Otherwise keeps only
 *  candidates whose advertised `region` equals `country` (already uppercased
 *  by the parse layer) — a provider that doesn't publish a region is never
 *  matched, since a country request means "must be in this country." */
export function filterByCountry<T extends { region?: string }>(
  candidates: T[],
  country: string | undefined,
): T[] {
  if (!country) return candidates;
  return candidates.filter((c) => c.region === country);
}

export class ProviderPayoutsNotEligibleError extends Error {
  readonly providerDid: string;
  constructor(providerDid: string) {
    super(
      `provider ${providerDid} has not enabled payouts; cannot accept paid jobs from another DID`,
    );
    this.name = "ProviderPayoutsNotEligibleError";
    this.providerDid = providerDid;
  }
}

async function pickProvider(
  advisorUrl: string,
  model: string,
  requesterDid: string,
  targetDid: string | undefined,
  targetMachineId: string | undefined,
  options: PickProviderOptions,
  allowedDids: Set<string> | undefined,
  /** Optional ISO 3166-1 alpha-2 country filter (uppercased). Applied after
   *  the model/friends filters in the open + friends paths. NOT applied to an
   *  explicit `targetDid` (the user pinned that machine) or a self-loop pick
   *  (it's the caller's own machine). */
  country: string | undefined,
  /** Providers already tried this dispatch (a prior attempt's `/jobs`
   *  failed because they'd flapped out between the snapshot and the
   *  dispatch). Excluded from re-selection so failover lands on a
   *  DIFFERENT machine. Never applied to an explicit `targetDid` — a
   *  pinned provider is the user's choice, not ours to reroute. */
  excludeDids?: Set<string>,
): Promise<AdvisorProviderRow> {
  const r = await fetch(`${advisorUrl}/providers`);
  if (!r.ok) throw new Error(`advisor /providers ${r.status}`);
  const list = (await r.json()) as AdvisorProviderRow[];
  const attested = list.filter((p) => p.attestedAt);
  if (attested.length === 0) throw new NoProvidersConnectedError();

  if (targetDid) {
    // When targetMachineId is set, require an exact (DID, machineId) match so
    // a Mac Mini and a Linux box under the same owner DID are distinguished.
    // Fall back to DID-only if no machineId was specified (or for legacy rows
    // that predate the field).
    const hit = targetMachineId
      ? (attested.find((p) => p.did === targetDid && p.machineId === targetMachineId) ??
        // Fall back only to legacy rows that predate the machineId field; a row with
        // a *different* machineId is a different machine and must not be silently selected.
        attested.find((p) => p.did === targetDid && !p.machineId))
      : attested.find((p) => p.did === targetDid);
    if (!hit) throw new TargetProviderNotConnectedError(targetDid);
    // Hard refusal on explicit target: surface why before the user
    // submits the (now doomed) job. We don't auto-fall-back to
    // some other provider — the user asked for this one.
    const targetPasses = filterByPayoutsEligibility([hit], options).length > 0;
    if (!targetPasses) throw new ProviderPayoutsNotEligibleError(targetDid);
    return hit;
  }

  const own = ownMachineCandidates(attested, requesterDid, model, excludeDids ?? new Set());
  if (own.length > 0) return own[0]!;

  // Drop providers a prior attempt already tried-and-failed so failover
  // doesn't keep re-picking the same flapped machine. The error counts
  // below still report `attested.length` (total connected) so the
  // diagnostic reads naturally on attempt 1 when nothing is excluded.
  const pool =
    excludeDids && excludeDids.size > 0
      ? attested.filter((p) => !excludeDids.has(p.did))
      : attested;

  // Friends gate runs BEFORE the model filter so we can report a
  // friend-specific error when the user has friends but none of
  // them are even online. Order matters here for diagnostic
  // quality — "no friends online" is more actionable than "no
  // provider for model X" when both are true.
  if (allowedDids !== undefined) {
    const friendsConnected = filterByAllowedDids(pool, allowedDids);
    if (friendsConnected.length === 0) {
      throw new NoFriendsAvailableError(allowedDids.size);
    }
    const friendFits = friendsConnected.filter(
      (p) => p.supportedModels.length === 0 || p.supportedModels.includes(model),
    );
    if (friendFits.length === 0) {
      throw new NoFriendsForModelError(model, allowedDids.size, friendsConnected.length);
    }
    const friendInCountry = filterByCountry(friendFits, country);
    if (friendInCountry.length === 0) {
      throw new NoProvidersForCountryError(model, country!, friendFits.length);
    }
    const eligible = filterByPayoutsEligibility(friendInCountry, options);
    if (eligible.length === 0) {
      // Surface a DID from the post-country-filter list so the diagnostic
      // points at a provider that's actually both model-fit and in-country,
      // not one the country filter already excluded.
      throw new ProviderPayoutsNotEligibleError(friendInCountry[0]!.did);
    }
    eligible.sort((a, b) => Date.parse(b.lastSeen) - Date.parse(a.lastSeen));
    return eligible[0]!;
  }

  const fits = pool.filter(
    (p) => p.supportedModels.length === 0 || p.supportedModels.includes(model),
  );
  if (fits.length === 0) throw new NoProvidersForModelError(model, attested.length);
  const inCountry = filterByCountry(fits, country);
  if (inCountry.length === 0) throw new NoProvidersForCountryError(model, country!, fits.length);
  const eligible = filterByPayoutsEligibility(inCountry, options);
  if (eligible.length === 0) {
    // No payouts-eligible provider serves this model. Surface the
    // first model-fit, in-country provider's DID so the caller can
    // hint at who's blocking; that DID's record will explain why (no
    // Stripe Connect under fiat semantics, etc.). Today this is
    // unreachable under closed-loop (payoutsEligibleDids is
    // always null) but the branch stays for the phase-two path.
    throw new ProviderPayoutsNotEligibleError(inCountry[0]!.did);
  }
  eligible.sort((a, b) => Date.parse(b.lastSeen) - Date.parse(a.lastSeen));
  return eligible[0]!;
}

function decodeBase64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function encodeBase64(b: Uint8Array): string {
  let bin = "";
  for (const v of b) bin += String.fromCharCode(v);
  return btoa(bin);
}

/** NaCl `crypto_box` wire format: nonce(24) || ciphertext+tag. Matches
 *  provider/src/crypto.rs's `seal_to` / `open_from`. */
function sealToProvider(
  plaintext: Uint8Array,
  recipientPubKey: Uint8Array,
  ephemeralSecret: Uint8Array,
): Uint8Array {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const body = nacl.box(plaintext, nonce, recipientPubKey, ephemeralSecret);
  const out = new Uint8Array(nonce.length + body.length);
  out.set(nonce, 0);
  out.set(body, nonce.length);
  return out;
}

function openFromProvider(
  framed: Uint8Array,
  senderPubKey: Uint8Array,
  ephemeralSecret: Uint8Array,
): Uint8Array | null {
  if (framed.length <= nacl.box.nonceLength) return null;
  const nonce = framed.slice(0, nacl.box.nonceLength);
  const body = framed.slice(nacl.box.nonceLength);
  return nacl.box.open(body, nonce, senderPubKey, ephemeralSecret) ?? null;
}

interface SseEvent {
  event: string;
  data: string;
}

/** Translate a thrown pickProvider error into the structured
 *  DispatchEvent code. Unknown errors (network, transient) get
 *  "advisor-transport" so the route layer can still 502 cleanly.
 *  Kept separate from runDispatch so route-layer tests can call it
 *  directly with a fixture error. */
export function classifyDispatchError(e: unknown): DispatchErrorCode {
  if (e instanceof NoProvidersConnectedError) return "no-providers-connected";
  if (e instanceof NoProvidersForModelError) return "no-providers-for-model";
  if (e instanceof NoProvidersForCountryError) return "no-providers-for-country";
  if (e instanceof NoFriendsAvailableError) return "no-friends-available";
  if (e instanceof NoFriendsForModelError) return "no-friends-for-model";
  if (e instanceof TargetProviderNotConnectedError) return "target-provider-not-connected";
  if (e instanceof ProviderPayoutsNotEligibleError) return "provider-payouts-not-eligible";
  return "advisor-transport";
}

async function* readSse(body: ReadableStream<Uint8Array>): AsyncGenerator<SseEvent> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buf.indexOf("\n\n")) !== -1) {
      const block = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      let event = "message";
      let data = "";
      for (const line of block.split("\n")) {
        if (line.startsWith("event: ")) event = line.slice(7);
        else if (line.startsWith("data: ")) data += line.slice(6);
      }
      yield { event, data };
    }
  }
}

/** How many distinct providers to try for one job before giving up.
 *  Each attempt re-picks (excluding prior failures), re-seals, and
 *  re-dispatches — bounded so a doomed request still fails fast. Only
 *  the open-pool / friends path fails over; a pinned `targetProviderDid`
 *  gets exactly one attempt. */
const MAX_DISPATCH_ATTEMPTS = 3;

/** User-facing message when failover is exhausted. Deliberately generic
 *  — no provider DID, no "attested", no advisor internals — and signals
 *  the right client behavior (retry), since capacity churn is transient. */
const TEMP_UNAVAILABLE_REASON = "The model is temporarily unavailable. Please retry.";

export async function* runDispatch(input: DispatchInputs): AsyncGenerator<DispatchEvent> {
  const config = cocoreConfig();

  // The exact bytes we seal to the provider and that inputCommitment is
  // computed over. Multimodal requests pass `payloadBytes` (the canonical
  // envelope); text requests fall back to the UTF-8 of the flattened prompt.
  const inputBytes = input.payloadBytes ?? new TextEncoder().encode(input.prompt);

  // 1. Publish job + auth to the requester's PDS via OAuth, then
  //    mirror to the AppView indexer so dashboards see it.
  let submitted;
  try {
    // Forward writes to the AppView when configured (so the AppView owns
    // the session + its single-writer refresh); otherwise publish via the
    // console's own OAuth session (legacy). Gated identically to the
    // /api/pds path so both flip together — flipping only one would leave
    // two processes refreshing the same session.
    const transport = isAppviewForwardConfigured()
      ? new AppviewForwardTransport()
      : new PdsPublishTransport({
          session: input.oauthSession,
          bridgeUrl: config.bridgeUrl,
        });
    submitted = await submitJob({
      transport,
      requesterDid: input.did,
      inputs: {
        model: input.model,
        inputBytes,
        ...(input.inputFormat ? { inputFormat: input.inputFormat } : {}),
        maxTokensOut: input.maxTokensOut,
        priceCeiling: input.priceCeiling,
        exchangeDid: config.exchangeDid,
      },
    });
  } catch (e) {
    yield {
      kind: "error",
      reason: `pds publish failed: ${(e as Error).message}`,
      code: "pds-publish-failed",
    };
    return;
  }

  // 2. Pick a provider.
  //
  // Under closed-loop there's no Stripe Connect gate on routing.
  // Every attested provider that advertises the requested model is
  // eligible — the ledger's tokenFloor check enforces "do you have
  // enough CC to dispatch this job" at submission time, and a
  // receipt failure surfaces as a balance-state issue, not a
  // payments-state one. The `payoutsEligibleDids` knob on
  // PickProviderOptions stays in the type for a possible phase-two
  // fiat-redeemable exchange that wants to re-introduce the gate.
  // Friends-only routing: when allowedProviderDids is set on the
  // inputs, the pin-target path bypasses it (the caller chose a
  // specific provider, presumably from their own machines or by
  // explicit consent). Otherwise pickProvider constrains its
  // candidate set to friends and returns a structured error if
  // the gate filters everything out.
  // Steps 2–4 run in a bounded FAILOVER loop. The console picks a
  // provider, seals the prompt to *that* provider's key, and pins the
  // job to it — so the advisor can't transparently reroute (only the
  // pinned provider can decrypt the ciphertext). Under Railway's edge
  // churn the picked provider often flaps out of the registry between
  // our `/providers` snapshot and the `/jobs` dispatch, and the advisor
  // returns 503. Rather than surfacing that to the API caller (the job
  // record is already published — the requester's `inputCommitment` is
  // over the plaintext, so it's stable no matter which provider serves),
  // we re-pick a DIFFERENT provider, re-seal, and retry. An explicitly
  // pinned `targetProviderDid` is never rerouted — one attempt only.
  const maxAttempts = input.targetProviderDid ? 1 : MAX_DISPATCH_ATTEMPTS;
  const excludeDids = new Set<string>();
  const sessionId = crypto.randomUUID();
  let provider: AdvisorProviderRow | null = null;
  let providerPubKey: Uint8Array | null = null;
  let ephemeral: nacl.BoxKeyPair | null = null;
  let advisorBody: ReadableStream<Uint8Array> | null = null;

  for (let attempt = 1; attempt <= maxAttempts && !advisorBody; attempt++) {
    // 2. Pick a provider (skipping any a prior attempt already burned).
    let candidate: AdvisorProviderRow;
    try {
      candidate = await pickProvider(
        config.advisorUrl,
        input.model,
        input.did,
        input.targetProviderDid,
        input.targetMachineId,
        { payoutsEligibleDids: null, selfLoopExempt: null },
        input.targetProviderDid ? undefined : input.allowedProviderDids,
        // No country filter on an explicit pin — the user chose that machine.
        input.targetProviderDid ? undefined : input.country,
        excludeDids,
      );
    } catch (e) {
      // On the first attempt this is the genuine "nothing matches"
      // diagnostic the caller needs. On a later attempt it means we've
      // exhausted the pool (every candidate we tried flapped) — collapse
      // to a clean, generic capacity error rather than leaking which
      // providers we burned through.
      if (attempt === 1) {
        yield { kind: "error", reason: (e as Error).message, code: classifyDispatchError(e) };
      } else {
        yield { kind: "error", reason: TEMP_UNAVAILABLE_REASON, code: "no-capacity" };
      }
      return;
    }

    // 3. Ephemeral X25519 + seal to THIS candidate.
    const candidatePubKey = decodeBase64(candidate.encryptionPubKey);
    if (candidatePubKey.byteLength !== nacl.box.publicKeyLength) {
      // A malformed key is a property of this one provider — on the open
      // pool, exclude it and try another; when pinned, it's fatal.
      if (input.targetProviderDid) {
        yield {
          kind: "error",
          reason: `provider published a malformed encryption key (${candidatePubKey.byteLength}B)`,
          code: "provider-encryption-key-malformed",
        };
        return;
      }
      excludeDids.add(candidate.did);
      continue;
    }
    const candidateEphemeral = nacl.box.keyPair();
    const candidateCiphertext = sealToProvider(
      inputBytes,
      candidatePubKey,
      candidateEphemeral.secretKey,
    );

    // 4. POST advisor /jobs, pinned to this candidate. `inputFormat` tells
    //    the provider how to interpret the opened bytes (raw prompt vs the
    //    messages-v1 multimodal envelope); omitted for the text path so old
    //    advisors/providers keep treating the payload as text.
    const req = await fetch(`${config.advisorUrl}/jobs`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "text/event-stream" },
      body: JSON.stringify({
        jobUri: submitted.job.ref.uri,
        jobCid: submitted.job.ref.cid,
        requesterDid: input.did,
        requesterPubKey: encodeBase64(candidateEphemeral.publicKey),
        model: input.model,
        maxTokensOut: input.maxTokensOut,
        ciphertext: [...candidateCiphertext],
        ...(input.inputFormat ? { inputFormat: input.inputFormat } : {}),
        sessionId,
        targetProviderDid: candidate.did,
        // Pin the exact machine we sealed the prompt to, the only one that can unseal.
        ...(candidate.machineId ? { targetMachineId: candidate.machineId } : {}),
      }),
    });

    if (req.ok && req.body) {
      provider = candidate;
      providerPubKey = candidatePubKey;
      ephemeral = candidateEphemeral;
      advisorBody = req.body;
      break;
    }

    // The dispatch was rejected (almost always a 503: the candidate
    // flapped out of the registry since the snapshot). Log the detail
    // server-side — it stays out of the response. A pinned target isn't
    // rerouted; the open pool excludes this one and retries.
    const detail = await req.text().catch(() => "");
    console.error(
      `[dispatch] /jobs ${req.status} provider=${candidate.did} attempt=${attempt}/${maxAttempts}: ${detail.slice(0, 200)}`,
    );
    if (input.targetProviderDid) {
      yield {
        kind: "error",
        reason: "the requested provider is currently unavailable; please retry",
        code: "advisor-rejected",
      };
      return;
    }
    excludeDids.add(candidate.did);
  }

  if (!provider || !providerPubKey || !ephemeral || !advisorBody) {
    // Every attempt's dispatch was rejected — real capacity is there
    // (we had candidates) but none accepted in time. Clean, retryable.
    yield { kind: "error", reason: TEMP_UNAVAILABLE_REASON, code: "no-capacity" };
    return;
  }

  // Kick off the provider-credit lookup now (right after selection)
  // so the AppView round-trip overlaps the model run; we await it only
  // at completion. Never rejects — resolveProviderCredit swallows its
  // own errors and returns a DID-only credit on failure.
  const creditPromise = resolveProviderCredit(provider.did, {
    machineId: provider.machineId,
    machineLabel: provider.machineLabel,
  });

  // Announce the job + the provider that actually accepted it (the meta
  // event waits until dispatch succeeds, so it names the real server
  // even when an earlier candidate flapped and we failed over).
  yield {
    kind: "meta",
    jobUri: submitted.job.ref.uri,
    jobCid: submitted.job.ref.cid,
    authUri: submitted.authorization.ref.uri,
    inputCommitment: submitted.job.record.inputCommitment,
    providerDid: provider.did,
    sessionId,
  };

  // 5. Stream the advisor's SSE and decrypt chunks.
  try {
    for await (const ev of readSse(advisorBody)) {
      if (ev.event === "open") continue;
      if (ev.event === "chunk") {
        let parsed: {
          seq: number;
          channel?: "content" | "reasoning";
          ciphertext: number[] | string;
        };
        try {
          parsed = JSON.parse(ev.data);
        } catch {
          continue;
        }
        const ct =
          typeof parsed.ciphertext === "string"
            ? decodeBase64(parsed.ciphertext)
            : new Uint8Array(parsed.ciphertext);
        const opened = openFromProvider(ct, providerPubKey, ephemeral.secretKey);
        if (!opened) {
          yield {
            kind: "error",
            reason: "chunk decrypt failed",
            code: "chunk-decrypt-failed",
          };
          continue;
        }
        yield {
          kind: "chunk",
          seq: parsed.seq,
          channel: parsed.channel ?? "content",
          text: new TextDecoder().decode(opened),
        };
        continue;
      }
      if (ev.event === "complete") {
        let parsed: { tokensIn: number; tokensOut: number; receiptUri: string };
        try {
          parsed = JSON.parse(ev.data);
        } catch {
          continue;
        }
        yield {
          kind: "complete",
          tokensIn: parsed.tokensIn,
          tokensOut: parsed.tokensOut,
          receiptUri: parsed.receiptUri,
          providerCredit: await creditPromise,
        };
        return;
      }
      if (ev.event === "error") {
        let reason = ev.data;
        try {
          const e = JSON.parse(ev.data) as { reason?: string };
          if (e.reason) reason = e.reason;
        } catch {
          // raw string
        }
        // Advisor-originating errors come over SSE as opaque
        // strings; we can't pattern-match them into our codes
        // without parsing the message. "advisor-rejected" is the
        // catch-all for that class — the route can still 502.
        yield { kind: "error", reason, code: "advisor-rejected" };
        return;
      }
    }
  } catch (e) {
    yield { kind: "error", reason: (e as Error).message, code: "unknown" };
  }
}
