// The end-to-end inference dispatch core, served by the AppView.
//
// This is the AppView-side port of the console's
// `inference-dispatch.server.ts`. The console version constructs its own
// transport (PdsPublish / AppviewForward) and resolves provider credit
// over HTTP; here both are injected as deps so the core stays free of any
// session/store machinery:
//
//   * `transport` writes the job + paymentAuthorization to the
//     requester's PDS. The route builds it over the OAuth session the
//     AppView owns (login handoff), so the AppView publishes directly
//     instead of forwarding the write back to itself.
//   * `getProfile` resolves the human + machine behind a completion. The
//     route wires it to the AppView's own indexed Store (it IS the
//     appview), not an HTTP round-trip.
//
// The full pipeline is unchanged from the console version:
//   1. submitJob → publish paymentAuthorization + job to the requester's
//      PDS via the injected transport.
//   2. pickProvider → GET advisor /providers, freshest-attested-first.
//   3. ephemeral X25519 keypair, seal prompt with NaCl crypto_box.
//   4. POST advisor /jobs, read SSE.
//   5. Decrypt each `chunk` event back to plaintext.
//
// Output is an AsyncIterable of typed events so the route can render them
// as SSE frames over node:http.

import type { RecordTransport } from "@cocore/sdk/publish";
import { submitJob } from "@cocore/sdk/publish";
import { FetchHttpClient, HttpClient, HttpClientRequest } from "@effect/platform";
import { makeRuntime } from "@cocore/o11y";
import { Effect } from "effect";
import nacl from "tweetnacl";

// One o11y runtime for the module — provides the tracing layer that
// `Effect.withSpan` reports through. The fetch-backed HttpClient is
// supplied per-call via `Effect.provide(FetchHttpClient.layer)`;
// `FetchHttpClient.layer` reads `globalThis.fetch` at request time, so
// test fetch-mocking keeps working unchanged. The SSE `/jobs` read is
// deliberately NOT routed through HttpClient yet (streaming follow-up).
const runtime = makeRuntime({ serviceName: "cocore-appview" });

export interface DispatchInputs {
  did: string;
  model: string;
  prompt: string;
  maxTokensOut: number;
  priceCeiling: { amount: number; currency: string };
  targetProviderDid?: string;
}

/** The slice of a provider's indexed profile the credit line needs.
 *  Mirrors `Store.getProfile`'s payload (handle/displayName + per-machine
 *  rkey/label) without coupling the core to the Store type. */
export interface ProfileForCredit {
  handle: string | null;
  displayName: string | null;
  machines: Array<{ rkey: string; machineLabel: string | null }>;
}

export interface DispatchDeps {
  /** HTTP base for the matchmaking advisor (`/providers`, `/jobs`). */
  advisorUrl: string;
  /** Exchange DID stamped onto the paymentAuthorization + job. */
  exchangeDid: string;
  /** Writes records to the requester's PDS. Built by the route over the
   *  AppView-owned OAuth session for the requester DID. */
  transport: RecordTransport;
  /** Best-effort lookup of the provider's indexed profile, used only to
   *  build the completion credit line. Never required to succeed. */
  getProfile: (did: string) => Promise<ProfileForCredit | null>;
}

/** Distinct error types so the route layer can translate them into
 *  precise error codes rather than collapsing every "advisor said no"
 *  into a generic 502. */
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

export class TargetProviderNotConnectedError extends Error {
  readonly providerDid: string;
  constructor(providerDid: string) {
    super(`provider ${providerDid} is not currently connected/attested`);
    this.name = "TargetProviderNotConnectedError";
    this.providerDid = providerDid;
  }
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

/** Stable codes for the error event. The route translates these to SSE
 *  `error` frames; clients switch on them. */
export type DispatchErrorCode =
  | "no-providers-connected"
  | "no-providers-for-model"
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
 *  response can credit the human + machine behind a completion. */
interface ProviderCredit {
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
      providerCredit?: ProviderCredit;
    }
  | { kind: "error"; reason: string; code: DispatchErrorCode };

/** Shorten a DID for display when no handle/display name is known. */
function shortDid(did: string): string {
  if (did.length <= 22) return did;
  return `${did.slice(0, 12)}…${did.slice(-6)}`;
}

/** Resolve the human + machine behind a served job so a completion can
 *  credit them. The machine is NOT guessed: `machineLabel` comes from the
 *  exact advisor row we selected and sealed the prompt to. The DID's
 *  handle / display name come from the AppView profile. Best-effort: a
 *  failed lookup still yields a sensible credit line. */
async function resolveProviderCredit(
  did: string,
  machine: { machineId?: string; machineLabel?: string },
  getProfile: DispatchDeps["getProfile"],
): Promise<ProviderCredit> {
  let handle: string | null = null;
  let displayName: string | null = null;
  // Authoritative: the label of the machine we routed to.
  let machineLabel = machine.machineLabel?.trim() || null;
  try {
    const profile = await getProfile(did);
    if (profile) {
      handle = profile.handle;
      displayName = profile.displayName;
      // Legacy fallback only: pre-machineLabel advisors don't carry the
      // label on the /providers row. Recover it from the exact provider
      // record by rkey (= machineId), then from any labeled machine.
      if (!machineLabel) {
        const exact = machine.machineId
          ? profile.machines.find((m) => m.rkey === machine.machineId)
          : undefined;
        machineLabel =
          (exact ?? profile.machines.find((m) => m.machineLabel))?.machineLabel ?? null;
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
  /** Per-machine identity (the agent's provider-record rkey). Optional:
   *  legacy agents that predate machine_id omit it. */
  machineId?: string;
  /** Human-readable label for this machine. Optional for legacy agents. */
  machineLabel?: string;
}

interface PickProviderOptions {
  payoutsEligibleDids: Set<string> | null;
  selfLoopExempt: string | null;
}

/** Pure filter — extracted so it's testable without an advisor. */
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

/** GET the advisor's provider registry. Runs on the module o11y runtime
 *  behind a span so the public async API stays a plain Promise. On a
 *  non-2xx response it rejects with `new Error(`advisor /providers
 *  ${status}`)` — identical to the prior `fetch` path. */
async function fetchProviders(advisorUrl: string): Promise<AdvisorProviderRow[]> {
  const effect = Effect.gen(function* () {
    const client = yield* HttpClient.HttpClient;
    const request = HttpClientRequest.get(`${advisorUrl}/providers`);
    const res = yield* client.execute(request);
    if (res.status < 200 || res.status >= 300) {
      return yield* Effect.fail(new Error(`advisor /providers ${res.status}`));
    }
    return (yield* res.json) as AdvisorProviderRow[];
  }).pipe(
    // Map any non-Error failure (transport / decode) into a thrown Error so
    // the external Promise rejects with an Error, matching the old
    // `await fetch(...)` boundary.
    Effect.catchAll((e) => Effect.fail(e instanceof Error ? e : new Error(String(e)))),
    Effect.withSpan("dispatch.advisor.providers", { attributes: { advisorUrl } }),
    Effect.provide(FetchHttpClient.layer),
  );
  return runtime.runPromise(effect);
}

async function pickProvider(
  advisorUrl: string,
  model: string,
  targetDid: string | undefined,
  options: PickProviderOptions,
  /** Providers already tried this dispatch (a prior attempt's `/jobs`
   *  failed because they'd flapped out). Excluded from re-selection so
   *  failover lands on a DIFFERENT machine. Never applied to an explicit
   *  `targetDid` — a pinned provider is the user's choice. */
  excludeDids: Set<string> | undefined,
): Promise<AdvisorProviderRow> {
  const list = await fetchProviders(advisorUrl);
  const attested = list.filter((p) => p.attestedAt);
  if (attested.length === 0) throw new NoProvidersConnectedError();

  if (targetDid) {
    const hit = attested.find((p) => p.did === targetDid);
    if (!hit) throw new TargetProviderNotConnectedError(targetDid);
    const targetPasses = filterByPayoutsEligibility([hit], options).length > 0;
    if (!targetPasses) throw new ProviderPayoutsNotEligibleError(targetDid);
    return hit;
  }

  const pool =
    excludeDids && excludeDids.size > 0
      ? attested.filter((p) => !excludeDids.has(p.did))
      : attested;

  const fits = pool.filter(
    (p) => p.supportedModels.length === 0 || p.supportedModels.includes(model),
  );
  if (fits.length === 0) throw new NoProvidersForModelError(model, attested.length);
  const eligible = filterByPayoutsEligibility(fits, options);
  if (eligible.length === 0) {
    throw new ProviderPayoutsNotEligibleError(fits[0]!.did);
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
export function sealToProvider(
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

export function openFromProvider(
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
 *  DispatchErrorCode. Unknown errors get "advisor-transport". */
export function classifyDispatchError(e: unknown): DispatchErrorCode {
  if (e instanceof NoProvidersConnectedError) return "no-providers-connected";
  if (e instanceof NoProvidersForModelError) return "no-providers-for-model";
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

/** How many distinct providers to try before giving up. Each attempt
 *  re-picks (excluding prior failures), re-seals, and re-dispatches.
 *  A pinned `targetProviderDid` gets exactly one attempt. */
const MAX_DISPATCH_ATTEMPTS = 3;

/** User-facing message when failover is exhausted. Deliberately generic
 *  and signals the right client behavior (retry). */
const TEMP_UNAVAILABLE_REASON = "The model is temporarily unavailable. Please retry.";

export async function* runDispatch(
  input: DispatchInputs,
  deps: DispatchDeps,
): AsyncGenerator<DispatchEvent> {
  // 1. Publish job + auth to the requester's PDS via the injected
  //    transport (the AppView-owned OAuth session for input.did).
  let submitted;
  try {
    submitted = await submitJob({
      transport: deps.transport,
      requesterDid: input.did,
      inputs: {
        model: input.model,
        prompt: input.prompt,
        maxTokensOut: input.maxTokensOut,
        priceCeiling: input.priceCeiling,
        exchangeDid: deps.exchangeDid,
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

  // Steps 2–4 run in a bounded FAILOVER loop. We pick a provider, seal the
  // prompt to *that* provider's key, and pin the job to it — so the advisor
  // can't transparently reroute (only the pinned provider can decrypt the
  // ciphertext). Under edge churn the picked provider often flaps out of
  // the registry between our snapshot and the `/jobs` dispatch; rather than
  // surfacing the 503 (the job record is already published and its
  // inputCommitment is stable), we re-pick a DIFFERENT provider and retry.
  // An explicitly pinned `targetProviderDid` is never rerouted.
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
        deps.advisorUrl,
        input.model,
        input.targetProviderDid,
        { payoutsEligibleDids: null, selfLoopExempt: null },
        excludeDids,
      );
    } catch (e) {
      // First attempt: the genuine "nothing matches" diagnostic. A later
      // attempt means we exhausted the pool — collapse to a clean,
      // generic capacity error rather than leaking which providers we
      // burned through.
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
      new TextEncoder().encode(input.prompt),
      candidatePubKey,
      candidateEphemeral.secretKey,
    );

    // 4. POST advisor /jobs, pinned to this candidate.
    const req = await fetch(`${deps.advisorUrl}/jobs`, {
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
        sessionId,
        targetProviderDid: candidate.did,
      }),
    });

    if (req.ok && req.body) {
      provider = candidate;
      providerPubKey = candidatePubKey;
      ephemeral = candidateEphemeral;
      advisorBody = req.body;
      break;
    }

    // Dispatch rejected (almost always a 503: the candidate flapped out
    // since the snapshot). Log server-side; a pinned target isn't
    // rerouted, the open pool excludes this one and retries.
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
    yield { kind: "error", reason: TEMP_UNAVAILABLE_REASON, code: "no-capacity" };
    return;
  }

  // Kick off the provider-credit lookup now so the AppView Store query
  // overlaps the model run; awaited only at completion. Never rejects.
  const creditPromise = resolveProviderCredit(
    provider.did,
    { machineId: provider.machineId, machineLabel: provider.machineLabel },
    deps.getProfile,
  );

  // Announce the job + the provider that actually accepted it.
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
          yield { kind: "error", reason: "chunk decrypt failed", code: "chunk-decrypt-failed" };
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
        yield { kind: "error", reason, code: "advisor-rejected" };
        return;
      }
    }
  } catch (e) {
    yield { kind: "error", reason: (e as Error).message, code: "unknown" };
  }
}
