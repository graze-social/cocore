// `POST /jobs` — Phase 2.5 dispatch endpoint.
//
// Accepts a sealed prompt + the requester's pubkey, picks an attested
// provider (or honors `targetProviderDid` when supplied), and forwards
// an `inference_request` over the chosen provider's WebSocket. Returns
// an SSE stream that relays the chunk + complete frames the provider
// emits.
//
// Body shape:
//   {
//     "jobUri":            string  // at:// strong-ref to the job record
//     "requesterDid":      string  // did:plc:… or did:web:…
//     "requesterPubKey":   string  // base64 X25519, 32 raw bytes
//     "model":             string  // opaque model id; empty = no filter
//     "maxTokensOut":      number
//     "ciphertext":        number[] | string  // bytes (array) or base64
//     "sessionId":         string?  // server generates if omitted
//     "targetProviderDid": string?  // pin dispatch; otherwise pickFor()
//   }
//
// Response: `text/event-stream`. The first event is `open`, followed
// by zero or more `chunk` events, terminated by `complete` (or
// `error` on failure / idle timeout).

import type { IncomingMessage, ServerResponse } from "node:http";

import { Headers, HttpServerRequest, HttpServerResponse } from "@effect/platform";
import { Effect, Exit, Mailbox, Metric, Stream } from "effect";

import { err } from "@cocore/o11y/http";

import type { BrokerageAuthority } from "./brokerage.ts";
import { dispatchOutcome } from "./metrics.ts";
import type { AdvisorMessage, InferenceRequest } from "./protocol.ts";
import { supportsToolCallsFor } from "./registry.ts";
import type { ProviderEntry, ProviderRegistry } from "./registry.ts";
import type { SseResponse } from "./sessions.ts";
import type { SessionManager } from "./sessions.ts";
import { meetsMinVersion } from "./version.ts";

interface JobBody {
  jobUri: string;
  /** Optional: CID half of the job strong-ref. Required for the
   *  provider to publish a receipt; without it `inference_complete`
   *  carries an empty `receipt_uri`. */
  jobCid?: string;
  requesterDid: string;
  requesterPubKey: string;
  model: string;
  maxTokensOut: number;
  ciphertext: number[] | string;
  /** How the provider should interpret the opened ciphertext bytes:
   *  absent/"text" (raw prompt) or "messages-v1" (multimodal envelope).
   *  Forwarded verbatim to the provider; the advisor never inspects the
   *  plaintext. */
  inputFormat?: string;
  sessionId?: string;
  targetProviderDid?: string;
  /** Optional: pin to a SPECIFIC machine under `targetProviderDid` (its
   *  provider-record rkey / advisor machine_id). Ignored unless
   *  `targetProviderDid` is also set. Lets the console route a "test this
   *  machine" probe at exactly one of an owner's machines. */
  targetMachineId?: string;
  /** Optional JSON Schema constraining the model's output. Forwarded
   *  verbatim to the provider; the advisor never inspects it. */
  outputSchema?: { name: string; strict?: boolean; schema: Record<string, unknown> };
  /** Optional tool definitions the model may call. Forwarded verbatim
   *  to the provider; the advisor never inspects them. */
  tools?: unknown;
  /** Optional tool-choice directive (e.g. "auto", "none", "required").
   *  Forwarded verbatim to the provider; the advisor never inspects it. */
  toolChoice?: unknown;
  /** Optional: minimum provider binaryVersion eligible for this job (e.g.
   *  `0.9.32` for an image request that needs messages-v1 support). Machines
   *  below it — or that don't report a version — are excluded (fail-closed).
   *  Backstops the open-pool path; the console also pre-filters before it
   *  seals + pins to a single machine. */
  minProviderVersion?: string;
}

interface ParsedJob {
  ok: true;
  body: Required<
    Omit<
      JobBody,
      | "jobCid"
      | "inputFormat"
      | "targetProviderDid"
      | "targetMachineId"
      | "outputSchema"
      | "tools"
      | "toolChoice"
      | "minProviderVersion"
    >
  > & {
    jobCid?: string;
    inputFormat?: string;
    targetProviderDid?: string;
    targetMachineId?: string;
    outputSchema?: { name: string; strict?: boolean; schema: Record<string, unknown> };
    tools?: unknown;
    toolChoice?: unknown;
    minProviderVersion?: string;
  };
}

interface ParseError {
  ok: false;
  status: number;
  error: string;
}

function parseJobBody(input: unknown, generateId: () => string): ParsedJob | ParseError {
  if (input === null || typeof input !== "object") {
    return { ok: false, status: 400, error: "body must be a JSON object" };
  }
  const b = input as Record<string, unknown>;
  const required: Array<keyof JobBody> = [
    "jobUri",
    "requesterDid",
    "requesterPubKey",
    "model",
    "maxTokensOut",
    "ciphertext",
  ];
  for (const k of required) {
    if (!(k in b)) return { ok: false, status: 400, error: `missing field: ${k}` };
  }
  if (typeof b["jobUri"] !== "string") {
    return { ok: false, status: 400, error: "jobUri must be a string" };
  }
  if (typeof b["requesterDid"] !== "string") {
    return { ok: false, status: 400, error: "requesterDid must be a string" };
  }
  if (typeof b["requesterPubKey"] !== "string") {
    return { ok: false, status: 400, error: "requesterPubKey must be a string" };
  }
  if (typeof b["model"] !== "string") {
    return { ok: false, status: 400, error: "model must be a string" };
  }
  if (typeof b["maxTokensOut"] !== "number" || !Number.isInteger(b["maxTokensOut"])) {
    return { ok: false, status: 400, error: "maxTokensOut must be an integer" };
  }
  const ct = b["ciphertext"];
  if (!(typeof ct === "string" || (Array.isArray(ct) && ct.every((n) => typeof n === "number")))) {
    return {
      ok: false,
      status: 400,
      error: "ciphertext must be a base64 string or number[] (array of byte values)",
    };
  }
  if (b["sessionId"] !== undefined && typeof b["sessionId"] !== "string") {
    return { ok: false, status: 400, error: "sessionId must be a string when provided" };
  }
  if (b["jobCid"] !== undefined && typeof b["jobCid"] !== "string") {
    return { ok: false, status: 400, error: "jobCid must be a string when provided" };
  }
  if (b["inputFormat"] !== undefined && typeof b["inputFormat"] !== "string") {
    return { ok: false, status: 400, error: "inputFormat must be a string when provided" };
  }
  if (b["targetProviderDid"] !== undefined && typeof b["targetProviderDid"] !== "string") {
    return { ok: false, status: 400, error: "targetProviderDid must be a string when provided" };
  }
  if (b["targetMachineId"] !== undefined && typeof b["targetMachineId"] !== "string") {
    return { ok: false, status: 400, error: "targetMachineId must be a string when provided" };
  }
  if (
    b["outputSchema"] !== undefined &&
    (typeof b["outputSchema"] !== "object" || b["outputSchema"] === null)
  ) {
    return { ok: false, status: 400, error: "outputSchema must be an object when provided" };
  }
  if (b["tools"] !== undefined && !Array.isArray(b["tools"])) {
    return { ok: false, status: 400, error: "tools must be an array when provided" };
  }
  if (b["toolChoice"] !== undefined && typeof b["toolChoice"] !== "string") {
    return { ok: false, status: 400, error: "toolChoice must be a string when provided" };
  }
  if (b["minProviderVersion"] !== undefined && typeof b["minProviderVersion"] !== "string") {
    return { ok: false, status: 400, error: "minProviderVersion must be a string when provided" };
  }
  return {
    ok: true,
    body: {
      jobUri: b["jobUri"] as string,
      jobCid: typeof b["jobCid"] === "string" ? b["jobCid"] : undefined,
      requesterDid: b["requesterDid"] as string,
      requesterPubKey: b["requesterPubKey"] as string,
      model: b["model"] as string,
      maxTokensOut: b["maxTokensOut"] as number,
      ciphertext: ct as number[] | string,
      inputFormat: typeof b["inputFormat"] === "string" ? b["inputFormat"] : undefined,
      sessionId: typeof b["sessionId"] === "string" ? b["sessionId"] : generateId(),
      targetProviderDid:
        typeof b["targetProviderDid"] === "string" ? b["targetProviderDid"] : undefined,
      targetMachineId: typeof b["targetMachineId"] === "string" ? b["targetMachineId"] : undefined,
      outputSchema:
        typeof b["outputSchema"] === "object" && b["outputSchema"] !== null
          ? (b["outputSchema"] as {
              name: string;
              strict?: boolean;
              schema: Record<string, unknown>;
            })
          : undefined,
      tools: Array.isArray(b["tools"]) ? b["tools"] : undefined,
      toolChoice: typeof b["toolChoice"] === "string" ? b["toolChoice"] : undefined,
      minProviderVersion:
        typeof b["minProviderVersion"] === "string" ? b["minProviderVersion"] : undefined,
    },
  };
}

/** Hard cap on a request body. `/jobs` is public (it's how requesters
 *  dispatch), so an unbounded read is a trivial memory-exhaustion DoS. A
 *  text prompt + metadata is well under 1 MiB, but a multimodal
 *  (messages-v1) request inlines base64 images inside the sealed envelope,
 *  which is then sent as a JSON number array (~4-7 bytes on the wire per
 *  plaintext byte). 32 MiB comfortably covers a handful of typical images
 *  while still bounding the read. */
const MAX_BODY_BYTES = 32 * 1024 * 1024;

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
    total += buf.length;
    if (total > MAX_BODY_BYTES) {
      throw new Error(`request body exceeds ${MAX_BODY_BYTES} bytes`);
    }
    chunks.push(buf);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf-8")) as unknown;
}

export interface JobsContext {
  registry: ProviderRegistry;
  sessions: SessionManager;
  generateId: () => string;
  /** Maximum age (ms) for a provider's last successful attestation
   *  before `pickFor` refuses to route to them. Belt-and-suspenders
   *  in front of the WebSocket-level re-challenge timeout: if the
   *  socket somehow stayed open without a fresh attestation, this
   *  still keeps stale providers out of dispatch.
   *
   *  Set from main.ts to `RECHALLENGE_INTERVAL_MS +
   *  CHALLENGE_RESPONSE_TIMEOUT_MS + 30_000` so a single missed
   *  challenge falls back inside the window but two consecutive
   *  ones do not. */
  attestationMaxAgeMs?: number;
  /** How long to wait for a provider to answer the preflight `ping`
   *  before treating it as unresponsive and failing over to the next
   *  candidate. Small by design — a healthy serve loop answers in a few
   *  ms; this only needs to clear network RTT. Defaults to 1500ms. */
  preflightTimeoutMs?: number;
  /** Called once per successful dispatch with the time-to-ack in ms
   *  (`/jobs` received → `inference_request` frame handed to the chosen
   *  provider's socket). The brokerage-latency headline; main.ts feeds it
   *  into the rolling window the `/ack` route serves + an OTLP histogram. */
  onDispatched?: (ms: number) => void;
  /** ADR-0004: the brokerage authority. When set (and the job carries the
   *  fields needed to bind it), the advisor countersigns each dispatch and
   *  attaches the block to the `inference_request`; the provider embeds it on
   *  the receipt. Null → no countersignature (confidential unavailable through
   *  this brokerage). */
  brokerage?: BrokerageAuthority | null;
}

/** Outcome of selecting + preflighting a provider for a parsed job. */
type SelectResult =
  | { kind: "error"; status: number; error: string }
  | { kind: "aborted" }
  | { kind: "ok"; provider: ProviderEntry; job: ParsedJob["body"] };

/** Parse the request body, build the candidate list, and preflight down to
 *  the first responsive provider. Pure of any response transport — both the
 *  raw-`ServerResponse` path (handleJobsRequest, used by tests) and the
 *  HttpRouter stream path (jobsRoute) share it.
 *
 *  `isAborted` lets the caller bail mid-preflight if the requester hung up
 *  (the raw path checks `res.writableEnded`; the stream path leaves it to the
 *  platform's stream cancellation). */
async function selectProvider(
  raw: unknown,
  ctx: JobsContext,
  isAborted: () => boolean,
): Promise<SelectResult> {
  const parsed = parseJobBody(raw, ctx.generateId);
  if (!parsed.ok) return { kind: "error", status: parsed.status, error: parsed.error };
  const job = parsed.body;

  const preflightTimeoutMs = ctx.preflightTimeoutMs ?? 1500;

  // A job carrying `tools` may only be routed to a machine with VERIFIED
  // tool-call support for its model (the engine passed the forced-tool
  // startup canary). Without this filter a tools request that clears the
  // console's "some provider supports tool calling" preflight can still land
  // on a sibling machine serving the same model WITHOUT tool calling enabled,
  // whose vLLM then rejects the request mid-stream.
  const wantsToolCalls = Array.isArray(job.tools) && job.tools.length > 0;

  // Build the candidate list. A pinned `targetProviderDid` restricts
  // dispatch to that owner's machines (optionally a single machine via
  // `targetMachineId`); otherwise we get the whole eligible list, best-first.
  // Either way we preflight + fail over through the resulting list — a DID
  // can now span several machines, so "pinned" still means "this owner" but
  // can land on whichever of their machines is live.
  let candidates: ProviderEntry[];
  if (job.targetProviderDid) {
    const now = Date.now();
    const maxAge = ctx.attestationMaxAgeMs;
    const machines = ctx.registry
      .getMachines(job.targetProviderDid)
      .filter((m) => !job.targetMachineId || m.machineId === job.targetMachineId);
    if (machines.length === 0) {
      return {
        kind: "error",
        status: 503,
        error: `provider ${job.targetProviderDid} not connected`,
      };
    }
    // Apply the same eligibility the open pool gets: owner-active, attested,
    // fresh, and in good standing. Naming a provider doesn't buy a pass on
    // attestation freshness or route work to a machine the owner stopped /
    // that's been flagged unhealthy.
    const eligible = machines.filter((m) => {
      if (m.active === false) return false;
      if (m.attestedAt === null) return false;
      if (typeof maxAge === "number" && Number.isFinite(maxAge) && now - m.attestedAt > maxAge) {
        return false;
      }
      if (m.unhealthyAt !== null) return false;
      // Version floor (e.g. image input → messages-v1). Fail-closed: a
      // machine that doesn't report a version is treated as below it.
      if (job.minProviderVersion && !meetsMinVersion(m.binaryVersion, job.minProviderVersion)) {
        return false;
      }
      // Tools in the request → the machine must have passed the forced-tool
      // canary for this model. Pinning a provider doesn't buy a pass: the
      // engine would reject the request anyway, so fail fast with the reason.
      if (wantsToolCalls && !supportsToolCallsFor(m, job.model || undefined)) {
        return false;
      }
      return true;
    });
    if (eligible.length === 0) {
      return {
        kind: "error",
        status: 503,
        error: wantsToolCalls
          ? `provider ${job.targetProviderDid} has no machine with verified tool-calling for this model available`
          : job.minProviderVersion
            ? `provider ${job.targetProviderDid} has no machine at version >= ${job.minProviderVersion} available`
            : `provider ${job.targetProviderDid} has no attested, healthy machine available`,
      };
    }
    eligible.sort((a, b) => b.lastSeen - a.lastSeen);
    candidates = eligible;
  } else {
    candidates = ctx.registry.pickCandidates(
      job.model || undefined,
      true,
      ctx.attestationMaxAgeMs,
      Date.now(),
      job.minProviderVersion ?? null,
      wantsToolCalls,
    );
    if (candidates.length === 0) {
      return {
        kind: "error",
        status: 503,
        error: wantsToolCalls
          ? "no attested providers with verified tool-calling for this model available"
          : job.minProviderVersion
            ? `no attested providers at version >= ${job.minProviderVersion} available`
            : "no attested providers available",
      };
    }
  }

  // Spread load across an owner's capable machines. The candidate list
  // arrives sorted freshest-heartbeat-first, and the preflight loop below
  // dispatches to the first responder — so a burst of near-simultaneous
  // requests would otherwise pile entirely onto whichever single machine is
  // instantaneously freshest, starving an equally-capable sibling that just
  // came online (the "resumed this machine but it serves nothing while the
  // other one does everything" report). Re-rank by current in-flight load so
  // each request in a burst lands on the least-busy machine; freshest
  // heartbeat stays the tie-break, so the single-machine and idle-fleet cases
  // behave exactly as before. The eligibility + preflight guarantees are
  // untouched — every candidate here is already attested, active, healthy,
  // and model-matching, and still gets a liveness ping before dispatch.
  candidates = [...candidates].sort((a, b) => {
    const loadA = ctx.sessions.inflightFor(a.did, a.machineId);
    const loadB = ctx.sessions.inflightFor(b.did, b.machineId);
    if (loadA !== loadB) return loadA - loadB;
    return b.lastSeen - a.lastSeen;
  });

  // Preflight each candidate and route to the first that answers. A
  // silent provider is marked unhealthy and told its standing changed
  // (so the operator gets a red ping), then we move on — the requester
  // transparently lands on a live machine instead of hanging on a dead
  // one. The chosen provider answered a round-trip through its serve loop
  // a moment ago, so it's genuinely ready to take the job.
  let provider: ProviderEntry | null = null;
  let probed = 0;
  for (const cand of candidates) {
    probed += 1;
    let alive = false;
    try {
      alive = await cand.ping(preflightTimeoutMs);
    } catch {
      alive = false;
    }
    // The requester may have hung up while we were probing.
    if (isAborted()) return { kind: "aborted" };
    if (alive) {
      ctx.registry.markHealthy(cand.did, cand.machineId);
      provider = cand;
      break;
    }
    ctx.registry.markUnhealthy(cand.did, cand.machineId, "preflight-no-response");
    try {
      // Tell the machine it's out of rotation AND ask it to self-right now,
      // rather than waiting for its next scheduled health tick. The console
      // can also trigger this on demand via /control.
      cand.send({ type: "health_notice", standing: "bad", reason: "preflight-no-response" });
      cand.send({ type: "recover_request", reason: "preflight-no-response" });
    } catch {
      // socket already gone; the sweeper / close hook will clean up
    }
    console.error(
      `[jobs] preflight no-response did=${cand.did} machine=${cand.machineId}; marking unhealthy, requesting self-right, trying next`,
    );
  }

  if (!provider) {
    return {
      kind: "error",
      status: 503,
      error: `no responsive providers available (preflighted ${probed}, none answered in ${preflightTimeoutMs}ms)`,
    };
  }

  return { kind: "ok", provider, job };
}

/** Open the SSE session against `sink` and forward the `inference_request`
 *  frame to the chosen provider. Transport-agnostic — `sink` is a raw
 *  `ServerResponse` (raw path) or the Mailbox-backed sink (HttpRouter
 *  stream path). */
function dispatch(
  sink: SseResponse,
  provider: ProviderEntry,
  job: ParsedJob["body"],
  receivedAt: number,
  ctx: JobsContext,
): void {
  ctx.sessions.open(
    job.sessionId,
    provider.did,
    provider.machineId,
    job.requesterDid,
    sink,
    receivedAt,
  );

  // ADR-0004: countersign this dispatch so the receipt can prove a trusted
  // brokerage routed THIS job to the attested machine. We can only bind when the
  // job carries a jobCid and the chosen provider has a published attestation URI
  // (both are part of the canonical witness); otherwise we attach nothing and
  // the receipt is best-effort through this brokerage.
  const countersignature =
    ctx.brokerage && job.jobCid && provider.attestationUri
      ? ctx.brokerage.sign({
          jobUri: job.jobUri,
          jobCid: job.jobCid,
          machineId: provider.machineId,
          attestation: provider.attestationUri,
          requester: job.requesterDid,
        })
      : undefined;

  const inferenceFrame: AdvisorMessage = {
    type: "inference_request",
    job_uri: job.jobUri,
    ...(job.jobCid ? { job_cid: job.jobCid } : {}),
    requester_did: job.requesterDid,
    requester_pub_key: job.requesterPubKey,
    model: job.model,
    max_tokens_out: job.maxTokensOut,
    ciphertext: job.ciphertext,
    ...(job.inputFormat ? { input_format: job.inputFormat } : {}),
    ...(job.outputSchema ? { output_schema: job.outputSchema } : {}),
    ...(job.tools ? { tools: job.tools } : {}),
    ...(job.toolChoice ? { tool_choice: job.toolChoice } : {}),
    ...(countersignature ? { brokerage_countersignature: countersignature } : {}),
    session_id: job.sessionId,
  } as InferenceRequest & { type: "inference_request" };

  try {
    provider.send(inferenceFrame);
    // Time-to-ack: the frame is now on the chosen provider's socket. This is
    // the brokerage latency — received → handed off to a live worker (the
    // preflight ping already proved it answers) — and explicitly NOT the
    // worker's model-load/prefill/first-token time. Recorded only on a
    // successful send so a dead-socket throw doesn't log a bogus 0.
    ctx.onDispatched?.(Date.now() - receivedAt);
    // Account the dispatch for silent-failure detection. `recordDispatch`
    // returns true on the heartbeat-free edge where this dispatch is the one
    // that tips the provider over the threshold with still-zero completions
    // — log the flip once so the operator sees a machine that's accepting
    // work and producing nothing.
    if (ctx.registry.recordDispatch(provider.did, provider.machineId)) {
      console.error(
        `[jobs] silent-failure detected did=${provider.did}: dispatched jobs but no completions observed`,
      );
    }
  } catch (e) {
    ctx.sessions.close(job.sessionId, `provider-send-failed: ${(e as Error).message}`);
  }
}

/** Handle one POST /jobs request against a raw Node `ServerResponse` (success:
 *  SSE stream owned by SessionManager; failure: JSON status). Kept for the
 *  raw-`createServer` callers + the integration tests; main.ts serves /jobs
 *  through {@link jobsRoute} on the HttpRouter instead. */
export async function handleJobsRequest(
  req: IncomingMessage,
  res: ServerResponse,
  ctx: JobsContext,
): Promise<void> {
  // Start of the time-to-first-token clock: the moment cocore received
  // this dispatch. Carried into the session so the first relayed chunk
  // records received → first-chunk.
  const receivedAt = Date.now();
  let raw: unknown;
  try {
    raw = await readBody(req);
  } catch (e) {
    return jsonError(res, 400, `invalid JSON body: ${(e as Error).message}`);
  }
  const sel = await selectProvider(raw, ctx, () => res.writableEnded);
  if (sel.kind === "aborted") return;
  if (sel.kind === "error") return jsonError(res, sel.status, sel.error);

  // Hook so we drop the session if the requester goes away mid-stream.
  req.on("close", () => {
    if (ctx.sessions.has(sel.job.sessionId)) {
      ctx.sessions.close(sel.job.sessionId, "client-disconnected");
    }
  });
  dispatch(res, sel.provider, sel.job, receivedAt, ctx);
}

/** An {@link SseResponse} that writes SSE frames into an Effect `Mailbox`
 *  (unbounded) instead of a socket. {@link Mailbox.toStream} turns the mailbox
 *  into the `Stream<Uint8Array>` `HttpServerResponse.stream` serves, so the
 *  SessionManager drives the response with the exact same frame-writing logic
 *  it uses for a raw socket. Frames written before the stream is consumed are
 *  buffered by the mailbox. */
class MailboxSink implements SseResponse {
  statusCode = 200;
  private readonly encoder = new TextEncoder();
  private ended = false;
  // NB: explicit field + assignment, not a TS parameter property. The advisor
  // runs under `node --experimental-strip-types`, which rejects parameter
  // properties (they emit code) with ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX.
  private readonly mailbox: Mailbox.Mailbox<Uint8Array>;
  constructor(mailbox: Mailbox.Mailbox<Uint8Array>) {
    this.mailbox = mailbox;
  }
  setHeader(): void {
    /* headers are set on the HttpServerResponse, not here */
  }
  flushHeaders(): void {
    /* no-op: the platform flushes when the stream starts */
  }
  write(chunk: string): boolean {
    if (this.ended) return false;
    return this.mailbox.unsafeOffer(this.encoder.encode(chunk));
  }
  end(): void {
    if (this.ended) return;
    this.ended = true;
    this.mailbox.unsafeDone(Exit.void);
  }
  get writableEnded(): boolean {
    return this.ended;
  }
}

/** HttpRouter handler for `POST /jobs`. Selects + preflights a provider, then
 *  returns the dispatch relay as `HttpServerResponse.stream` over a
 *  Mailbox-backed SSE sink (SSE frame format identical to the raw path). All
 *  error/status paths are preserved; the dispatch outcome is recorded as a
 *  metric and the whole route is spanned `advisor.dispatch`. */
export function jobsRoute(ctx: JobsContext) {
  return Effect.gen(function* () {
    const httpReq = yield* HttpServerRequest.HttpServerRequest;
    const nodeReq = httpReq.source as IncomingMessage;
    const receivedAt = Date.now();

    const body = yield* Effect.tryPromise({
      try: () => readBody(nodeReq),
      catch: (e) => e as Error,
    }).pipe(Effect.either);
    if (body._tag === "Left") {
      yield* recordOutcome("rejected");
      return err(400, { error: `invalid JSON body: ${body.left.message}` });
    }

    const sel = yield* Effect.promise(() => selectProvider(body.right, ctx, () => false));
    if (sel.kind === "aborted") {
      // The stream path never aborts mid-preflight (isAborted is constant
      // false; the platform cancels the stream on disconnect instead), but
      // keep the branch total.
      yield* recordOutcome("no-capacity");
      return err(503, { error: "request aborted" });
    }
    if (sel.kind === "error") {
      yield* recordOutcome(sel.status === 503 ? "no-capacity" : "rejected");
      return err(sel.status, { error: sel.error });
    }

    yield* recordOutcome("ok");
    const mailbox = yield* Mailbox.make<Uint8Array>();
    const sink = new MailboxSink(mailbox);
    dispatch(sink, sel.provider, sel.job, receivedAt, ctx);

    const sessionId = sel.job.sessionId;
    const stream = Mailbox.toStream(mailbox).pipe(
      // Drop the session if the platform tears the stream down (client
      // disconnect) — mirrors the raw path's `req.on("close")`. A clean
      // complete already removed the session, so this is then a no-op.
      Stream.ensuring(
        Effect.sync(() => {
          if (ctx.sessions.has(sessionId)) ctx.sessions.close(sessionId, "client-disconnected");
        }),
      ),
    );

    return HttpServerResponse.stream(stream, {
      contentType: "text/event-stream; charset=utf-8",
      headers: Headers.fromInput({
        "cache-control": "no-cache, no-transform",
        connection: "keep-alive",
        "x-accel-buffering": "no",
      }),
    });
  }).pipe(Effect.withSpan("advisor.dispatch"));
}

const recordOutcome = (outcome: "ok" | "no-capacity" | "rejected") =>
  Metric.increment(dispatchOutcome(outcome));

function jsonError(res: ServerResponse, status: number, error: string): void {
  res.statusCode = status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.end(JSON.stringify({ error }));
}
