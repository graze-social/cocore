// Inference XRPC handler, served by the AppView.
//
//   /xrpc/dev.cocore.inference.dispatch  (POST, service-auth)  — submit an
//     inference request and stream the result back as Server-Sent Events.
//
// dispatch is a real public XRPC method authed via AT Protocol service
// auth (the requester's PDS proxies the call to `#cocore_appview`). The
// AppView verifies the requester's DID, restores the OAuth session it owns
// for that DID (login handoff), publishes the job to the requester's PDS,
// routes to a provider via the advisor, and streams decrypted output.
//
// SSE is served idiomatically via @effect/platform's
// `HttpServerResponse.stream`: the dispatch event AsyncIterable becomes an
// Effect `Stream` of encoded SSE frames. The platform cancels the stream
// (and thus the dispatch generator) when the client disconnects.

import type { Did } from "@atcute/lexicons";
import type { PublishedRecord, RecordTransport } from "@cocore/sdk/publish";
import { Headers, HttpRouter, HttpServerRequest, HttpServerResponse } from "@effect/platform";
import { Effect, Stream } from "effect";

import { bearer, err, jsonBody } from "../api/http-app.ts";
import {
  type AppviewOAuthClient,
  type RestoredSession,
  restoreSession,
} from "../auth/oauth-client.ts";
import {
  buildEnvelopeBytes,
  coerceEnvelopeMessages,
  hasImageParts,
  hasToolMessages,
  MESSAGES_V1,
} from "@cocore/sdk/multimodal-envelope";

import { verifyServiceAuthToken } from "../auth/service-auth.ts";
import type { Store } from "../store.ts";
import { type DispatchInputs, type ProfileForCredit, runDispatch } from "./dispatch.ts";

export interface InferenceContext {
  /** Indexed record store — read for the provider-credit line. */
  store: Store;
  /** OAuth client used to restore the requester's DPoP-bound session for
   *  the PDS job write. */
  oauth: AppviewOAuthClient;
  /** This AppView's service DID — the `aud` that dispatch's service-auth
   *  JWT must target. */
  appviewDid: string;
  /** HTTP base for the matchmaking advisor. */
  advisorUrl: string;
  /** Exchange DID stamped onto the paymentAuthorization + job. */
  exchangeDid: string;
  /** Bridge base URL for the best-effort AppView-cache mirror on the job
   *  write. When unset, writes still land on the PDS and firehose catches up. */
  bridgeUrl?: string;
}

interface DispatchBody {
  model?: unknown;
  prompt?: unknown;
  /** Optional structured multimodal turns (forwarded by the console). When
   *  present with any image part, the dispatch seals the canonical
   *  messages-v1 envelope instead of the flattened prompt. */
  messages?: unknown;
  maxTokensOut?: unknown;
  priceCeiling?: unknown;
  targetProviderDid?: unknown;
  targetMachineId?: unknown;
  /** Optional ISO 3166-1 alpha-2 country to route by (advisory). */
  country?: unknown;
  /** Optional JSON Schema constraining the model's output. */
  outputSchema?: unknown;
  /** Optional list of tool/function definitions. */
  tools?: unknown;
  /** Optional tool choice strategy. */
  toolChoice?: unknown;
  /** Optional DID allow-set the console resolved (pro-bono / friends /
   *  verified) and forwarded. Constrains provider selection. */
  allowedProviderDids?: unknown;
  /** Optional explicit minimum provider binaryVersion to route to (e.g.
   *  `0.9.32` to require a feature). When absent, an image (messages-v1)
   *  request still derives the messages-v1 floor automatically. */
  minProviderVersion?: unknown;
}

// Minimum provider binaryVersion required to serve a multimodal
// (messages-v1) request. Mirrors the console's constant; configurable via
// the same env so both surfaces move the floor together.
const MESSAGES_V1_MIN_VERSION = process.env["COCORE_MIN_VERSION_MESSAGES_V1"] ?? "0.9.32";

type ParsedDispatch = Omit<DispatchInputs, "did">;

function parseDispatch(body: DispatchBody): ParsedDispatch | string {
  if (typeof body.model !== "string" || body.model.length === 0) return "model required";
  if (typeof body.prompt !== "string" || body.prompt.length === 0) return "prompt required";
  if (
    typeof body.maxTokensOut !== "number" ||
    !Number.isInteger(body.maxTokensOut) ||
    body.maxTokensOut < 1
  ) {
    return "maxTokensOut must be a positive integer";
  }
  const pc = body.priceCeiling as { amount?: unknown; currency?: unknown } | undefined;
  if (
    !pc ||
    typeof pc.amount !== "number" ||
    !Number.isInteger(pc.amount) ||
    pc.amount < 0 ||
    typeof pc.currency !== "string" ||
    pc.currency.length === 0
  ) {
    return "priceCeiling must be { amount: int, currency: string }";
  }
  if (body.targetProviderDid !== undefined && typeof body.targetProviderDid !== "string") {
    return "targetProviderDid must be a string when provided";
  }
  if (body.targetMachineId !== undefined && typeof body.targetMachineId !== "string") {
    return "targetMachineId must be a string when provided";
  }
  if (body.targetMachineId !== undefined && body.targetProviderDid === undefined) {
    return "targetMachineId requires targetProviderDid";
  }
  let country: string | undefined;
  if (body.country !== undefined) {
    if (typeof body.country !== "string" || !/^[A-Za-z]{2}$/.test(body.country.trim())) {
      return "country must be a 2-letter ISO 3166-1 alpha-2 code";
    }
    country = body.country.trim().toUpperCase();
  }
  let allowedProviderDids: Set<string> | undefined;
  if (body.allowedProviderDids !== undefined) {
    if (
      !Array.isArray(body.allowedProviderDids) ||
      !body.allowedProviderDids.every((d): d is string => typeof d === "string")
    ) {
      return "allowedProviderDids must be an array of DID strings";
    }
    allowedProviderDids = new Set(body.allowedProviderDids);
  }
  if (body.minProviderVersion !== undefined && typeof body.minProviderVersion !== "string") {
    return "minProviderVersion must be a string when provided";
  }
  // Build the messages-v1 envelope when the client sent images.
  let envelope: Pick<DispatchInputs, "payloadBytes" | "inputFormat"> = {};
  if (body.messages !== undefined) {
    const coerced = coerceEnvelopeMessages(body.messages);
    if (!coerced) return "messages must be an array of { role, content } turns";
    if (hasImageParts(coerced) || hasToolMessages(coerced)) {
      envelope = { payloadBytes: buildEnvelopeBytes(coerced), inputFormat: MESSAGES_V1 };
    }
  }
  // Optional JSON Schema for structured output.
  let outputSchema: DispatchInputs["outputSchema"];
  if (body.outputSchema !== undefined) {
    if (typeof body.outputSchema !== "object" || body.outputSchema === null) {
      return "outputSchema must be an object when provided";
    }
    const os = body.outputSchema as { name?: unknown; strict?: unknown; schema?: unknown };
    if (typeof os.name !== "string" || os.name.length === 0) {
      return "outputSchema.name must be a non-empty string";
    }
    if (os.strict !== undefined && typeof os.strict !== "boolean") {
      return "outputSchema.strict must be a boolean when provided";
    }
    if (typeof os.schema !== "object" || os.schema === null) {
      return "outputSchema.schema must be an object";
    }
    outputSchema = {
      name: os.name,
      ...(typeof os.strict === "boolean" ? { strict: os.strict } : {}),
      schema: os.schema as Record<string, unknown>,
    };
  }
  // Optional tools for tool calling.
  let tools: DispatchInputs["tools"];
  if (body.tools !== undefined) {
    if (!Array.isArray(body.tools)) {
      return "tools must be an array when provided";
    }
    tools = body.tools as DispatchInputs["tools"];
  }
  let toolChoice: DispatchInputs["toolChoice"];
  if (body.toolChoice !== undefined) {
    if (typeof body.toolChoice !== "string") {
      return "toolChoice must be a string when provided";
    }
    if (!["auto", "none", "required"].includes(body.toolChoice)) {
      return "toolChoice must be 'auto', 'none', or 'required'";
    }
    toolChoice = body.toolChoice as DispatchInputs["toolChoice"];
  }
  // An explicit floor wins; otherwise an image request derives the
  // messages-v1 floor so it only reaches providers that can parse it.
  const minProviderVersion =
    typeof body.minProviderVersion === "string"
      ? body.minProviderVersion
      : envelope.inputFormat === MESSAGES_V1
        ? MESSAGES_V1_MIN_VERSION
        : undefined;
  return {
    model: body.model,
    prompt: body.prompt,
    ...envelope,
    maxTokensOut: body.maxTokensOut,
    priceCeiling: { amount: pc.amount, currency: pc.currency },
    ...(typeof body.targetProviderDid === "string"
      ? { targetProviderDid: body.targetProviderDid }
      : {}),
    ...(typeof body.targetProviderDid === "string" && typeof body.targetMachineId === "string"
      ? { targetMachineId: body.targetMachineId }
      : {}),
    ...(country ? { country } : {}),
    ...(outputSchema ? { outputSchema } : {}),
    ...(tools ? { tools } : {}),
    ...(toolChoice ? { toolChoice } : {}),
    ...(allowedProviderDids ? { allowedProviderDids } : {}),
    ...(minProviderVersion ? { minProviderVersion } : {}),
  };
}

/** A RecordTransport that writes to the requester's PDS through an
 *  already-restored, DPoP-bound session, mirroring each write to the
 *  bridge so the in-app dashboard sees the job without waiting for the
 *  firehose. Mirrors `doCreate` in pds/write.ts, but returns the
 *  published ref to the SDK rather than writing an HTTP response. */
function sessionTransport(
  session: RestoredSession,
  bridgeUrl: string | undefined,
): RecordTransport {
  return {
    async publish<T extends Record<string, unknown>>(args: {
      repo: string;
      collection: string;
      record: T;
    }): Promise<PublishedRecord> {
      const r = await session.handle("/xrpc/com.atproto.repo.createRecord", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          repo: args.repo,
          collection: args.collection,
          record: args.record,
        }),
      });
      if (!r.ok) {
        const text = await r.text().catch(() => "");
        throw new Error(
          `createRecord ${args.collection} returned ${r.status}: ${text.slice(0, 300)}`,
        );
      }
      const out = (await r.json()) as { uri: string; cid: string };
      if (bridgeUrl) {
        const rkey = out.uri.split("/").pop() ?? "";
        void fetch(`${bridgeUrl.replace(/\/$/, "")}/xrpc/dev.cocore.bridge.publish`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            uri: out.uri,
            cid: out.cid,
            collection: args.collection,
            repo: args.repo,
            rkey,
            body: args.record,
          }),
        }).catch(() => {
          /* swallowed — cache hint, not a checkpoint */
        });
      }
      return { uri: out.uri, cid: out.cid };
    },
  };
}

/** Adapt the AppView's indexed Store to the dispatch core's credit
 *  fetcher. Best-effort; returns null when the DID has no footprint. */
function storeProfileFetcher(store: Store): (did: string) => Promise<ProfileForCredit | null> {
  return async (did) => {
    const profile = store.getProfile(did);
    if (!profile) return null;
    return {
      handle: profile.handle,
      displayName: profile.displayName,
      machines: profile.machines.map((m) => ({ rkey: m.rkey, machineLabel: m.machineLabel })),
    };
  };
}

function sseFrame(event: string, data: string): string {
  return `event: ${event}\ndata: ${data}\n\n`;
}

export function buildInferenceRouter(ctx: InferenceContext): HttpRouter.HttpRouter<never, never> {
  return HttpRouter.empty.pipe(
    // `all` + method guard so a wrong-method request returns 405 (not the
    // router's default 404), matching the previous hand-rolled behavior.
    HttpRouter.all(
      "/xrpc/dev.cocore.inference.dispatch",
      Effect.gen(function* () {
        const req = yield* HttpServerRequest.HttpServerRequest;
        if (req.method !== "POST") return err(405, { error: "MethodNotAllowed" });
        const token = yield* bearer;
        const auth = yield* Effect.promise(() =>
          verifyServiceAuthToken(token, {
            audience: ctx.appviewDid,
            lxm: "dev.cocore.inference.dispatch",
          }),
        );
        if (!auth.ok) return err(auth.status, { error: auth.error, message: auth.message });
        const did = auth.did;

        const parsedBody = yield* Effect.either(jsonBody);
        if (parsedBody._tag === "Left") {
          return err(400, { error: "InvalidRequest", message: parsedBody.left.message });
        }
        const parsed = parseDispatch(parsedBody.right as DispatchBody);
        if (typeof parsed === "string") {
          return err(400, { error: "InvalidRequest", message: parsed });
        }

        // The AppView publishes the job under the session it owns for this
        // requester (login handoff). No session → fail before opening the
        // stream so the client gets a clean 401.
        const session = yield* Effect.promise(() => restoreSession(ctx.oauth, did as Did));
        if (!session) {
          return err(401, {
            error: "AuthRequired",
            message: "no AppView-owned session for this DID; sign in to the console first",
          });
        }

        const events = runDispatch(
          { did, ...parsed },
          {
            advisorUrl: ctx.advisorUrl,
            exchangeDid: ctx.exchangeDid,
            transport: sessionTransport(session, ctx.bridgeUrl),
            getProfile: storeProfileFetcher(ctx.store),
          },
        );

        const encoder = new TextEncoder();
        const body = Stream.fromAsyncIterable(events, (e) => e).pipe(
          Stream.map((ev) => {
            if (ev.kind === "meta") {
              return encoder.encode(
                sseFrame(
                  "meta",
                  JSON.stringify({
                    jobUri: ev.jobUri,
                    jobCid: ev.jobCid,
                    authUri: ev.authUri,
                    inputCommitment: ev.inputCommitment,
                    providerDid: ev.providerDid,
                    sessionId: ev.sessionId,
                  }),
                ),
              );
            }
            if (ev.kind === "chunk") {
              return encoder.encode(
                sseFrame(
                  "chunk",
                  JSON.stringify({ seq: ev.seq, channel: ev.channel, text: ev.text }),
                ),
              );
            }
            if (ev.kind === "complete") {
              return encoder.encode(
                sseFrame(
                  "complete",
                  JSON.stringify({
                    tokensIn: ev.tokensIn,
                    tokensOut: ev.tokensOut,
                    receiptUri: ev.receiptUri,
                    ...(ev.providerCredit ? { providerCredit: ev.providerCredit } : {}),
                  }),
                ),
              );
            }
            return encoder.encode(
              sseFrame("error", JSON.stringify({ reason: ev.reason, code: ev.code })),
            );
          }),
          Stream.catchAll((e) =>
            Stream.succeed(
              encoder.encode(
                sseFrame(
                  "error",
                  JSON.stringify({ reason: (e as Error).message, code: "unknown" }),
                ),
              ),
            ),
          ),
        );

        return HttpServerResponse.stream(body, {
          contentType: "text/event-stream; charset=utf-8",
          headers: Headers.fromInput({
            "cache-control": "no-cache, no-transform",
            "x-accel-buffering": "no",
          }),
        });
      }).pipe(Effect.withSpan("appview.inference.dispatch")),
    ),
  );
}
