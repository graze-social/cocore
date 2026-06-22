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
  maxTokensOut?: unknown;
  priceCeiling?: unknown;
  targetProviderDid?: unknown;
}

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
  return {
    model: body.model,
    prompt: body.prompt,
    maxTokensOut: body.maxTokensOut,
    priceCeiling: { amount: pc.amount, currency: pc.currency },
    ...(typeof body.targetProviderDid === "string"
      ? { targetProviderDid: body.targetProviderDid }
      : {}),
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
