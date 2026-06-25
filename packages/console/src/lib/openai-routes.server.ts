// Shared request handlers for the OpenAI-compatible HTTP surface.
//
// These are referenced by two parallel route trees so the wire
// behavior is identical no matter which base URL a client uses:
//
//   * `/api/v1/*`  — cocore's historical mount point (documented in
//                    older openapi versions; still honored).
//   * `/v1/*`      — the canonical OpenAI layout. Point any OpenAI
//                    SDK / LiteLLM / etc. at
//                    `base_url="https://cocore.dev/v1"` and
//                    it appends `/chat/completions`, `/models`, … the
//                    way it appends them to `https://api.openai.com/v1`.
//
// Both mounts call the SAME functions below, so there is no second
// implementation to drift. The route files are thin shells; the logic
// lives here.

import type { Did } from "@atcute/lexicons";
import { isDid } from "@atcute/lexicons/syntax";
import type { OAuthSession } from "@atcute/oauth-node-client";

import { runTraced } from "@/lib/o11y.server.ts";

import { restoreAtprotoSessionEffect } from "@/integrations/auth/atproto.server.ts";
import { appviewBackedSession, appviewSessionInfo } from "@/lib/appview-backed-session.server.ts";
import { isAppviewForwardConfigured } from "@/lib/appview-pds-forward.server.ts";
import { type DispatchInputs, runDispatch } from "@/lib/inference-dispatch.server.ts";
import { listMyFriendDids } from "@/lib/friends.server.ts";
import { resolveProBonoProviderKeys } from "@/lib/pro-bono.server.ts";
import {
  buildJobInput,
  bufferedResponse,
  jsonError,
  type OpenAiChatRequest,
  parseRequest,
  readBearer,
  streamingResponse,
} from "@/lib/openai-chat-completions.server.ts";
import { resolveBearerKey } from "@/lib/api-keys.server.ts";
import { buildModelDirectory } from "@/lib/model-directory.server.ts";
import {
  parseTrustFloor,
  resolveVerifiedProviderDids,
  type TrustFloor,
} from "@/lib/verified-standing.server.ts";

// priceCeiling shape (currency + amount) flows into BOTH the job
// record and the paymentAuthorization record. The exchange's
// strict-verify in `verifyForCharge` compares this currency against
// receipt.price.currency (and authorization.ceiling.currency) for
// equality — a mismatch rejects the receipt and the settlement is
// never published. Currency MUST match the receipt's "CC" (set in
// provider/src/pricing.rs); a mismatch silently drops settlement
// records while leaving token-ledger balances correct.
//
// Amount is the per-call ceiling. In CC at the canonical 1:1 rate
// (1 model-token = 1 CC), 100_000 CC covers calls up to 100K tokens —
// well above the DEFAULT_MAX_TOKENS of 1024 and most real requests.
const DEFAULT_PRICE_CEILING = { amount: 100_000, currency: "CC" };

/** Authenticate the bearer key and restore the underlying ATProto
 *  session. On success returns the resolved DID + live session; on
 *  failure returns a ready-to-send error Response. */
async function authenticate(
  request: Request,
): Promise<{ did: string; oauthSession: OAuthSession } | Response> {
  const bearer = readBearer(request);
  if (!bearer) {
    return jsonError(401, "Missing Authorization: Bearer header", "authentication_error");
  }
  const resolved = resolveBearerKey(bearer);
  if (!resolved) {
    return jsonError(401, "Invalid API key", "authentication_error");
  }
  if (!isDid(resolved.did)) {
    return jsonError(500, "Stored DID is malformed", "server_error");
  }

  // Single-owner cutover: when forwarding is configured the AppView owns and
  // solely refreshes this DID's session. Restoring locally here would
  // refresh in parallel and cannibalize the single-use refresh token, so
  // hand back an AppView-backed session (every PDS call + service-auth mint
  // is replayed by the AppView). Only a DEFINITIVE "session absent" 401s;
  // a transient AppView blip doesn't (the session likely still exists).
  if (isAppviewForwardConfigured()) {
    const info = await appviewSessionInfo(resolved.did);
    if (info.checked && !info.present) {
      return jsonError(
        401,
        "API key's underlying ATProto session is no longer valid; mint a new key after re-authenticating",
        "authentication_error",
      );
    }
    return { did: resolved.did, oauthSession: appviewBackedSession(resolved.did as Did) };
  }

  // Restore the OAuth session for this DID. The session store is
  // SQLite-backed and persists across deploys, so as long as the user
  // hasn't explicitly revoked the chain, this resolves.
  const oauthSession = await runTraced(
    "auth.restoreSession",
    restoreAtprotoSessionEffect(resolved.did as Did),
  );
  if (!oauthSession) {
    return jsonError(
      401,
      "API key's underlying ATProto session is no longer valid; mint a new key after re-authenticating",
      "authentication_error",
    );
  }
  return { did: resolved.did, oauthSession };
}

/** POST /v1/chat/completions — open-network OpenAI chat completions. */
export async function handleChatCompletions(request: Request): Promise<Response> {
  const auth = await authenticate(request);
  if (auth instanceof Response) return auth;

  let raw: OpenAiChatRequest;
  try {
    raw = (await request.json()) as OpenAiChatRequest;
  } catch {
    return jsonError(400, "Body must be JSON");
  }
  const parsed = parseRequest(raw);
  if (typeof parsed === "string") return jsonError(400, parsed);

  const id = `chatcmpl-${crypto.randomUUID().replace(/-/g, "")}`;
  let payload: Awaited<ReturnType<typeof buildJobInput>>;
  try {
    payload = await buildJobInput(parsed.messages);
  } catch (e) {
    return jsonError(400, `failed to prepare input: ${(e as Error).message}`);
  }
  const inputs: DispatchInputs = {
    did: auth.did,
    oauthSession: auth.oauthSession,
    model: parsed.model,
    prompt: "",
    payloadBytes: payload.payloadBytes,
    inputFormat: payload.inputFormat,
    maxTokensOut: parsed.maxTokens,
    priceCeiling: DEFAULT_PRICE_CEILING,
    country: parsed.country,
  };

  if (parsed.stream) {
    return streamingResponse(id, parsed.model, runDispatch(inputs));
  }
  return await bufferedResponse(id, parsed.model, runDispatch(inputs));
}

/** POST /v1/private/chat/completions — friends-only routing. Identical
 *  wire format, but the candidate provider pool is constrained to DIDs
 *  the caller has friended (dev.cocore.account.friend records). */
export async function handlePrivateChatCompletions(request: Request): Promise<Response> {
  const auth = await authenticate(request);
  if (auth instanceof Response) return auth;

  let raw: OpenAiChatRequest;
  try {
    raw = (await request.json()) as OpenAiChatRequest;
  } catch {
    return jsonError(400, "Body must be JSON");
  }
  const parsed = parseRequest(raw);
  if (typeof parsed === "string") return jsonError(400, parsed);

  // Pull the friend set BEFORE submitting the job to the PDS. A failure
  // here (e.g. listRecords transient 500) shouldn't produce an
  // unfounded `no_friends_available` — surface the transport error so
  // the operator can tell "I really have no friends" from "the PDS
  // coughed."
  let allowedProviderDids: Set<string>;
  try {
    allowedProviderDids = await listMyFriendDids(auth.oauthSession);
  } catch (e) {
    return jsonError(
      502,
      `failed to load friend list: ${(e as Error).message}`,
      "server_error",
      "friend_list_failed",
    );
  }

  const id = `chatcmpl-${crypto.randomUUID().replace(/-/g, "")}`;
  let payload: Awaited<ReturnType<typeof buildJobInput>>;
  try {
    payload = await buildJobInput(parsed.messages);
  } catch (e) {
    return jsonError(400, `failed to prepare input: ${(e as Error).message}`);
  }
  const inputs: DispatchInputs = {
    did: auth.did,
    oauthSession: auth.oauthSession,
    model: parsed.model,
    prompt: "",
    payloadBytes: payload.payloadBytes,
    inputFormat: payload.inputFormat,
    maxTokensOut: parsed.maxTokens,
    priceCeiling: DEFAULT_PRICE_CEILING,
    // `allowedProviderDids` here is what tips runDispatch into
    // friends-only mode. The set may be empty (user has no friends);
    // pickProvider surfaces NoFriendsAvailableError and the buffered/
    // streaming responders map that to a 503 (no_friends_available).
    allowedProviderDids,
    country: parsed.country,
  };

  if (parsed.stream) {
    return streamingResponse(id, parsed.model, runDispatch(inputs));
  }
  return await bufferedResponse(id, parsed.model, runDispatch(inputs));
}

/** POST /v1/verified/chat/completions — route ONLY to providers whose
 *  attestation is cryptographically verified to meet a trust floor. Identical
 *  wire format to `/v1/chat/completions` plus an optional `min_trust` body
 *  field: `"hardware-attested"` (default — accept any verified machine) or
 *  `"confidential"` (strict `attested-confidential`). Fails CLOSED with a 503
 *  when no verified provider serves the model, so a privacy/integrity request
 *  never silently downgrades. The allow-set is proof-backed (see
 *  verified-standing.server.ts): a self-asserted `trustLevel` can't get a
 *  provider routed here — only a verified Apple-rooted attestation can. */
export async function handleVerifiedChatCompletions(request: Request): Promise<Response> {
  const auth = await authenticate(request);
  if (auth instanceof Response) return auth;

  let raw: OpenAiChatRequest & { min_trust?: unknown };
  try {
    raw = (await request.json()) as typeof raw;
  } catch {
    return jsonError(400, "Body must be JSON");
  }
  const parsed = parseRequest(raw);
  if (typeof parsed === "string") return jsonError(400, parsed);

  // Floor defaults to hardware-attested ("any verified machine"). An explicit
  // unrecognized value is a 400, never a silent downgrade.
  let floor: TrustFloor = "hardware-attested";
  if (raw.min_trust !== undefined) {
    const f = parseTrustFloor(raw.min_trust);
    if (!f) {
      return jsonError(
        400,
        'min_trust must be "hardware-attested" or "confidential"',
        "invalid_request_error",
        "invalid_min_trust",
      );
    }
    floor = f;
  }

  let allowedProviderDids: Set<string>;
  try {
    allowedProviderDids = await resolveVerifiedProviderDids(floor, parsed.model);
  } catch (e) {
    return jsonError(
      502,
      `failed to resolve verified providers: ${(e as Error).message}`,
      "server_error",
      "verified_lookup_failed",
    );
  }
  if (allowedProviderDids.size === 0) {
    return jsonError(
      503,
      `no provider is currently verified at the '${floor}' tier for model ${parsed.model}`,
      "service_unavailable_error",
      "no_verified_providers",
    );
  }

  const id = `chatcmpl-${crypto.randomUUID().replace(/-/g, "")}`;
  let payload: Awaited<ReturnType<typeof buildJobInput>>;
  try {
    payload = await buildJobInput(parsed.messages);
  } catch (e) {
    return jsonError(400, `failed to prepare input: ${(e as Error).message}`);
  }
  const inputs: DispatchInputs = {
    did: auth.did,
    oauthSession: auth.oauthSession,
    model: parsed.model,
    prompt: "",
    payloadBytes: payload.payloadBytes,
    inputFormat: payload.inputFormat,
    maxTokensOut: parsed.maxTokens,
    priceCeiling: DEFAULT_PRICE_CEILING,
    // Same mechanism as the friends path, but the set is the proof-backed
    // verified-provider list rather than the caller's friends.
    allowedProviderDids,
    country: parsed.country,
  };

  if (parsed.stream) {
    return streamingResponse(id, parsed.model, runDispatch(inputs));
  }
  return await bufferedResponse(id, parsed.model, runDispatch(inputs));
}

/** POST /v1/probono/chat/completions — the pro-bono completion path. Routes
 *  ONLY to providers whose `proBono` policy elects to serve THIS requester for
 *  free (`mode: any`, or `mode: direct` with the caller's DID listed). A
 *  matched job is served unmetered at zero price with no exchange cut, so a
 *  requester with no token balance can still get a completion. Identical wire
 *  format to `/v1/chat/completions` (and `country` still narrows by region).
 *  Fails CLOSED with a 503 when no connected provider currently offers the
 *  caller pro bono, rather than silently falling back to a billed job. Same
 *  `allowedProviderDids` mechanism as the friends + verified paths. */
export async function handleProBonoChatCompletions(request: Request): Promise<Response> {
  const auth = await authenticate(request);
  if (auth instanceof Response) return auth;

  let raw: OpenAiChatRequest;
  try {
    raw = (await request.json()) as OpenAiChatRequest;
  } catch {
    return jsonError(400, "Body must be JSON");
  }
  const parsed = parseRequest(raw);
  if (typeof parsed === "string") return jsonError(400, parsed);

  // Resolve the specific MACHINES that currently serve this DID pro bono BEFORE
  // submitting the job (composite `did:machineId` keys — pro bono is per-machine,
  // so we can't widen to an owner's other billed machines). A lookup failure
  // surfaces as a transport error (so the caller can tell "nobody offers me pro
  // bono" from "the AppView coughed").
  let allowedProviderDids: Set<string>;
  try {
    allowedProviderDids = await resolveProBonoProviderKeys(auth.did);
  } catch (e) {
    return jsonError(
      502,
      `failed to resolve pro-bono providers: ${(e as Error).message}`,
      "server_error",
      "pro_bono_lookup_failed",
    );
  }
  if (allowedProviderDids.size === 0) {
    return jsonError(
      503,
      "no provider currently offers you pro-bono compute; use /v1/chat/completions for a normal (billed) request",
      "service_unavailable_error",
      "no_pro_bono_providers",
    );
  }

  const id = `chatcmpl-${crypto.randomUUID().replace(/-/g, "")}`;
  let payload: Awaited<ReturnType<typeof buildJobInput>>;
  try {
    payload = await buildJobInput(parsed.messages);
  } catch (e) {
    return jsonError(400, `failed to prepare input: ${(e as Error).message}`);
  }
  const inputs: DispatchInputs = {
    did: auth.did,
    oauthSession: auth.oauthSession,
    model: parsed.model,
    prompt: "",
    payloadBytes: payload.payloadBytes,
    inputFormat: payload.inputFormat,
    maxTokensOut: parsed.maxTokens,
    priceCeiling: DEFAULT_PRICE_CEILING,
    // Constrain routing to providers that serve this requester free — same
    // gate as the friends/verified paths, just a different allow-set.
    allowedProviderDids,
    country: parsed.country,
  };

  if (parsed.stream) {
    return streamingResponse(id, parsed.model, runDispatch(inputs));
  }
  return await bufferedResponse(id, parsed.model, runDispatch(inputs));
}

function jsonResponse(payload: unknown): Response {
  return new Response(JSON.stringify(payload), {
    headers: {
      "content-type": "application/json",
      "cache-control": "public, max-age=30, stale-while-revalidate=300",
    },
  });
}

/** GET /v1/models — the model directory.
 *
 *  Default response is the canonical OpenAI list shape
 *  (`{object:"list", data:[{id, object:"model", …}]}`) so an
 *  unmodified OpenAI client's `GET /v1/models` populates its model
 *  picker. cocore's richer, proprietary views are opt-in:
 *
 *    * `?view=directory` — full per-machine detail + activity windows
 *      (the shape the console's api-docs page renders).
 *    * `?view=summary`   — lean {modelId, machineCount, price} rows.
 */
export async function handleModelsDirectory(request: Request): Promise<Response> {
  const directory = await buildModelDirectory();
  const view = new URL(request.url).searchParams.get("view");

  if (view === "directory") {
    return jsonResponse(directory);
  }

  if (view === "summary") {
    return jsonResponse({
      models: directory.models.map((m) => ({
        modelId: m.modelId,
        machineCount: m.machineCount,
        inputPricePerMTok: m.inputPricePerMTok,
        outputPricePerMTok: m.outputPricePerMTok,
        currency: m.currency,
        recommended: m.recommended,
      })),
      generatedAt: directory.generatedAt,
      appviewUnreachable: directory.appviewUnreachable,
    });
  }

  // Canonical OpenAI shape. `created` is the freshest provider sighting
  // for the model (falling back to the snapshot time); `owned_by` is
  // the network rather than any single provider, since a model is
  // served by however many machines currently advertise it.
  const generatedAtSecs = Math.floor(new Date(directory.generatedAt).getTime() / 1000);
  const data = directory.models.map((m) => ({
    id: m.modelId,
    object: "model" as const,
    created: m.freshestAt ? Math.floor(new Date(m.freshestAt).getTime() / 1000) : generatedAtSecs,
    owned_by: "cocore",
  }));
  return jsonResponse({ object: "list", data });
}
