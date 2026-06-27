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
import { type AdvisorProviderRow, type DispatchInputs, runDispatch } from "@/lib/inference-dispatch.server.ts";
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
import { cocoreConfig } from "@/lib/cocore-config.ts";
import { resolveBearerKeyViaAppview } from "@/lib/api-keys-appview.server.ts";
import { verifyServiceAuth } from "@/lib/service-auth.server.ts";
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

// Minimum provider binaryVersion required to serve a multimodal
// (`messages-v1`) request — i.e. one carrying images. Image support and the
// Register-frame version reporting that lets the advisor enforce this both
// land in the same release, so the floor is that release. Configurable via
// env for when a later release moves it; the default is the first version
// that reports its version AND parses images. A text request has no floor.
const MESSAGES_V1_MIN_VERSION = process.env["COCORE_MIN_VERSION_MESSAGES_V1"] ?? "0.9.32";

/** The provider version floor implied by an input format. Images
 *  (`messages-v1`) require a capable provider; plain text has no floor. */
function minVersionForInput(inputFormat: string | undefined): string | undefined {
  return inputFormat === "messages-v1" ? MESSAGES_V1_MIN_VERSION : undefined;
}

// The method NSID a service-auth token must be minted for (its `lxm`
// claim) to authenticate inference. The OpenAI-compatible surface forwards
// to `dev.cocore.inference.dispatch`, so we bind to that NSID — one token
// works across both the XRPC dispatch and this endpoint.
const INFERENCE_LXM = "dev.cocore.inference.dispatch";

/** Distinguish an AT Protocol service-auth JWT (three base64url segments)
 *  from a `cocore-…` API key. A caller can authenticate inference with
 *  either; a service token (minted by the caller's PDS via getServiceAuth)
 *  needs no key provisioning at all. */
function looksLikeServiceToken(bearer: string): boolean {
  return !bearer.startsWith("cocore-") && bearer.split(".").length === 3;
}

/** The DID resolved fine, but it has no authorized cocore session — so
 *  there's no way to publish the job/payment to its PDS. The remedy differs
 *  by credential: an API-key holder re-mints after re-auth; a service-token
 *  caller's account owner must complete cocore onboarding once. */
function sessionAbsentError(viaServiceToken: boolean): Response {
  if (viaServiceToken) {
    return jsonError(
      401,
      "This DID has no authorized cocore session, so inference cannot run on its behalf. The account owner must connect cocore once at https://cocore.dev, then retry.",
      "authentication_error",
      "onboarding_required",
    );
  }
  return jsonError(
    401,
    "API key's underlying ATProto session is no longer valid; mint a new key after re-authenticating",
    "authentication_error",
  );
}

/** Authenticate the request and restore the underlying ATProto session.
 *  Accepts either a cocore API key (resolved against the console store,
 *  then — for keys minted via the documented AppView endpoint — the AppView
 *  store) or an AT Protocol service-auth JWT. On success returns the
 *  resolved DID + live session; on failure returns a ready-to-send error. */
async function authenticate(
  request: Request,
): Promise<{ did: string; oauthSession: OAuthSession } | Response> {
  const bearer = readBearer(request);
  if (!bearer) {
    return jsonError(401, "Missing Authorization: Bearer header", "authentication_error");
  }

  // Resolve the caller to a DID via whichever credential they presented.
  let did: string;
  let viaServiceToken = false;
  if (looksLikeServiceToken(bearer)) {
    viaServiceToken = true;
    const auth = await verifyServiceAuth(request, INFERENCE_LXM);
    if (!auth.ok) return jsonError(auth.status, auth.message, "authentication_error", auth.error);
    did = auth.did;
  } else {
    // Local console.db first (console-minted keys + console-paired agents),
    // then the AppView store (keys minted via the documented createApiKey,
    // which lands in account.db). The AppView helper self-gates on the
    // internal channel being configured and on the `cocore-` prefix.
    const resolved = resolveBearerKey(bearer) ?? (await resolveBearerKeyViaAppview(bearer));
    if (!resolved) {
      return jsonError(401, "Invalid API key", "authentication_error", "invalid_api_key");
    }
    did = resolved.did;
  }

  if (!isDid(did)) {
    return jsonError(500, "Resolved DID is malformed", "server_error");
  }

  // Single-owner cutover: when forwarding is configured the AppView owns and
  // solely refreshes this DID's session. Restoring locally here would
  // refresh in parallel and cannibalize the single-use refresh token, so
  // hand back an AppView-backed session (every PDS call + service-auth mint
  // is replayed by the AppView). Only a DEFINITIVE "session absent" 401s;
  // a transient AppView blip doesn't (the session likely still exists).
  if (isAppviewForwardConfigured()) {
    const info = await appviewSessionInfo(did);
    if (info.checked && !info.present) {
      return sessionAbsentError(viaServiceToken);
    }
    return { did, oauthSession: appviewBackedSession(did as Did) };
  }

  // Restore the OAuth session for this DID. The session store is
  // SQLite-backed and persists across deploys, so as long as the user
  // hasn't explicitly revoked the chain, this resolves.
  const oauthSession = await runTraced(
    "auth.restoreSession",
    restoreAtprotoSessionEffect(did as Did),
  );
  if (!oauthSession) {
    return sessionAbsentError(viaServiceToken);
  }
  return { did, oauthSession };
}

/**
 * Check whether at least one connected provider supports tool calling for
 * the requested model. Returns `null` if OK (tools allowed or no tools in
 * request), or an error message string if the request should be rejected.
 *
 * When `allowedDids` is provided, the pool is filtered to those DIDs
 * (friends-only routing). Otherwise the full attested pool is considered.
 */
async function checkToolCallSupport(
  model: string,
  tools: unknown,
  allowedDids?: Set<string>,
): Promise<string | null> {
  // No tools in the request — nothing to gate.
  if (!tools || !Array.isArray(tools) || tools.length === 0) return null;

  const config = cocoreConfig();
  let list: AdvisorProviderRow[];
  try {
    const r = await fetch(`${config.advisorUrl}/providers`);
    if (!r.ok) return null; // advisor unreachable — don't block the request
    list = (await r.json()) as AdvisorProviderRow[];
  } catch {
    return null; // network error — don't block the request
  }

  // Filter to attested, active, model-matching providers.
  let pool = list.filter(
    (p) =>
      p.attestedAt &&
      p.active !== false &&
      (p.supportedModels.length === 0 || p.supportedModels.includes(model)),
  );

  // Friends-only: further filter to the allowed DID set.
  if (allowedDids !== undefined) {
    pool = pool.filter((p) => allowedDids.has(p.did));
  }

  // Check if at least one provider in the pool has verified tool calling for
  // this exact model. Legacy providers that predate `toolCallModels` fall back
  // to the coarse boolean; new providers report a per-model canary-passed set.
  const toolCapable = pool.some((p) => {
    if (Array.isArray(p.toolCallModels)) return p.toolCallModels.includes(model);
    return p.supportsToolCalls === true;
  });
  if (!toolCapable) {
    return (
      "No connected provider supports tool calling for this model. " +
      "The provider must be started with vLLM tool calling enabled and pass " +
      "the startup forced-tool canary."
    );
  }
  return null;
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

  // Tool calling gate: if the request includes tools, verify at least one
  // connected provider supports tool calling for this model.
  const toolError = await checkToolCallSupport(parsed.model, parsed.tools);
  if (toolError) return jsonError(400, toolError, "tool_calls_not_supported");

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
    // Image requests must only reach providers running a release that
    // supports the messages-v1 envelope (fail-closed at the advisor).
    minProviderVersion: minVersionForInput(payload.inputFormat),
    maxTokensOut: parsed.maxTokens,
    priceCeiling: DEFAULT_PRICE_CEILING,
    country: parsed.country,
    ...(parsed.outputSchema ? { outputSchema: parsed.outputSchema } : {}),
    ...(parsed.tools ? { tools: parsed.tools } : {}),
    ...(parsed.toolChoice ? { toolChoice: parsed.toolChoice } : {}),
    ...(parsed.toolChoiceFunction ? { toolChoiceFunction: parsed.toolChoiceFunction } : {}),
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

  // Tool calling gate: if the request includes tools, verify at least one
  // friend provider supports tool calling for this model.
  const toolError = await checkToolCallSupport(
    parsed.model,
    parsed.tools,
    allowedProviderDids,
  );
  if (toolError) return jsonError(400, toolError, "tool_calls_not_supported");

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
    // Image requests must only reach providers running a release that
    // supports the messages-v1 envelope (fail-closed at the advisor).
    minProviderVersion: minVersionForInput(payload.inputFormat),
    maxTokensOut: parsed.maxTokens,
    priceCeiling: DEFAULT_PRICE_CEILING,
    // `allowedProviderDids` here is what tips runDispatch into
    // friends-only mode. The set may be empty (user has no friends);
    // pickProvider surfaces NoFriendsAvailableError and the buffered/
    // streaming responders map that to a 503 (no_friends_available).
    allowedProviderDids,
    country: parsed.country,
    ...(parsed.outputSchema ? { outputSchema: parsed.outputSchema } : {}),
    ...(parsed.tools ? { tools: parsed.tools } : {}),
    ...(parsed.toolChoice ? { toolChoice: parsed.toolChoice } : {}),
    ...(parsed.toolChoiceFunction ? { toolChoiceFunction: parsed.toolChoiceFunction } : {}),
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
    // Image requests must only reach providers running a release that
    // supports the messages-v1 envelope (fail-closed at the advisor).
    minProviderVersion: minVersionForInput(payload.inputFormat),
    maxTokensOut: parsed.maxTokens,
    priceCeiling: DEFAULT_PRICE_CEILING,
    // Same mechanism as the friends path, but the set is the proof-backed
    // verified-provider list rather than the caller's friends.
    allowedProviderDids,
    country: parsed.country,
    ...(parsed.outputSchema ? { outputSchema: parsed.outputSchema } : {}),
    ...(parsed.tools ? { tools: parsed.tools } : {}),
    ...(parsed.toolChoice ? { toolChoice: parsed.toolChoice } : {}),
    ...(parsed.toolChoiceFunction ? { toolChoiceFunction: parsed.toolChoiceFunction } : {}),
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
    // Image requests must only reach providers running a release that
    // supports the messages-v1 envelope (fail-closed at the advisor).
    minProviderVersion: minVersionForInput(payload.inputFormat),
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
