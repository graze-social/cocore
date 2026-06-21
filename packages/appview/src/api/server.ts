// HTTP read API over indexed cocore records.
//
// We keep the HTTP read API intentionally small and deliberately
// avoid the full xrpc-server framework so the AppView starts without
// pulling in the entire @atproto stack. M3 wires the same handlers
// behind an XRPC server using @atproto/xrpc-server with a generated
// lexicon manifest.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { hydrateDids } from "../bsky-hydrate.ts";
import { Store } from "../store.ts";
import { verifyReceipt, verifySettlementChain } from "@cocore/sdk/validate";
import { verifyReceiptSignature } from "@cocore/sdk/p256";
import { MdaError, verifyChain } from "@cocore/sdk/mda";
import { timingSafeEqual } from "node:crypto";
import { ids, lexicons } from "@cocore/sdk/lex";
import { accountRoutes } from "./account-routes.ts";
import { AccountStore } from "../operational/account-store.ts";
import {
  type AppviewOAuthClient,
  isOAuthConfigured,
  makeAppviewOAuth,
} from "../auth/oauth-client.ts";
import { internalPdsRoutes, pdsRoutes } from "../pds/write.ts";
import { PairStore } from "../devicepair/pair-store.ts";
import { devicePairRoutes } from "../devicepair/routes.ts";
import { inferenceRoutes } from "../inference/routes.ts";
import type {
  AttestationRecord,
  JobRecord,
  ReceiptRecord,
  PaymentAuthorizationRecord,
  SettlementRecord,
} from "@cocore/sdk/types";

interface Routes {
  [path: string]: (req: IncomingMessage, res: ServerResponse, url: URL) => void | Promise<void>;
}

export interface BuildServerOptions {
  /** Operational store for API keys + OAuth sessions. When provided
   *  together with `appviewDid`, the dev.cocore.account.* methods are
   *  registered. */
  accountStore?: AccountStore;
  /** This AppView's service DID — the `aud` that account.* service-auth
   *  JWTs must target. Required to enable the account methods. */
  appviewDid?: string;
  /** Bridge base URL for the best-effort cache mirror on PDS writes. */
  bridgeUrl?: string;
  /** Shared secret the console presents to hand off a freshly minted
   *  OAuth session (`POST /internal/oauth-session`). When unset, the
   *  handoff endpoint is not registered. */
  internalSecret?: string;
  /** HTTP base for the matchmaking advisor (`/providers`, `/jobs`).
   *  Required to enable `dev.cocore.inference.dispatch`. */
  advisorUrl?: string;
  /** Exchange DID stamped onto dispatch's paymentAuthorization + job. */
  exchangeDid?: string;
}

/** Constant-time string compare that tolerates length differences. */
function secretEquals(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/** Build the AppView request handler. Returns a function that handles one
 *  request and resolves `true` when a route (or `/healthz`) matched and a
 *  response was sent, or `false` when no route matched so the caller can
 *  decide the 404. Sharing one handler instance (one OAuth client over one
 *  session store) is required — two would dual-refresh the same session.
 *  Used both standalone (see {@link buildServer}) and merged onto the
 *  bridge's public port. */
export function buildAppviewHandler(store: Store, opts: BuildServerOptions = {}) {
  const routes: Routes = {
    "/xrpc/dev.cocore.compute.listProviders": (_req, res) => {
      const items = store.listByCollection("dev.cocore.compute.provider", 100);
      json(res, 200, { providers: items });
    },
    "/xrpc/dev.cocore.account.listProfiles": (_req, res) => {
      // Returns every `dev.cocore.account.profile` record we've
      // indexed. Used by the models page to render display-name +
      // avatar chips for the DIDs hosting machines.
      const items = store.listByCollection("dev.cocore.account.profile", 500);
      json(res, 200, { profiles: items });
    },
    "/xrpc/dev.cocore.account.getProfile": async (_req, res, url) => {
      // Full profile-page payload for one DID — account fields,
      // machines they own, activity counts, incoming-friends count.
      // The console's /u/$identifier route consumes this in one
      // round-trip.
      //
      // Hydration: when the DID hasn't published a
      // `dev.cocore.account.profile` record locally (the common
      // case for users who OAuth'd in before the auto-provision
      // path was fully wired), fall back to the public bsky
      // appview's `getProfile` so the page shows a handle +
      // display name instead of a raw DID.
      const did = url.searchParams.get("did") ?? "";
      if (!did.startsWith("did:")) {
        json(res, 400, { error: "did query param required" });
        return;
      }
      const profile = store.getProfile(did);
      if (!profile) {
        json(res, 404, { error: "no cocore footprint for this DID" });
        return;
      }
      if (!profile.handle || !profile.displayName || !profile.avatarUrl) {
        const hydrated = await hydrateDids([did]);
        const h = hydrated.get(did);
        if (h) {
          if (!profile.handle) profile.handle = h.handle;
          if (!profile.displayName) profile.displayName = h.displayName;
          if (!profile.avatarUrl) profile.avatarUrl = h.avatarUrl;
        }
      }
      json(res, 200, { profile });
    },
    "/xrpc/dev.cocore.account.listIncomingFriends": async (_req, res, url) => {
      // "Who has trusted me with work?" — every friend record whose
      // body.subject equals the queried DID. Newest first; capped.
      // Hydrates frienders via the public bsky appview so the UI
      // shows a handle instead of a raw DID even when we don't
      // have a local profile record for them.
      const did = url.searchParams.get("did") ?? "";
      if (!did.startsWith("did:")) {
        json(res, 400, { error: "did query param required" });
        return;
      }
      const limit = clampInt(url.searchParams.get("limit"), 50, 1, 200);
      const friends = store.listIncomingFriends(did, limit);
      const needsHydration = friends
        .filter((f) => f.frienderHandle === null)
        .map((f) => f.friender);
      if (needsHydration.length > 0) {
        const hydrated = await hydrateDids(needsHydration);
        for (const f of friends) {
          const h = hydrated.get(f.friender);
          if (h && !f.frienderHandle) f.frienderHandle = h.handle;
        }
      }
      json(res, 200, { friends, total: friends.length });
    },
    "/xrpc/dev.cocore.account.listFriendEdges": (_req, res, url) => {
      // Every directed trust edge in the network (friender → subject),
      // for the explorer's friend graph. No hydration here — the
      // console joins handles/avatars from listAccounts; this endpoint
      // stays a cheap, pure edge list.
      const limit = clampInt(url.searchParams.get("limit"), 5000, 1, 20000);
      const edges = store.listFriendEdges(limit);
      json(res, 200, { edges, total: edges.length });
    },
    "/xrpc/dev.cocore.account.listAccounts": async (_req, res, url) => {
      // Discovery directory used by the /friends page. Returns every
      // signed-up DID (any DID with a record under `dev.cocore.*`),
      // joined with profile + provider counts so the UI can render
      // a card grid without further fan-out.
      //
      // Query params:
      //   * limit (1..100, default 24)
      //   * offset (default 0)
      //   * sortBy=recent|newest (default recent — last activity desc)
      //   * providersOnly=true|false (default false)
      //   * viewerDid — excludes the caller's own DID from results so
      //     "discover" doesn't surface "friend yourself."
      //   * excludeViewerFriends=true — with viewerDid, also omits DIDs
      //     the viewer has already published a friend record for.
      //   * q — optional substring (case-insensitive) on profile handle and/or
      //     DID for directory search / typeahead. Leading @ is ignored.
      //
      // For DIDs that haven't published a profile record locally,
      // we fan out to the public bsky appview's `getProfile` to fill
      // in handle/displayName/avatar. Results are cached server-
      // side for 1h, so warm-cache page loads do zero bsky calls.
      const limit = clampInt(url.searchParams.get("limit"), 24, 1, 100);
      const offset = Math.max(0, parseIntOr(url.searchParams.get("offset"), 0));
      const sortParam = url.searchParams.get("sortBy");
      const sortBy: "recent" | "newest" = sortParam === "newest" ? "newest" : "recent";
      const providersOnly = url.searchParams.get("providersOnly") === "true";
      const viewerDid = url.searchParams.get("viewerDid") ?? undefined;
      const excludeViewerFriends = url.searchParams.get("excludeViewerFriends") === "true";
      const q = url.searchParams.get("q")?.trim() ?? undefined;

      const { accounts, total } = store.listAccounts({
        limit,
        offset,
        sortBy,
        providersOnly,
        viewerDid,
        excludeViewerFriends,
        query: q && q.length > 0 ? q : undefined,
      });

      const needsHydration = accounts
        .filter((a) => !a.handle || !a.displayName || !a.avatarUrl)
        .map((a) => a.did);
      if (needsHydration.length > 0) {
        const hydrated = await hydrateDids(needsHydration);
        for (const a of accounts) {
          const h = hydrated.get(a.did);
          if (!h) continue;
          if (!a.handle) a.handle = h.handle;
          if (!a.displayName) a.displayName = h.displayName;
          if (!a.avatarUrl) a.avatarUrl = h.avatarUrl;
        }
      }

      json(res, 200, {
        accounts,
        total,
        limit,
        offset,
        sortBy,
        providersOnly,
        excludeViewerFriends,
        ...(q ? { q } : {}),
      });
    },
    "/xrpc/dev.cocore.compute.modelActivity": (_req, res) => {
      // Aggregate receipt activity per model + per time window.
      // Walks indexed receipts (capped at 5000 most-recent), groups
      // by `body.model`, and tallies requests + tokens within four
      // windows: 1h, 24h, 7d, 30d. Per-provider counts are returned
      // so the models page can show "this machine served N requests"
      // in each window alongside the per-model totals.
      const now = Date.now();
      const windows = {
        hour: now - 60 * 60_000,
        day: now - 24 * 60 * 60_000,
        week: now - 7 * 24 * 60 * 60_000,
        month: now - 30 * 24 * 60 * 60_000,
      } as const;
      type Window = keyof typeof windows;
      const emptyStats = (): Record<Window, { requests: number; tokens: number }> => ({
        hour: { requests: 0, tokens: 0 },
        day: { requests: 0, tokens: 0 },
        week: { requests: 0, tokens: 0 },
        month: { requests: 0, tokens: 0 },
      });
      const byModel = new Map<string, ReturnType<typeof emptyStats>>();
      const byModelProvider = new Map<string, Map<string, ReturnType<typeof emptyStats>>>();
      const rows = store.listByCollection("dev.cocore.compute.receipt", 5000);
      for (const row of rows) {
        const body = row.body as {
          model?: string;
          tokens?: { in?: number; out?: number };
          completedAt?: string;
        };
        const model = body.model;
        if (typeof model !== "string" || model.length === 0) continue;
        const completedAtMs = body.completedAt ? Date.parse(body.completedAt) : Number.NaN;
        const tsMs = Number.isFinite(completedAtMs)
          ? completedAtMs
          : Date.parse(row.indexedAt ?? "");
        if (!Number.isFinite(tsMs)) continue;
        const tokens = (body.tokens?.in ?? 0) + (body.tokens?.out ?? 0);

        let modelStats = byModel.get(model);
        if (!modelStats) {
          modelStats = emptyStats();
          byModel.set(model, modelStats);
        }
        let providerMap = byModelProvider.get(model);
        if (!providerMap) {
          providerMap = new Map();
          byModelProvider.set(model, providerMap);
        }
        let providerStats = providerMap.get(row.repo);
        if (!providerStats) {
          providerStats = emptyStats();
          providerMap.set(row.repo, providerStats);
        }

        for (const w of ["hour", "day", "week", "month"] as Window[]) {
          if (tsMs >= windows[w]) {
            modelStats[w].requests += 1;
            modelStats[w].tokens += tokens;
            providerStats[w].requests += 1;
            providerStats[w].tokens += tokens;
          }
        }
      }

      const models = Array.from(byModel.entries()).map(([modelId, stats]) => ({
        modelId,
        totals: stats,
        byProvider: Array.from(byModelProvider.get(modelId)?.entries() ?? []).map(([did, s]) => ({
          did,
          stats: s,
        })),
      }));
      json(res, 200, { generatedAt: new Date().toISOString(), models });
    },
    "/xrpc/dev.cocore.compute.latency": (_req, res) => {
      // Network latency rollup, derived purely from indexed receipts'
      // signed `startedAt`/`completedAt` pairs — the last ≤100 per
      // group (overall, per-provider, per-model). No side metrics
      // store: the receipts are the source of truth, so the numbers
      // can't drift from them.
      json(res, 200, store.latencyOverview());
    },
    "/xrpc/dev.cocore.compute.listReceipts": (_req, res, url) => {
      const provider = url.searchParams.get("provider");
      const requester = url.searchParams.get("requester");
      const job = url.searchParams.get("job");
      const items = store.listByCollection("dev.cocore.compute.receipt", 200).filter((r) => {
        if (provider && r.repo !== provider) return false;
        const body = r.body as { requester?: string; job?: { uri?: string } };
        if (requester && body.requester !== requester) return false;
        if (job && body.job?.uri !== job) return false;
        return true;
      });
      json(res, 200, { receipts: items });
    },
    "/xrpc/dev.cocore.compute.listJobs": (_req, res, url) => {
      const requester = url.searchParams.get("requester");
      const items = store.listByCollection("dev.cocore.compute.job", 500).filter((r) => {
        if (!requester) return false;
        return r.repo === requester;
      });
      json(res, 200, { jobs: items });
    },
    "/xrpc/dev.cocore.compute.listSettlements": (_req, res, url) => {
      const receipt = url.searchParams.get("receipt");
      const requester = url.searchParams.get("requester");
      const items = store.listByCollection("dev.cocore.compute.settlement", 200).filter((r) => {
        const body = r.body as {
          receipt?: { uri?: string };
          requesterAuthorization?: { uri?: string };
        };
        if (receipt && body.receipt?.uri !== receipt) return false;
        if (requester) {
          // Authorization URIs are at://<requester>/...; cheap prefix match.
          const authUri = body.requesterAuthorization?.uri ?? "";
          if (!authUri.startsWith(`at://${requester}/`)) return false;
        }
        return true;
      });
      json(res, 200, { settlements: items });
    },
    "/xrpc/dev.cocore.compute.verifyReceipt": async (_req, res, url) => {
      const uri = url.searchParams.get("uri");
      if (!uri) {
        json(res, 400, { error: "missing query param: uri" });
        return;
      }
      const receiptRow = store.get(uri);
      if (!receiptRow) {
        json(res, 404, { error: "receipt not indexed" });
        return;
      }
      const receipt = receiptRow.body as ReceiptRecord;
      const jobRow = store.get(receipt.job.uri);
      const attRow = store.get(receipt.attestation.uri);
      if (!jobRow || !attRow) {
        json(res, 404, { error: "job or attestation not indexed" });
        return;
      }
      const att = attRow.body as AttestationRecord;
      const structural = verifyReceipt(receipt, jobRow.body as JobRecord, att);
      // Cryptographic check: P-256 ECDSA-DER signature in
      // receipt.enclaveSignature against attestation.publicKey, over
      // the canonical bytes of the receipt body. This is what makes
      // the federation invariant cryptographically (not just
      // structurally) sound.
      const sigOk = await verifyReceiptSignature(
        receipt as unknown as Record<string, unknown> & { enclaveSignature: string },
        att.publicKey,
      );
      const findings = [...structural.findings];

      // Lexicon schema validation: catch record bodies that are
      // structurally well-formed (have an enclaveSignature, etc.)
      // but violate the lexicon's type rules (e.g. wrong field
      // type, missing required field, oversize string). The
      // generated lexicons live in packages/sdk/src/lex/ — gitignored
      // per CLAUDE.md — lex codegen output lands in packages/sdk/src/lex/ (gitignored).
      //
      // The lexicon declares `bytes` fields (enclaveSignature,
      // attestation.selfSignature, mdaCertChain) as actual byte
      // arrays. On our HTTP wire we ship them as base64 strings, so
      // we decode just for the validation pass. The cryptographic
      // verify in verifyReceiptSignature operates on the original
      // string-bearing JSON so the canonical bytes match what was
      // signed.
      try {
        lexicons.assertValidRecord(ids.DevCocoreComputeReceipt, {
          $type: ids.DevCocoreComputeReceipt,
          ...decodeBytesFields(receipt as unknown as Record<string, unknown>),
        });
      } catch (e) {
        findings.push({
          severity: "error",
          code: "lexicon-invalid",
          message: `receipt fails lexicon validation: ${(e as Error).message}`,
        });
      }

      if (!sigOk) {
        findings.push({
          severity: "error",
          code: "signature-invalid",
          message: "enclaveSignature does not verify against attestation.publicKey",
        });
      }
      // Hardware attestation: when the attestation carries an MDA
      // cert chain, run it against Apple's embedded Enterprise
      // Attestation Root CA. This is what backs the
      // `trustLevel: hardware-attested` claim — without a passing
      // chain, the receipt at most rises to the self-attested
      // level the software identity already provides.
      let trustLevel: "self-attested" | "hardware-attested" = "self-attested";
      if (att.mdaCertChain && att.mdaCertChain.length > 0) {
        try {
          const chain = att.mdaCertChain.map((b64: string) =>
            Uint8Array.from(Buffer.from(b64, "base64")),
          );
          const mda = verifyChain(chain);
          if (!mda.valid) {
            findings.push({
              severity: "error",
              code: "mda-invalid",
              message: mda.error ?? "MDA chain validation failed",
            });
          } else if (mda.leafPublicKey !== att.publicKey) {
            // The chain is a valid Apple chain, but its leaf certifies a
            // DIFFERENT key than the one that signs this provider's
            // receipts — i.e. someone stapled an unrelated (possibly
            // harvested) device's attestation onto their own key. Refuse
            // the hardware claim: a chain only earns `hardware-attested`
            // when it's BOUND to the receipt-signing key.
            findings.push({
              severity: "error",
              code: "mda-not-bound",
              message:
                "MDA leaf does not certify attestation.publicKey " +
                "(chain not bound to the receipt-signing key)",
            });
          } else {
            trustLevel = "hardware-attested";
          }
        } catch (e) {
          const code = e instanceof MdaError ? `mda-${e.code}` : "mda-error";
          findings.push({
            severity: "error",
            code,
            message: (e as Error).message,
          });
        }
      }
      json(res, 200, {
        ok:
          structural.ok &&
          sigOk &&
          !findings.some((f) => f.code.startsWith("mda-")) &&
          !findings.some((f) => f.code === "lexicon-invalid"),
        trustLevel,
        findings,
      });
    },
    "/xrpc/dev.cocore.compute.verifySettlement": (_req, res, url) => {
      const uri = url.searchParams.get("uri");
      if (!uri) {
        json(res, 400, { error: "missing query param: uri" });
        return;
      }
      const stRow = store.get(uri);
      if (!stRow) {
        json(res, 404, { error: "settlement not indexed" });
        return;
      }
      const st = stRow.body as SettlementRecord;
      const receiptRow = store.get(st.receipt.uri);
      const authRow = store.get(st.requesterAuthorization.uri);
      if (!receiptRow || !authRow) {
        json(res, 404, { error: "receipt or authorization not indexed" });
        return;
      }
      const r = verifySettlementChain(
        st,
        receiptRow.body as ReceiptRecord,
        authRow.body as PaymentAuthorizationRecord,
        stRow.repo,
      );
      json(res, 200, r);
    },
  };

  // Operational write methods (API-key management). Registered only when
  // the AppView is configured with a service identity + account store —
  // additive, so a deploy without them serves exactly the read API it
  // did before.
  if (opts.accountStore && opts.appviewDid) {
    Object.assign(routes, accountRoutes(opts.accountStore, opts.appviewDid));
  }

  // Single shared OAuth client (when configured). One client over one
  // session store is required — two would dual-refresh the same session.
  // Both /pds and inference.dispatch draw from this one instance.
  let oauth: AppviewOAuthClient | null = null;
  if (opts.accountStore && isOAuthConfigured()) {
    try {
      oauth = makeAppviewOAuth(opts.accountStore);
    } catch (e) {
      // A misconfigured OAuth client (e.g. bad ATPROTO_PRIVATE_KEY_JWK)
      // must not take down the read API — leave it null and keep serving.
      console.error(`appview: OAuth client init failed: ${(e as Error).message}`);
    }
  }

  // PDS-write executor: /pds/{create,put,delete}Record. Registered only
  // when an account store exists (for bearer-key resolution) and the
  // OAuth client initialized so it can restore DPoP-bound sessions.
  // Additive: absent otherwise.
  if (opts.accountStore && oauth) {
    const pctx = { accounts: opts.accountStore, oauth, bridgeUrl: opts.bridgeUrl };
    const pds = pdsRoutes(pctx);
    Object.assign(routes, pds);
    // Alias at /api/pds/* so a paired agent whose apiBase is the AppView
    // (baked-in path `${apiBase}/api/pds/...`) reaches the same handlers.
    for (const [path, h] of Object.entries(pds)) routes[`/api${path}`] = h;
    // Back-compat for pre-cutover release agents: they still write via the
    // deprecated `/api/xrpc/dev.cocore.proxy.{create,put,delete}Record` path
    // (bearer-key, identical body to /pds/*). The console keeps these shims,
    // but post-cutover an agent's apiBase points HERE (the AppView), so serve
    // them as aliases of the same handlers — otherwise old agents that pair
    // after the cutover 404 on every write.
    const proxyAlias: Record<string, string> = {
      "/pds/createRecord": "/api/xrpc/dev.cocore.proxy.createRecord",
      "/pds/putRecord": "/api/xrpc/dev.cocore.proxy.putRecord",
      "/pds/deleteRecord": "/api/xrpc/dev.cocore.proxy.deleteRecord",
    };
    for (const [path, h] of Object.entries(pds)) {
      const alias = proxyAlias[path];
      if (alias) routes[alias] = h;
    }
    // Internal trusted-DID write path (the console forwards key-resolved
    // writes here so the OAuth session work lives only in the AppView).
    // Private-network only; gated on the shared secret.
    if (opts.internalSecret) Object.assign(routes, internalPdsRoutes(pctx, opts.internalSecret));
    console.error(
      `appview: /pds write endpoints enabled${opts.internalSecret ? " (+ /internal/pds)" : ""}`,
    );
  }

  // Inference dispatch: /xrpc/dev.cocore.inference.dispatch (SSE). Needs a
  // service identity (the service-auth `aud`), the shared OAuth client (to
  // publish the job under the requester's AppView-owned session), and the
  // advisor URL to route to a provider. Additive: absent otherwise.
  if (opts.accountStore && opts.appviewDid && oauth && opts.advisorUrl) {
    Object.assign(
      routes,
      inferenceRoutes({
        store,
        oauth,
        appviewDid: opts.appviewDid,
        advisorUrl: opts.advisorUrl,
        exchangeDid: opts.exchangeDid ?? "did:web:exchange.local",
        bridgeUrl: opts.bridgeUrl,
      }),
    );
    console.error("appview: inference.dispatch endpoint enabled");
  }

  // OAuth session handoff: the console pushes a freshly minted session
  // here after login so the AppView becomes its sole owner (single-writer
  // refresh). Gated on a shared secret + an account store to persist to.
  if (opts.accountStore && opts.internalSecret) {
    const accountStore = opts.accountStore;
    const secret = opts.internalSecret;
    routes["/internal/oauth-session"] = async (req, res) => {
      if (req.method !== "POST") {
        json(res, 405, { error: "MethodNotAllowed" });
        return;
      }
      const presented = req.headers["x-cocore-internal-secret"];
      if (typeof presented !== "string" || !secretEquals(presented, secret)) {
        json(res, 403, { error: "Forbidden" });
        return;
      }
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      let body: { did?: unknown; data?: unknown };
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as typeof body;
      } catch {
        json(res, 400, { error: "InvalidRequest", message: "body must be JSON" });
        return;
      }
      if (typeof body.did !== "string" || !body.did.startsWith("did:")) {
        json(res, 400, { error: "InvalidRequest", message: "did required" });
        return;
      }
      if (body.data === undefined || body.data === null) {
        json(res, 400, { error: "InvalidRequest", message: "data (StoredSession) required" });
        return;
      }
      // `data` is the StoredSession blob; accept it as an object or an
      // already-serialized string and store the canonical JSON string.
      const data = typeof body.data === "string" ? body.data : JSON.stringify(body.data);
      accountStore.putOAuthSession(body.did, data);
      console.error(`appview: stored OAuth session handoff for ${body.did}`);
      json(res, 200, { ok: true });
    };

    // Provisioning primitive: mint an API key for a DID. The console
    // (which authenticates the browser via its cookie session) calls this
    // with the user's DID to provision a key in the AppView's store. Gated
    // on the shared secret — the same console<->AppView trust boundary as
    // the session handoff.
    routes["/internal/account/mint-key"] = async (req, res) => {
      if (req.method !== "POST") {
        json(res, 405, { error: "MethodNotAllowed" });
        return;
      }
      const presented = req.headers["x-cocore-internal-secret"];
      if (typeof presented !== "string" || !secretEquals(presented, secret)) {
        json(res, 403, { error: "Forbidden" });
        return;
      }
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      let body: { did?: unknown; name?: unknown };
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as typeof body;
      } catch {
        json(res, 400, { error: "InvalidRequest", message: "body must be JSON" });
        return;
      }
      if (typeof body.did !== "string" || !body.did.startsWith("did:")) {
        json(res, 400, { error: "InvalidRequest", message: "did required" });
        return;
      }
      const name = typeof body.name === "string" && body.name.length > 0 ? body.name : "console";
      const out = accountStore.createKey({ did: body.did, name });
      json(res, 200, { key: out.key, secret: out.secret });
    };

    // Reset a DID's operational auth state: revoke every API key and drop
    // the stored OAuth session. The console calls this (browser-authed to
    // the DID) as the AppView half of "reset connection" — the repair flow
    // that clears a wedged session/key without deleting any PDS records.
    // Deliberately does NOT touch receipts or the firehose-indexed cache.
    routes["/internal/account/reset-did"] = async (req, res) => {
      if (req.method !== "POST") {
        json(res, 405, { error: "MethodNotAllowed" });
        return;
      }
      const presented = req.headers["x-cocore-internal-secret"];
      if (typeof presented !== "string" || !secretEquals(presented, secret)) {
        json(res, 403, { error: "Forbidden" });
        return;
      }
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      let body: { did?: unknown };
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as typeof body;
      } catch {
        json(res, 400, { error: "InvalidRequest", message: "body must be JSON" });
        return;
      }
      if (typeof body.did !== "string" || !body.did.startsWith("did:")) {
        json(res, 400, { error: "InvalidRequest", message: "did required" });
        return;
      }
      const keysRevoked = accountStore.revokeAllKeysForDid(body.did);
      accountStore.deleteOAuthSession(body.did);
      console.error(`appview: reset auth state for ${body.did} (${keysRevoked} keys revoked)`);
      json(res, 200, { ok: true, keysRevoked });
    };
  }

  // Device pairing: in-memory pair-store + start/poll (public, agent-facing)
  // and confirm (internal — the console authenticates the browser, mints the
  // scoped API key, and forwards the approval). Gated on the shared secret.
  if (opts.accountStore && opts.appviewDid) {
    const verificationBase = (
      process.env["CONSOLE_PUBLIC_URL"] ||
      process.env["ATPROTO_BASE_URL"] ||
      process.env["BETTER_AUTH_URL"] ||
      "http://localhost:3000"
    ).replace(/\/$/, "");
    // The agent posts records to the AppView's own public origin (derived
    // from its did:web), which serves the /api/pds alias above.
    const apiBase = opts.appviewDid.startsWith("did:web:")
      ? `https://${opts.appviewDid.slice("did:web:".length)}`
      : verificationBase;
    Object.assign(
      routes,
      devicePairRoutes(new PairStore(verificationBase), {
        accountStore: opts.accountStore,
        appviewDid: opts.appviewDid,
        apiBase,
      }),
    );
    console.error("appview: device-pair endpoints enabled");
  }

  // did:web DID document, so a requester's PDS can resolve this AppView's
  // `#cocore_appview` service endpoint and proxy service-auth calls here.
  const didDoc = opts.appviewDid?.startsWith("did:web:")
    ? {
        "@context": ["https://www.w3.org/ns/did/v1"],
        id: opts.appviewDid,
        service: [
          {
            id: "#cocore_appview",
            type: "CocoreAppView",
            serviceEndpoint: `https://${opts.appviewDid.slice("did:web:".length)}`,
          },
        ],
      }
    : null;

  return async (req: IncomingMessage, res: ServerResponse, url: URL): Promise<boolean> => {
    if (didDoc && url.pathname === "/.well-known/did.json") {
      json(res, 200, didDoc);
      return true;
    }
    // Liveness probe. Mirrors the bridge's /healthz so a deploy healthcheck
    // works whichever port it targets — and probing this one confirms the
    // read API itself (the part that went down) is serving.
    if (url.pathname === "/healthz") {
      json(res, 200, { ok: true });
      return true;
    }
    const handler = routes[url.pathname];
    if (!handler) return false;
    await handler(req, res, url);
    return true;
  };
}

/** Standalone AppView HTTP server on its own port. For the merged
 *  single-port deployment, callers use {@link buildAppviewHandler} and
 *  delegate to it from the bridge instead. */
export function buildServer(store: Store, opts: BuildServerOptions = {}) {
  const handle = buildAppviewHandler(store, opts);
  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
      if (!(await handle(req, res, url))) {
        json(res, 404, { error: "no such route" });
      }
    } catch (e) {
      json(res, 500, { error: (e as Error).message });
    }
  });
}

/** Decode the base64-string-on-the-wire form of every lexicon
 *  `bytes` field in a record body back to Uint8Array, so the
 *  lexicon validator (which checks types strictly) is happy. The
 *  cryptographic verify deliberately runs on the *string* form so
 *  the canonical bytes match what was signed. */
const BYTES_FIELDS = new Set(["enclaveSignature", "selfSignature"]);
function decodeBytesFields(body: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...body };
  for (const k of BYTES_FIELDS) {
    const v = out[k];
    if (typeof v === "string") {
      out[k] = Uint8Array.from(Buffer.from(v, "base64"));
    }
  }
  if (Array.isArray(out["mdaCertChain"])) {
    out["mdaCertChain"] = (out["mdaCertChain"] as unknown[]).map((b) =>
      typeof b === "string" ? Uint8Array.from(Buffer.from(b, "base64")) : b,
    );
  }
  return out;
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

/** Parse a positive integer from a query-param string with a default
 *  fallback. Returns the default on null / undefined / non-numeric
 *  input so the route handler can stay branchless. */
function parseIntOr(raw: string | null, dflt: number): number {
  if (raw === null) return dflt;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) ? n : dflt;
}

/** Same as parseIntOr but clamps into a [min, max] range. */
function clampInt(raw: string | null, dflt: number, min: number, max: number): number {
  const v = parseIntOr(raw, dflt);
  return Math.min(Math.max(v, min), max);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env["COCORE_API_PORT"] ?? 8080);
  const dbPath = process.env["COCORE_DB"] ?? "./appview.db";
  const store = new Store(dbPath);
  // Enable dev.cocore.account.* only when a service DID is configured.
  const appviewDid = process.env["COCORE_APPVIEW_DID"];
  const accountStore = appviewDid
    ? new AccountStore(process.env["COCORE_ACCOUNT_DB"] ?? "./appview-account.db")
    : undefined;
  buildServer(store, {
    accountStore,
    appviewDid,
    bridgeUrl: process.env["COCORE_BRIDGE_URL"],
    internalSecret: process.env["COCORE_INTERNAL_SECRET"],
  }).listen(port, () => {
    console.error(
      `appview api: listening on :${port} db=${dbPath}` +
        (appviewDid ? ` account=on(aud=${appviewDid})` : ""),
    );
  });
}
