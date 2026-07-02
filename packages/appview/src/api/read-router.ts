// Read API as an @effect/platform HttpRouter (the transport-swap target).
//
// Each route is an Effect returning an HttpServerResponse: `ok(data)` for
// 200, `err(status, { error })` for failures, `searchParams` for the query
// string. Handlers close over the indexed `Store` and the bsky `hydrateDids`
// (dependency injection by closure — no Context tags needed). Every route
// carries an `appview.<name>` span; the serve-model's tracing layer exports
// them to Honeycomb when OTLP is configured.
//
// This mirrors the legacy read handlers in server.ts verbatim in behavior;
// once all route groups are on HttpRouter, server.ts switches to mounting
// this and the legacy `routes` object is removed.

import { HttpRouter } from "@effect/platform";
import { Effect } from "effect";

import { MdaError, verifyChain } from "@cocore/sdk/mda";
import { verifyAppAttestB64, APP_ATTEST_APP_ID } from "@cocore/sdk/appattest";
import { freshnessBindsKey } from "@cocore/sdk/verify-provider";
import { verifyReceiptSignature } from "@cocore/sdk/p256";
import { ids, lexicons } from "@cocore/sdk/lex";
import type {
  AttestationRecord,
  JobRecord,
  PaymentAuthorizationRecord,
  ReceiptRecord,
  SettlementRecord,
} from "@cocore/sdk/types";
import { verifyReceipt, verifySettlementChain } from "@cocore/sdk/validate";

import { hydrateDids } from "../bsky-hydrate.ts";
import type { Store } from "../store.ts";
import { clampInt, parseIntOr } from "./query.ts";
import { err, ok, searchParams } from "./http-app.ts";

// modelActivity JSON-walks the 5000 most-recent receipt bodies on every hit and
// is unauthenticated — a cheap way to force a full scan in a loop. Memoize the
// result for a short TTL so a hot page (or an attacker) can't drive repeated
// full scans. Override with COCORE_MODEL_ACTIVITY_TTL_MS.
const MODEL_ACTIVITY_TTL_MS = Number(process.env["COCORE_MODEL_ACTIVITY_TTL_MS"] ?? 30_000);
let modelActivityCache: { at: number; body: unknown } | null = null;

// Lexicon `bytes` fields ship as base64 strings on the wire; decode them for
// the schema-validation pass in verifyReceipt (the cryptographic verify runs
// on the original string-bearing JSON so canonical bytes match what was signed).
const BYTES_FIELDS = new Set(["enclaveSignature", "selfSignature"]);
function decodeBytesFields(body: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...body };
  for (const k of BYTES_FIELDS) {
    const v = out[k];
    if (typeof v === "string") out[k] = Uint8Array.from(Buffer.from(v, "base64"));
  }
  if (Array.isArray(out["mdaCertChain"])) {
    out["mdaCertChain"] = (out["mdaCertChain"] as unknown[]).map((b) =>
      typeof b === "string" ? Uint8Array.from(Buffer.from(b, "base64")) : b,
    );
  }
  return out;
}

export function buildReadRouter(store: Store): HttpRouter.HttpRouter<never, never> {
  return HttpRouter.empty.pipe(
    HttpRouter.get(
      "/xrpc/dev.cocore.compute.listProviders",
      Effect.sync(() =>
        ok({ providers: store.listByCollection("dev.cocore.compute.provider", 100) }),
      ).pipe(Effect.withSpan("appview.listProviders")),
    ),
    HttpRouter.get(
      "/xrpc/dev.cocore.account.listProfiles",
      Effect.sync(() =>
        ok({ profiles: store.listByCollection("dev.cocore.account.profile", 500) }),
      ).pipe(Effect.withSpan("appview.listProfiles")),
    ),
    HttpRouter.get(
      "/xrpc/dev.cocore.account.getProfile",
      Effect.gen(function* () {
        const sp = yield* searchParams;
        const did = sp.get("did") ?? "";
        if (!did.startsWith("did:")) return err(400, { error: "did query param required" });
        const profile = store.getProfile(did);
        if (!profile) return err(404, { error: "no cocore footprint for this DID" });
        if (!profile.handle || !profile.displayName || !profile.avatarUrl) {
          const hydrated = yield* Effect.promise(() => hydrateDids([did]));
          const h = hydrated.get(did);
          if (h) {
            if (!profile.handle) profile.handle = h.handle;
            if (!profile.displayName) profile.displayName = h.displayName;
            if (!profile.avatarUrl) profile.avatarUrl = h.avatarUrl;
          }
        }
        return ok({ profile });
      }).pipe(Effect.withSpan("appview.getProfile")),
    ),
    HttpRouter.get(
      "/xrpc/dev.cocore.account.listIncomingFriends",
      Effect.gen(function* () {
        const sp = yield* searchParams;
        const did = sp.get("did") ?? "";
        if (!did.startsWith("did:")) return err(400, { error: "did query param required" });
        const limit = clampInt(sp.get("limit"), 50, 1, 200);
        const friends = store.listIncomingFriends(did, limit);
        const needsHydration = friends
          .filter((f) => f.frienderHandle === null)
          .map((f) => f.friender);
        if (needsHydration.length > 0) {
          const hydrated = yield* Effect.promise(() => hydrateDids(needsHydration));
          for (const f of friends) {
            const h = hydrated.get(f.friender);
            if (h && !f.frienderHandle) f.frienderHandle = h.handle;
          }
        }
        return ok({ friends, total: friends.length });
      }).pipe(Effect.withSpan("appview.listIncomingFriends")),
    ),
    HttpRouter.get(
      "/xrpc/dev.cocore.account.listFriendEdges",
      Effect.gen(function* () {
        const sp = yield* searchParams;
        // Hard cap lowered 20000 -> 1000: an unauthenticated caller could pull
        // 20k edge rows and serialize them per request as a memory-amplification
        // lever. 1000 is ample for the friends UI; larger reads should paginate.
        const limit = clampInt(sp.get("limit"), 1000, 1, 1000);
        const edges = store.listFriendEdges(limit);
        return ok({ edges, total: edges.length });
      }).pipe(Effect.withSpan("appview.listFriendEdges")),
    ),
    HttpRouter.get(
      "/xrpc/dev.cocore.account.listAccounts",
      Effect.gen(function* () {
        const sp = yield* searchParams;
        const limit = clampInt(sp.get("limit"), 24, 1, 100);
        const offset = Math.max(0, parseIntOr(sp.get("offset"), 0));
        const sortBy: "recent" | "newest" = sp.get("sortBy") === "newest" ? "newest" : "recent";
        const providersOnly = sp.get("providersOnly") === "true";
        const viewerDid = sp.get("viewerDid") ?? undefined;
        const excludeViewerFriends = sp.get("excludeViewerFriends") === "true";
        const q = sp.get("q")?.trim() ?? undefined;
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
          const hydrated = yield* Effect.promise(() => hydrateDids(needsHydration));
          for (const a of accounts) {
            const h = hydrated.get(a.did);
            if (!h) continue;
            if (!a.handle) a.handle = h.handle;
            if (!a.displayName) a.displayName = h.displayName;
            if (!a.avatarUrl) a.avatarUrl = h.avatarUrl;
          }
        }
        return ok({
          accounts,
          total,
          limit,
          offset,
          sortBy,
          providersOnly,
          excludeViewerFriends,
          ...(q ? { q } : {}),
        });
      }).pipe(Effect.withSpan("appview.listAccounts")),
    ),
    HttpRouter.get(
      "/xrpc/dev.cocore.compute.listReceipts",
      Effect.gen(function* () {
        const sp = yield* searchParams;
        const provider = sp.get("provider");
        const requester = sp.get("requester");
        const job = sp.get("job");
        const items = store.listByCollection("dev.cocore.compute.receipt", 200).filter((r) => {
          if (provider && r.repo !== provider) return false;
          const body = r.body as { requester?: string; job?: { uri?: string } };
          if (requester && body.requester !== requester) return false;
          if (job && body.job?.uri !== job) return false;
          return true;
        });
        return ok({ receipts: items });
      }).pipe(Effect.withSpan("appview.listReceipts")),
    ),
    HttpRouter.get(
      "/xrpc/dev.cocore.compute.listJobs",
      Effect.gen(function* () {
        const sp = yield* searchParams;
        const requester = sp.get("requester");
        const items = store.listByCollection("dev.cocore.compute.job", 500).filter((r) => {
          if (!requester) return false;
          return r.repo === requester;
        });
        return ok({ jobs: items });
      }).pipe(Effect.withSpan("appview.listJobs")),
    ),
    HttpRouter.get(
      "/xrpc/dev.cocore.compute.listSettlements",
      Effect.gen(function* () {
        const sp = yield* searchParams;
        const receipt = sp.get("receipt");
        const requester = sp.get("requester");
        const items = store.listByCollection("dev.cocore.compute.settlement", 200).filter((r) => {
          const body = r.body as {
            receipt?: { uri?: string };
            requesterAuthorization?: { uri?: string };
          };
          if (receipt && body.receipt?.uri !== receipt) return false;
          if (requester) {
            const authUri = body.requesterAuthorization?.uri ?? "";
            if (!authUri.startsWith(`at://${requester}/`)) return false;
          }
          return true;
        });
        return ok({ settlements: items });
      }).pipe(Effect.withSpan("appview.listSettlements")),
    ),
    HttpRouter.get(
      "/xrpc/dev.cocore.compute.latency",
      Effect.suspend(() => ok(store.latencyOverview())).pipe(Effect.withSpan("appview.latency")),
    ),
    HttpRouter.get(
      "/xrpc/dev.cocore.compute.modelActivity",
      Effect.sync(() => {
        // Serve a memoized result within the TTL to bound repeated full scans.
        const cached = modelActivityCache;
        if (cached && Date.now() - cached.at < MODEL_ACTIVITY_TTL_MS) {
          return ok(cached.body);
        }
        // Aggregate receipt activity per model + per time window (1h/24h/7d/
        // 30d), with per-provider counts, over the 5000 most-recent receipts.
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
        const body = { generatedAt: new Date().toISOString(), models };
        modelActivityCache = { at: Date.now(), body };
        return ok(body);
      }).pipe(Effect.withSpan("appview.modelActivity")),
    ),
    HttpRouter.get(
      "/xrpc/dev.cocore.compute.verifyReceipt",
      Effect.gen(function* () {
        const sp = yield* searchParams;
        const uri = sp.get("uri");
        if (!uri) return err(400, { error: "missing query param: uri" });
        const receiptRow = store.get(uri);
        if (!receiptRow) return err(404, { error: "receipt not indexed" });
        const receipt = receiptRow.body as ReceiptRecord;
        const jobRow = store.get(receipt.job.uri);
        const attRow = store.get(receipt.attestation.uri);
        if (!jobRow || !attRow) return err(404, { error: "job or attestation not indexed" });
        const att = attRow.body as AttestationRecord;
        const structural = verifyReceipt(receipt, jobRow.body as JobRecord, att);
        const sigOk = yield* Effect.promise(() =>
          verifyReceiptSignature(
            receipt as unknown as Record<string, unknown> & { enclaveSignature: string },
            att.publicKey,
          ),
        );
        const findings = [...structural.findings];
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
        let trustLevel: "self-attested" | "hardware-attested" = "self-attested";

        // Hardware attestation via App Attest (the MDM-free path): present AND
        // bound to attestation.publicKey by construction (clientDataHash =
        // sha256(publicKey), checked through the credCert nonce extension).
        const aa = att.appAttest;
        let appAttestBound = false;
        if (aa && aa.object && aa.keyId) {
          appAttestBound = verifyAppAttestB64(
            aa.object,
            aa.keyId,
            att.publicKey,
            APP_ATTEST_APP_ID,
          );
          if (!appAttestBound) {
            findings.push({
              severity: "error",
              code: "appattest-not-bound",
              message: "App Attest object did not verify or is not bound to attestation.publicKey",
            });
          }
        }

        if (appAttestBound) {
          trustLevel = "hardware-attested";
        } else if (att.mdaCertChain && att.mdaCertChain.length > 0) {
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
            } else {
              // Bind by EITHER the leaf key being the signing key (option A) OR
              // the freshness-code commitment sha256(publicKey) (option B) —
              // matching the SDK verifier (verify-provider.ts) and mda.rs.
              // Previously only option A was checked, so an option-B (freshness)
              // chain was wrongly reported self-attested here.
              const leafBinds = mda.leafPublicKey === att.publicKey;
              const freshBinds = yield* Effect.promise(() =>
                freshnessBindsKey(mda.freshnessCode, att.publicKey),
              );
              if (!leafBinds && !freshBinds) {
                findings.push({
                  severity: "error",
                  code: "mda-not-bound",
                  message:
                    "MDA chain is not bound to attestation.publicKey " +
                    "(neither leaf-key nor freshness-code binding holds)",
                });
              } else {
                trustLevel = "hardware-attested";
              }
            }
          } catch (e) {
            const code = e instanceof MdaError ? `mda-${e.code}` : "mda-error";
            findings.push({ severity: "error", code, message: (e as Error).message });
          }
        }
        return ok({
          ok:
            structural.ok &&
            sigOk &&
            !findings.some((f) => f.code.startsWith("mda-")) &&
            !findings.some((f) => f.code.startsWith("appattest-")) &&
            !findings.some((f) => f.code === "lexicon-invalid"),
          trustLevel,
          findings,
        });
      }).pipe(Effect.withSpan("appview.verifyReceipt")),
    ),
    HttpRouter.get(
      "/xrpc/dev.cocore.compute.verifySettlement",
      Effect.gen(function* () {
        const sp = yield* searchParams;
        const uri = sp.get("uri");
        if (!uri) return err(400, { error: "missing query param: uri" });
        const stRow = store.get(uri);
        if (!stRow) return err(404, { error: "settlement not indexed" });
        const st = stRow.body as SettlementRecord;
        const receiptRow = store.get(st.receipt.uri);
        const authRow = store.get(st.requesterAuthorization.uri);
        if (!receiptRow || !authRow) {
          return err(404, { error: "receipt or authorization not indexed" });
        }
        return ok(
          verifySettlementChain(
            st,
            receiptRow.body as ReceiptRecord,
            authRow.body as PaymentAuthorizationRecord,
            stRow.repo,
          ),
        );
      }).pipe(Effect.withSpan("appview.verifySettlement")),
    ),
  );
}
