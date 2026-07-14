// GET /api/agent/status
//
// Bearer-key authed provider status for the menu-bar app. Returns the
// real trust level + agent version (from the published provider record)
// and the credit balance + 24h earnings (from the services-bridge
// ledger). Same API-key auth as /api/agent/whoami; read-only.
//
// Credits, not dollars: cocore is a closed-loop token economy. Provider
// income lands as `receipt-in` ledger events (see
// packages/exchange/src/token-balance.ts).

import type { Did } from "@atcute/lexicons";
import { createFileRoute } from "@tanstack/react-router";

import { runTraced } from "@/lib/o11y.server.ts";

import { appviewListProvidersEffect } from "@/integrations/appview/appview.server.ts";
import { sessionNeedsReauth } from "@/integrations/auth/atproto.server.ts";
import { resolveBearerKey } from "@/lib/api-keys.server.ts";
import { appviewSessionInfo } from "@/lib/appview-backed-session.server.ts";
import { isAppviewForwardConfigured } from "@/lib/appview-pds-forward.server.ts";
import { cocoreConfig } from "@/lib/cocore-config.ts";
import { sumReceiptInSince } from "@/lib/earnings.ts";
import { getBalance, listEvents } from "@/lib/exchange-balance.server.ts";

// The ledger client returns most-recent-first; 500 covers any realistic
// 24h provider volume. A heavier provider would need a dedicated 24h
// aggregate on the bridge — tracked as a follow-up.
const EVENT_LIMIT = 500;

function readBearer(request: Request): string | null {
  const h = request.headers.get("authorization");
  if (!h) return null;
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1]!.trim() : null;
}

function jsonError(status: number, message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

interface ConfidentialLegs {
  selfTierConfidential?: boolean;
  cdHashKnownGood?: boolean;
  challengeVerifiedSip?: boolean;
  codeAttested?: boolean;
}

interface ConfidentialStanding {
  /** The advisor verified this machine confidential (all four legs hold). */
  verified: boolean;
  /** When the owner asked for confidential but it isn't verified yet, the
   *  single most-actionable blocking leg, phrased for the operator. Null when
   *  verified, or when we can't reach the advisor to know. */
  blockedReason: string | null;
  /** The machine is live on the advisor but registered WITHOUT proving control
   *  of its DID (`registrationAuthenticated === false`) — its OAuth session has
   *  expired, so it can't mint the service-auth JWT. This is the un-fixable-by-
   *  waiting leg: the owner must sign in again. Distinct from a transient
   *  advisor-unreachable ("can't tell"). */
  needsReauth: boolean;
}

/** The C1 re-auth prompt. Phrased as an action, not a diagnosis: this is what
 *  the owner sees when a confidential-desired machine can't authenticate. */
const REAUTH_REASON =
  "This Mac needs to sign in again — its co/core account session expired, so it can't prove its identity to the network. Open the app and choose “Sign in again”.";

/** Map the advisor's per-leg breakdown to ONE operator-facing reason, in
 *  most-actionable-first order. Returns null when every leg holds (verified).
 *  Mirrors the AND in the advisor's `recomputeConfidential`. */
function blockingLegReason(legs: ConfidentialLegs): string | null {
  if (legs.selfTierConfidential === false)
    return "The agent hasn't come up on the confidential worker yet — it's still starting or restarting.";
  if (legs.cdHashKnownGood === false)
    return "This build isn't recognized yet (its code hash isn't in the known-good set). Update to the latest secure build.";
  if (legs.challengeVerifiedSip === false)
    return "System Integrity Protection looks disabled on this Mac — confidential serving needs SIP on.";
  if (legs.codeAttested === false)
    return "Waiting for this Mac to answer the hardware code-identity challenge. This can take a moment after the agent (re)starts.";
  return null;
}

/** The advisor's VERIFIED confidential standing for this machine plus, when
 *  the owner wants confidential but it isn't verified, WHY. A DID can hold
 *  MULTIPLE advisor rows (one per connected machine, plus stale ghosts): the
 *  live attested row wins, so we treat the DID as verified when ANY row is,
 *  and otherwise report the blocking leg from the row that's furthest along
 *  (the one claiming the confidential tier). Degrades to
 *  `{verified:false, blockedReason:null}` when the advisor is unreachable —
 *  "can't tell", distinct from a known leg failure. */
async function fetchConfidentialStanding(did: string): Promise<ConfidentialStanding> {
  try {
    const base = cocoreConfig().advisorUrl.replace(/\/$/, "");
    const r = await fetch(`${base}/providers`);
    if (!r.ok) return { verified: false, blockedReason: null, needsReauth: false };
    const list = (await r.json()) as Array<{
      did: string;
      confidentialEligible?: boolean;
      trustTier?: string;
      // C1: whether this registration proved control of its DID. `false` means
      // the agent couldn't mint a service-auth JWT — an expired OAuth session.
      registrationAuthenticated?: boolean;
      confidentialLegs?: ConfidentialLegs;
    }>;
    const mine = list.filter((p) => p.did === did);
    const verified = mine.some(
      (p) => p.confidentialEligible === true || p.trustTier === "attested-confidential",
    );
    if (verified) return { verified: true, blockedReason: null, needsReauth: false };
    // Not verified on any row. Prefer the row that's claiming the confidential
    // tier (furthest along) for the most relevant blocking leg; fall back to
    // any row. With no rows at all the machine isn't connected to the advisor.
    const best = mine.find((p) => p.confidentialLegs?.selfTierConfidential) ?? mine[0];
    if (!best) {
      return {
        verified: false,
        blockedReason:
          "This Mac isn't connected to the co/core network yet — confidential can't be verified until it is.",
        needsReauth: false,
      };
    }
    // An unauthenticated registration can never reach an attested tier — the
    // OAuth session that proves the DID has expired. This is the MOST-actionable
    // block (it also silently pins the worker to best-effort and fails receipt
    // publishing), so it outranks the per-leg reasons: tell the owner to sign in
    // again rather than the misleading "not connected to the network".
    if (best.registrationAuthenticated === false) {
      return { verified: false, blockedReason: REAUTH_REASON, needsReauth: true };
    }
    return {
      verified: false,
      blockedReason: blockingLegReason(best.confidentialLegs ?? {}),
      needsReauth: false,
    };
  } catch {
    return { verified: false, blockedReason: null, needsReauth: false };
  }
}

export const Route = createFileRoute("/api/agent/status")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const bearer = readBearer(request);
        if (!bearer) return jsonError(401, "missing Authorization: Bearer header");
        const resolved = resolveBearerKey(bearer);
        if (!resolved) return jsonError(401, "invalid API key");

        const did = resolved.did;
        const since = Date.now() - 24 * 60 * 60 * 1000;

        // "Does the agent need a fresh sign-in?" — a NON-refreshing read of
        // the stored OAuth session. The old probe called restore(), which
        // refreshes/rotates the single-use refresh token on every status poll;
        // because the AppView is the designated refresher, that parallel
        // rotation cannibalized the session it was meant to monitor.
        //
        // When AppView forwarding is configured, the AUTHORITATIVE session lives
        // in the AppView (the console hands it off at login and never refreshes
        // locally — see appview-backed-session.server.ts). The console's LOCAL
        // store therefore goes stale/empty after handoff, so probing it reports
        // a FALSE "session expired" even while the agent is actively publishing
        // (Secure Mode / confidential live prove the session works). So prefer
        // the AppView's authoritative, non-refreshing session-info and only
        // report re-auth when it DEFINITIVELY says the session is gone
        // (`checked && !present`) — never on a transient unreachable-AppView
        // blip. Fall back to the local probe only in the legacy single-store
        // deployment where forwarding isn't configured.
        let needsReauth: boolean;
        if (isAppviewForwardConfigured()) {
          const info = await appviewSessionInfo(did);
          needsReauth = info.checked ? !info.present : false;
        } else {
          needsReauth = sessionNeedsReauth(did as Did);
        }

        // All three degrade gracefully so a single backend hiccup yields
        // partial data the menu can still render, not a 500.
        const [balance, events, providers, standing] = await Promise.all([
          getBalance(did).catch(() => null),
          listEvents(did, EVENT_LIMIT).catch(() => ({ events: [] })),
          runTraced("appview.listProviders", appviewListProvidersEffect).catch(() => ({
            providers: [],
          })),
          fetchConfidentialStanding(did),
        ]);

        const earned24h = sumReceiptInSince(events.events, since);

        const mine = providers.providers.find((p) => p.repo === did);
        const body = (mine?.body ?? {}) as {
          trustLevel?: string;
          binaryVersion?: string;
          desiredTier?: string;
          attestationFault?: { code?: string; message?: string; at?: string };
          advisorFault?: { code?: string; message?: string; observedAt?: string };
        };

        // Surface an attestation build/publish failure: a machine in this
        // state is online but cannot produce verifiable receipts, so without
        // this it just looks idle. Mirrors how engineFault is surfaced.
        const attestationFault = body.attestationFault
          ? {
              code: body.attestationFault.code ?? null,
              message: body.attestationFault.message ?? null,
              at: body.attestationFault.at ?? null,
            }
          : null;

        // Surface an advisor-connectivity failure: a machine in this state is
        // serving locally but invisible to the network (its WebSocket to the
        // advisor never connects), so without this it just looks idle. Same
        // shape and posture as attestationFault above.
        const advisorFault = body.advisorFault
          ? {
              code: body.advisorFault.code ?? null,
              message: body.advisorFault.message ?? null,
              observedAt: body.advisorFault.observedAt ?? null,
            }
          : null;

        // The owner's DURABLE intent (written by `agent confidential`), distinct
        // from the advisor's verified standing. The app needs both: intent that
        // survives restarts, plus what's actually verified, so it can render an
        // honest "Applying… / Active / Best-effort" instead of a single boolean
        // that looks like the setting was forgotten during the verify window.
        const confidentialDesired = body.desiredTier === "attested-confidential";
        // Only surface a blocking reason when the owner actually wants
        // confidential — a best-effort machine isn't "blocked", it's off.
        const confidentialBlockedReason =
          confidentialDesired && !standing.verified ? standing.blockedReason : null;

        // A confidential-desired machine that's live on the advisor but
        // registered unauthenticated (registrationAuthenticated === false) is a
        // DEFINITIVE re-auth condition the session probe above can miss: the
        // agent's OAuth session is dead but its WebSocket is healthy, so the
        // AppView session store may not have observed the death. Trust the
        // advisor-derived signal so the app's existing "Sign in again" prompt
        // fires reliably. Scoped to confidential so a best-effort agent that's
        // merely unauthenticated during staged rollout isn't nagged.
        if (confidentialDesired && standing.needsReauth) needsReauth = true;

        return new Response(
          JSON.stringify({
            did,
            currency: "credits",
            balance: balance?.balance ?? null,
            earned24h,
            trustLevel: body.trustLevel ?? null,
            // `confidential` stays = verified for back-compat with older app
            // builds; new builds read confidentialVerified/Desired/BlockedReason.
            confidential: standing.verified,
            confidentialVerified: standing.verified,
            confidentialDesired,
            confidentialBlockedReason,
            agentVersion: body.binaryVersion ?? null,
            attestationFault,
            advisorFault,
            needsReauth,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      },
    },
  },
});
