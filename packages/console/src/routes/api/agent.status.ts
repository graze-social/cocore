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
}

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
    if (!r.ok) return { verified: false, blockedReason: null };
    const list = (await r.json()) as Array<{
      did: string;
      confidentialEligible?: boolean;
      trustTier?: string;
      confidentialLegs?: ConfidentialLegs;
    }>;
    const mine = list.filter((p) => p.did === did);
    const verified = mine.some(
      (p) => p.confidentialEligible === true || p.trustTier === "attested-confidential",
    );
    if (verified) return { verified: true, blockedReason: null };
    // Not verified on any row. Prefer the row that's claiming the confidential
    // tier (furthest along) for the most relevant blocking leg; fall back to
    // any row. With no rows at all the machine isn't connected to the advisor.
    const best = mine.find((p) => p.confidentialLegs?.selfTierConfidential) ?? mine[0];
    if (!best) {
      return {
        verified: false,
        blockedReason:
          "This Mac isn't connected to the co/core network yet — confidential can't be verified until it is.",
      };
    }
    return { verified: false, blockedReason: blockingLegReason(best.confidentialLegs ?? {}) };
  } catch {
    return { verified: false, blockedReason: null };
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
        // the stored OAuth session (see sessionNeedsReauth). The old probe
        // called restore(), which refreshes/rotates the single-use refresh
        // token on every status poll; because the AppView is the designated
        // refresher, that parallel rotation was cannibalizing the session it
        // was meant to monitor and causing the recurring write 401s. This
        // read only reports re-auth when the session is genuinely gone.
        const needsReauth = sessionNeedsReauth(did as Did);

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
            needsReauth,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      },
    },
  },
});
