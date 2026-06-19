// GET /lexicons/<nsid>
//
// Serves the canonical JSON document for a single dev.cocore.*
// lexicon (compute + account namespaces). Anyone can fetch these without auth — that's the whole
// point of "publishing" them. We bundle the JSON files at build time
// via the same imports the SDK uses, so this stays in lockstep with
// what we ship at runtime; no separate copy to drift.
//
// We accept the NSID with or without a trailing `.json` so that both
// `/lexicons/dev.cocore.compute.receipt` (atproto-canonical) and
// `/lexicons/dev.cocore.compute.receipt.json` (curl-friendly) work.
//
// Why URL-rooted JSON instead of just the lex-cli registry: outside
// consumers (third-party verifiers, tools written in other
// languages, future SDKs) need a stable URL to fetch the schema.
// Once a record references an NSID, the schema for that NSID is part
// of the public commitment surface — it has to be reachable.

import { createFileRoute } from "@tanstack/react-router";

import accountCreateApiKey from "../../../../lexicons/dev/cocore/account/createApiKey.json" with { type: "json" };
import accountDefs from "../../../../lexicons/dev/cocore/account/defs.json" with { type: "json" };
import accountDeleteApiKey from "../../../../lexicons/dev/cocore/account/deleteApiKey.json" with { type: "json" };
import accountListApiKeys from "../../../../lexicons/dev/cocore/account/listApiKeys.json" with { type: "json" };
import accountProfile from "../../../../lexicons/dev/cocore/account/profile.json" with { type: "json" };
import accountRevokeApiKey from "../../../../lexicons/dev/cocore/account/revokeApiKey.json" with { type: "json" };
import attestation from "../../../../lexicons/dev/cocore/compute/attestation.json" with { type: "json" };
import defs from "../../../../lexicons/dev/cocore/compute/defs.json" with { type: "json" };
import dispute from "../../../../lexicons/dev/cocore/compute/dispute.json" with { type: "json" };
import exchangeAttestation from "../../../../lexicons/dev/cocore/compute/exchangeAttestation.json" with { type: "json" };
import exchangePolicy from "../../../../lexicons/dev/cocore/compute/exchangePolicy.json" with { type: "json" };
import job from "../../../../lexicons/dev/cocore/compute/job.json" with { type: "json" };
import paymentAuthorization from "../../../../lexicons/dev/cocore/compute/paymentAuthorization.json" with { type: "json" };
import provider from "../../../../lexicons/dev/cocore/compute/provider.json" with { type: "json" };
import receipt from "../../../../lexicons/dev/cocore/compute/receipt.json" with { type: "json" };
import settlement from "../../../../lexicons/dev/cocore/compute/settlement.json" with { type: "json" };
import termsAcceptance from "../../../../lexicons/dev/cocore/compute/termsAcceptance.json" with { type: "json" };

const REGISTRY: Record<string, unknown> = {
  "dev.cocore.account.createApiKey": accountCreateApiKey,
  "dev.cocore.account.defs": accountDefs,
  "dev.cocore.account.deleteApiKey": accountDeleteApiKey,
  "dev.cocore.account.listApiKeys": accountListApiKeys,
  "dev.cocore.account.profile": accountProfile,
  "dev.cocore.account.revokeApiKey": accountRevokeApiKey,
  "dev.cocore.compute.attestation": attestation,
  "dev.cocore.compute.defs": defs,
  "dev.cocore.compute.dispute": dispute,
  "dev.cocore.compute.exchangeAttestation": exchangeAttestation,
  "dev.cocore.compute.exchangePolicy": exchangePolicy,
  "dev.cocore.compute.job": job,
  "dev.cocore.compute.paymentAuthorization": paymentAuthorization,
  "dev.cocore.compute.provider": provider,
  "dev.cocore.compute.receipt": receipt,
  "dev.cocore.compute.settlement": settlement,
  "dev.cocore.compute.termsAcceptance": termsAcceptance,
};

function notFound(nsid: string): Response {
  return new Response(
    JSON.stringify({
      error: "lexicon-not-found",
      message: `no lexicon registered at ${nsid}`,
      known: Object.keys(REGISTRY).sort(),
    }),
    {
      status: 404,
      headers: { "content-type": "application/json; charset=utf-8" },
    },
  );
}

export const Route = createFileRoute("/lexicons/$nsid")({
  server: {
    handlers: {
      GET: ({ params }) => {
        const raw = params.nsid;
        const nsid = raw.endsWith(".json") ? raw.slice(0, -".json".length) : raw;
        const doc = REGISTRY[nsid];
        if (!doc) return notFound(nsid);
        return new Response(JSON.stringify(doc, null, 2), {
          status: 200,
          headers: {
            "content-type": "application/json; charset=utf-8",
            // Schemas are content-addressable in spirit (an
            // immutable JSON for a given NSID@version). We don't yet
            // version per-record, so cache for an hour and let CDN /
            // proxies refresh.
            "cache-control": "public, max-age=3600",
            "x-lexicon-nsid": nsid,
          },
        });
      },
    },
  },
});
