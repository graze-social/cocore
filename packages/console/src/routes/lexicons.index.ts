// GET /lexicons
//
// Index of every dev.cocore.* lexicon this deployment publishes
// (compute + account namespaces). Lets a consumer discover the set
// without a priori knowledge of which records exist. Each entry
// includes the NSID and the absolute URL to fetch the JSON.
//
// The list of NSIDs is the same registry that `/lexicons/$nsid`
// serves from; keeping both in this file would risk drift, so the
// canonical registry lives in lexicons.$nsid.ts and we re-export
// just the NSID list here.

import { createFileRoute } from "@tanstack/react-router";

const NSIDS = [
  "dev.cocore.account.createApiKey",
  "dev.cocore.account.defs",
  "dev.cocore.account.deleteApiKey",
  "dev.cocore.account.listApiKeys",
  "dev.cocore.account.profile",
  "dev.cocore.account.revokeApiKey",
  "dev.cocore.compute.attestation",
  "dev.cocore.compute.defs",
  "dev.cocore.compute.dispute",
  "dev.cocore.compute.exchangeAttestation",
  "dev.cocore.compute.exchangePolicy",
  "dev.cocore.compute.job",
  "dev.cocore.compute.paymentAuthorization",
  "dev.cocore.compute.provider",
  "dev.cocore.compute.receipt",
  "dev.cocore.compute.settlement",
  "dev.cocore.compute.termsAcceptance",
] as const;

export const Route = createFileRoute("/lexicons/")({
  server: {
    handlers: {
      GET: ({ request }) => {
        const origin = new URL(request.url).origin;
        const lexicons = NSIDS.map((nsid) => ({
          nsid,
          url: `${origin}/lexicons/${nsid}`,
        }));
        return new Response(
          JSON.stringify(
            {
              namespace: "dev.cocore",
              lexicons,
            },
            null,
            2,
          ),
          {
            status: 200,
            headers: {
              "content-type": "application/json; charset=utf-8",
              "cache-control": "public, max-age=300",
            },
          },
        );
      },
    },
  },
});
