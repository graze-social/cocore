// The single source of truth for the cocore OAuth scope list.
//
// Both the MINTING client (the console, which calls `authorize()`) and the
// RESTORING client (the AppView, which refreshes handed-off sessions) must
// present the same grant, or the client-metadata won't match at refresh.
// They used to keep two hand-mirrored copies; this is the shared constant
// they both import instead.
//
// The `repo` grants enumerate every NSID cocore publishes to a user's PDS:
//   * dev.cocore.compute.provider             — pair-machine flow
//   * dev.cocore.compute.job                  — inference dispatch
//   * dev.cocore.compute.paymentAuthorization — inference dispatch
//   * dev.cocore.account.profile              — /account auto-provision + edits
//   * dev.cocore.account.friend               — /friends add / remove
//   * dev.cocore.account.tokenGrant           — exchange-side onboarding grants
//   * dev.cocore.account.tokenPatronage       — exchange-side monthly rebates
//   * (+ the exchange-operator compute.* collections)
// Without a matching repo grant ATProto returns
//   `ScopeMissingError: Missing required scope "repo:<nsid>?action=create"`.
//
// The `rpc` grant authorizes service-auth minting:
// `com.atproto.server.getServiceAuth` returns 403 under the granular OAuth
// model unless the token holds a matching `rpc` permission. We mint
// service-auth JWTs server-side (from the user's session) so the AppView can
// verify the caller's DID for:
//   * dev.cocore.devicePair.confirm — approve a device-pairing
//   * dev.cocore.inference.dispatch — forward an inference dispatch
//   * dev.cocore.compute.register  — the agent's DID-bound advisor
//     registration (the agent posts /api/pds/getServiceAuth with this lxm;
//     without the grant every agent falls back to registering with the
//     advisor unauthenticated — seen fleet-wide as `ScopeMissingError` in
//     agent logs, e.g. ticket br_23e56917 — which blocks ever enforcing
//     DID-auth at the advisor).
// `aud: "*"` keeps the grant environment-agnostic (this static list can't
// name a per-env AppView DID); the console only ever targets the AppView.
//
// Changing this list (a new collection, a new minted method) requires users
// to RE-AUTHORIZE — tokens issued before the change don't retroactively gain
// the new grant.

import { scope as atprotoScope } from "@atcute/oauth-types";

export const oauthScopes = [
  atprotoScope.account({ attr: "email", action: "read" }),
  atprotoScope.blob({ accept: ["image/*", "video/*"] }),
  atprotoScope.repo({
    collection: [
      "dev.cocore.compute.provider",
      "dev.cocore.compute.job",
      "dev.cocore.compute.paymentAuthorization",
      "dev.cocore.compute.attestation",
      "dev.cocore.compute.receipt",
      "dev.cocore.compute.settlement",
      "dev.cocore.compute.exchangePolicy",
      "dev.cocore.compute.exchangeAttestation",
      "dev.cocore.compute.termsAcceptance",
      "dev.cocore.compute.dispute",
      "dev.cocore.account.profile",
      "dev.cocore.account.friend",
      "dev.cocore.account.tokenGrant",
      "dev.cocore.account.tokenPatronage",
    ],
    action: ["create", "update", "delete"],
  }),
  atprotoScope.rpc({
    lxm: [
      "dev.cocore.devicePair.confirm",
      "dev.cocore.inference.dispatch",
      "dev.cocore.compute.register",
    ],
    aud: "*",
  }),
];
