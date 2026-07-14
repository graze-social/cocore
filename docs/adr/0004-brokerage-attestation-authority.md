# ADR-0004: The brokerage is a forkable attestation authority (notary / countersignature model)

Status: proposed (accepted in principle — Devin, 2026-07-05)
Date: 2026-07-05

## Context

Two public exploits by astra (2026-07-01, 2026-07-05) showed the confidential
tier being defeated. ADR-0002 and the ADR-0003 verifier hardening fixed the
specific bugs, but the deeper analysis is that the *class* of hole is structural
(see the "why d-inference doesn't have this" discussion):

- cocore made attestation **self-published** to each provider's PDS (invariant
  #1) and made the advisor **non-authoritative** — "an accelerator, not the
  authority" — with the real trust decision pushed to the client edge, offline,
  against those self-published records.
- That splits *publish*, *route*, *verify*, and *serve* across separate parties,
  and every seam between them is a place an attacker can stand. astra's exploits
  all live in those seams (publish-a-confidential-record / serve-from-a-Strix;
  route-to-an-unattested-sibling; advisor-hint disagreeing with client-offline).
- d-inference (darkbloom) avoids the whole class because a **single coordinator**
  holds the session, runs the attestation challenge, routes inference, and *is*
  the canonical record — attest and serve are bound in one session. Its own
  README is explicit that this is defense-in-depth on Apple silicon, **not** a
  cryptographic guarantee (ADR-0003 update: App Attest — the only thing that
  could prove key residency — does not function on macOS at all).

Invariant #5 ("no coordinator-shaped components") forbade the very binding that
would close the seam. This ADR resolves that tension.

## Decision

**Accept centralization for the purposes of attestation and security, but keep
the authority forkable.** A "brokerage" (what the advisor grows into) is a
first-class, load-bearing **attestation authority**, and confidential validity
is gated on its signature — but the authority is just an account, so anyone can
run their own brokerage and compete.

1. **A brokerage is an authority identified by a DID + signing key.** cocore's
   reference brokerage already has one (`COCORE_ADVISOR_DID`,
   `did:web:advisor.cocore.dev`, with the DID-auth infra from C1). Its signing
   key is published in its DID document and verified offline from there.

2. **Records stay self-published; the countersignature elevates them.** Providers
   still write `dev.cocore.compute.*` to their own PDS (invariant #1's storage
   model is intact). A receipt only counts as **confidential** if it also carries
   a valid brokerage countersignature from an authority the verifier trusts. The
   PDS stores the record; the brokerage signature is the attribute that makes it
   confidential-valid. Best-effort needs no countersignature and stays purely
   federated.

3. **The countersignature MUST be session-bound (this is load-bearing).** The
   brokerage co-signs the *receipt/session*, over the job ref + the specific
   machine identity + the live-challenge nonce it issued on that socket this
   session — i.e. *"I, brokerage X, live-challenged the machine that served THIS
   job."* Signing a standing attestation is theater (astra splits: genuine Mac
   earns the standing, another box serves). Only the per-session, socket-bound
   countersignature welds attest-to-serve, which is exactly d-inference's session
   binding — re-expressed as a signature on a federated record.

4. **Trust is relative to a named authority.** A verifier configures which
   brokerage DID(s) it trusts (default: cocore's), the way a browser trusts CAs.
   This unlocks the open network: providers register with multiple brokerages;
   requesters pick which they trust; brokerages compete on reliability, price,
   attestation rigor, and coverage. A future requester can require K-of-N
   countersignatures for higher assurance.

5. **This REPLACES the unachievable App Attest residency gate.** ADR-0003 chased
   `keyId == sha256(publicKey)` App Attest assertions to prove key residency —
   impossible on macOS. The brokerage countersignature is the achievable
   substitute: it does not *cryptographically* prove residency, it proves *a
   trusted authority witnessed a live challenge pass on the serving socket*. The
   SDK verifiers (assertion path, `sigScheme`) remain in the tree for a future
   confidential-compute backend, but the Mac confidential tier gates on the
   brokerage countersignature, not App Attest.

## Invariant amendments (supersede the originals in CLAUDE.md)

- **#1 (source of truth).** Unchanged for storage: the provider's PDS remains the
  source of truth for a record's existence and the provider's own claims.
  Refinement: for the confidential tier, a receipt is confidential-valid only
  with a trusted brokerage's session-bound countersignature. AppViews remain
  caches/indexes.
- **#5 (was "no coordinator-shaped components").** New: *there is no hardcoded
  singleton coordinator.* A brokerage is a first-class attestation authority
  identified by a DID; the reference deployment runs cocore's, but the code and
  protocol let anyone stand up a competing brokerage, and confidential validity
  is always relative to a named brokerage authority the verifier chooses to
  trust. Federation is "forkable, competing authorities + federated storage,"
  not "no authority." Routing, discovery, and settlement remain federable.

## What this closes

- **Publish-vs-serve** (astra's 07-05 split): a self-published confidential
  record is worthless without the session-bound countersignature, which the
  brokerage only issues to the socket it live-challenged and dispatched to.
- **Route-vs-verify** (astra's 07-01 sibling): the countersignature names the
  specific machine that served; an unattested sibling can't be substituted.
- **Advisor-hint-vs-client-offline disagreement:** collapses into one
  authoritative, offline-verifiable signature; the client stops re-deriving
  trust from attacker-controlled self-published records.

## What this does NOT close (keep the honest framing)

- **The Apple-silicon ceiling is unchanged.** The countersignature means "a
  trusted brokerage witnessed a live challenge pass" — posture + code-identity
  assurance, authoritatively bound, **not** a hardware key-residency or
  memory-isolation proof (no App Attest / TEE on macOS). A determined operator
  running a genuine Mac as a live-challenge oracle is still out of scope. The
  copy stays d-inference-honest: hardened + attested + defense-in-depth, not a
  cryptographic guarantee. Reserve guarantee language for a confidential-compute
  backend.
- **Trust concentration (CA-compromise analogy).** A malicious/compromised
  brokerage can vouch for bad providers to clients that trust it. Mitigations:
  reputation, multi-brokerage + K-of-N threshold trust, and transparency (a
  brokerage publishes what it countersigns so mis-vouching is detectable).

## Consequences

- **Liveness cost is scoped.** Confidential now depends on a brokerage being up
  to countersign; best-effort does not. Mitigate with multiple/federated
  brokerages.
- **Not a big rebuild.** The advisor already holds the socket, runs the
  challenge, and computes eligibility. The delta is: (a) give it an authority
  signing key in its DID doc (C1 infra already publishes its DID), (b) co-sign
  the receipt bound to the live-challenged serving socket + challenge nonce, and
  (c) make the SDK/console require that countersignature from a trusted authority
  for confidential, instead of re-deriving offline.
- **Enables multi-brokerage competition** — the long-term "open network of
  competing brokerages" the storage federation was always meant to enable, now
  with attestation that actually binds.

## Build status (2026-07-05)

Data-plane DONE end-to-end and tested across all components — the
countersignature is produced at dispatch, rides the wire, is embedded on the
published receipt, and is verifiable:

- **Lexicon:** `dev.cocore.compute.receipt#brokerageCountersignature` added (with
  the exact canonical witness message pinned normatively).
- **SDK (TS) `brokerage.ts`:** `brokerageWitnessMessage` (the cross-language
  contract) + `verifyBrokerageCountersignature` (trust-set + DID-key + bound-field
  checks); `verifyReceiptSignature` strips it before checking enclaveSignature.
- **Python `brokerage.py`:** mirror + the same strip. 4 tests green.
- **Advisor `brokerage.ts`:** `loadBrokerageAuthority` (P-256 key from env) signs
  each dispatch; wired into `jobs.ts` (attaches to `inference_request`), the
  `protocol.ts` frame, and `main.ts` (boot-loads + logs the pubkey to publish).
  Round-trip test (advisor signs → SDK verifies) green — proves byte-identical
  canonical parity.
- **Provider (Rust):** `protocol.rs` wire struct + `receipt.rs` model; `build()`
  copies it onto the record but EXCLUDES it from the enclaveSignature; test
  proves the signed bytes are unchanged. 177 lib tests green.

Consumer-side gate DONE + tested (the SDK verification surface):
- **SDK `brokerage.ts`:** `verifyConfidentialReceipt` — the one call a
  confidential requester/auditor makes: requires BOTH the provider enclaveSignature
  AND a trusted brokerage countersignature (a self-published receipt with no
  trusted witness is best-effort — the astra case, proven closed in a test).
  Plus `makeBrokerageKeyResolver` (did:web `/.well-known/did.json` + did:plc,
  cached), `brokerageKeyFromDidDoc` (pure P-256-JWK extractor), `didDocumentUrl`,
  and `DEFAULT_TRUSTED_BROKERAGE`. All tested with a stub-fetch DID doc.
- **App Attest residency gate RETIRED for the Mac tier:** `requireHardwareBoundKey`
  now defaults FALSE in both SDK verifiers (ADR-0003 dead-end); kept opt-in for a
  future confidential-compute backend. Tests updated.

appview integration DONE:
- **`GET /xrpc/dev.cocore.compute.verifyReceipt`** now reports `confidential`
  (whether a TRUSTED brokerage countersigned the dispatch) + `brokerageAuthority`,
  and adds a `brokerage-countersignature-invalid` finding when a countersignature
  is present but doesn't verify. Trust set (`COCORE_TRUSTED_BROKERAGES`, default
  cocore's) + resolver are injectable into `buildReadRouter` for config/tests.

EXCHANGE: NOT integrated, deliberately. Settlement is price-based payment, which
is orthogonal to the confidential tier — `verifyForChargeStrict` gates
chargeability (receipt sig + attestation binding), and there is no confidential
premium in the pricing model (price is per-MTok, tier-independent). Requiring a
brokerage countersignature to settle would wrongly block payment for best-effort
work and for confidential work brokered by an authority the EXCHANGE doesn't
trust. Confidential-validity is a REQUESTER/appview concern, verified there; the
exchange moves money regardless of tier. (Superseding this ADR's earlier
speculative "optionally require it before settling.")

REMAINING (ops + copy):
- console copy: honest Mac-tier framing (hardened, not guaranteed) per ADR-0003/4.
- Ops: generate the authority keypair, set `COCORE_BROKERAGE_SIGNING_KEY_PEM`,
  publish the pubkey (P-256 JWK) in `did:web:advisor.cocore.dev`'s DID document.

## Implementation sketch (own PRs, lexicon-first)

1. **Lexicon:** add an optional `brokerageCountersignature` to
   `dev.cocore.compute.receipt` — `{ authority: DID, challengeNonce, sig }` (sig
   over a canonical `{ job, provider, machineId, challengeNonce, completedAt }`).
   Additive; a confidential requester requires it from a trusted `authority`.
2. **Advisor (brokerage):** load an authority signing key; on `inference_complete`
   for a live-challenged socket, sign the countersignature and return it into the
   receipt path.
3. **SDK/console verifier:** confidential requires a valid `brokerageCountersignature`
   from a DID in the caller's trust set (default cocore), verified against that
   DID's doc, session-bound. This is the Mac confidential gate (App Attest gate
   retired for Mac).
4. **Trust set:** config for which brokerage DIDs a verifier trusts; K-of-N later.

## Open questions

- Exactly which fields the session countersignature must bind to make socket↔job
  unforgeable (challenge nonce + machineId + job CID at minimum).
- Whether the countersignature lives on the receipt, a separate
  `dev.cocore.compute.brokerageWitness` record strong-ref'd by the receipt, or
  both.
- Threshold-trust semantics and how requesters express their trust set on the
  wire.
