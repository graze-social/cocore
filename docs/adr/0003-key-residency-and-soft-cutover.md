# ADR-0003: Signing-key residency for confidential, and soft-cutover enforcement

Status: proposed
Date: 2026-07-05

## Context

A second public exploit (Astra, 2026-07-05) served `min_trust: confidential`
traffic from an AMD/Linux "Strix Halo" box while presenting a genuine Apple
attestation for an M4 MacBook. The completion admitted it: *"a strix halo box
in a trenchcoat."* This lands after ADR-0002's machine-scoped fixes, so it is
not the old per-DID widening — it is a deeper, structural gap.

Root cause: **`attested-confidential` binds trust to a KEY, and that key is
exportable.** The provider's signing identity is a software P-256 key persisted
at `~/.cocore/identity.pem` (`SoftwareIdentity`, `is_hardware_bound() == false`;
the `secure_enclave` cargo feature is off in every shipped build). The
"hardware-attested" proof is a genuine Apple MDA chain bound to that key via the
freshness code `freshnessCode == sha256(publicKey)`. But Apple's Managed Device
Attestation attests *arbitrary clientData on a genuine device* — so an operator
with ONE real Apple device mints a bound chain for a software key, then copies
`(identity.pem, MDA chain, blessed cdHash, encryption key)` to any host. Every
downstream proof — `selfSignature`, the advisor SIP challenge signature, the
APNs code-identity signature — is producible by whoever holds the software key,
regardless of the hardware running it. The MDA chain proves *a genuine Apple
device once vouched for this public key*, never *the machine signing right now
is that device*.

## Problem statement

Make `attested-confidential` mean the prompt was handled by a non-exportable
signing identity resident on genuine Apple hardware — provably, from the receipt
plus Apple's CAs, with no coordinator in the trust path (invariants #1, #2). And
do it WITHOUT a flag-flip that instantly bricks the fleet: machines that ship the
fix earn confidential; machines that don't are DOWNGRADED (kept serving at a
weaker tier) with a clear upgrade nudge — never disconnected.

## The residency gap, precisely

There are two layers, and the first is a trap:

1. **Require a bound App Attest object.** Necessary but NOT sufficient. App
   Attest binds via `clientDataHash = sha256(publicKey)` and checks
   `keyId == sha256(ATTESTED key)`. It never checks `attested key == signing
   key`. So a genuine SE App-Attest key can attest a *commitment to* a software
   signing key's value — the object is bound-but-portable. Cost to forge: one
   `attestKey` call on a real Apple device, same as minting an MDA chain.

2. **Require the attested key to BE the signing identity, via assertions.** This
   is the sufficient fix. The confidential identity is the App Attest key itself
   (`keyId == sha256(publicKey)`), and receipts/attestations are signed with
   `DCAppAttestService.generateAssertion` (an SE assertion the verifier checks
   against the attested credential key + monotonic counter), NOT raw ECDSA. A
   DCAppAttest key is non-exportable by construction and cannot raw-sign
   arbitrary bytes, so the identity cannot be lifted onto another host. This
   replaces raw-ECDSA `selfSignature` / session-key / `enclaveSignature` with
   assertion signatures for the confidential tier.

Note the consequence: layer 2 is INCOMPATIBLE with the current raw-ECDSA record
scheme (an App Attest key can't produce `selfSignature` over canonical JSON). So
closing the hole is a provider signing re-architecture, not a verifier tweak.

## Decision

1. **`attested-confidential` requires a Secure-Enclave-resident signing key**,
   proven by App Attest, in addition to the ADR-0002/existing gates (bound Apple
   attestation, known-good cdHash, hardened posture, fresh session key, APNs
   code-identity). The lexicon `#tier` / `#trustLevel` definitions are updated to
   say so (this ADR's sibling lexicon change). An MDA-freshness binding tops out
   at `hardware-attested`.

2. **The complete proof is assertion-based signing** (layer 2 above): the App
   Attest key is the signing identity (`keyId == sha256(publicKey)`) and
   attestations/receipts carry App Attest assertions. Layer 1 (a bound App Attest
   object) is the interim rung the verifier enforces first; layer 2 is the
   provider re-architecture that actually removes portability. Both ship behind
   the same soft cutover.

3. **Enforcement is a per-machine DOWNGRADE, never a disconnect or a fleet
   flag-flip.** A machine that can't prove residency keeps serving at
   `hardware-attested` / `best-effort`; confidential *requesters* fail closed
   (503 `no_verified_providers`) rather than route to a portable-key machine. The
   tier is recomputed from evidence per machine (verified-standing.server.ts is
   the authority; the advisor is an accelerator), so old machines downgrade
   automatically the moment enforcement turns on — nothing to revoke.

4. **Generalize the same soft-cutover shape to C1** (DID-bound registration
   auth). Today `COCORE_ADVISOR_REQUIRE_AUTH=true` *closes the socket* on a
   missing register JWT — a hard break that takes an un-upgraded machine fully
   offline. Replace the default path with: admit the socket, mark it
   `registrationAuthenticated=false`, and CAP it out of the attested tiers (it
   can't prove it controls the DID whose attestation a verifier would fetch). It
   still serves best-effort. The hard reject remains available as an explicit
   Phase-3 escalation, but the default is downgrade.

## Rollout (soft cutover)

The invariant: flipping enforcement only ever downgrades machines that DIDN'T
upgrade — never a healthy, upgraded one, and never a disconnect.

- **Phase 0 — containment.** None beyond monitoring. (Astra is deliberately left
  unrevoked as an adversarial fuzzer — see the team decision; fix classes, not
  the actor.)
- **Phase 1 — ship the proof, enforce nothing.** Provider release: SE-generated
  App Attest identity + assertion signing, emitting the `appAttest` object and
  (layer 2) `keyId == sha256(publicKey)`. `binary_version` already flows to the
  advisor. Verifier/console code deploys DORMANT (`COCORE_CONFIDENTIAL_REQUIRE_-
  APP_ATTEST` unset/false). Encourage upgrades.
- **Phase 2 — enforce (downgrade).** Flip `COCORE_CONFIDENTIAL_REQUIRE_APP_-
  ATTEST=true`. Machines without a residency proof recompute from
  `attested-confidential` to `hardware-attested`; the console shows the
  `verifiedTierReason` nudge ("upgrade to an App-Attest build to regain
  confidential"). Confidential capacity is whatever has upgraded; requesters fail
  closed. Seed a first-party App-Attest machine so the tier isn't empty.
  Likewise set `COCORE_ADVISOR_DID` to turn on the C1 soft downgrade.
- **Phase 3 — cleanup.** Once telemetry shows the confidential fleet has moved,
  optionally hard-reject legacy confidential attestations and flip
  `COCORE_ADVISOR_REQUIRE_AUTH=true`. Often unnecessary: the Phase-2 downgrade
  already removed the vulnerability.

## Consequences

- Confidential capacity temporarily shrinks to upgraded machines after Phase 2.
  Correct (fail-closed > fake-confidential); requesters already 503 rather than
  silently downgrade.
- The provider gains a real signing re-architecture (assertion-based) for the
  confidential identity — the load-bearing, hardware-dependent work. The
  `secure_enclave` / App Attest scaffolding exists (`appattest.rs`,
  `mda_loader::load_appattest`, the SE FFI) but is dormant; Phase 1 is wiring the
  macOS App Attest helper + assertion signing and shipping it.
- `hardware-attested` is unchanged and still meaningful (genuine Apple device
  vouched for the key); only `attested-confidential` tightens.
- No coordinator is added: residency is proven offline from the receipt + Apple's
  CAs (invariants #1, #2 hold). The APNs code-identity leg remains the one
  documented advisor-asserted carve-out.

## Status of the sibling fixes (this change set, not just the ADR)

Implemented now (the soft-cutover framework + interim gate + C1 downgrade):

- **SDK verifier (TS + Py):** `requireHardwareBoundKey` (default true) emits a
  `key-not-hardware-bound` finding when there's no bound App Attest object. It is
  a confidential-only blocker (NOT in `HARDWARE_BLOCKER_CODES`), so an MDA-only
  machine caps at `hardware-attested`. This is layer-1 (interim); layer-2
  (`keyId == sha256(publicKey)` + assertion verification) is future work tracked
  here.
- **Console (verified-standing.server.ts):** `resolveVerifiedTier` recomputes per
  machine, gating confidential on key residency behind
  `COCORE_CONFIDENTIAL_REQUIRE_APP_ATTEST` (Phase gate) and on C1
  `registrationAuthenticated`, returning a `verifiedTierReason` nudge surfaced in
  MachineDetail.
- **Advisor:** `registrationAuthenticated` on the entry + `/providers`;
  connection handler admits-but-downgrades on a missing register JWT instead of
  closing; `confidentialEligible` also requires it (defense in depth).
- **Lexicon:** `#tier` / `#trustLevel` descriptions codify the residency
  requirement.

Remaining (Phase 1 provider work, hardware-dependent):

- macOS App Attest key generation + assertion-based signing for the confidential
  identity (`keyId == sha256(publicKey)`), replacing raw-ECDSA signing on that
  tier; then extend the verifier to require + check assertions (layer 2).

## ⛔ Update 2026-07-05: App Attest is unavailable on macOS — the assertion path is dead on Macs

Empirically confirmed on an M1 Mac mini (macOS 26.4.1) and in Apple's own
documentation: **`DCAppAttestService.isSupported` is always `false` on any Mac**,
including Apple Silicon, even with the correct entitlement and provisioning
profile. App Attest is functionally iOS/iPadOS/tvOS only.

Consequence: the "assertion-based signing where the App Attest key IS the
identity" design (the *sufficient* fix above) **cannot be implemented on macOS**
— there is no Apple API to remotely attest that a signing key is
Secure-Enclave-resident on a Mac. Therefore **confidential-with-provable-key-
residency is not achievable on commodity Macs at all.**

What survives: the verifier hardening (this change set — SDK TS/Py/Rust
assertion verifiers, the `keyId == sha256(publicKey)` residency gate, the
`sigScheme` dispatch) is correct and stays. It makes the tier fail *closed*: a
provider that cannot prove residency is capped at `hardware-attested`, so
astra's software-key spoof is no longer *accepted* as confidential. But since no
Mac can produce the residency proof, enforcing it means **no Mac earns
confidential** — which is the honest truth, not a bug.

Direction (supersedes Phase B's App Attest producer work):
1. **On Macs, stop offering `attested-confidential`.** The top honest tier is
   `hardware-attested` (genuine Apple device via MDA / an App Attest *object*)
   plus best-effort posture. Update product copy to match (it is already
   "experimental / aims to"; make it "hardware-attested, not confidential" on
   Mac).
2. **Real confidential = confidential-compute hardware** (SEV-SNP / TDX /
   H100-CC / PCC-style attested nodes) as a separate backend. That is the only
   substrate on which the residency + memory-isolation guarantee holds.
3. Optionally make the Mac agent's signing key SE-resident (SecKeyCreateRandomKey
   + `kSecAttrTokenIDSecureEnclave`) so the honest key can't be exfiltrated —
   good hygiene, but NOT verifiable remotely, so it does not by itself stop the
   spoof.

## Scope note: this closes the exploit, not the whole guarantee

Assertion-based signing closes the specific hole (a portable signing identity).
It does NOT by itself make the confidential guarantee unconditional, because the
prompt is sealed to a separate encryption key and, on commodity Apple silicon,
there is no general-compute TEE — so "the operator cannot read the prompt"
ultimately rests on OS posture, not hardware memory isolation. The maximal
Mac-side stack (non-portable identity, an SE-resident decryption key that can't
leave the box, un-spoofable posture, plaintext hygiene, and a public known-good
transparency log) plus the on-device reproduction of the attack as the
acceptance gate is laid out in **docs/plans/0003-confidential-hardening-plan.md**.
An unconditional guarantee against a determined owner (kernel 0-day / physical
RAM attack) is out of reach on a Mac and needs confidential-compute hardware — a
separate track.
